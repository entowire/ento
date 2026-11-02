package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"time"

	"entowire.com/ento/internal/api"
)

// Linked networks on a device (see docs/design.md, "Linked networks"). Each one has a directory
// under <state dir>/links/<name>/:
//
//	request     written by `ento agent link`: join this linked network
//	remove      written by `ento agent unlink`: leave it and delete everything
//	error       why the last join attempt failed
//	state.json  the device's membership: key, address, control nodes, port, approval
//	posture-failing  the posture checks the device fails there (while it fails any)
//	home-posture-failing  the checks of the home network's link the device fails: while it does,
//	                 the home network refuses it credentials for this linked network
//
// The running agent acts on these files, so joining and leaving need no restart.

// NamespaceName returns the network namespace of a linked network.
func NamespaceName(link string) string { return "ento-" + link }

// Linked networks live in network namespaces, which only Linux has.
var errNoLinks = errors.New("linked networks need Linux (network namespaces)")

// LinkState is a device's membership in a linked network.
type LinkState struct {
	State
	ListenPort    int       `json:"listen_port"`
	ApprovedUntil time.Time `json:"approved_until"`
}

var validLinkName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,9}$`)

// ValidLinkName reports whether name can be a linked network's name.
func ValidLinkName(name string) bool { return validLinkName.MatchString(name) }

// LinksDir is where the linked networks of an agent are kept.
func LinksDir(stateDir string) string { return filepath.Join(stateDir, "links") }

func linkInterface(name string) string { return "enl-" + name }

// LoadLinkState reads a linked network's membership.
func LoadLinkState(stateDir, name string) (LinkState, error) {
	var ls LinkState
	b, err := os.ReadFile(filepath.Join(LinksDir(stateDir), name, stateFile))
	if errors.Is(err, os.ErrNotExist) {
		return ls, ErrNotEnrolled
	}
	if err != nil {
		return ls, err
	}
	if err := json.Unmarshal(b, &ls); err != nil {
		return ls, fmt.Errorf("corrupt link state: %w", err)
	}
	return ls, nil
}

func saveLinkState(stateDir, name string, ls LinkState) error {
	dir := filepath.Join(LinksDir(stateDir), name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(ls, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, stateFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, stateFile))
}

// RequestLink asks the running agent to join a linked network.
func RequestLink(stateDir, name string) error {
	if !linksSupported {
		return errNoLinks
	}
	if !ValidLinkName(name) {
		return errors.New("link name: 1 to 10 lowercase letters, digits or dashes")
	}
	dir := filepath.Join(LinksDir(stateDir), name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(dir, "error"))
	return os.WriteFile(filepath.Join(dir, "request"), nil, 0o600)
}

// RequestUnlink asks the running agent to leave a linked network.
func RequestUnlink(stateDir, name string) error {
	dir := filepath.Join(LinksDir(stateDir), name)
	if _, err := os.Stat(dir); err != nil {
		return fmt.Errorf("not linked to %s", name)
	}
	return os.WriteFile(filepath.Join(dir, "remove"), nil, 0o600)
}

// LinkError returns the error of the last join attempt, if any.
func LinkError(stateDir, name string) string {
	b, _ := os.ReadFile(filepath.Join(LinksDir(stateDir), name, "error"))
	return string(b)
}

// linkFailingFile is where a linked network's runner keeps the posture checks the device fails there.
func linkFailingFile(stateDir, name string) string {
	return filepath.Join(LinksDir(stateDir), name, "posture-failing")
}

// writeFailing keeps the checks a device fails in a file (removed when it fails none).
func writeFailing(path string, failing []api.PostureFailure) {
	if len(failing) == 0 {
		_ = os.Remove(path)
		return
	}
	b, err := json.Marshal(failing)
	if err != nil {
		return
	}
	if os.WriteFile(path+".tmp", b, 0o600) == nil {
		_ = os.Rename(path+".tmp", path)
	}
}

// linkHomeFailingFile is where the checks that the home network's link requires and the device fails
// are kept (from the home network's last refusal).
func linkHomeFailingFile(stateDir, name string) string {
	return filepath.Join(LinksDir(stateDir), name, "home-posture-failing")
}

// firstReportWait is how long, after the agent started, a request for a link's credential waits
// for the home network to take the device's first posture report: a link that requires checks
// refuses a device it holds no recent report of (a device that was off longer than its credential
// lasted renews at once). A home network that takes no reports (older than ento 0.13) delays only
// the requests of this first moment. staleRetry is how soon a request refused only for want of a
// recent report is made again (a report was just asked for), at most staleRetries times in a row.
// Variables for tests.
var (
	firstReportWait = 15 * time.Second
	staleRetry      = 5 * time.Second
)

const staleRetries = 3

// homeCredential asks the home network for a credential for linked network name (a token too when
// req.Join). Its answer is kept in homeFailing: the checks of the home network's link the device
// fails when it was refused over its posture, nothing otherwise (no file: no answer). stale reports
// a refusal only for want of a recent report: the home runner reports at once, and asking again in
// a few seconds is worth it.
func homeCredential(ctx context.Context, home *runner, name, homeFailing string, req api.LinkCredentialRequest) (res api.LinkCredentialResponse, stale bool, err error) {
	home.awaitReport(ctx, firstReportWait)
	homeAPI := &AdminClient{Controls: home.controls(), Key: home.key()}
	err = homeAPI.Do(ctx, "POST", api.PathLinks+"/"+name+"/credential", req, &res)
	if err == nil || HTTPStatus(err) != 0 { // an answer: refused over posture, or not
		writeFailing(homeFailing, PostureRefusal(err))
	}
	if onlyStale(PostureRefusal(err)) {
		home.askReport()
		stale = true
	}
	return res, stale, err
}

// onlyStale reports whether every failing check only lacks a recent report (none at all: false).
func onlyStale(f []api.PostureFailure) bool {
	return len(f) > 0 && !slices.ContainsFunc(f, func(x api.PostureFailure) bool { return !staleFailure([]api.PostureFailure{x}) })
}

// LinkHomePostureFailing returns the posture checks the home network's link requires that the device
// failed when it last asked for a credential: until it passes them, it gets none (and, once its
// credential expires, loses its access there).
func LinkHomePostureFailing(stateDir, name string) []api.PostureFailure {
	var out []api.PostureFailure
	if b, err := os.ReadFile(linkHomeFailingFile(stateDir, name)); err == nil {
		_ = json.Unmarshal(b, &out)
	}
	return out
}

// LinkPostureFailing returns the posture checks the device fails in a linked network, as the
// running agent last heard from it.
func LinkPostureFailing(stateDir, name string) []api.PostureFailure {
	var out []api.PostureFailure
	if b, err := os.ReadFile(linkFailingFile(stateDir, name)); err == nil {
		_ = json.Unmarshal(b, &out)
	}
	return out
}

// Links lists the names of the linked networks known to an agent.
func Links(stateDir string) []string {
	entries, _ := os.ReadDir(LinksDir(stateDir))
	var out []string
	for _, e := range entries {
		if e.IsDir() && ValidLinkName(e.Name()) {
			out = append(out, e.Name())
		}
	}
	return out
}

func exists(path string) bool { _, err := os.Stat(path); return err == nil }
