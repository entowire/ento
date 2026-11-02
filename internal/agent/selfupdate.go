//go:build (linux && !android) || (darwin && !ios)

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/update"
)

// Self-updates (0.37): when its home network's map offers a newer release (api.NetMap.Update), the
// agent fetches its manifest, the manifest's signatures and its own platform's file from the
// control node it talks to, checks them with the keys built into its own binary (never an older
// version), writes the new binary beside itself, keeps the old one as <binary>.prev and starts
// itself again in its place (exec: same process, so the service manager sees nothing; with kernel
// WireGuard the tunnel stays up). A new binary that starts three times without receiving a network
// map is replaced by the previous one again, and that release is left alone afterwards.

const (
	pendingUpdateFile = "update-pending.json"
	failedUpdateFile  = "update-failed"
	maxUpdateStarts   = 3
)

type pendingUpdate struct {
	From   string    `json:"from"`
	To     string    `json:"to"`
	Starts int       `json:"starts"`
	At     time.Time `json:"at"`
}

var updating atomic.Bool

// selfPath and execSelf are this binary's path and starting it again in this process; replaced in tests.
var (
	selfPath = binaryPath
	execSelf = func(exe string) error { return syscall.Exec(exe, os.Args, os.Environ()) }
)

// CheckPendingUpdate runs first when the agent starts: a release installed by a self-update counts
// its starts until it receives a network map (confirmUpdate); one that keeps failing is put back.
func CheckPendingUpdate(stateDir, version string, logf func(string, ...any)) {
	path := filepath.Join(stateDir, pendingUpdateFile)
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var p pendingUpdate
	if json.Unmarshal(b, &p) != nil || p.To != version {
		os.Remove(path) // another version runs now (put back, or installed otherwise)
		return
	}
	p.Starts++
	if p.Starts <= maxUpdateStarts {
		if b, err := json.Marshal(p); err == nil {
			os.WriteFile(path, b, 0o600)
		}
		return
	}
	exe, err := selfPath()
	if err != nil {
		logf("update: %s failed to start %d times, and the previous binary cannot be found: %v", version, maxUpdateStarts, err)
		return
	}
	if err := os.Rename(exe+".prev", exe); err != nil {
		logf("update: %s failed to start %d times, and %s could not be put back: %v", version, maxUpdateStarts, p.From, err)
		return
	}
	os.WriteFile(filepath.Join(stateDir, failedUpdateFile), []byte(version+"\n"), 0o600)
	os.Remove(path)
	logf("update: %s did not come up after %d starts: %s put back, and %s will not be taken again", version, maxUpdateStarts, p.From, version)
	if err := execSelf(exe); err != nil {
		logf("update: start %s again: %v", p.From, err)
	}
}

// confirmUpdate: the first network map since a self-update proves the new release works.
func (a *runner) confirmUpdate() {
	path := filepath.Join(a.cfg.StateDir, pendingUpdateFile)
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var p pendingUpdate
	if json.Unmarshal(b, &p) == nil && p.To == a.cfg.Version {
		a.cfg.Logf("update: %s running and connected (was %s)", p.To, p.From)
	}
	os.Remove(path)
}

// maybeUpdate starts installing an offered release in the background, when it is one to take.
func (a *runner) maybeUpdate(ctx context.Context, ctl api.Control, u *api.Update) {
	if u == nil || a.cfg.NoSelfUpdate || !update.Newer(u.Version, a.cfg.Version) {
		return
	}
	if b, err := os.ReadFile(filepath.Join(a.cfg.StateDir, failedUpdateFile)); err == nil && strings.TrimSpace(string(b)) == u.Version {
		return
	}
	if !updating.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer updating.Store(false)
		if err := a.selfUpdate(ctx, ctl, u.Version); err != nil {
			a.cfg.Logf("update: %s not installed: %v", u.Version, err)
			// Asked again with a later map, at most every hour.
			select {
			case <-ctx.Done():
			case <-time.After(time.Hour):
			}
		}
	}()
}

func (a *runner) selfUpdate(ctx context.Context, ctl api.Control, v string) error {
	base := fmt.Sprintf("http://%s%s/%s/", ctl.Address, api.PathUpdate, v)
	get := func(name string, limit int64) ([]byte, error) {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+name, nil)
		if err != nil {
			return nil, err
		}
		resp, err := a.env.http.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%s: %s", name, resp.Status)
		}
		return io.ReadAll(io.LimitReader(resp.Body, limit))
	}
	var parts [3][]byte
	for i, n := range []string{"manifest.json", "manifest.json.sig", "manifest.json.p256.sig"} {
		b, err := get(n, 1<<20)
		if err != nil {
			return err
		}
		parts[i] = b
	}
	m, err := update.Verify(parts[0], parts[1], parts[2])
	if err != nil {
		return err
	}
	if m.Version != v || !update.Newer(m.Version, a.cfg.Version) {
		return fmt.Errorf("the manifest is for %s, not a newer release than %s", m.Version, a.cfg.Version)
	}
	f, ok := m.Files[runtime.GOOS+"-"+runtime.GOARCH]
	if !ok {
		return fmt.Errorf("no file for %s-%s", runtime.GOOS, runtime.GOARCH)
	}
	raw, err := get(f.Name, f.Size+1)
	if err != nil {
		return err
	}
	bin, err := f.Check(strings.NewReader(string(raw)))
	if err != nil {
		return err
	}
	exe, err := selfPath()
	if err != nil {
		return err
	}
	next := exe + ".new"
	if err := os.WriteFile(next, bin, 0o755); err != nil {
		return fmt.Errorf("write %s: %w", next, err)
	}
	if err := os.Chmod(next, 0o755); err != nil { // whatever the umask
		os.Remove(next)
		return err
	}
	vctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	out, err := exec.CommandContext(vctx, next, "version").Output()
	cancel()
	if err != nil || strings.TrimSpace(string(out)) != v {
		os.Remove(next)
		return fmt.Errorf("the new binary answers %q (%v)", strings.TrimSpace(string(out)), err)
	}
	os.Remove(exe + ".prev")
	if err := os.Link(exe, exe+".prev"); err != nil {
		os.Remove(next)
		return fmt.Errorf("keep the previous binary: %w", err)
	}
	p, _ := json.Marshal(pendingUpdate{From: a.cfg.Version, To: v, At: time.Now().UTC()})
	if err := os.WriteFile(filepath.Join(a.cfg.StateDir, pendingUpdateFile), p, 0o600); err != nil {
		os.Remove(next)
		return err
	}
	if err := os.Rename(next, exe); err != nil {
		os.Remove(filepath.Join(a.cfg.StateDir, pendingUpdateFile))
		return err
	}
	a.cfg.Logf("update: %s installed over %s (checked with this binary's release keys); starting it", v, a.cfg.Version)
	return execSelf(exe)
}

func binaryPath() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	p, err = filepath.EvalSymlinks(p)
	if err != nil {
		return "", err
	}
	if p == "" {
		return "", errors.New("no path for this binary")
	}
	return p, nil
}
