package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"entowire.com/ento/internal/agent"
	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/update"
)

const defaultReleases = update.DefaultReleases

func updateCmd(ctx context.Context, args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return updateNow(ctx, args)
	}
	switch cmd, args := sub(args); cmd {
	case "check":
		return updateCheck(ctx, args)
	case "verify":
		return updateVerify(args)
	case "install":
		return updateInstall(ctx, args)
	case "rollback":
		return updateRollback(args)
	case "keys":
		s, p := update.Fingerprints()
		fmt.Printf("release keys built into this binary:\n  ssh   %s\n  p256  %s\n", s, p)
		return nil
	default:
		return errors.New("usage: ento update [--from URL] | check [--from URL] [--short] | install --version V [--dir DIR] [--from URL] | rollback [--dir DIR] | verify DIR | keys")
	}
}

// updateCheck fetches the current release's manifest, checks it with the keys built into this binary
// and says whether it is newer than this one.
func updateCheck(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("update check", flag.ContinueOnError)
	from := fs.String("from", defaultReleases, "where releases are published")
	short := fs.Bool("short", false, "one line for scripts: VERSION RELEASED(unix) newer|current")
	if err := fs.Parse(args); err != nil {
		return err
	}
	base := strings.TrimRight(*from, "/")
	get := func(name string) ([]byte, error) { return fetch(ctx, base+"/"+name, 1<<20) }
	m, err := fetchManifest(get)
	if err != nil {
		return err
	}
	if *short {
		state := "current"
		if update.Newer(m.Version, version) {
			state = "newer"
		}
		fmt.Printf("%s %d %s\n", m.Version, m.Released.Unix(), state)
		return nil
	}
	fmt.Printf("installed  %s\nreleased   %s (%s, signed with both release keys)\n", version, m.Version, m.Released.Format(time.DateOnly))
	if f, ok := m.Files[platform()]; ok {
		fmt.Printf("this platform (%s): %s, %d bytes\n", platform(), f.Name, f.Size)
	}
	if update.Newer(m.Version, version) {
		fmt.Println("an update is available")
		return exitCode{code: 10}
	}
	fmt.Println("up to date")
	return nil
}

// updateVerify checks a release directory as published: its manifest's signatures with the keys
// built into this binary, and every file it lists (scripts/publish-site.sh, before deploying).
func updateVerify(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: ento update verify DIR")
	}
	dir := args[0]
	m, err := fetchManifest(func(name string) ([]byte, error) { return os.ReadFile(filepath.Join(dir, name)) })
	if err != nil {
		return err
	}
	platforms := make([]string, 0, len(m.Files))
	for p := range m.Files {
		platforms = append(platforms, p)
	}
	sort.Strings(platforms)
	for _, p := range platforms {
		f := m.Files[p]
		r, err := os.Open(filepath.Join(dir, f.Name))
		if err != nil {
			return err
		}
		_, err = f.Check(r)
		r.Close()
		if err != nil {
			return err
		}
	}
	fmt.Printf("%s: manifest and %d files verified\n", m.Version, len(platforms))
	return nil
}

func fetchManifest(get func(string) ([]byte, error)) (*update.Manifest, error) {
	var parts [3][]byte
	for i, name := range []string{"manifest.json", "manifest.json.sig", "manifest.json.p256.sig"} {
		b, err := get(name)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		parts[i] = b
	}
	return update.Verify(parts[0], parts[1], parts[2])
}

func fetch(ctx context.Context, url string, limit int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err == nil && int64(len(b)) > limit {
		err = fmt.Errorf("%s: larger than %d bytes", url, limit)
	}
	return b, err
}

// platform names this binary's file in a manifest.
func platform() string { return runtime.GOOS + "-" + runtime.GOARCH }

// updateNow installs the newest published release, if it is newer than this one, and starts the
// agent again with it (0.58): what `ento update check` finds, with no version to type. The
// network's own rollout (ento admin updates) decides when its devices update by themselves; this
// is root's choice to update now, as update install always was.
func updateNow(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	from := fs.String("from", defaultReleases, "where releases are published")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return errors.New("usage: ento update [--from URL]")
	}
	if runtime.GOOS == "windows" {
		return errors.New("on Windows, run the installer again, in a PowerShell run as administrator: irm https://entowire.com/install.ps1 | iex")
	}
	base := strings.TrimRight(*from, "/")
	m, err := fetchManifest(func(name string) ([]byte, error) { return fetch(ctx, base+"/"+name, 1<<20) })
	if err != nil {
		return err
	}
	if !update.Newer(m.Version, version) {
		fmt.Printf("ento %s is up to date (the newest release is %s)\n", version, m.Version)
		return nil
	}
	fmt.Printf("updating ento %s to %s...\n", version, m.Version)
	if err := installRelease(ctx, *from, "", m.Version); err != nil {
		if errors.Is(err, os.ErrPermission) {
			return fmt.Errorf("%w (run it with sudo)", err)
		}
		return err
	}
	restarted, err := agent.Restart(agent.Config{})
	switch {
	case err != nil:
		return fmt.Errorf("installed, but the agent did not start again: %w (sudo ento up, or restart its service)", err)
	case restarted:
		fmt.Printf("the agent runs %s now\n", m.Version)
	}
	return nil
}

// updateInstall replaces this binary (or DIR/ento) with release VERSION: its manifest checked with the
// keys built into the running binary, the version newer than the running one, the file's SHA-256
// and size as the manifest says, and the new binary answering with that version, before it is
// renamed into place. The replaced binary stays as ento.prev (update rollback). Restarting the
// agent or control node is left to the caller, which knows its units.
func updateInstall(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("update install", flag.ContinueOnError)
	want := fs.String("version", "", "the release to install (X.Y.Z)")
	from := fs.String("from", defaultReleases, "where releases are published")
	dir := fs.String("dir", "", "the directory of the binary to replace (default: this binary's)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return installRelease(ctx, *from, *dir, *want)
}

// installRelease is update install's work: release want, from where releases are published, over
// this binary (or dir/ento).
func installRelease(ctx context.Context, from, dir, want string) error {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return errors.New("update install: Linux and macOS only for now")
	}
	target, err := binaryPath(dir)
	if err != nil {
		return err
	}
	if want == version {
		fmt.Printf("%s is installed already\n", version)
		return nil
	}
	if !update.Newer(want, version) {
		return fmt.Errorf("update install: %s is not newer than %s (never downgraded)", want, version)
	}
	base := strings.TrimRight(from, "/") + "/" + want
	m, err := fetchManifest(func(name string) ([]byte, error) { return fetch(ctx, base+"/"+name, 1<<20) })
	if err != nil {
		return err
	}
	if m.Version != want {
		return fmt.Errorf("update install: the manifest of %s says %s", want, m.Version)
	}
	f, ok := m.Files[platform()]
	if !ok {
		return fmt.Errorf("update install: release %s has no file for %s", want, platform())
	}
	raw, err := fetch(ctx, base+"/"+f.Name, f.Size)
	if err != nil {
		return err
	}
	b, err := f.Check(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	next := target + ".new"
	if err := os.WriteFile(next, b, 0o755); err != nil {
		return err
	}
	// Whatever the umask (the members' executor has 0077): services running as users of their own
	// start it too.
	if err := os.Chmod(next, 0o755); err != nil {
		os.Remove(next)
		return err
	}
	out, err := exec.CommandContext(ctx, next, "version").Output()
	if err != nil || strings.TrimSpace(string(out)) != want {
		os.Remove(next)
		return fmt.Errorf("update install: the new binary answers %q (%v), not %s", strings.TrimSpace(string(out)), err, want)
	}
	prev := target + ".prev"
	os.Remove(prev)
	if err := os.Link(target, prev); err != nil {
		os.Remove(next)
		return fmt.Errorf("update install: keeping the previous binary: %w", err)
	}
	if err := os.Rename(next, target); err != nil {
		return err
	}
	fmt.Printf("installed %s over %s (previous kept as %s)\n", want, version, prev)
	return nil
}

// updateRollback puts ento.prev back in place.
func updateRollback(args []string) error {
	fs := flag.NewFlagSet("update rollback", flag.ContinueOnError)
	dir := fs.String("dir", "", "the directory of the binary (default: this binary's)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	target, err := binaryPath(*dir)
	if err != nil {
		return err
	}
	if _, err := os.Stat(target + ".prev"); err != nil {
		return fmt.Errorf("update rollback: no previous binary: %w", err)
	}
	if err := os.Rename(target+".prev", target); err != nil {
		return err
	}
	fmt.Println("previous binary back in place")
	return nil
}

func binaryPath(dir string) (string, error) {
	if dir != "" {
		return filepath.Join(dir, "ento"), nil
	}
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(p)
}

// adminUpdatesCmd shows or sets how the network's devices take new releases (0.37).
func adminUpdatesCmd(ctx context.Context, c *agent.AdminClient, args []string) error {
	const usage = "usage: ento admin updates [auto | approve VERSION | off] [--first GROUP --after HOURS]"
	if len(args) == 0 {
		var info api.UpdatesInfo
		if err := c.Do(ctx, "GET", api.PathAdminUpdates, nil, &info); err != nil {
			if code := agent.HTTPStatus(err); code == 404 || code == 405 {
				return errors.New("the control plane offers no updates (older than ento 0.37)")
			}
			return err
		}
		p := info.Policy
		how := p.Mode
		if p.Mode == "approve" {
			how += " " + p.Approved
		}
		if p.FirstGroup != "" {
			how += fmt.Sprintf(", group %s first, the others %d hours later", p.FirstGroup, p.FirstHours)
		}
		if p.SetBy != "" {
			how += fmt.Sprintf(" (set by %s at %s)", p.SetBy, p.SetAt)
		}
		fmt.Printf("policy   %s\n", how)
		if info.Release != "" {
			fmt.Printf("release  %s, first offered %s\n", info.Release, info.OfferedAt)
		} else {
			fmt.Printf("release  none offered: %s\n", info.Problem)
		}
		if info.Except != "" {
			fmt.Printf("except   group %s (updated otherwise)\n", info.Except)
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "\nID\tNAME\tOS\tVERSION\tUPDATE")
		for _, d := range info.Devices {
			state := "-"
			switch {
			case d.Excluded:
				state = "updated otherwise"
			case d.Version == info.Release && info.Release != "":
				state = "current"
			case d.Offered:
				state = "offered " + info.Release
			case info.Release != "":
				state = "waiting"
			}
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n", d.ID, d.Name, cell(d.OS), cell(d.Version), state)
		}
		return w.Flush()
	}
	var req api.UpdatesPolicy
	mode, rest := sub(args)
	req.Mode = mode
	if mode == "approve" {
		if len(rest) == 0 {
			return errors.New(usage)
		}
		req.Approved, rest = rest[0], rest[1:]
	}
	fs := flag.NewFlagSet("admin updates", flag.ContinueOnError)
	first := fs.String("first", "", "a group offered each release first")
	after := fs.Int("after", 0, "with --first: hours until the other devices are offered it")
	if err := fs.Parse(rest); err != nil || fs.NArg() > 0 {
		return errors.New(usage)
	}
	req.FirstGroup, req.FirstHours = *first, *after
	var out api.UpdatesPolicy
	if err := c.Do(ctx, "PUT", api.PathAdminUpdates, req, &out); err != nil {
		return err
	}
	fmt.Printf("updates: %s%s\n", out.Mode, map[bool]string{true: " " + out.Approved, false: ""}[out.Approved != ""])
	return nil
}
