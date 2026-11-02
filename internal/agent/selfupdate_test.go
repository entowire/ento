//go:build (linux && !android) || (darwin && !ios)

package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/update"
)

// releaseServer serves a release of version v as a control node does (api.PathUpdate), signed with
// throwaway keys made the pinned ones for the test; its binary for this platform is body.
func releaseServer(t *testing.T, v, body string) (*httptest.Server, string) {
	t.Helper()
	for _, tool := range []string{"ssh-keygen", "openssl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not found")
		}
	}
	keys, root := t.TempDir(), t.TempDir()
	run := func(stdin []byte, name string, args ...string) []byte {
		cmd := exec.Command(name, args...)
		cmd.Stdin = bytes.NewReader(stdin)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s %v: %v", name, args, err)
		}
		return out
	}
	run(nil, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(keys, "ed"))
	run(nil, "openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", filepath.Join(keys, "p.key"))
	pem := run(nil, "openssl", "ec", "-in", filepath.Join(keys, "p.key"), "-pubout")
	pub, _ := os.ReadFile(filepath.Join(keys, "ed.pub"))
	t.Cleanup(update.UseKeysForTest(pub, pem))

	dir := filepath.Join(root, strings.TrimPrefix(api.PathUpdate, "/"), v)
	os.MkdirAll(dir, 0o755)
	name := "ento-" + runtime.GOOS + "-" + runtime.GOARCH
	os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644)
	sum := sha256.Sum256([]byte(body))
	m, _ := json.Marshal(map[string]any{"version": v, "released": "2026-10-13T09:00:00Z", "files": map[string]any{
		runtime.GOOS + "-" + runtime.GOARCH: map[string]any{"name": name, "sha256": hex.EncodeToString(sum[:]), "size": len(body)}}})
	mf := filepath.Join(dir, "manifest.json")
	os.WriteFile(mf, m, 0o644)
	run(nil, "ssh-keygen", "-Y", "sign", "-q", "-f", filepath.Join(keys, "ed"), "-n", update.Namespace, mf)
	os.WriteFile(mf+".p256.sig", run(m, "openssl", "dgst", "-sha256", "-sign", filepath.Join(keys, "p.key")), 0o644)
	srv := httptest.NewServer(http.FileServer(http.Dir(root)))
	t.Cleanup(srv.Close)
	return srv, filepath.Join(dir, name)
}

func TestSelfUpdate(t *testing.T) {
	// The "binaries" are scripts answering `version` as ento does.
	script := func(v string) string { return "#!/bin/sh\necho " + v + "\n" }
	srv, _ := releaseServer(t, "0.37.0", script("0.37.0"))
	bin := filepath.Join(t.TempDir(), "ento")
	os.WriteFile(bin, []byte(script("0.36.0")), 0o755)
	state := t.TempDir()
	var execed []string
	oldPath, oldExec := selfPath, execSelf
	defer func() { selfPath, execSelf = oldPath, oldExec }()
	selfPath = func() (string, error) { return bin, nil }
	execSelf = func(exe string) error { execed = append(execed, exe); return nil }

	var logs []string
	a := &runner{cfg: Config{Version: "0.36.0", StateDir: state, Logf: func(f string, args ...any) { logs = append(logs, f) }},
		env: netEnv{http: srv.Client()}}
	ctl := api.Control{Address: strings.TrimPrefix(srv.URL, "http://")}

	// Not newer: nothing fetched.
	if err := a.selfUpdate(context.Background(), ctl, "0.35.0"); err == nil {
		t.Fatal("installed an older release")
	}
	// The offered release: verified, installed, the previous kept, started again; executable by
	// everyone whatever the umask (0077 left it root's alone, so a control node's own user could not
	// start it).
	old := syscall.Umask(0o077)
	err := a.selfUpdate(context.Background(), ctl, "0.37.0")
	syscall.Umask(old)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(bin); fi.Mode().Perm() != 0o755 {
		t.Fatalf("installed with mode %v", fi.Mode().Perm())
	}
	if b, _ := os.ReadFile(bin); string(b) != script("0.37.0") {
		t.Fatalf("binary now %q", b)
	}
	if b, _ := os.ReadFile(bin + ".prev"); string(b) != script("0.36.0") {
		t.Fatalf("previous binary %q", b)
	}
	if len(execed) != 1 || execed[0] != bin {
		t.Fatalf("started again: %v", execed)
	}

	// The new release starts but never receives a map: put back after three starts.
	for i := 0; i < maxUpdateStarts; i++ {
		CheckPendingUpdate(state, "0.37.0", t.Logf)
	}
	if b, _ := os.ReadFile(bin); string(b) != script("0.37.0") {
		t.Fatal("put back too early")
	}
	CheckPendingUpdate(state, "0.37.0", t.Logf)
	if b, _ := os.ReadFile(bin); string(b) != script("0.36.0") {
		t.Fatalf("not put back: %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(state, failedUpdateFile)); strings.TrimSpace(string(b)) != "0.37.0" {
		t.Fatalf("failed release not remembered: %q", b)
	}
	// A release that failed here is not taken again.
	a.maybeUpdate(context.Background(), ctl, &api.Update{Version: "0.37.0"})
	if updating.Load() {
		t.Fatal("a release that failed here was taken again")
	}

	// A release that comes up: its first map confirms it.
	os.Remove(filepath.Join(state, failedUpdateFile))
	os.WriteFile(bin, []byte(script("0.36.0")), 0o755)
	if err := a.selfUpdate(context.Background(), ctl, "0.37.0"); err != nil {
		t.Fatal(err)
	}
	CheckPendingUpdate(state, "0.37.0", t.Logf)
	b := &runner{cfg: Config{Version: "0.37.0", StateDir: state, Logf: t.Logf}}
	b.confirmUpdate()
	if _, err := os.Stat(filepath.Join(state, pendingUpdateFile)); !os.IsNotExist(err) {
		t.Fatal("the pending update stayed after the first map")
	}

	// A file that does not match its manifest (a control node serving something else) is refused,
	// and the binary stays as it was.
	bad, file := releaseServer(t, "0.38.0", script("0.38.0"))
	os.WriteFile(file, []byte(script("0.38.1")), 0o644) // same size, other bytes
	before, _ := os.ReadFile(bin)
	a.cfg.Version = "0.37.0"
	a.env.http = bad.Client()
	err = a.selfUpdate(context.Background(), api.Control{Address: strings.TrimPrefix(bad.URL, "http://")}, "0.38.0")
	if err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("a tampered binary: %v", err)
	}
	if after, _ := os.ReadFile(bin); !bytes.Equal(before, after) {
		t.Fatal("the binary changed on a failed update")
	}
	if _, err := os.Stat(bin + ".new"); !os.IsNotExist(err) {
		t.Fatal("a .new file was left")
	}
}
