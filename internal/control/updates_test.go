package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/store"
	"entowire.com/ento/internal/update"
)

// signedRelease writes a release of version v (one file per platform) signed with throwaway keys
// it makes the pinned ones for the test, as publish-site.sh signs (ssh-keygen -Y, openssl).
func signedRelease(t *testing.T, dir, v string) {
	t.Helper()
	for _, tool := range []string{"ssh-keygen", "openssl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not found")
		}
	}
	keys := t.TempDir()
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

	os.MkdirAll(dir, 0o755)
	files := map[string]any{}
	for _, p := range []string{"linux-amd64", "darwin-arm64"} {
		name := "ento-" + p
		body := []byte("binary " + v + " " + p)
		os.WriteFile(filepath.Join(dir, name), body, 0o644)
		sum := sha256.Sum256(body)
		files[p] = map[string]any{"name": name, "sha256": hex.EncodeToString(sum[:]), "size": len(body)}
	}
	m, _ := json.Marshal(map[string]any{"version": v, "released": "2026-10-13T09:00:00Z", "files": files})
	mf := filepath.Join(dir, "manifest.json")
	os.WriteFile(mf, m, 0o644)
	run(nil, "ssh-keygen", "-Y", "sign", "-q", "-f", filepath.Join(keys, "ed"), "-n", update.Namespace, mf)
	os.WriteFile(mf+".p256.sig", run(m, "openssl", "dgst", "-sha256", "-sign", filepath.Join(keys, "p.key")), 0o644)
}

func TestUpdates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The release is published on a web server the control node downloads it from.
	pub := t.TempDir()
	signedRelease(t, filepath.Join(pub, "0.37.0"), "0.37.0")
	web := httptest.NewServer(http.FileServer(http.Dir(pub)))
	defer web.Close()

	srv, st := startTestNetwork(t, ctx, "100.64.0.0/16")
	srv.cfg.Version, srv.cfg.UpdatesDir, srv.cfg.Releases, srv.cfg.UpdatesExcept = "0.37.0", t.TempDir(), web.URL, "servers"
	if err := srv.prepareRelease(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(srv.cfg.UpdatesDir, "0.37.0", "ento-linux-amd64")); err != nil {
		t.Fatalf("not downloaded: %v", err)
	}
	admin := adminOf(t, ctx, srv, st, "ops-laptop", "admins")
	device := func(name string, groups ...string) (*testClient, store.Peer) {
		tok, _, _ := IssueToken(ctx, st, TokenOptions{Approve: true, Groups: groups, Name: name})
		srv.checkVersion(ctx)
		c, res := enroll(t, tok, name)
		p, _ := st.PeerByAddress(ctx, netip.MustParseAddr(res.Address))
		return c, p
	}
	laptop, _ := device("laptop-1", "laptops")
	canary, _ := device("canary-1", "canaries")
	member, _ := device("node-a", "servers")
	offered := func(c *testClient) string {
		var nm api.NetMap
		c.do(t, "GET", api.PathNetMap, nil, &nm)
		if nm.Update == nil {
			return ""
		}
		return nm.Update.Version
	}

	// By default (auto) every device is offered the node's release, except the servers.
	if v := offered(laptop); v != "0.37.0" {
		t.Fatalf("auto: laptop offered %q", v)
	}
	if v := offered(member); v != "" {
		t.Fatalf("a server was offered %q", v)
	}

	// The files: the manifest, its signatures and the listed files, nothing else.
	get := func(c *testClient, path string) int { return c.do(t, "GET", path, nil, nil) }
	if code := get(laptop, api.PathUpdate+"/0.37.0/ento-linux-amd64"); code != 200 {
		t.Fatalf("file: HTTP %d", code)
	}
	for _, p := range []string{"/0.37.0/secret", "/0.36.0/manifest.json", "/0.37.0/..%2fmanifest.json"} {
		if code := get(laptop, api.PathUpdate+p); code != http.StatusNotFound {
			t.Errorf("%s: HTTP %d", p, code)
		}
	}

	// Validation of the policy, and admins only.
	for _, bad := range []api.UpdatesPolicy{
		{Mode: "sometimes"},
		{Mode: "approve"},
		{Mode: "approve", Approved: "0.37"},
		{Mode: "auto", Approved: "0.37.0"},
		{Mode: "auto", FirstGroup: "canaries"},
		{Mode: "auto", FirstHours: 3},
	} {
		if code := admin.do(t, "PUT", api.PathAdminUpdates, bad, nil); code != http.StatusBadRequest {
			t.Errorf("%+v: HTTP %d", bad, code)
		}
	}
	if code := laptop.do(t, "PUT", api.PathAdminUpdates, api.UpdatesPolicy{Mode: "off"}, nil); code != http.StatusForbidden {
		t.Fatalf("a device set the policy: HTTP %d", code)
	}

	// approve: only the approved release.
	admin.do(t, "PUT", api.PathAdminUpdates, api.UpdatesPolicy{Mode: "approve", Approved: "0.36.9"}, nil)
	if v := offered(laptop); v != "" {
		t.Fatalf("approve 0.36.9: offered %q", v)
	}
	admin.do(t, "PUT", api.PathAdminUpdates, api.UpdatesPolicy{Mode: "approve", Approved: "0.37.0"}, nil)
	if v := offered(laptop); v != "0.37.0" {
		t.Fatalf("approve 0.37.0: offered %q", v)
	}

	// A group first: the others only hours after the release was first offered.
	admin.do(t, "PUT", api.PathAdminUpdates, api.UpdatesPolicy{Mode: "auto", FirstGroup: "canaries", FirstHours: 24}, nil)
	if v := offered(canary); v != "0.37.0" {
		t.Fatalf("first group: offered %q", v)
	}
	if v := offered(laptop); v != "" {
		t.Fatalf("not in the first group: offered %q", v)
	}
	if _, ok, _ := srv.offerFor(ctx, mustPeer(t, ctx, st, "laptop-1"), time.Now().Add(25*time.Hour)); !ok {
		t.Fatal("not offered 25 hours later")
	}

	// off: nothing.
	admin.do(t, "PUT", api.PathAdminUpdates, api.UpdatesPolicy{Mode: "off"}, nil)
	if v := offered(canary); v != "" {
		t.Fatalf("off: offered %q", v)
	}

	// The admins' view.
	var info api.UpdatesInfo
	admin.do(t, "GET", api.PathAdminUpdates, nil, &info)
	if info.Release != "0.37.0" || info.Policy.Mode != "off" || info.Except != "servers" || len(info.Devices) < 4 {
		t.Fatalf("info %+v", info)
	}

	// A release whose files do not match their manifest is not offered.
	bad := t.TempDir()
	signedRelease(t, filepath.Join(bad, "0.38.0"), "0.38.0")
	os.WriteFile(filepath.Join(bad, "0.38.0", "ento-linux-amd64"), []byte("tampered"), 0o644)
	web2 := httptest.NewServer(http.FileServer(http.Dir(bad)))
	defer web2.Close()
	srv.cfg.Version, srv.cfg.Releases = "0.38.0", web2.URL
	if err := srv.prepareRelease(ctx); err == nil {
		t.Fatal("a tampered release was prepared")
	}
	srv.release.mu.Lock()
	still := srv.release.version
	srv.release.mu.Unlock()
	if still != "0.37.0" {
		t.Fatalf("after a failed release the node offers %q", still)
	}
}

func mustPeer(t *testing.T, ctx context.Context, st store.Store, name string) store.Peer {
	t.Helper()
	peers, _ := st.Peers(ctx)
	for _, p := range peers {
		if p.Hostname == name {
			return p
		}
	}
	t.Fatalf("no peer %s", name)
	return store.Peer{}
}
