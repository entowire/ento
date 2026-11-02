package update

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The pinned keys are the release keys of the repository.
func TestPinnedKeys(t *testing.T) {
	for embedded, file := range map[string]string{string(sshKey): "../../release-signing.pub", string(p256Key): "../../release-signing-p256.pem"} {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if embedded != string(b) {
			t.Fatalf("keys/%s differs from %s: copy it again", filepath.Base(file), file)
		}
	}
}

// testKeys swaps the pinned keys for throwaway ones made with ssh-keygen and openssl, the tools
// publish-site.sh signs with, and returns a signer.
func testKeys(t *testing.T) func(msg []byte, ns string) ([]byte, []byte) {
	for _, tool := range []string{"ssh-keygen", "openssl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not found")
		}
	}
	dir := t.TempDir()
	run := func(stdin []byte, name string, args ...string) []byte {
		cmd := exec.Command(name, args...)
		cmd.Stdin = bytes.NewReader(stdin)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s %v: %v", name, args, err)
		}
		return out
	}
	run(nil, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(dir, "ed"))
	run(nil, "openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", filepath.Join(dir, "p256.key"))
	run(nil, "openssl", "ec", "-in", filepath.Join(dir, "p256.key"), "-pubout", "-out", filepath.Join(dir, "p256.pem"))
	oldSSH, oldP := sshKey, p256Key
	t.Cleanup(func() { sshKey, p256Key = oldSSH, oldP })
	sshKey, _ = os.ReadFile(filepath.Join(dir, "ed.pub"))
	p256Key, _ = os.ReadFile(filepath.Join(dir, "p256.pem"))
	return func(msg []byte, ns string) ([]byte, []byte) {
		f := filepath.Join(dir, "msg")
		os.WriteFile(f, msg, 0o600)
		os.Remove(f + ".sig")
		run(nil, "ssh-keygen", "-Y", "sign", "-q", "-f", filepath.Join(dir, "ed"), "-n", ns, f)
		s, _ := os.ReadFile(f + ".sig")
		p := run(msg, "openssl", "dgst", "-sha256", "-sign", filepath.Join(dir, "p256.key"))
		return s, p
	}
}

const good = `{"version": "0.36.0", "released": "2026-10-13T09:00:00Z", "files": {"linux-amd64": {"name": "ento-linux-amd64", "sha256": "` +
	"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" + `", "size": 5}}}`

func TestVerify(t *testing.T) {
	sign := testKeys(t)
	s, p := sign([]byte(good), Namespace)
	m, err := Verify([]byte(good), s, p)
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != "0.36.0" || m.Files["linux-amd64"].Name != "ento-linux-amd64" {
		t.Fatalf("%+v", m)
	}
	if _, err := m.Files["linux-amd64"].Check(strings.NewReader("hello")); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{"hellO", "hell", "hello!"} {
		if _, err := m.Files["linux-amd64"].Check(strings.NewReader(body)); err == nil {
			t.Fatalf("%q passed", body)
		}
	}

	changed := []byte(strings.Replace(good, "0.36.0", "0.36.1", 1))
	if _, err := Verify(changed, s, p); err == nil {
		t.Fatal("a changed manifest verified")
	}
	// Each signature is required: one valid signature with the other missing or wrong fails.
	s2, p2 := sign(changed, Namespace)
	if _, err := Verify(changed, s2, p); err == nil {
		t.Fatal("verified with the P-256 signature of another manifest")
	}
	if _, err := Verify(changed, s, p2); err == nil {
		t.Fatal("verified with the SSH signature of another manifest")
	}
	if _, err := Verify(changed, nil, p2); err == nil {
		t.Fatal("verified without the SSH signature")
	}
	// A release file's signature (namespace ento-release) is not a manifest's.
	s3, p3 := sign([]byte(good), "ento-release")
	if _, err := Verify([]byte(good), s3, p3); err == nil || !strings.Contains(err.Error(), "namespace") {
		t.Fatalf("another namespace: %v", err)
	}
	// Unknown fields and bad entries are refused even when signed.
	for _, bad := range []string{
		strings.Replace(good, `"files"`, `"keys": 1, "files"`, 1),
		strings.Replace(good, "ento-linux-amd64", "../ento", 1),
		strings.Replace(good, "0.36.0", "0.36", 1),
		strings.Replace(good, `"size": 5`, `"size": 0`, 1),
	} {
		s, p := sign([]byte(bad), Namespace)
		if _, err := Verify([]byte(bad), s, p); err == nil {
			t.Fatalf("verified: %s", bad)
		}
	}
}

// Signed with the real keys? Not here: they never leave SOPS. Another pinned key must refuse.
func TestOtherKey(t *testing.T) {
	sign := testKeys(t)
	s, p := sign([]byte(good), Namespace)
	sshKey, p256Key = []byte(oldSSHForTest), []byte(oldP256ForTest)
	if _, err := Verify([]byte(good), s, p); err == nil {
		t.Fatal("verified with keys other than the pinned ones")
	}
}

var oldSSHForTest, oldP256ForTest = string(sshKey), string(p256Key)

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"0.36.0", "0.35.1", true},
		{"0.35.10", "0.35.9", true},
		{"1.0.0", "0.99.99", true},
		{"0.35.1", "0.35.1", false},
		{"0.35.0", "0.35.1", false},
		{"0.36.0", "dev", true},
		{"dev", "0.1.0", false},
		{"0.36.0-rc1", "0.35.0", true},
		{"0.35.1", "0.35.1-3-gabc123", false},
		{"0.35.1", "0.35.1-3-gabc123-dirty", false},
		{"0.35.2", "0.35.1-3-gabc123", true},
		{"0.35.1-3-gabc123", "0.35.1", true},
		{"0.35.1", "dev-abc123", true},
	} {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%s, %s) = %v", c.a, c.b, got)
		}
	}
}
