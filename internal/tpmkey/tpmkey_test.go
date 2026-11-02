//go:build linux && !android

package tpmkey

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// swtpm starts a software TPM listening on a socket in a temporary directory (skipped without
// swtpm), with its state in dir.
func swtpm(t *testing.T, dir string) string {
	t.Helper()
	bin, err := exec.LookPath("swtpm")
	if err != nil {
		t.Skip("no swtpm")
	}
	sock := filepath.Join(t.TempDir(), "tpm.sock")
	cmd := exec.Command(bin, "socket", "--tpm2", "--tpmstate", "dir="+dir,
		"--server", "type=unixio,path="+sock, "--ctrl", "type=unixio,path="+sock+".ctrl",
		"--flags", "startup-clear,not-need-init")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	for i := 0; i < 100 && !Available(sock); i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if !Available(sock) {
		t.Fatal("swtpm did not start")
	}
	return sock
}

func TestKey(t *testing.T) {
	state := t.TempDir()
	sock := swtpm(t, t.TempDir())
	k, err := Load(sock, state)
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256([]byte("hello"))
	sig, err := k.SignDigest(d[:])
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(k.Public(), d[:], sig) {
		t.Fatal("the signature does not verify")
	}
	// Loaded again from the blob: the same key.
	k2, err := Load(sock, state)
	if err != nil {
		t.Fatal(err)
	}
	if !k2.Public().Equal(k.Public()) {
		t.Fatal("another key after loading the blob again")
	}
	if fi, err := os.Stat(filepath.Join(state, File)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("blob file: %v %v", fi, err)
	}
	// The blob copied to a machine with another TPM: refused, never replaced.
	other := swtpm(t, t.TempDir())
	if _, err := Load(other, state); err == nil {
		t.Fatal("another TPM took the key")
	}
	k3, err := Load(sock, state)
	if err != nil || !k3.Public().Equal(k.Public()) {
		t.Fatalf("the blob was replaced: %v", err)
	}
}
