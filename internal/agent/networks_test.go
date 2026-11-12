package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Without the agent's state (root's), --network says to use sudo, not that the device is in no
// network (0.53.1).
func TestNetworkStateDirNotRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every directory")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	_, err := NetworkStateDir(dir, "md.example.com")
	if err == nil || !strings.Contains(err.Error(), "sudo") {
		t.Fatalf("got %v", err)
	}
}

// TestDefaultNetwork: `ento network DOMAIN` makes a joined network the one commands act for
// without --network; the first network's domain puts it back, and so does leaving it.
func TestDefaultNetwork(t *testing.T) {
	dir := t.TempDir()
	if err := SaveState(dir, State{RecordDomain: "first.example.com"}); err != nil {
		t.Fatal(err)
	}
	joined := NetworkDir(dir, "md.example.com")
	if err := os.MkdirAll(joined, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(joined, membershipFile), []byte(`{"domain":"md.example.com"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if d := DefaultNetwork(dir); d != "" {
		t.Fatalf("default before any choice: %q", d)
	}
	if err := SetDefaultNetwork(dir, "other.example.com"); err == nil {
		t.Fatal("a network the device is not in became the default")
	}
	if err := SetDefaultNetwork(dir, "MD.example.com."); err != nil {
		t.Fatal(err)
	}
	if d := DefaultNetwork(dir); d != "md.example.com" {
		t.Fatalf("default: %q", d)
	}
	if err := SetDefaultNetwork(dir, "first.example.com"); err != nil {
		t.Fatal(err)
	}
	if d := DefaultNetwork(dir); d != "" {
		t.Fatalf("default after choosing the first: %q", d)
	}
	_ = SetDefaultNetwork(dir, "md.example.com")
	if err := os.RemoveAll(joined); err != nil {
		t.Fatal(err)
	}
	if d := DefaultNetwork(dir); d != "" {
		t.Fatalf("default after leaving it: %q", d)
	}
}
