package agent

import (
	"os"
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
