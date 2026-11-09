package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"entowire.com/ento/internal/agent"
)

// waitEnrolled reports completion once the agent saved its state, and the agent's reason when
// redeeming the invitation failed, instead of claiming the device joined.
func TestWaitEnrolled(t *testing.T) {
	ctx := context.Background()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "enroll.token"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	agent.SetEnrollError(dir, errors.New("enrollment refused: 403 token used"))
	err := waitEnrolled(ctx, dir, "example.com")
	if err == nil || !strings.Contains(err.Error(), "used up") {
		t.Fatalf("refused invitation: got %v", err)
	}
	agent.SetEnrollError(dir, errors.New("enrollment failed: timeout"))
	if err := waitEnrolled(ctx, dir, "example.com"); err == nil || !strings.Contains(err.Error(), "tries again") {
		t.Fatalf("failed attempt: got %v", err)
	}
	agent.SetEnrollError(dir, nil)
	if agent.EnrollError(dir) != "" || !agent.Joining(dir) {
		t.Fatal("a cleared error is gone, the invitation still pending")
	}

	if err := agent.SaveState(dir, agent.State{}); err != nil {
		t.Fatal(err)
	}
	if err := waitEnrolled(ctx, dir, "example.com"); err != nil {
		t.Fatalf("enrolled: got %v", err)
	}
}
