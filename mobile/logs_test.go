//go:build linux

package mobile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLogs(t *testing.T) {
	dir := t.TempDir()
	done := make(chan error, 1)
	go func() { done <- StartLogs(dir) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("StartLogs did not return")
	}
	AppLog("Connect tapped")
	agentLogf("posture reported: %s", "disk encrypted")
	got := Logs()
	for _, want := range []string{"app: started, agent", "app: Connect tapped", "agent: posture reported: disk encrypted", "===== crash-go.txt"} {
		if !strings.Contains(got, want) {
			t.Errorf("logs lack %q:\n%s", want, got)
		}
	}
	// Rotation keeps one older file, and what is shared stays bounded.
	line := strings.Repeat("x", 1000)
	for i := 0; i < 2500; i++ {
		AppLog(line)
	}
	if _, err := os.Stat(filepath.Join(dir, "ento.log.1")); err != nil {
		t.Fatalf("not rotated: %v", err)
	}
	if fi, _ := os.Stat(filepath.Join(dir, "ento.log")); fi.Size() >= logMax {
		t.Fatalf("log %d bytes", fi.Size())
	}
	if n := len(Logs()); n > shareMax+(64<<10) {
		t.Fatalf("shared %d bytes", n)
	}
}
