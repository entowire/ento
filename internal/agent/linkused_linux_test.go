//go:build linux

package agent

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A linked network's last use is kept on disk (at most once an hour unless forced), so that one
// nobody uses is left after Config.LinkIdle across restarts of the agent too.
func TestLinkLastUsed(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(LinksDir(dir), "acme"), 0o700); err != nil {
		t.Fatal(err)
	}
	if !linkLastUsed(dir, "acme").IsZero() {
		t.Fatal("a use before any was recorded")
	}
	markLinkUsed(dir, "acme", true)
	first := linkLastUsed(dir, "acme")
	if time.Since(first) > time.Minute {
		t.Fatalf("recorded %v", first)
	}
	old := time.Now().Add(-8 * 24 * time.Hour).UTC().Format(time.RFC3339)
	if err := os.WriteFile(filepath.Join(LinksDir(dir), "acme", usedFile), []byte(old+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	markLinkUsed(dir, "acme", false) // within the hour of the last write: not written again
	if time.Since(linkLastUsed(dir, "acme")) < 7*24*time.Hour {
		t.Fatal("an unforced mark within the hour was written")
	}
	markLinkUsed(dir, "acme", true)
	if time.Since(linkLastUsed(dir, "acme")) > time.Minute {
		t.Fatal("a forced mark was not written")
	}
}
