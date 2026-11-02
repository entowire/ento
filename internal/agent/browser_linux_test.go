//go:build linux

package agent

import (
	"testing"
	"time"
)

// Without a graphical session (tests, SSH, servers) nothing is opened and nothing blocks: the
// link is only printed.
func TestOpenBrowserWithoutSession(t *testing.T) {
	t.Setenv("ENTO_NO_BROWSER", "1")
	if openBrowser("https://example.invalid/") {
		t.Fatal("opened a browser although ENTO_NO_BROWSER is set")
	}
	t.Setenv("ENTO_NO_BROWSER", "")
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")
	start := time.Now()
	if openBrowser("https://example.invalid/") {
		t.Fatal("reported a browser without any graphical session")
	}
	if time.Since(start) > 10*time.Second {
		t.Fatal("openBrowser blocked")
	}
}
