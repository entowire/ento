//go:build windows

package agent

import (
	"os"
	"os/exec"
)

// openBrowser opens url with the user's default browser, best effort (the command runs in the
// user's own, elevated, session).
func openBrowser(url string) bool {
	if os.Getenv("ENTO_NO_BROWSER") != "" {
		return false
	}
	return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start() == nil
}
