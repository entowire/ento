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

// canOpenBrowser reports whether openBrowser may open a link here: always, unless turned off. (Only
// the Linux agent guards the device's own sign-in so far, so elsewhere the control nodes answer
// with a device code whatever this says.)
func canOpenBrowser() bool { return os.Getenv("ENTO_NO_BROWSER") == "" }
