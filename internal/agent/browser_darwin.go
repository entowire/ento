//go:build darwin

package agent

import (
	"os"
	"os/exec"
	"strconv"
)

// openBrowser opens url in the desktop session of the user who ran the command (sudo), best effort.
func openBrowser(url string) bool {
	if os.Getenv("ENTO_NO_BROWSER") != "" {
		return false
	}
	if uid := os.Getenv("SUDO_UID"); os.Geteuid() == 0 && uid != "" {
		// Open it in that user's GUI session (launchctl asuser), not as root.
		if _, err := strconv.Atoi(uid); err != nil {
			return false
		}
		return exec.Command("launchctl", "asuser", uid, "sudo", "-u", os.Getenv("SUDO_USER"), "open", url).Start() == nil
	}
	return exec.Command("open", url).Start() == nil
}

// canOpenBrowser reports whether openBrowser may open a link here: always, unless turned off. (Only
// the Linux agent guards the device's own sign-in so far, so elsewhere the control nodes answer
// with a device code whatever this says.)
func canOpenBrowser() bool { return os.Getenv("ENTO_NO_BROWSER") == "" }
