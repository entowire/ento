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
