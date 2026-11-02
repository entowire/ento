//go:build linux

package agent

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"time"
)

// openBrowser opens url in the desktop session of the user who ran the command, best effort.
// Commands run with sudo, and a browser started as root would be the wrong user on the wrong
// display, so it is started as that user (SUDO_USER, or the current user when not root), with the
// display variables of their graphical session, read from their systemd user manager. It returns
// false when there is no graphical session to open it in (e.g. over SSH), and the link is only
// printed.
func openBrowser(url string) bool {
	if os.Getenv("ENTO_NO_BROWSER") != "" {
		return false
	}
	name := os.Getenv("SUDO_USER")
	if os.Geteuid() != 0 || name == "" || name == "root" {
		if os.Geteuid() == 0 {
			return false // a root shell: no user desktop to open it in
		}
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return false
		}
		return exec.Command("xdg-open", url).Start() == nil
	}
	u, err := user.Lookup(name)
	if err != nil {
		return false
	}
	runtime := "/run/user/" + u.Uid
	base := []string{"XDG_RUNTIME_DIR=" + runtime, "DBUS_SESSION_BUS_ADDRESS=unix:path=" + runtime + "/bus",
		"HOME=" + u.HomeDir, "USER=" + u.Username, "PATH=/usr/local/bin:/usr/bin:/bin"}
	out, err := exec.Command("runuser", append([]string{"-u", u.Username, "--", "env"},
		append(base, "systemctl", "--user", "show-environment")...)...).Output()
	if err != nil {
		return false
	}
	var display []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		for _, k := range []string{"DISPLAY=", "WAYLAND_DISPLAY=", "XAUTHORITY="} {
			if strings.HasPrefix(sc.Text(), k) {
				display = append(display, sc.Text())
			}
		}
	}
	if len(display) == 0 {
		return false
	}
	cmd := exec.Command("runuser", append([]string{"-u", u.Username, "--", "env"},
		append(append(base, display...), "xdg-open", url)...)...)
	cmd.Stdout, cmd.Stderr = nil, nil
	if err := cmd.Start(); err != nil {
		return false
	}
	// xdg-open returns once the browser was asked; do not wait for the browser itself.
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err == nil
	case <-time.After(5 * time.Second):
		return true
	}
}
