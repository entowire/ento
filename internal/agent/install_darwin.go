//go:build darwin

package agent

import (
	"errors"
	"fmt"
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	installBinary = "/usr/local/bin/ento"
	launchdLabel  = "ento.agent"
	plistPath     = "/Library/LaunchDaemons/" + launchdLabel + ".plist"
	logPath       = "/Library/Logs/ento-agent.log"
)

// Install copies the running binary, writes the launchd daemon and (re)starts the agent. A token,
// if given, is kept for the first start and deleted once enrolled. A device turned off with Down
// stays off: the daemon is updated, but not loaded. On an enrolled device a token is refused, unless
// force: then the old enrollment is removed first (checkEnrollment).
func Install(cfg Config, token string, force bool) error {
	cfg.defaults()
	if os.Geteuid() != 0 {
		return errors.New("install must run as root (sudo)")
	}
	replace, err := checkEnrollment(cfg.StateDir, token, force)
	if err != nil {
		return err
	}
	if replace {
		if err := Uninstall(cfg, true); err != nil {
			return fmt.Errorf("remove the old enrollment: %w", err)
		}
	}
	if err := prepareInstall(cfg, token, installBinary); err != nil {
		return err
	}
	args := []string{installBinary, "agent", "run", "--state-dir", cfg.StateDir,
		"--listen-port", strconv.Itoa(cfg.ListenPort), "--mtu", strconv.Itoa(cfg.MTU),
		"--token-file", filepath.Join(cfg.StateDir, "enroll.token"), "--delete-token"}
	if cfg.LogDrops {
		args = append(args, "--log-drops")
	}
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>` + launchdLabel + `</string>
  <key>ProgramArguments</key>
  <array>
`
	for _, a := range args {
		plist += "    <string>" + html.EscapeString(a) + "</string>\n"
	}
	plist += `  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>` + logPath + `</string>
  <key>StandardErrorPath</key><string>` + logPath + `</string>
</dict>
</plist>
`
	if err := os.WriteFile(plistPath, []byte(plist), 0o644); err != nil {
		return err
	}
	// Re-running install is how a device picks up a new binary: replace the loaded daemon.
	_ = exec.Command("launchctl", "bootout", "system/"+launchdLabel).Run()
	if IsDown(cfg.StateDir) {
		return nil
	}
	if err := launchctl("enable", "system/"+launchdLabel); err != nil {
		return err
	}
	return launchctl("bootstrap", "system", plistPath)
}

// ServiceInstalled reports whether the agent's launchd daemon is installed for stateDir.
func ServiceInstalled(stateDir string) bool {
	b, err := os.ReadFile(plistPath)
	return err == nil && sameDir(stateDirArg(plistStrings(string(b))), stateDir)
}

var plistString = regexp.MustCompile(`<string>([^<]*)</string>`)

// plistStrings returns the strings of a property list, in order (ProgramArguments among them).
func plistStrings(plist string) []string {
	var out []string
	for _, m := range plistString.FindAllStringSubmatch(plist, -1) {
		out = append(out, html.UnescapeString(m[1]))
	}
	return out
}

// RunningAsService reports whether launchd started this process.
func RunningAsService() bool { return os.Getppid() == 1 }

// Down turns the tunnel off until Up: it unloads the daemon and disables it, which launchd
// remembers across reboots (or it stops an agent running in the foreground). The interface goes
// away with the agent.
func Down(cfg Config) error {
	cfg.defaults()
	if os.Geteuid() != 0 {
		return errors.New("down must run as root (sudo)")
	}
	if ServiceInstalled(cfg.StateDir) {
		if err := launchctl("disable", "system/"+launchdLabel); err != nil {
			return err
		}
		_ = exec.Command("launchctl", "bootout", "system/"+launchdLabel).Run()
	}
	// Whatever still runs (the daemon on its way out, or an agent in a terminal) is stopped too.
	if err := stopForeground(cfg.StateDir); err != nil {
		return err
	}
	return setDown(cfg.StateDir, true)
}

// Up undoes Down: the daemon is enabled and loaded again (or started, if it is loaded).
func Up(cfg Config) error {
	cfg.defaults()
	if os.Geteuid() != 0 {
		return errors.New("up must run as root (sudo)")
	}
	if err := setDown(cfg.StateDir, false); err != nil {
		return err
	}
	if err := launchctl("enable", "system/"+launchdLabel); err != nil {
		return err
	}
	if exec.Command("launchctl", "print", "system/"+launchdLabel).Run() == nil {
		return launchctl("kickstart", "system/"+launchdLabel)
	}
	return launchctl("bootstrap", "system", plistPath)
}

func launchctl(args ...string) error {
	out, err := exec.Command("launchctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return nil
}

// agentProcess reports whether process pid runs the agent (and is not another process that got the
// PID of one that is gone).
func agentProcess(pid int) bool {
	out, err := exec.Command("ps", "-o", "command=", "-p", strconv.Itoa(pid)).Output()
	return err == nil && isAgentCommand(strings.Fields(string(out)))
}

// Uninstall stops the agent and removes the daemon; with purge, the state (the device's identity)
// too. The interface goes away with the agent.
func Uninstall(cfg Config, purge bool) error {
	cfg.defaults()
	if os.Geteuid() != 0 {
		return errors.New("uninstall must run as root (sudo)")
	}
	_ = exec.Command("launchctl", "bootout", "system/"+launchdLabel).Run()
	if err := os.Remove(plistPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if purge {
		return os.RemoveAll(cfg.StateDir)
	}
	return setDown(cfg.StateDir, false)
}
