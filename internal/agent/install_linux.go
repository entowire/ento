//go:build linux

package agent

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

const (
	// installBinary is the command; since 0.50 a symbolic link to installReal, in a directory of
	// its own that the unit lets the agent write, so that it can replace itself (selfupdate.go):
	// /usr/local/bin is read-only in its sandbox (ProtectSystem=strict).
	installBinary = "/usr/local/bin/ento"
	installDir    = "/usr/local/lib/ento"
	installReal   = installDir + "/ento"
	unitName      = "ento-agent.service"
	unitPath      = "/etc/systemd/system/" + unitName
	netnsUnitPath = "/etc/systemd/system/ento-netns@.service"
)

// netnsUnit creates the network namespace of a linked network outside the agent's sandbox, so it
// is visible to the whole system (ip netns exec). The agent starts and stops it.
const netnsUnit = `[Unit]
Description=ento namespace of linked network %%i
Documentation=https://entowire.com
StopWhenUnneeded=no

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=%[1]s agent netns add %%i
ExecStop=%[1]s agent netns del %%i
`

// unit runs the agent with only the capabilities it needs: CAP_NET_ADMIN for its WireGuard
// interfaces, CAP_SYS_ADMIN to enter the namespaces of linked networks.
const unit = `[Unit]
Description=ento agent
Documentation=https://entowire.com
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%[1]s agent run --state-dir %[2]s --interface %[3]s --listen-port %[4]d --mtu %[5]d --token-file %[2]s/enroll.token --delete-token%[6]s
Restart=always
RestartSec=5

CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=%[2]s /etc/netns /usr/local/lib/ento
ProtectHome=yes
PrivateTmp=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX
RestrictNamespaces=net
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
%[7]s
[Install]
WantedBy=multi-user.target
`

// Install copies the running binary, writes the systemd unit and starts the agent. A token, if
// given, is stored (mode 0600) for the first start and deleted once enrollment succeeded. A device
// turned off with Down stays off: the unit is updated, but not started. On an enrolled device a
// token is refused, unless force: then the old enrollment is removed first (checkEnrollment).
func Install(cfg Config, token string, force bool) error {
	cfg.defaults()
	if err := ServiceSupported(); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("install must run as root")
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
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(installDir, 0o755); err != nil { // root's alone, whatever the umask
		return err
	}
	if err := prepareInstall(cfg, token, installReal); err != nil {
		return err
	}
	if err := linkCommand(installBinary, installReal); err != nil {
		return err
	}
	if err := os.MkdirAll(netnsEtcDir, 0o755); err != nil {
		return err
	}
	// Drop logging stays as the service had it (install also updates an installed agent, with no
	// options), unless asked otherwise.
	extra := ""
	if old, err := os.ReadFile(unitPath); cfg.LogDrops || !cfg.LogDropsOff && err == nil && slices.Contains(unitArgs(string(old)), "--log-drops") {
		extra = " --log-drops"
	}
	content := fmt.Sprintf(unit, installBinary, cfg.StateDir, cfg.Interface, cfg.ListenPort, cfg.MTU, extra, tpmGroupLine(tpmDevice))
	if err := os.WriteFile(unitPath, []byte(content), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(netnsUnitPath, []byte(fmt.Sprintf(netnsUnit, installBinary)), 0o644); err != nil {
		return err
	}
	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	keepNetworkManagerAway(cfg.Interface)
	if IsDown(cfg.StateDir) {
		return nil
	}
	if err := systemctl("enable", unitName); err != nil {
		return err
	}
	// Restart rather than start: re-running install is how a device picks up a new binary or unit.
	return systemctl("restart", unitName)
}

// systemdDir exists only on a system booted with systemd (sd_booted(3)).
var systemdDir = "/run/systemd/system"

// ServiceSupported tells why the agent cannot be installed as a service here: on Linux it is a
// systemd service, and some systems run another init (QNAP's QTS, Alpine, OpenWrt, containers).
// install asks it before the words, so that nobody types them for nothing (0.56.6; before, install
// stopped at writing the unit, after the words: "open /etc/systemd/system/ento-agent.service: no
// such file or directory", found on a QNAP NAS).
func ServiceSupported() error {
	if _, err := os.Stat(systemdDir); err != nil {
		return errors.New("this system does not run systemd (" + systemdDir + " is missing), and on Linux the ento agent " +
			"is installed as a systemd service; nothing was installed or changed")
	}
	return nil
}

// ServiceInstalled reports whether the agent's systemd unit is installed for stateDir.
func ServiceInstalled(stateDir string) bool {
	b, err := os.ReadFile(unitPath)
	return err == nil && sameDir(stateDirArg(unitArgs(string(b))), stateDir)
}

// unitArgs returns the command line of a unit's ExecStart.
func unitArgs(unit string) []string {
	for _, line := range strings.Split(strings.ReplaceAll(unit, "\\\n", " "), "\n") {
		if cmd, ok := strings.CutPrefix(strings.TrimSpace(line), "ExecStart="); ok {
			return strings.Fields(cmd)
		}
	}
	return nil
}

// RunningAsService reports whether systemd started this process.
func RunningAsService() bool { return underSystemd() }

// Down turns the tunnel off until Up: it stops the service and keeps it from starting at boot (or
// stops an agent running in the foreground), then removes the WireGuard interfaces, which the
// kernel keeps when the agent merely stops, so that restarts interrupt nothing.
func Down(cfg Config) error {
	cfg.defaults()
	if os.Geteuid() != 0 {
		return errors.New("down must run as root")
	}
	ifname := cfg.Interface
	if r, _ := RunningAgent(cfg.StateDir); r.Interface != "" {
		ifname = r.Interface
	}
	if ServiceInstalled(cfg.StateDir) {
		if err := systemctl("disable", "--now", unitName); err != nil {
			return err
		}
	}
	// An agent may also run outside the service, in a terminal or a container.
	if err := stopForeground(cfg.StateDir); err != nil {
		return err
	}
	if err := setDown(cfg.StateDir, true); err != nil {
		return err
	}
	return removeInterfaces(cfg.StateDir, ifname)
}

// Up undoes Down: the service starts again, now and at boot.
func Up(cfg Config) error {
	cfg.defaults()
	if os.Geteuid() != 0 {
		return errors.New("up must run as root")
	}
	if err := setDown(cfg.StateDir, false); err != nil {
		return err
	}
	return systemctl("enable", "--now", unitName)
}

// removeInterfaces deletes the WireGuard interfaces of the home network, of the networks joined
// besides it and of every linked network. The namespaces of linked networks stay, empty, for the
// agent's next start.
func removeInterfaces(stateDir, ifname string) error {
	errs := []error{deleteWireGuard(netns.None(), ifname)}
	for _, i := range memberInterfaces(stateDir) {
		errs = append(errs, deleteWireGuard(netns.None(), i))
	}
	for _, name := range Links(stateDir) {
		ns, err := netns.GetFromName(NamespaceName(name))
		if err != nil {
			continue // no namespace, so no interface either
		}
		if err := deleteWireGuard(ns, linkInterface(name)); err != nil {
			errs = append(errs, fmt.Errorf("linked network %s: %w", name, err))
		}
		ns.Close()
	}
	return errors.Join(errs...)
}

// deleteWireGuard deletes interface name in namespace ns, if it is a WireGuard interface (the
// kernel's: userspace WireGuard goes away with the agent).
func deleteWireGuard(ns netns.NsHandle, name string) error {
	var h *netlink.Handle
	var err error
	if ns.IsOpen() {
		h, err = netlink.NewHandleAt(ns)
	} else {
		h, err = netlink.NewHandle()
	}
	if err != nil {
		return err
	}
	defer h.Close()
	l, err := h.LinkByName(name)
	var notFound netlink.LinkNotFoundError
	switch {
	case errors.As(err, &notFound):
		return nil
	case err != nil:
		return err
	case l.Type() != "wireguard":
		return nil
	}
	return h.LinkDel(l)
}

// agentProcess reports whether process pid runs the agent (and is not another process that got the
// PID of one that is gone).
func agentProcess(pid int) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	return err == nil && isAgentCommand(strings.Split(strings.TrimRight(string(b), "\x00"), "\x00"))
}

// Uninstall stops the agent, removes the unit and the interface. With purge, the state (and so the
// device's identity) is deleted too.
// linkCommand makes path a symbolic link to target, replacing what is there (an older install's
// binary, or the installer's) in one rename.
func linkCommand(path, target string) error {
	if dest, err := os.Readlink(path); err == nil && dest == target {
		return nil
	}
	tmp := path + ".link"
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func Uninstall(cfg Config, purge bool) error {
	cfg.defaults()
	if os.Geteuid() != 0 {
		return errors.New("uninstall must run as root")
	}
	_ = systemctl("disable", "--now", unitName)
	for _, name := range Links(cfg.StateDir) {
		_ = removeLinkNetwork(name)
		_ = systemctl("stop", fmt.Sprintf(netnsUnitFmt, name))
		_ = DeleteNamespace(name)
	}
	for _, path := range []string{unitPath, netnsUnitPath} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	_ = systemctl("daemon-reload")
	if err := os.Remove(nmConfPath); err == nil {
		_ = exec.Command("systemctl", "try-reload-or-restart", "NetworkManager").Run()
	}
	_ = deleteWireGuard(netns.None(), cfg.Interface)
	for _, i := range memberInterfaces(cfg.StateDir) {
		_ = deleteWireGuard(netns.None(), i)
		_ = applyInboundFilter(netns.None(), i, nil)
	}
	if purge {
		return os.RemoveAll(cfg.StateDir)
	}
	return setDown(cfg.StateDir, false)
}

func systemctl(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %v: %v: %s", args, err, out)
	}
	return nil
}

// nmConfPath keeps NetworkManager away from the agent's interfaces. Left to it, it lists them in the
// desktop's network menu as connections of its own, and Disconnect there takes their address away
// (the agent puts it back, see RepairAddress). "+=" adds to devices other files leave unmanaged.
const nmConfPath = "/etc/NetworkManager/conf.d/90-ento.conf"

const nmConf = `# Written by ento agent install (removed by ento agent uninstall): the ento agent
# configures its own interfaces, so NetworkManager leaves them alone.
[keyfile]
unmanaged-devices+=interface-name:ento*
`

// keepNetworkManagerAway writes nmConfPath where NetworkManager is installed, has it read it, and
// releases the current interface (named otherwise than ento*, it is released for now only).
func keepNetworkManagerAway(ifname string) {
	if _, err := os.Stat("/etc/NetworkManager"); err != nil {
		return
	}
	if old, err := os.ReadFile(nmConfPath); err != nil || string(old) != nmConf {
		if err := os.MkdirAll(filepath.Dir(nmConfPath), 0o755); err != nil {
			return
		}
		if err := os.WriteFile(nmConfPath, []byte(nmConf), 0o644); err != nil {
			return
		}
		_ = exec.Command("systemctl", "try-reload-or-restart", "NetworkManager").Run()
	}
	if nmcli, err := exec.LookPath("nmcli"); err == nil {
		_ = exec.Command(nmcli, "device", "set", ifname, "managed", "no").Run()
	}
}

// tpmDevice is the TPM's resource manager, which the hardware key opens (tpmkey).
const tpmDevice = "/dev/tpmrm0"

// tpmGroupLine gives the agent the group that owns the TPM device (Ubuntu, Debian: tss, mode
// 0660), so that it can open it: the unit's capability set leaves out CAP_DAC_OVERRIDE, without
// which root may not open a device it does not own, and the hardware key was unusable ("open
// /dev/tpmrm0: permission denied", 0.38.2). Empty without a TPM, or when root owns it.
func tpmGroupLine(device string) string {
	fi, err := os.Stat(device)
	if err != nil {
		return ""
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Gid == 0 {
		return ""
	}
	g, err := user.LookupGroupId(strconv.Itoa(int(st.Gid)))
	if err != nil {
		return ""
	}
	return "# The TPM's group, for the hardware key (" + device + ").\nSupplementaryGroups=" + g.Name + "\n"
}
