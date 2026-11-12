//go:build windows

package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	// ServiceName is the agent's Windows service.
	ServiceName = "ento"
	installDir  = `C:\Program Files\ento`
)

var installBinary = filepath.Join(installDir, "ento.exe")

func elevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

// Install copies the running binary and wintun.dll (which must sit next to it) into Program Files,
// registers the agent as a Windows service and (re)starts it. A token, if given, is kept for the
// first start and deleted once enrolled. A device turned off with Down stays off: the service is
// updated, but stays disabled. On an enrolled device a token is refused, unless force: then the old
// enrollment is removed first (checkEnrollment).
func Install(cfg Config, token string, force bool) error {
	cfg.defaults()
	if !elevated() {
		return errors.New("install must run as Administrator")
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
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return err
	}
	// The state holds the device's private key: SYSTEM and Administrators only.
	if err := protectStateDir(cfg.StateDir); err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	// A running service holds the binary: stop it before replacing it.
	if s, err := m.OpenService(ServiceName); err == nil {
		stopService(s)
		s.Close()
	}
	if err := prepareInstall(cfg, token, installBinary); err != nil {
		return err
	}
	dll := filepath.Join(filepath.Dir(self), "wintun.dll")
	if filepath.Dir(self) != installDir {
		if err := copyFile(dll, filepath.Join(installDir, "wintun.dll"), 0o644); err != nil {
			return fmt.Errorf("wintun.dll must be next to ento.exe: %w", err)
		}
	}
	if err := installTray(filepath.Dir(self)); err != nil {
		cfg.Logf("the tray program was not installed (signing in still works with ento login): %v", err)
	}
	args := []string{"agent", "run", "--state-dir", cfg.StateDir, "--listen-port", strconv.Itoa(cfg.ListenPort),
		"--mtu", strconv.Itoa(cfg.MTU), "--token-file", filepath.Join(cfg.StateDir, "enroll.token"), "--delete-token"}
	if cfg.LogDrops {
		args = append(args, "--log-drops")
	}
	down := IsDown(cfg.StateDir)
	startType := uint32(mgr.StartAutomatic)
	if down {
		startType = mgr.StartDisabled
	}
	s, err := m.OpenService(ServiceName)
	if err != nil {
		s, err = m.CreateService(ServiceName, installBinary, mgr.Config{
			DisplayName: "ento agent", Description: "WireGuard mesh VPN agent (ento)",
			StartType: startType}, args...)
		if err != nil {
			return err
		}
	} else {
		c, err := s.Config()
		if err != nil {
			s.Close()
			return err
		}
		c.BinaryPathName = windows.EscapeArg(installBinary)
		for _, a := range args {
			c.BinaryPathName += " " + windows.EscapeArg(a)
		}
		c.StartType = startType
		if err := s.UpdateConfig(c); err != nil {
			s.Close()
			return err
		}
	}
	defer s.Close()
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 5 * time.Second}}, 60)
	if down {
		return nil
	}
	return s.Start()
}

// ServiceSupported: the service manager is always there.
func ServiceSupported() error { return nil }

// ServiceInstalled reports whether the agent's service is installed for stateDir. It needs no
// Administrator rights: reading a service's configuration is open to every user.
func ServiceInstalled(stateDir string) bool {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false
	}
	defer windows.CloseServiceHandle(scm)
	name, err := windows.UTF16PtrFromString(ServiceName)
	if err != nil {
		return false
	}
	h, err := windows.OpenService(scm, name, windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return false
	}
	s := &mgr.Service{Name: ServiceName, Handle: h}
	defer s.Close()
	c, err := s.Config()
	if err != nil {
		return false
	}
	args, err := windows.DecomposeCommandLine(c.BinaryPathName)
	return err == nil && sameDir(stateDirArg(args), stateDir)
}

// RunningAsService reports whether the service control manager started this process.
func RunningAsService() bool {
	ok, _ := svc.IsWindowsService()
	return ok
}

// Down turns the tunnel off until Up: the service is stopped and disabled, so it does not start at
// boot either. The interface goes away with the agent.
func Down(cfg Config) error {
	cfg.defaults()
	if !elevated() {
		return errors.New("down must run as Administrator")
	}
	if ServiceInstalled(cfg.StateDir) {
		if err := stopDisabled(); err != nil {
			return err
		}
		// The service reports itself stopped just before its process ends.
		_ = waitStopped(cfg.StateDir, 10*time.Second)
	}
	if r, ok := RunningAgent(cfg.StateDir); ok {
		return fmt.Errorf("the agent runs in a console (process %d): stop it there with Ctrl-C", r.PID)
	}
	return setDown(cfg.StateDir, true)
}

// stopDisabled stops the service and keeps it from starting again.
func stopDisabled() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := setStartType(s, mgr.StartDisabled); err != nil {
		return err
	}
	stopService(s)
	if st, err := s.Query(); err != nil {
		return err
	} else if st.State != svc.Stopped {
		return errors.New("the ento service did not stop")
	}
	return nil
}

// Up undoes Down: the service starts again, now and at boot.
func Up(cfg Config) error {
	cfg.defaults()
	if !elevated() {
		return errors.New("up must run as Administrator")
	}
	if err := setDown(cfg.StateDir, false); err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := setStartType(s, mgr.StartAutomatic); err != nil {
		return err
	}
	if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return err
	}
	return nil
}

func setStartType(s *mgr.Service, startType uint32) error {
	c, err := s.Config()
	if err != nil {
		return err
	}
	if c.StartType == startType {
		return nil
	}
	c.StartType = startType
	return s.UpdateConfig(c)
}

// agentProcess reports whether process pid is alive. Down on Windows stops only the service; an
// agent in a console is reported, not stopped, so a reused PID costs at most a wrong message.
func agentProcess(pid int) bool { return processAlive(pid) }

// Uninstall stops and removes the service; with purge, the state (the device's identity) too.
func Uninstall(cfg Config, purge bool) error {
	cfg.defaults()
	if !elevated() {
		return errors.New("uninstall must run as Administrator")
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if s, err := m.OpenService(ServiceName); err == nil {
		stopService(s)
		err = s.Delete()
		s.Close()
		if err != nil {
			return err
		}
	}
	removeTrayStart()
	if purge {
		return os.RemoveAll(cfg.StateDir)
	}
	return setDown(cfg.StateDir, false)
}

const (
	trayName = "ento-tray"
	runKey   = `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
)

// installTray puts ento-tray.exe, shipped next to ento.exe in the release zip, into Program Files
// and starts it at every sign-in to Windows, for every account (0.35): it tells the person when
// their session ended and signs them in without an administrator. Without the file (a build of
// ento.exe alone) the agent is installed without it. A tray program running in someone's session
// keeps its file open, so the old file is moved aside (Windows lets a running program's file be
// renamed, not replaced) and the new one starts at the next sign-in.
func installTray(srcDir string) error {
	dst := filepath.Join(installDir, trayName+".exe")
	if old, _ := filepath.Glob(dst + ".*.old"); len(old) > 0 {
		for _, f := range old {
			_ = os.Remove(f) // still running somewhere: removed next time
		}
	}
	if !sameDir(srcDir, installDir) {
		src := filepath.Join(srcDir, trayName+".exe")
		if _, err := os.Stat(src); err != nil {
			return nil
		}
		if _, err := os.Stat(dst); err == nil {
			if err := os.Rename(dst, fmt.Sprintf("%s.%d.old", dst, time.Now().UnixNano())); err != nil {
				return err
			}
		}
		if err := copyFile(src, dst, 0o755); err != nil {
			return err
		}
	} else if _, err := os.Stat(dst); err != nil {
		return nil
	}
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(trayName, `"`+dst+`"`)
}

// removeTrayStart stops starting the tray program at sign-in (uninstall).
func removeTrayStart() {
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, runKey, registry.SET_VALUE); err == nil {
		_ = k.DeleteValue(trayName)
		k.Close()
	}
}

func stopService(s *mgr.Service) {
	st, err := s.Control(svc.Stop)
	for i := 0; err == nil && st.State != svc.Stopped && i < 50; i++ {
		time.Sleep(200 * time.Millisecond)
		st, err = s.Query()
	}
}
