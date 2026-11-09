package agent

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// downFile marks a device whose tunnel was turned off with `ento agent down`: install then leaves
// the service off, and status says so, until `ento agent up` (or until an agent runs again).
const downFile = "down"

// IsDown reports whether the device's tunnel was turned off with `ento agent down`.
func IsDown(stateDir string) bool {
	_, err := os.Stat(filepath.Join(stateDir, downFile))
	return err == nil
}

func setDown(stateDir string, down bool) error {
	path := filepath.Join(stateDir, downFile)
	if !down {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return os.WriteFile(path, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o600)
}

// stateDirArg returns the --state-dir of an agent command line, "" if it has none.
func stateDirArg(args []string) string {
	for i, a := range args {
		name, value, hasValue := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if !strings.HasPrefix(a, "-") || name != "state-dir" {
			continue
		}
		if hasValue {
			return value
		}
		if i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// isAgentCommand reports whether a command line runs the agent (`ento agent run`, or `up` as
// older services have it).
func isAgentCommand(args []string) bool {
	return len(args) >= 3 && args[1] == "agent" && (args[2] == "run" || args[2] == "up")
}

// sameDir reports whether two paths name the same existing directory.
func sameDir(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	fa, err := os.Stat(a)
	if err != nil {
		return false
	}
	fb, err := os.Stat(b)
	return err == nil && os.SameFile(fa, fb)
}

// waitStopped waits until no agent runs for stateDir.
func waitStopped(stateDir string, timeout time.Duration) error {
	for deadline := time.Now().Add(timeout); ; time.Sleep(100 * time.Millisecond) {
		r, ok := RunningAgent(stateDir)
		if !ok || !agentProcess(r.PID) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the agent (process %d) did not stop", r.PID)
		}
	}
}

// ErrForceWithoutToken is returned by Install when force is set without a token.
var ErrForceWithoutToken = errors.New("--force replaces the device's enrollment with a token's: give the token")

// checkEnrollment decides what Install does with a token on a device that may be enrolled already.
// A token is only used for a first enrollment: on an enrolled device it is refused (it used to be
// ignored, and the device kept an identity the control plane may have deleted), unless force is
// set, in which case replace is true and the caller removes the old enrollment (Uninstall with
// purge) before installing. Without a token, install updates the service and keeps the enrollment.
func checkEnrollment(stateDir, token string, force bool) (replace bool, err error) {
	if token == "" {
		if force {
			return false, ErrForceWithoutToken
		}
		return false, nil
	}
	st, err := LoadState(stateDir)
	switch {
	case errors.Is(err, ErrNotEnrolled):
		return false, nil
	case force:
		return true, nil
	case err != nil:
		return false, fmt.Errorf("%s: %w; the token was not used (--force replaces the state with the token's enrollment)", stateDir, err)
	}
	return false, fmt.Errorf("this device is already enrolled (address %s, public key %s); the token was not used.\n"+
		"To replace this enrollment with the token's: ento agent install --force --token-file FILE (the old device\n"+
		"stays on the control plane until an administrator deletes it). To keep it and only update the service:\n"+
		"ento agent install (without a token)",
		st.Address, wgtypes.Key(st.PrivateKey).PublicKey())
}

// prepareInstall copies the running binary to binary and, for a device not enrolled yet, stores
// the token (mode 0600) for the service's first start; the agent deletes it once enrolled.
func prepareInstall(cfg Config, token, binary string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if self, err = filepath.EvalSymlinks(self); err != nil {
		return err
	}
	if self != binary {
		if err := os.MkdirAll(filepath.Dir(binary), 0o755); err != nil {
			return err
		}
		if err := copyFile(self, binary, 0o755); err != nil {
			return fmt.Errorf("install binary: %w", err)
		}
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return err
	}
	if _, err := LoadState(cfg.StateDir); errors.Is(err, ErrNotEnrolled) {
		if token == "" {
			return errors.New("not enrolled: a token is required for the first installation")
		}
		_ = os.Remove(filepath.Join(cfg.StateDir, enrollErrorFile)) // a new invitation: the last one's error is gone
		return os.WriteFile(filepath.Join(cfg.StateDir, "enroll.token"), []byte(token+"\n"), 0o600)
	} else if err != nil {
		return err
	}
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}
