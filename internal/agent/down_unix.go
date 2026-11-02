//go:build linux || darwin

package agent

import (
	"syscall"
	"time"
)

// stopForeground stops an agent that runs for stateDir outside the service manager (in a terminal
// or a container) and waits until it has exited.
func stopForeground(stateDir string) error {
	r, ok := RunningAgent(stateDir)
	if !ok || !agentProcess(r.PID) {
		return nil
	}
	if err := syscall.Kill(r.PID, syscall.SIGTERM); err != nil {
		return err
	}
	return waitStopped(stateDir, 15*time.Second)
}
