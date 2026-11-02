//go:build windows

package main

import (
	"context"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"entowire.com/ento/internal/agent"
)

// runService runs fn under the Windows service manager when the process was started by it (the
// agent installed with `ento agent install`); stopping the service cancels fn's context. A service
// has no console, so its output goes to <state dir>\agent.log (0.32.1; before, a service that
// stopped said nothing anywhere).
func runService(fn func(ctx context.Context) error, stateDir string) (bool, error) {
	if ok, err := svc.IsWindowsService(); err != nil || !ok {
		return false, err
	}
	if f := openServiceLog(stateDir); f != nil {
		defer f.Close()
		log.SetOutput(f)
		os.Stderr = f
		_ = windows.SetStdHandle(windows.STD_ERROR_HANDLE, windows.Handle(f.Fd())) // a crash's trace too
	}
	return true, svc.Run(agent.ServiceName, handler{fn})
}

// openServiceLog opens the service's log for appending; past 5 MB it starts over, keeping the
// previous one as agent.log.1. The state directory is SYSTEM's and Administrators' only.
func openServiceLog(dir string) *os.File {
	if dir == "" || os.MkdirAll(dir, 0o700) != nil {
		return nil
	}
	p := filepath.Join(dir, "agent.log")
	if fi, err := os.Stat(p); err == nil && fi.Size() > 5<<20 {
		_ = os.Rename(p, p+".1")
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil
	}
	return f
}

type handler struct {
	fn func(ctx context.Context) error
}

func (h handler) Execute(_ []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.fn(ctx) }()
	s <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			cancel()
			if err != nil {
				log.Printf("ento: %v", err)
				return false, 1
			}
			return false, 0
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				s <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				s <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				return false, 0
			}
		}
	}
}
