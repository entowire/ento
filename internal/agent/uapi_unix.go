//go:build !windows

package agent

import (
	"net"
	"syscall"

	"golang.zx2c4.com/wireguard/ipc"
)

func uapiListen(name string) (net.Listener, error) {
	f, err := ipc.UAPIOpen(name)
	if err != nil {
		return nil, err
	}
	return ipc.UAPIListen(name, f)
}

func processAlive(pid int) bool { return syscall.Kill(pid, 0) == nil }
