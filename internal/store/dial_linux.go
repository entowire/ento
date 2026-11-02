package store

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// setUserTimeout sets TCP_USER_TIMEOUT (see dialDB).
func setUserTimeout(network, address string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, int(dbUserTimeout.Milliseconds()))
	})
	if err != nil {
		return err
	}
	return serr
}
