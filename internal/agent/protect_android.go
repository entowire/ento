package agent

import (
	"fmt"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

// protectSockets hands WireGuard's UDP sockets (IPv4 and, if open, IPv6) to protect.
func protectSockets(dev *device.Device, protect func(fd int) bool) error {
	b, ok := dev.Bind().(conn.PeekLookAtSocketFd)
	if !ok {
		return fmt.Errorf("protect: the WireGuard bind does not expose its sockets")
	}
	fd4, err4 := b.PeekLookAtSocketFd4()
	fd6, err6 := b.PeekLookAtSocketFd6()
	if err4 != nil && err6 != nil {
		return fmt.Errorf("protect: no WireGuard socket: %v", err4)
	}
	for _, s := range []struct {
		fd  int
		err error
	}{{fd4, err4}, {fd6, err6}} {
		if s.err == nil && !protect(s.fd) {
			return fmt.Errorf("protect: the system refused socket %d", s.fd)
		}
	}
	return nil
}
