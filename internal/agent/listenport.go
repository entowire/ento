package agent

import (
	"errors"
	"net"
	"syscall"
)

// ChooseListenPort keeps cfg.ListenPort when it is free and otherwise takes the next free UDP port
// above it (up to 100 further), saying so: another WireGuard client on the same machine (another
// network's agent, wg-quick) using the port must not keep this agent from starting (0.38.2; it
// had exited at once, "address already in use", and the service restarted it for ever). The port
// only matters for direct connections, and peers learn it from the control nodes.
func ChooseListenPort(cfg *Config) {
	cfg.defaults()
	if udpPortFree(cfg.ListenPort) {
		return
	}
	for p := cfg.ListenPort + 1; p <= cfg.ListenPort+100 && p <= 65535; p++ {
		if udpPortFree(p) {
			cfg.Logf("WireGuard port %d is in use on this machine (another WireGuard client?): using %d", cfg.ListenPort, p)
			cfg.ListenPort = p
			return
		}
	}
	cfg.Logf("WireGuard port %d and the 100 above it are in use: starting anyway", cfg.ListenPort)
}

// udpPortFree reports whether nothing holds the UDP port, IPv4 or IPv6 (a system without IPv6
// counts as free there).
func udpPortFree(port int) bool {
	for _, network := range []string{"udp4", "udp6"} {
		c, err := net.ListenUDP(network, &net.UDPAddr{Port: port})
		if err != nil {
			if errors.Is(err, syscall.EADDRINUSE) {
				return false
			}
			continue
		}
		c.Close()
	}
	return true
}
