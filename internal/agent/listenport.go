package agent

import (
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
)

// DefaultListenPort is the agent's WireGuard UDP port; WSLListenPort is its default inside WSL.
// With WSL's mirrored networking Windows and Linux share one port space, but neither lists the
// other's sockets as in use: an ento on Windows and one in WSL both on 51830 either fail to bind
// or have one take the other's handshake replies (0.56.5, found on canti: the Windows agent sent
// its handshakes and never saw an answer). Apart, they never meet.
const (
	DefaultListenPort = 51830
	WSLListenPort     = 51880
)

// inWSL reports whether this is Linux inside Windows' WSL (its kernels name Microsoft).
var inWSL = func() bool {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	return err == nil && strings.Contains(strings.ToLower(string(b)), "microsoft")
}

// ChooseListenPort keeps cfg.ListenPort when it is free and otherwise takes the next free UDP port
// above it (up to 100 further), saying so: another WireGuard client on the same machine (another
// network's agent, wg-quick) using the port must not keep this agent from starting (0.38.2; it
// had exited at once, "address already in use", and the service restarted it for ever). The port
// only matters for direct connections, and peers learn it from the control nodes.
//
// Inside WSL the default port is WSLListenPort, also for agents installed with 51830 in their
// service: Windows' own ento keeps 51830.
func ChooseListenPort(cfg *Config) {
	cfg.defaults()
	if cfg.ListenPort == DefaultListenPort && inWSL() {
		cfg.ListenPort = WSLListenPort
	}
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
