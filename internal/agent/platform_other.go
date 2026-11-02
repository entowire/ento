//go:build !linux

package agent

// openHostTunnel opens the home network's interface: WireGuard inside the agent, on the system's
// TUN driver.
func openHostTunnel(cfg Config) (tunnel, error) {
	return openUserspace(cfg.Interface, cfg.ListenPort, cfg.MTU, cfg.Logf)
}
