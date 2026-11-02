//go:build linux

package agent

// DefaultStateDir is where the agent keeps its identity and state.
const DefaultStateDir = "/var/lib/ento"

// openHostTunnel opens the home network's interface: kernel WireGuard, or WireGuard inside the
// agent when asked (Config.Userspace) or when the kernel has no WireGuard (e.g. some containers).
func openHostTunnel(cfg Config) (tunnel, error) {
	if !cfg.Userspace {
		ifc, err := OpenIface(cfg.Interface, cfg.ListenPort, cfg.MTU)
		if err == nil {
			return ifc, nil
		}
		cfg.Logf("kernel WireGuard unavailable (%v); running WireGuard inside the agent", err)
	}
	return openUserspace(cfg.Interface, cfg.ListenPort, cfg.MTU, cfg.Logf)
}
