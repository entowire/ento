package agent

import (
	"net/netip"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
)

// plainPeers are the WireGuard peers of the plain WireGuard peers this device carries as their
// gateway (Constitution 6.2): each its own address, its preshared key from its configuration (9.3),
// no endpoint (it comes to the gateway: WireGuard learns where from), no keepalive. Only the
// kernel's WireGuard on Linux forwards their traffic (filter_linux.go); elsewhere they are left
// out, and said so once. The caller holds a.mu.
func (a *runner) plainPeers(nm api.NetMap, controls, seen map[wgtypes.Key]bool) []PeerConfig {
	if len(nm.Self.Plain) == 0 {
		a.plainNoted = false
		return nil
	}
	if !plainSupported(a.ifc) || a.linked() {
		if !a.plainNoted {
			a.plainNoted = true
			a.cfg.Logf("this device carries %d plain WireGuard peers, but only a Linux device with the kernel's WireGuard forwards for them: left out", len(nm.Self.Plain))
		}
		return nil
	}
	var out []PeerConfig
	for _, p := range nm.Self.Plain {
		key, err := wgtypes.ParseKey(p.PublicKey)
		if err != nil {
			continue
		}
		ip, err := netip.ParseAddr(p.Address)
		if err != nil || !ip.Is4() || controls[key] || seen[key] {
			continue
		}
		seen[key] = true
		pc := PeerConfig{PublicKey: key, AllowedIPs: []netip.Prefix{netip.PrefixFrom(ip, 32)}}
		if p.PresharedKey != "" {
			if k, err := wgtypes.ParseKey(p.PresharedKey); err == nil {
				pc.PresharedKey = k
			}
		}
		out = append(out, pc)
	}
	return out
}
