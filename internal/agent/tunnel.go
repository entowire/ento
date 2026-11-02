package agent

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// tunnel is a network's WireGuard interface on this device: the kernel's (Linux) or wireguard-go
// running inside the agent with the system's TUN driver (every platform).
type tunnel interface {
	// SetAddress makes prefix the only address of the interface; its length decides which overlay
	// destinations are routed into it.
	SetAddress(prefix netip.Prefix) error
	// AddRoute routes dst into the interface (control addresses during enrollment, routes' networks);
	// RemoveRoute takes such a route away again.
	AddRoute(dst netip.Prefix) error
	RemoveRoute(dst netip.Prefix) error
	// RepairAddress puts prefix back as the interface's address, and brings it up, when another
	// program removed it or took it down (NetworkManager's Disconnect); true when it had to.
	RepairAddress(prefix netip.Prefix) (bool, error)
	// Status returns WireGuard's view of every peer.
	Status() (map[wgtypes.Key]PeerStatus, error)
	// Configure sets the private key and makes the peers match desired; unchanged peers are left
	// alone, so established sessions survive network map updates.
	Configure(key wgtypes.Key, desired []PeerConfig) error
	// Close releases the handles; a kernel interface stays up, an in-process one goes away.
	Close() error
	// Delete removes the interface.
	Delete() error
	// IfName is the interface's name as the system knows it (macOS picks utunN itself).
	IfName() string
	// SetExit sends all traffic but the device's own networks and WireGuard's packets into the
	// interface (an exit in use: exit.go), or stops it; turning it off when it is off cleans up after
	// an agent that stopped without.
	SetExit(on bool) error
	// PersonTraffic is how many bytes of the person's traffic (the filter's person rules) the device
	// sent since the filter was last applied.
	PersonTraffic() (uint64, error)
	// SetFilter applies the network map's inbound filter (nil: everything passes); an unchanged
	// filter is left alone.
	SetFilter(f *inboundFilter) error
}

// PeerConfig is the desired configuration of one WireGuard peer.
type PeerConfig struct {
	PublicKey    wgtypes.Key
	PresharedKey wgtypes.Key // zero for none
	// AllowedIPs: the peer's overlay address, and the networks reached through it (routes).
	AllowedIPs []netip.Prefix
	Endpoint   string // "" keeps whatever the device has learned
	// Keepalive is WireGuard's persistent keepalive towards the peer (0: none, so an idle peer costs
	// nothing; a phone's radio wakes for every packet).
	Keepalive time.Duration
}

// PeerStatus is what WireGuard reports about a peer.
type PeerStatus struct {
	Endpoint      string
	LastHandshake time.Time
	RxBytes       int64
	TxBytes       int64
}

// keepalive keeps NAT mappings open and lets control nodes see that a device is alive.
const keepalive = 25 * time.Second

func deviceStatus(dev *wgtypes.Device) map[wgtypes.Key]PeerStatus {
	out := make(map[wgtypes.Key]PeerStatus, len(dev.Peers))
	for _, p := range dev.Peers {
		st := PeerStatus{LastHandshake: p.LastHandshakeTime, RxBytes: p.ReceiveBytes, TxBytes: p.TransmitBytes}
		if p.Endpoint != nil {
			st.Endpoint = p.Endpoint.String()
		}
		out[p.PublicKey] = st
	}
	return out
}

// planConfig returns the change that makes dev match key, port and desired, or nil when it already
// does.
func planConfig(dev *wgtypes.Device, key wgtypes.Key, port int, desired []PeerConfig) (*wgtypes.Config, error) {
	want := map[wgtypes.Key]PeerConfig{}
	for _, p := range desired {
		want[p.PublicKey] = p
	}
	var peers []wgtypes.PeerConfig
	current := map[wgtypes.Key]wgtypes.Peer{}
	for _, cur := range dev.Peers {
		current[cur.PublicKey] = cur
		if _, ok := want[cur.PublicKey]; !ok {
			peers = append(peers, wgtypes.PeerConfig{PublicKey: cur.PublicKey, Remove: true})
		}
	}
	for _, p := range desired {
		ka := p.Keepalive
		pc := wgtypes.PeerConfig{
			PublicKey:                   p.PublicKey,
			ReplaceAllowedIPs:           true,
			PersistentKeepaliveInterval: &ka,
		}
		for _, a := range p.AllowedIPs {
			pc.AllowedIPs = append(pc.AllowedIPs, net.IPNet{IP: a.Addr().AsSlice(), Mask: net.CIDRMask(a.Bits(), 32)})
		}
		psk := p.PresharedKey
		pc.PresharedKey = &psk
		if p.Endpoint != "" {
			addr, err := net.ResolveUDPAddr("udp", p.Endpoint)
			if err != nil {
				return nil, fmt.Errorf("endpoint %s: %w", p.Endpoint, err)
			}
			pc.Endpoint = addr
		}
		if cur, ok := current[p.PublicKey]; ok && sameConfig(cur, pc) {
			continue
		}
		peers = append(peers, pc)
	}
	cfg := wgtypes.Config{ListenPort: &port, Peers: peers}
	if dev.PrivateKey != key {
		cfg.PrivateKey = &key
	}
	if cfg.PrivateKey == nil && len(peers) == 0 && dev.ListenPort == port {
		return nil, nil
	}
	return &cfg, nil
}

func sameConfig(cur wgtypes.Peer, want wgtypes.PeerConfig) bool {
	if cur.PresharedKey != *want.PresharedKey || len(cur.AllowedIPs) != len(want.AllowedIPs) {
		return false
	}
	have := map[string]bool{}
	for _, a := range cur.AllowedIPs {
		have[a.String()] = true
	}
	for _, a := range want.AllowedIPs {
		if !have[a.String()] {
			return false
		}
	}
	if want.Endpoint != nil && (cur.Endpoint == nil || cur.Endpoint.String() != want.Endpoint.String()) {
		return false
	}
	return cur.PersistentKeepaliveInterval == *want.PersistentKeepaliveInterval
}
