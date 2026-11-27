package control

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// wgPeer is the WireGuard configuration of one peer of the control node.
type wgPeer struct {
	PresharedKey wgtypes.Key // zero for none
	AllowedIP    netip.Addr
	// Endpoint, if known, is only used when the peer is added: the node then initiates the
	// handshake itself, so sessions come back right after a restart instead of waiting for the
	// agents' WireGuard timers. It is not part of the peer's identity: an endpoint change must not
	// reset an established session.
	Endpoint string
	// Quiet: a phone, sent no keepalives (each wakes its radio); it keeps its way to the control
	// nodes open itself, with the network map's long poll.
	Quiet bool
	// Carried: the addresses of the plain WireGuard peers this peer carries as their gateway
	// (sorted), whose traffic with the control nodes passes through its tunnel.
	Carried []netip.Addr
}

// same reports whether two configurations need no change on the device.
func (p wgPeer) same(o wgPeer) bool {
	return p.PresharedKey == o.PresharedKey && p.AllowedIP == o.AllowedIP && p.Quiet == o.Quiet && slices.Equal(p.Carried, o.Carried)
}

// allowedIPs is the peer's allowed_ip lines.
func (p wgPeer) allowedIPs() string {
	s := fmt.Sprintf("replace_allowed_ips=true\nallowed_ip=%s/32\n", p.AllowedIP)
	for _, a := range p.Carried {
		s += fmt.Sprintf("allowed_ip=%s/32\n", a)
	}
	return s
}

// wgStatus is what the device reports about a peer.
type wgStatus struct {
	Endpoint      string
	LastHandshake time.Time
}

// userspaceWG is a WireGuard device whose tunnel ends in an in-process network stack, so the
// control API is only reachable through WireGuard and the process needs no privileges.
type userspaceWG struct {
	dev   *device.Device
	net   *netstack.Net
	peers map[wgtypes.Key]wgPeer
}

func hexKey(k wgtypes.Key) string { return hex.EncodeToString(k[:]) }

func newUserspaceWG(key wgtypes.Key, listenPort int, address netip.Addr, mtu int, logf func(string, ...any)) (*userspaceWG, error) {
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{address}, nil, mtu)
	if err != nil {
		return nil, err
	}
	logger := &device.Logger{Verbosef: device.DiscardLogf, Errorf: func(f string, a ...any) { logf("wireguard: "+f, a...) }}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)
	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n", hexKey(key), listenPort)); err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}
	return &userspaceWG{dev: dev, net: tnet, peers: map[wgtypes.Key]wgPeer{}}, nil
}

func (w *userspaceWG) Close() { w.dev.Close() }

// Sync makes the device's peers match desired, touching only peers that changed so established
// sessions are kept: a changed peer is changed in place, never removed and added again, so a new
// preshared key (an all-zero one removes it) takes effect at the next handshake while the running
// session carries traffic (Constitution 9.2).
func (w *userspaceWG) Sync(desired map[wgtypes.Key]wgPeer) error {
	var b strings.Builder
	for k := range w.peers {
		if _, ok := desired[k]; !ok {
			fmt.Fprintf(&b, "public_key=%s\nremove=true\n", hexKey(k))
		}
	}
	for k, p := range desired {
		cur, known := w.peers[k]
		if known && cur.same(p) {
			continue
		}
		fmt.Fprintf(&b, "public_key=%s\n", hexKey(k))
		if known {
			// The endpoint stays as WireGuard learned it (roaming), and the keepalive changes only
			// when the peer became quiet or stopped being so.
			fmt.Fprintf(&b, "preshared_key=%s\n", hexKey(p.PresharedKey))
			if p.Quiet != cur.Quiet {
				if p.Quiet {
					b.WriteString("persistent_keepalive_interval=0\n")
				} else {
					b.WriteString("persistent_keepalive_interval=25\n")
				}
			}
			b.WriteString(p.allowedIPs())
			continue
		}
		if p.PresharedKey != (wgtypes.Key{}) {
			fmt.Fprintf(&b, "preshared_key=%s\n", hexKey(p.PresharedKey))
		}
		switch {
		case p.Quiet:
			if p.Endpoint != "" {
				fmt.Fprintf(&b, "endpoint=%s\n", p.Endpoint)
			}
			b.WriteString("persistent_keepalive_interval=0\n")
		case p.Endpoint != "":
			// A keepalive right away makes this node send a handshake initiation.
			fmt.Fprintf(&b, "endpoint=%s\npersistent_keepalive_interval=25\n", p.Endpoint)
		}
		b.WriteString(p.allowedIPs())
	}
	if b.Len() == 0 {
		return nil
	}
	if err := w.dev.IpcSet(b.String()); err != nil {
		return err
	}
	w.peers = make(map[wgtypes.Key]wgPeer, len(desired))
	for k, p := range desired {
		w.peers[k] = p
	}
	return nil
}

// Status returns the endpoint and last handshake of every peer.
func (w *userspaceWG) Status() (map[wgtypes.Key]wgStatus, error) {
	out, err := w.dev.IpcGet()
	if err != nil {
		return nil, err
	}
	res := map[wgtypes.Key]wgStatus{}
	var cur wgtypes.Key
	have := false
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			b, err := hex.DecodeString(v)
			if err != nil || len(b) != 32 {
				have = false
				continue
			}
			copy(cur[:], b)
			have = true
			res[cur] = wgStatus{}
		case "endpoint":
			if have {
				s := res[cur]
				s.Endpoint = v
				res[cur] = s
			}
		case "last_handshake_time_sec":
			if have {
				sec, _ := strconv.ParseInt(v, 10, 64)
				if sec > 0 {
					s := res[cur]
					s.LastHandshake = time.Unix(sec, 0)
					res[cur] = s
				}
			}
		}
	}
	return res, sc.Err()
}
