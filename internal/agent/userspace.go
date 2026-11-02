package agent

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// userTunnel is WireGuard running inside the agent (wireguard-go) on the system's TUN driver:
// utun on macOS, Wintun on Windows, /dev/net/tun on Linux. The interface exists as long as the agent
// runs. Addresses and routes are set through the platform's own interface (sys* functions).
type userTunnel struct {
	name string // as the system named it (e.g. utun5 on macOS)
	port int
	tun  *filterTUN // the system's TUN, with the inbound filter in its path
	dev  *device.Device
	noOS bool // addresses and routes are not ours to set (in-process stack, or a system's VPN service)
}

// openUserspace creates the TUN interface (name is a request: macOS always picks utunN itself)
// and starts WireGuard on it.
func openUserspace(name string, port, mtu int, logf func(string, ...any)) (*userTunnel, error) {
	t, err := tun.CreateTUN(tunName(name), mtu)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", name, err)
	}
	real, err := t.Name()
	if err != nil {
		t.Close()
		return nil, err
	}
	logger := &device.Logger{
		Verbosef: func(string, ...any) {},
		Errorf:   func(format string, args ...any) { logf("wireguard: "+format, args...) },
	}
	ft := newFilterTUN(t)
	u := &userTunnel{name: real, port: port, tun: ft, dev: device.NewDevice(ft, conn.NewDefaultBind(), logger)}
	if err := u.dev.IpcSet(fmt.Sprintf("listen_port=%d\n", port)); err != nil {
		u.dev.Close()
		return nil, fmt.Errorf("listen on UDP %d: %w", port, err)
	}
	if err := u.dev.Up(); err != nil {
		u.dev.Close()
		return nil, err
	}
	// The standard WireGuard control socket (a Unix socket in /var/run/wireguard, a named pipe on
	// Windows), so other processes read the device as they would the kernel's: `ento agent status`,
	// `wg show`.
	if l, err := uapiListen(real); err != nil {
		logf("wireguard control socket: %v", err)
	} else {
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go u.dev.IpcHandle(c)
			}
		}()
		go func() { <-u.dev.Wait(); l.Close() }()
	}
	return u, nil
}

func (u *userTunnel) SetAddress(prefix netip.Prefix) error {
	if u.noOS {
		return nil
	}
	return sysSetAddress(u.tun, u.name, prefix)
}

func (u *userTunnel) RepairAddress(prefix netip.Prefix) (bool, error) {
	if u.noOS {
		return false, nil
	}
	return sysRepairAddress(u.tun, u.name, prefix)
}

func (u *userTunnel) AddRoute(dst netip.Prefix) error {
	if u.noOS {
		return nil
	}
	return sysAddRoute(u.tun, u.name, dst)
}

func (u *userTunnel) RemoveRoute(dst netip.Prefix) error {
	if u.noOS {
		return nil
	}
	return sysRemoveRoute(u.tun, u.name, dst)
}

// SetExit routes for an exit (exit.go): WireGuard's packets marked, the system's routing told.
// Where an app's VPN service routes (noOS), the app does it.
func (u *userTunnel) SetExit(on bool) error {
	if u.noOS {
		return nil
	}
	if !on && runtime.GOOS != "linux" {
		return nil
	}
	// Marked before the routing sends anything unmarked into the interface, unmarked after it stopped.
	if !on {
		if err := sysSetExit(u.name, false); err != nil {
			return err
		}
		return u.dev.IpcSet("fwmark=0\n")
	}
	if err := u.dev.IpcSet(fmt.Sprintf("fwmark=%d\n", exitMark)); err != nil {
		return err
	}
	return sysSetExit(u.name, true)
}

// setTunDNS puts a resolver in the packet path of the agent's own WireGuard at addr (r nil: none);
// false where the tunnel is the kernel's.
func setTunDNS(t tunnel, addr netip.Addr, r *resolver) bool {
	u, ok := t.(*userTunnel)
	if ok {
		u.tun.setDNS(addr, r)
	}
	return ok
}

func (u *userTunnel) Status() (map[wgtypes.Key]PeerStatus, error) {
	dev, err := u.device()
	if err != nil {
		return nil, err
	}
	return deviceStatus(dev), nil
}

func (u *userTunnel) Configure(key wgtypes.Key, desired []PeerConfig) error {
	dev, err := u.device()
	if err != nil {
		return err
	}
	cfg, err := planConfig(dev, key, u.port, desired)
	if err != nil || cfg == nil {
		return err
	}
	return u.dev.IpcSet(uapiConfig(*cfg))
}

// Close stops WireGuard and removes the interface: it lives only as long as the agent.
func (u *userTunnel) Close() error {
	u.dev.Close()
	return nil
}

func (u *userTunnel) Delete() error { return u.Close() }

func (u *userTunnel) IfName() string { return u.name }

// PersonTraffic counts what the filter takes for the person's traffic (it only grows).
func (u *userTunnel) PersonTraffic() (uint64, error) { return u.tun.person.Load(), nil }

// SetFilter puts the network map's inbound filter in the packet path (nil: everything passes).
func (u *userTunnel) SetFilter(f *inboundFilter) error {
	u.tun.set(f)
	return nil
}

func (u *userTunnel) device() (*wgtypes.Device, error) {
	text, err := u.dev.IpcGet()
	if err != nil {
		return nil, err
	}
	return parseUAPI(text)
}

// uapiConfig writes cfg in WireGuard's cross-platform configuration protocol ("set" operation).
func uapiConfig(cfg wgtypes.Config) string {
	var b strings.Builder
	if cfg.PrivateKey != nil {
		fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(cfg.PrivateKey[:]))
	}
	if cfg.ListenPort != nil {
		fmt.Fprintf(&b, "listen_port=%d\n", *cfg.ListenPort)
	}
	for _, p := range cfg.Peers {
		fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(p.PublicKey[:]))
		if p.Remove {
			b.WriteString("remove=true\n")
			continue
		}
		if p.PresharedKey != nil {
			fmt.Fprintf(&b, "preshared_key=%s\n", hex.EncodeToString(p.PresharedKey[:]))
		}
		if p.Endpoint != nil {
			fmt.Fprintf(&b, "endpoint=%s\n", p.Endpoint.String())
		}
		if p.PersistentKeepaliveInterval != nil {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", int(p.PersistentKeepaliveInterval.Seconds()))
		}
		if p.ReplaceAllowedIPs {
			b.WriteString("replace_allowed_ips=true\n")
		}
		for _, ip := range p.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", ip.String())
		}
	}
	return b.String()
}

// parseUAPI reads the answer to a "get" operation.
func parseUAPI(text string) (*wgtypes.Device, error) {
	dev := &wgtypes.Device{Type: wgtypes.Userspace}
	var peer *wgtypes.Peer
	var hsSec, hsNsec int64
	flush := func() {
		if peer != nil {
			if hsSec != 0 || hsNsec != 0 {
				peer.LastHandshakeTime = time.Unix(hsSec, hsNsec)
			}
			dev.Peers = append(dev.Peers, *peer)
		}
		hsSec, hsNsec = 0, 0
	}
	key := func(v string) (wgtypes.Key, error) {
		var k wgtypes.Key
		b, err := hex.DecodeString(v)
		if err != nil || len(b) != len(k) {
			return k, fmt.Errorf("uapi: bad key")
		}
		copy(k[:], b)
		return k, nil
	}
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		var err error
		switch k {
		case "private_key":
			if dev.PrivateKey, err = key(v); err == nil {
				dev.PublicKey = dev.PrivateKey.PublicKey()
			}
		case "listen_port":
			dev.ListenPort, err = strconv.Atoi(v)
		case "public_key":
			flush()
			peer = &wgtypes.Peer{}
			peer.PublicKey, err = key(v)
		case "preshared_key":
			if peer != nil {
				peer.PresharedKey, err = key(v)
			}
		case "endpoint":
			if peer != nil {
				peer.Endpoint, err = net.ResolveUDPAddr("udp", v)
			}
		case "persistent_keepalive_interval":
			if peer != nil {
				var s int
				s, err = strconv.Atoi(v)
				peer.PersistentKeepaliveInterval = time.Duration(s) * time.Second
			}
		case "allowed_ip":
			if peer != nil {
				var n *net.IPNet
				_, n, err = net.ParseCIDR(v)
				if err == nil {
					peer.AllowedIPs = append(peer.AllowedIPs, *n)
				}
			}
		case "last_handshake_time_sec":
			hsSec, err = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			hsNsec, err = strconv.ParseInt(v, 10, 64)
		case "rx_bytes":
			if peer != nil {
				peer.ReceiveBytes, err = strconv.ParseInt(v, 10, 64)
			}
		case "tx_bytes":
			if peer != nil {
				peer.TransmitBytes, err = strconv.ParseInt(v, 10, 64)
			}
		case "errno":
			if v != "0" {
				return nil, fmt.Errorf("uapi: errno %s", v)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("uapi %s: %w", k, err)
		}
	}
	flush()
	return dev, sc.Err()
}
