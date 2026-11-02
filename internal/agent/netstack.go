package agent

import (
	"fmt"
	"net/http"
	"net/netip"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// tunDevice is a TUN interface someone else created (see RunOnTUN).
type tunDevice = tun.Device

// openNetstack runs WireGuard on a network stack inside the agent, with addr as its only address,
// and returns an HTTP client whose connections go through it. No interface, no privileges.
func openNetstack(addr netip.Addr, mtu int, logf func(string, ...any)) (tunnel, *http.Client, error) {
	t, tnet, err := netstack.CreateNetTUN([]netip.Addr{addr}, nil, mtu)
	if err != nil {
		return nil, nil, err
	}
	logger := &device.Logger{Verbosef: func(string, ...any) {}, Errorf: func(f string, a ...any) { logf("wireguard: "+f, a...) }}
	ft := newFilterTUN(t)
	u := &userTunnel{name: "netstack", port: 0, tun: ft, dev: device.NewDevice(ft, conn.NewDefaultBind(), logger), noOS: true}
	if err := u.dev.Up(); err != nil {
		u.dev.Close()
		return nil, nil, err
	}
	c := &http.Client{Timeout: httpClient.Timeout, Transport: &http.Transport{DialContext: tnet.DialContext}}
	return u, c, nil
}

// userspaceOnTUN runs WireGuard inside the agent on a TUN interface someone else created and
// configured; addresses and routes are theirs, so SetAddress and AddRoute do nothing. protect, if
// set, is given WireGuard's UDP sockets so the system keeps them out of that interface.
func userspaceOnTUN(t tun.Device, port int, protect func(fd int) bool, logf func(string, ...any)) (tunnel, error) {
	name, _ := t.Name()
	logger := &device.Logger{Verbosef: func(string, ...any) {}, Errorf: func(f string, a ...any) { logf("wireguard: "+f, a...) }}
	ft := newFilterTUN(t)
	u := &userTunnel{name: name, port: port, tun: ft, dev: device.NewDevice(ft, conn.NewDefaultBind(), logger), noOS: true}
	if err := u.dev.IpcSet(fmt.Sprintf("listen_port=%d\n", port)); err != nil {
		u.dev.Close()
		return nil, err
	}
	if err := u.dev.Up(); err != nil {
		u.dev.Close()
		return nil, err
	}
	if protect != nil {
		if err := protectSockets(u.dev, protect); err != nil {
			u.dev.Close()
			return nil, err
		}
	}
	return u, nil
}
