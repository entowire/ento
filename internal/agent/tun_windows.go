//go:build windows

package agent

import (
	"errors"
	"net/netip"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func tunName(name string) string { return name }

func luid(t tun.Device) (winipcfg.LUID, error) {
	// The agent's WireGuard reads and writes through the inbound filter (0.19): the interface is the
	// device inside it.
	if f, ok := t.(*filterTUN); ok {
		t = f.Device
	}
	nt, ok := t.(*tun.NativeTun)
	if !ok {
		return 0, errors.New("not a Wintun interface")
	}
	return winipcfg.LUID(nt.LUID()), nil
}

// sysSetAddress sets the Wintun interface's only IPv4 address; Windows routes the prefix into it.
func sysSetAddress(t tun.Device, _ string, prefix netip.Prefix) error {
	l, err := luid(t)
	if err != nil {
		return err
	}
	return l.SetIPAddressesForFamily(windows.AF_INET, []netip.Prefix{prefix})
}

func sysAddRoute(t tun.Device, _ string, dst netip.Prefix) error {
	l, err := luid(t)
	if err != nil {
		return err
	}
	err = l.AddRoute(dst.Masked(), netip.IPv4Unspecified(), 0)
	if errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		return nil
	}
	return err
}

func sysRemoveRoute(t tun.Device, _ string, dst netip.Prefix) error {
	l, err := luid(t)
	if err != nil {
		return err
	}
	err = l.DeleteRoute(dst.Masked(), netip.IPv4Unspecified())
	if errors.Is(err, windows.ERROR_NOT_FOUND) {
		return nil
	}
	return err
}

// sysRepairAddress does nothing here: the system does not take addresses from the agent's
// interface (on Linux, NetworkManager may).
func sysRepairAddress(tun.Device, string, netip.Prefix) (bool, error) { return false, nil }
