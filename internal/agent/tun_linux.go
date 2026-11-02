//go:build linux

package agent

import (
	"net"
	"net/netip"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/tun"
)

func tunName(name string) string { return name }

func sysSetAddress(_ tun.Device, name string, prefix netip.Prefix) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	want := &netlink.Addr{IPNet: &net.IPNet{IP: prefix.Addr().AsSlice(), Mask: net.CIDRMask(prefix.Bits(), 32)}}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	for _, a := range addrs {
		if !a.IPNet.IP.Equal(want.IPNet.IP) || a.IPNet.Mask.String() != want.IPNet.Mask.String() {
			if err := netlink.AddrDel(link, &a); err != nil {
				return err
			}
		}
	}
	if err := netlink.AddrReplace(link, want); err != nil {
		return err
	}
	return netlink.LinkSetUp(link)
}

func sysRemoveRoute(_ tun.Device, name string, dst netip.Prefix) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	err = netlink.RouteDel(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       &net.IPNet{IP: dst.Addr().AsSlice(), Mask: net.CIDRMask(dst.Bits(), 32)},
		Scope:     netlink.SCOPE_LINK,
	})
	if err != nil && strings.Contains(err.Error(), "no such process") {
		return nil
	}
	return err
}

// sysRepairAddress puts the address back when another program removed it (see tunnel).
func sysRepairAddress(t tun.Device, name string, prefix netip.Prefix) (bool, error) {
	h, err := netlink.NewHandle()
	if err != nil {
		return false, err
	}
	defer h.Close()
	if ok, err := linkIntact(h, name, prefix); err != nil || ok {
		return false, err
	}
	return true, sysSetAddress(t, name, prefix)
}

func sysAddRoute(_ tun.Device, name string, dst netip.Prefix) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	return netlink.RouteReplace(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       &net.IPNet{IP: dst.Addr().AsSlice(), Mask: net.CIDRMask(dst.Bits(), 32)},
		Scope:     netlink.SCOPE_LINK,
	})
}
