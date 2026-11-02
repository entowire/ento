//go:build linux

package agent

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Iface is a kernel WireGuard interface. It may live in another network namespace than the agent
// (linked networks): it is then created here, so its UDP socket stays in the agent's namespace,
// and moved there; addresses, routes and WireGuard configuration go through handles opened in
// that namespace.
type Iface struct {
	Name          string
	ListenPort    int
	MTU           int
	ns            netns.NsHandle // closed handle: the agent's own namespace
	filter        *inboundFilter // the inbound filter last applied (filter_linux.go)
	filterSet     bool
	filterChecked time.Time
	nl            *netlink.Handle
	wg            *wgctrl.Client
}

// OpenIface creates the interface if needed and brings it up, in the agent's own namespace.
func OpenIface(name string, listenPort, mtu int) (*Iface, error) {
	return OpenIfaceIn(netns.None(), name, listenPort, mtu)
}

// OpenIfaceIn creates the interface if needed in namespace ns (see Iface) and brings it up.
func OpenIfaceIn(ns netns.NsHandle, name string, listenPort, mtu int) (*Iface, error) {
	i := &Iface{Name: name, ListenPort: listenPort, MTU: mtu, ns: ns}
	var err error
	if ns.IsOpen() {
		i.nl, err = netlink.NewHandleAt(ns)
	} else {
		i.nl, err = netlink.NewHandle()
	}
	if err != nil {
		return nil, err
	}
	if err := inNamespace(ns, func() error {
		var err error
		i.wg, err = wgctrl.New()
		return err
	}); err != nil {
		i.nl.Close()
		return nil, err
	}
	fail := func(err error) (*Iface, error) {
		i.Close()
		return nil, err
	}
	link, err := i.nl.LinkByName(name)
	if err != nil {
		var nf netlink.LinkNotFoundError
		if !errors.As(err, &nf) {
			return fail(err)
		}
		// Created in the agent's namespace (the socket's home), then moved if needed.
		if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: name, MTU: mtu}}); err != nil {
			return fail(fmt.Errorf("create %s (is the wireguard kernel module available?): %w", name, err))
		}
		if ns.IsOpen() {
			created, err := netlink.LinkByName(name)
			if err != nil {
				return fail(err)
			}
			if err := netlink.LinkSetNsFd(created, int(ns)); err != nil {
				_ = netlink.LinkDel(created)
				return fail(fmt.Errorf("move %s into its namespace: %w", name, err))
			}
		}
		if link, err = i.nl.LinkByName(name); err != nil {
			return fail(err)
		}
	}
	if err := i.nl.LinkSetMTU(link, mtu); err != nil {
		return fail(err)
	}
	if err := i.nl.LinkSetUp(link); err != nil {
		return fail(err)
	}
	return i, nil
}

// Close releases the netlink handles; the interface stays up.
func (i *Iface) Close() error {
	if i.nl != nil {
		i.nl.Close()
	}
	if i.wg != nil {
		return i.wg.Close()
	}
	return nil
}

// IfName is the interface's name.
func (i *Iface) IfName() string { return i.Name }

// Delete removes the interface.
func (i *Iface) Delete() error {
	link, err := i.nl.LinkByName(i.Name)
	if err != nil {
		return err
	}
	return i.nl.LinkDel(link)
}

// SetAddress makes prefix the only address of the interface (the prefix length decides which
// overlay destinations are routed into it).
func (i *Iface) SetAddress(prefix netip.Prefix) error {
	link, err := i.nl.LinkByName(i.Name)
	if err != nil {
		return err
	}
	want := &netlink.Addr{IPNet: &net.IPNet{IP: prefix.Addr().AsSlice(), Mask: net.CIDRMask(prefix.Bits(), 32)}}
	addrs, err := i.nl.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	for _, a := range addrs {
		if !a.IPNet.IP.Equal(want.IPNet.IP) || a.IPNet.Mask.String() != want.IPNet.Mask.String() {
			if err := i.nl.AddrDel(link, &a); err != nil {
				return err
			}
		}
	}
	return i.nl.AddrReplace(link, want)
}

// RepairAddress puts the address back and brings the interface up when another program removed
// it or took it down (see tunnel).
func (i *Iface) RepairAddress(prefix netip.Prefix) (bool, error) {
	if ok, err := linkIntact(i.nl, i.Name, prefix); err != nil || ok {
		return false, err
	}
	link, err := i.nl.LinkByName(i.Name)
	if err != nil {
		return false, err
	}
	if err := i.nl.LinkSetUp(link); err != nil {
		return false, err
	}
	return true, i.SetAddress(prefix)
}

// linkIntact reports whether an interface is up with prefix among its addresses.
func linkIntact(h *netlink.Handle, name string, prefix netip.Prefix) (bool, error) {
	link, err := h.LinkByName(name)
	if err != nil {
		return false, err
	}
	if link.Attrs().Flags&net.FlagUp == 0 {
		return false, nil
	}
	addrs, err := h.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return false, err
	}
	for _, a := range addrs {
		if ones, _ := a.IPNet.Mask.Size(); ones == prefix.Bits() && a.IPNet.IP.Equal(prefix.Addr().AsSlice()) {
			return true, nil
		}
	}
	return false, nil
}

// AddRoute routes dst into the interface (used for control addresses during enrollment).
func (i *Iface) AddRoute(dst netip.Prefix) error {
	link, err := i.nl.LinkByName(i.Name)
	if err != nil {
		return err
	}
	return i.nl.RouteReplace(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       &net.IPNet{IP: dst.Addr().AsSlice(), Mask: net.CIDRMask(dst.Bits(), 32)},
		Scope:     netlink.SCOPE_LINK,
	})
}

// RemoveRoute takes away a route into the interface (a route's network no longer reached).
func (i *Iface) RemoveRoute(dst netip.Prefix) error {
	link, err := i.nl.LinkByName(i.Name)
	if err != nil {
		return err
	}
	err = i.nl.RouteDel(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       &net.IPNet{IP: dst.Addr().AsSlice(), Mask: net.CIDRMask(dst.Bits(), 32)},
		Scope:     netlink.SCOPE_LINK,
	})
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	return err
}

// Status returns the kernel's view of every peer.
func (i *Iface) Status() (map[wgtypes.Key]PeerStatus, error) {
	dev, err := i.wg.Device(i.Name)
	if err != nil {
		return nil, err
	}
	return deviceStatus(dev), nil
}

// Configure sets the private key and makes the peers match desired (see tunnel).
func (i *Iface) Configure(key wgtypes.Key, desired []PeerConfig) error {
	dev, err := i.wg.Device(i.Name)
	if err != nil {
		return err
	}
	cfg, err := planConfig(dev, key, i.ListenPort, desired)
	if err != nil || cfg == nil {
		return err
	}
	return i.wg.ConfigureDevice(i.Name, *cfg)
}

// kernelTunnel reports whether t is the kernel's WireGuard (gateways forward only with it).
func kernelTunnel(t tunnel) bool {
	_, ok := t.(*Iface)
	return ok
}
