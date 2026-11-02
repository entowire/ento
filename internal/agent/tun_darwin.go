//go:build darwin

package agent

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"

	"golang.zx2c4.com/wireguard/tun"
)

// macOS names TUN interfaces itself (utunN).
func tunName(string) string { return "utun" }

// sysSetAddress gives the point-to-point utun interface its address and routes the overlay range
// (prefix) into it.
func sysSetAddress(_ tun.Device, name string, prefix netip.Prefix) error {
	a := prefix.Addr().String()
	if err := run("ifconfig", name, "inet", a, a, "netmask", "255.255.255.255", "up"); err != nil {
		return err
	}
	if prefix.Bits() < 32 {
		return sysAddRoute(nil, name, prefix.Masked())
	}
	return nil
}

func sysAddRoute(_ tun.Device, name string, dst netip.Prefix) error {
	d := dst.Masked().String()
	if err := run("route", "-q", "-n", "add", "-inet", d, "-interface", name); err != nil {
		// Already there (e.g. from a previous interface): point it at this one.
		return run("route", "-q", "-n", "change", "-inet", d, "-interface", name)
	}
	return nil
}

func sysRemoveRoute(_ tun.Device, name string, dst netip.Prefix) error {
	if err := run("route", "-q", "-n", "delete", "-inet", dst.Masked().String(), "-interface", name); err != nil &&
		!strings.Contains(err.Error(), "not in table") {
		return err
	}
	return nil
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// sysRepairAddress does nothing here: the system does not take addresses from the agent's
// interface (on Linux, NetworkManager may).
func sysRepairAddress(tun.Device, string, netip.Prefix) (bool, error) { return false, nil }
