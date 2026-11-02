//go:build !linux

package agent

import (
	"errors"
	"net/netip"
)

var errNoExits = errors.New("this system cannot use exits yet (Linux and Android can)")

func sysSetExit(name string, on bool) error {
	if on {
		return errNoExits
	}
	return nil
}

func setSystemDNS(ifName string, server netip.Addr, domains []string, all bool) (dnsOutcome, error) {
	return dnsNotTold, nil
}

// resolverSupported: not yet on macOS and Windows (nothing would send it queries).
func resolverSupported(t tunnel) bool { return exitsSupported(t) }

func exitsSupported(t tunnel) bool {
	u, ok := t.(*userTunnel)
	return ok && u.noOS // an app's VPN service routes for the agent
}

func ownsSystemDNS(t tunnel) bool { return false }

// sysBootID identifies the boot where /proc does not: macOS's boot time (exact, from the kernel);
// "" on Windows, where it is only known to the second through the uptime, which would make a boot
// out of a rounding.
func sysBootID() string { return sysBootTime() }
