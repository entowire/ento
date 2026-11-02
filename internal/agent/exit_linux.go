//go:build linux

package agent

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// SetExit sends everything but the device's own networks and WireGuard's packets into the
// interface, or stops it (see exit.go).
func (i *Iface) SetExit(on bool) error {
	if i.ns.IsOpen() {
		if on {
			return errors.New("exits are for the device's own network")
		}
		return nil
	}
	// Marked before the routing sends anything unmarked into the interface, unmarked after it stopped.
	setMark := func(mark int) error {
		if err := i.wg.ConfigureDevice(i.Name, wgtypes.Config{FirewallMark: &mark}); err != nil {
			return fmt.Errorf("mark WireGuard's packets: %w", err)
		}
		return nil
	}
	if !on {
		if err := exitRouting(i.nl, i.Name, false); err != nil {
			return err
		}
		return setMark(0)
	}
	if err := setMark(exitMark); err != nil {
		return err
	}
	return exitRouting(i.nl, i.Name, true)
}

// sysSetExit routes for an exit on the agent's own WireGuard (its packets are marked by the caller).
func sysSetExit(name string, on bool) error {
	nl, err := netlink.NewHandle()
	if err != nil {
		return err
	}
	defer nl.Close()
	return exitRouting(nl, name, on)
}

// exitRouting adds (or removes) the exit's table and rules: IPv4's default into the interface,
// IPv6's unreachable; the main table without its default route first, then unmarked packets to the
// exit's table. Adding is idempotent, so it also puts back what another program removed.
func exitRouting(nl *netlink.Handle, ifName string, on bool) error {
	families := []int{netlink.FAMILY_V4, netlink.FAMILY_V6}
	if !on {
		var errs []error
		for _, fam := range families {
			rules, err := nl.RuleList(fam)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			for _, r := range rules {
				if r.Priority == exitRulePref || r.Priority == exitRulePref+1 {
					if err := nl.RuleDel(&r); err != nil && !errors.Is(err, unix.ENOENT) {
						errs = append(errs, err)
					}
				}
			}
		}
		routes, err := nl.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: exitTable}, netlink.RT_FILTER_TABLE)
		if err != nil {
			errs = append(errs, err)
		}
		for _, r := range routes {
			if err := nl.RouteDel(&r); err != nil && !errors.Is(err, unix.ESRCH) {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}
	link, err := nl.LinkByName(ifName)
	if err != nil {
		return err
	}
	if err := nl.RouteReplace(&netlink.Route{LinkIndex: link.Attrs().Index, Table: exitTable, Scope: netlink.SCOPE_LINK,
		Dst: &net.IPNet{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)}}); err != nil {
		return fmt.Errorf("default route into %s: %w", ifName, err)
	}
	if err := nl.RouteReplace(&netlink.Route{Table: exitTable, Type: unix.RTN_UNREACHABLE,
		Dst: &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}}); err != nil {
		return fmt.Errorf("IPv6 unreachable beside the exit: %w", err)
	}
	// Answers arrive on the interface from addresses its default route covers only for unmarked
	// packets: reverse-path filtering must see the mark (as wg-quick sets it).
	if err := os.WriteFile("/proc/sys/net/ipv4/conf/all/src_valid_mark", []byte("1\n"), 0o644); err != nil {
		return fmt.Errorf("src_valid_mark: %w", err)
	}
	for _, fam := range families {
		main := netlink.NewRule()
		main.Family, main.Priority, main.Table, main.SuppressPrefixlen = fam, exitRulePref, unix.RT_TABLE_MAIN, 0
		into := netlink.NewRule()
		into.Family, into.Priority, into.Table, into.Mark, into.Invert = fam, exitRulePref+1, exitTable, exitMark, true
		have, err := nl.RuleList(fam)
		if err != nil {
			return err
		}
		for _, want := range []*netlink.Rule{main, into} {
			found := false
			for _, r := range have {
				if r.Priority != want.Priority {
					continue
				}
				if r.Table == want.Table && r.SuppressPrefixlen == want.SuppressPrefixlen && r.Mark == want.Mark && r.Invert == want.Invert {
					found = true
					continue
				}
				if err := nl.RuleDel(&r); err != nil && !errors.Is(err, unix.ENOENT) {
					return err
				}
			}
			if !found {
				if err := nl.RuleAdd(want); err != nil && !errors.Is(err, unix.EEXIST) {
					return fmt.Errorf("routing rule %d: %w", want.Priority, err)
				}
			}
		}
	}
	return nil
}

// setSystemDNS tells systemd-resolved to send the domains (and with all, every name: the routing
// domain "~.") to server, as the interface's DNS server, or gives the interface's settings back
// (server invalid). dnsNotTold: there is no systemd-resolved to tell; dnsUnused: told, but
// /etc/resolv.conf does not name its stub, so programs reading it do not ask it. Not from another
// network namespace than the system's: resolved, in the system's, would take the interface's name
// for one of its own interfaces.
func setSystemDNS(ifName string, server netip.Addr, domains []string, all bool) (dnsOutcome, error) {
	path, err := exec.LookPath("resolvectl")
	if err != nil || !inSystemNetns(path, ifName) {
		return dnsNotTold, nil
	}
	run := func(args ...string) error {
		out, err := exec.Command(path, args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("resolvectl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	if !server.IsValid() {
		return dnsTold, run("revert", ifName)
	}
	routing := []string{"domain", ifName}
	for _, d := range domains {
		routing = append(routing, "~"+d)
	}
	if all {
		routing = append(routing, "~.")
	}
	defaultRoute := "no"
	if all {
		defaultRoute = "yes"
	}
	for _, args := range [][]string{{"dns", ifName, server.String()}, routing, {"default-route", ifName, defaultRoute}} {
		if err := run(args...); err != nil {
			return dnsNotTold, err
		}
	}
	// Programs read /etc/resolv.conf: resolved decides only when it names its stub.
	if b, err := os.ReadFile("/etc/resolv.conf"); err == nil && (strings.Contains(string(b), "127.0.0.53") || strings.Contains(string(b), "127.0.0.54")) {
		return dnsTold, nil
	}
	return dnsUnused, nil
}

// inSystemNetns reports whether the agent runs in the system's network namespace (that of process 1,
// where systemd-resolved runs). Where process 1's namespace cannot be read (a service without the
// right to inspect other processes), systemd-resolved is asked which interface it knows by the
// interface's index here: the same name means the same namespace.
func inSystemNetns(resolvectl, ifName string) bool {
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return false
	}
	if init, err := os.Readlink("/proc/1/ns/net"); err == nil {
		return self == init
	}
	ifc, err := net.InterfaceByName(ifName)
	if err != nil {
		return false
	}
	out, err := exec.Command(resolvectl, "status", ifName).Output()
	if err != nil {
		return false
	}
	m := regexp.MustCompile(`Link (\d+) \(([^)]+)\)`).FindStringSubmatch(string(out))
	return m != nil && m[1] == strconv.Itoa(ifc.Index) && m[2] == ifName
}

// resolverSupported reports whether the agent runs its resolver here: Linux (systemd-resolved is
// told about it), and an app's VPN service (Android: the VPN names it).
func resolverSupported(t tunnel) bool { return true }

// exitsSupported reports whether this system can use an exit: Linux, and an app's VPN service that
// routes for the agent (Android).
func exitsSupported(t tunnel) bool { return true }

// ownsSystemDNS reports whether the agent sets the system's DNS for an exit itself (not where an
// app's VPN service does).
func ownsSystemDNS(t tunnel) bool {
	u, ok := t.(*userTunnel)
	return !(ok && u.noOS)
}

// sysBootID: Linux has its boot ID in /proc (bootID).
func sysBootID() string { return "" }
