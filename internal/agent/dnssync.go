package agent

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"entowire.com/ento/internal/api"
)

// dnsSettings are what the system's resolver is told for the network's interface: send the domains
// (or with all, every name) to server; the zero value gives the interface's settings back.
type dnsSettings struct {
	server  netip.Addr
	domains []string
	all     bool
}

// what names the names the settings send.
func (d dnsSettings) what() string {
	list := slices.Clone(d.domains)
	if d.all {
		list = append(list, "every other name")
	}
	return strings.Join(list, ", ")
}

func (d dnsSettings) key() string {
	if !d.server.IsValid() {
		return ""
	}
	return fmt.Sprintf("%s %s %v", d.server, strings.Join(d.domains, ","), d.all)
}

// dnsOutcome is what telling the system's resolver came to.
type dnsOutcome int

const (
	dnsTold    dnsOutcome = iota
	dnsUnused             // told, but programs do not ask it (/etc/resolv.conf names other servers)
	dnsNotTold            // no systemd-resolved to tell (or another network namespace)
)

// dnsRecheck is how often the system's resolver is told again what it was told (it forgets an
// interface's settings when the interface goes down).
const dnsRecheck = 5 * time.Minute

// upstreamDNS are the DNS servers of the network a phone uses beside the VPN (SetUpstreamDNS).
var upstreamDNS atomic.Pointer[[]string]

// SetUpstreamDNS gives the agent running in this process (RunOnTUN) the DNS servers of the network
// the phone uses beside the VPN: its resolver asks them for every name that is neither the
// network's nor an exit's. The app gives them again when the phone changes networks.
func SetUpstreamDNS(servers []string) {
	var out []string
	for _, s := range servers {
		if a, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil && a.Is4() {
			out = append(out, netip.AddrPortFrom(a, 53).String())
		}
	}
	upstreamDNS.Store(&out)
}

func upstream() []string {
	if p := upstreamDNS.Load(); p != nil {
		return *p
	}
	return nil
}

// syncResolver runs the agent's resolver while something needs it (the network's DNS, an exit in
// use, devices using this one as their exit), gives it the map's names, and tells the system's
// resolver about it. The caller holds a.mu.
func (a *runner) syncResolver(nm api.NetMap, f *inboundFilter) {
	conf := newResolverConf(nm.DNS)
	if !a.linked() {
		dropped := strings.Join(claimNames(a.ifc.IfName(), recordFQDN(a.st.RecordDomain), conf), ", ")
		if dropped != a.dnsTaken {
			a.dnsTaken = dropped
			if dropped != "" {
				a.cfg.Logf("DNS: %s left out: another network of this device holds it", dropped)
			}
		}
	}
	if a.exit != nil {
		conf.exit = a.exit.Addr
	}
	if nm.Self.Exit && kernelTunnel(a.ifc) && f != nil {
		for c := range f.exits {
			conf.clients[c] = true
		}
	}
	inPath := !ownsSystemDNS(a.ifc) // a phone: the resolver in the packet path, which its VPN sends every name
	if inPath {
		conf.upstream = upstream()
	}
	want := resolverSupported(a.ifc) && (conf.domain != "" || len(conf.zones) > 0 || len(conf.fixed) > 0 || conf.exit.IsValid() || len(conf.clients) > 0)
	if a.resolver != nil && (!want || a.resolver.addr != a.st.Address) {
		if inPath {
			setTunDNS(a.ifc, netip.Addr{}, nil)
		}
		a.resolver.close()
		a.resolver = nil
	}
	if want && a.resolver == nil {
		if inPath {
			a.resolver = newResolver(a.st.Address, a.cfg.Logf)
			setTunDNS(a.ifc, dnsAddress(a.st.Network), a.resolver)
			a.cfg.Logf("DNS: resolver at %s port 53, in the agent", dnsAddress(a.st.Network))
		} else if r, err := startResolver(a.st.Address, 53, a.cfg.Logf); err != nil {
			a.noteDNS(fmt.Sprintf("DNS: no resolver on %s port 53 (%v): the network's names do not resolve on this device", a.st.Address, err))
		} else {
			a.resolver = r
			a.dnsNoted = ""
			a.cfg.Logf("DNS: resolver on %s port 53", a.st.Address)
		}
	}
	var want2 dnsSettings
	switch {
	case a.resolver != nil:
		a.resolver.set(conf)
		if domains := conf.domains(); len(domains) > 0 || conf.exit.IsValid() {
			want2 = dnsSettings{server: a.st.Address, domains: domains, all: conf.exit.IsValid()}
		}
	case conf.exit.IsValid(): // no resolver of its own: every name to the exit's gateway
		want2 = dnsSettings{server: conf.exit, all: true}
	}
	if !a.dnsInit { // once: give back what an agent that stopped without left
		a.dnsInit = true
		if a.dnsApplied == "" {
			a.dnsApplied = "?"
		}
	}
	if ownsSystemDNS(a.ifc) && (want2.key() != a.dnsApplied || want2.key() != "" && time.Since(a.dnsAt) > dnsRecheck) {
		a.applySystemDNS(want2)
	}
}

// applySystemDNS tells the system's resolver (Linux: systemd-resolved) the settings. The caller
// holds a.mu.
func (a *runner) applySystemDNS(d dnsSettings) {
	outcome, err := setSystemDNS(a.ifc.IfName(), d.server, d.domains, d.all)
	changed := d.key() != a.dnsApplied
	a.dnsApplied, a.dnsAt = d.key(), time.Now()
	switch {
	case err != nil:
		a.dnsApplied = "?" // told again at the next application
		a.noteDNS(fmt.Sprintf("DNS: %v", err))
	case d.server.IsValid() && outcome == dnsNotTold && changed:
		a.noteDNS(fmt.Sprintf("DNS: the system's resolver was not told (no systemd-resolved, or another network namespace): send %s to %s yourself", d.what(), d.server))
	case d.server.IsValid() && outcome == dnsUnused && changed:
		a.noteDNS(fmt.Sprintf("DNS: systemd-resolved sends %s to %s, but /etc/resolv.conf names other servers, so programs reading it do not get them (resolvectl query does)", d.what(), d.server))
	case d.server.IsValid() && changed:
		a.cfg.Logf("DNS: the system sends %s to %s", d.what(), d.server)
	}
}

// noteDNS logs what keeps the network's DNS from working, once while it stays the same; the caller
// holds a.mu.
func (a *runner) noteDNS(msg string) {
	if msg != a.dnsNoted {
		a.dnsNoted = msg
		a.cfg.Logf("%s", msg)
	}
}

// InProcessDNS returns the DNS server the VPN of the agent running in this process (RunOnTUN)
// names, "" for none: the agent's resolver in the packet path (dnsAddress), once it can answer every
// name (an exit in use, or the phone's DNS servers known: SetUpstreamDNS).
func InProcessDNS() string {
	a := current.Load()
	if a == nil {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.resolver == nil {
		return ""
	}
	c := a.resolver.conf.Load()
	if !c.exit.IsValid() && len(c.upstream) == 0 {
		return ""
	}
	return dnsAddress(a.st.Network).String()
}
