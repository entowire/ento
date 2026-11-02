package agent

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/ports"
)

// The inbound filter: what each peer may open on this device, from the network map (Peer.Accept,
// NetMap.Filter). The device protects itself: a peer's own agent cannot be trusted to hold back.
// Answers to this device's own connections always pass, and so does everything from the control
// nodes (the control plane, relayed frames). Kernel WireGuard on Linux enforces it with nftables
// (filter_linux.go), the agent's own WireGuard in the packet path (filterTUN below).

// inboundFilter is a map's filter; nil passes everything (a map without one, from control nodes
// older than 0.19).
type inboundFilter struct {
	self     netip.Addr // the device's overlay address: what peers open on the device itself
	controls map[netip.Addr]bool
	accept   map[netip.Addr]ports.Set
	// routes: what each peer may open in the networks this device serves as a gateway; serves those
	// networks, overlay the network's range (forwarded traffic is masqueraded from it).
	routes  map[netip.Addr][]routeRule
	serves  []netip.Prefix
	overlay netip.Prefix
	// exits: what each peer that uses this device as an exit may open on the internet (public
	// addresses only, exitBlocked); they may also ask its DNS forwarder, on its own address.
	exits map[netip.Addr]ports.Set
	// person tells the person's traffic among what the device sends (person.go; nil: not counted).
	person *personRules
	// logDrops, when set, logs the new connections the filter refuses (Config.LogDrops).
	logDrops *dropLog
	key      string // canonical text, to leave an unchanged filter alone
}

// exitBlocked are the destinations an exit never forwards to: private, shared and special ranges (an
// office's LAN, the overlay, link-local such as a cloud's metadata endpoint, multicast). A network
// there is reached through a route of its own, which policies name. Nor does an exit forward to the
// gateway's own addresses (filter_linux.go: fib daddr type local).
var exitBlocked = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// dnsPorts are what the devices using an exit may open on the gateway itself: its DNS forwarder.
var dnsPorts = ports.ParseSet([]string{"udp/53", "tcp/53"})

type routeRule struct {
	network netip.Prefix
	set     ports.Set
}

// filterFromMap reads the filter a network map carries.
func filterFromMap(nm api.NetMap) *inboundFilter {
	if !nm.Filter {
		return nil
	}
	f := &inboundFilter{controls: map[netip.Addr]bool{}, accept: map[netip.Addr]ports.Set{}, routes: map[netip.Addr][]routeRule{},
		exits: map[netip.Addr]ports.Set{}}
	var key []string
	if a, err := netip.ParseAddr(nm.Self.Address); err == nil && a.Is4() {
		f.self = a
		key = append(key, "s "+a.String())
	}
	if p, err := netip.ParsePrefix(nm.Network); err == nil {
		f.overlay = p.Masked()
		key = append(key, "o "+f.overlay.String())
	}
	for _, s := range nm.Self.Routes {
		if p, err := netip.ParsePrefix(s); err == nil && p.Addr().Is4() && p.Bits() > 0 {
			f.serves = append(f.serves, p.Masked())
			key = append(key, "g "+p.Masked().String())
		}
	}
	for _, c := range nm.Controls {
		if a, err := netip.ParseAddr(c.Address); err == nil && a.Is4() {
			f.controls[a] = true
			key = append(key, "c "+a.String())
		}
	}
	exitPorts := map[netip.Addr][][]string{}
	for _, p := range nm.Peers {
		a, err := netip.ParseAddr(p.Address)
		if err != nil || !a.Is4() || f.controls[a] {
			continue
		}
		set := ports.ParseSet(p.Accept)
		f.accept[a] = set
		key = append(key, "p "+a.String()+" "+setKey(set))
		for _, ra := range p.RouteAccept {
			n, err := netip.ParsePrefix(ra.Network)
			if err != nil {
				continue
			}
			list := ra.Ports
			if len(list) == 0 {
				list = []string{"all"}
			}
			if n.Bits() == 0 && n.Addr().Is4() {
				if nm.Self.Exit { // only as an exit (several exits through this device: their ports together)
					exitPorts[a] = append(exitPorts[a], list)
				}
				continue
			}
			rs := ports.ParseSet(list)
			if !slices.Contains(f.serves, n.Masked()) {
				continue // only networks this device serves
			}
			f.routes[a] = append(f.routes[a], routeRule{network: n.Masked(), set: rs})
			key = append(key, "r "+a.String()+" "+n.Masked().String()+" "+setKey(rs))
		}
	}
	for a, lists := range exitPorts {
		rs := ports.ParseSet(ports.Union(lists...))
		f.exits[a] = rs
		key = append(key, "x "+a.String()+" "+setKey(rs))
	}
	slices.Sort(key)
	f.key = strings.Join(key, "\n")
	f.person = personRulesFrom(nm, f)
	f.key += "\n" + f.person.key()
	return f
}

// countPerson sets what the device counts as the person's traffic (nil: nothing).
func (f *inboundFilter) countPerson(r *personRules) {
	if f == nil {
		return
	}
	f.key = strings.TrimSuffix(f.key, "\n"+f.person.key()) + "\n" + r.key()
	f.person = r
}

func setKey(set ports.Set) string {
	var rules []string
	for _, r := range set {
		rules = append(rules, r.String())
	}
	return strings.Join(rules, ",")
}

func (f *inboundFilter) sameAs(g *inboundFilter) bool {
	return (f == nil) == (g == nil) && (f == nil || f.key == g.key)
}

// passes decides an IPv4 packet arriving from the network. A TCP packet that is not the opening of
// a connection passes (an answer; or nothing the system accepts, which it resets); UDP passes as an
// answer to a datagram this device sent (flows), else as the peer's rules say; ICMP echo requests as
// the rules say ("icmp"), other ICMP (answers, errors) passes.
func (f *inboundFilter) passes(p []byte, flows *udpFlows) bool {
	if len(p) < 1 || p[0]>>4 != 4 {
		return true // not IPv4: WireGuard delivers only the peers' IPv4 addresses
	}
	if len(p) < 20 {
		return false
	}
	ihl := int(p[0]&0x0f) * 4
	if ihl < 20 || len(p) < ihl {
		return false
	}
	src, dst := netip.AddrFrom4([4]byte(p[12:16])), netip.AddrFrom4([4]byte(p[16:20]))
	if f.controls[src] {
		return true
	}
	set := f.accept[src]
	if f.self.IsValid() && dst != f.self {
		// Not for this device: into a network it serves, as the peer's rules there say; else, for a
		// device using it as an exit, to a public address.
		set = nil
		if i := slices.IndexFunc(f.routes[src], func(r routeRule) bool { return r.network.Contains(dst) }); i >= 0 {
			set = f.routes[src][i].set
		} else if es, ok := f.exits[src]; ok && !exitBlockedAddr(dst) {
			set = es
		} else {
			return false
		}
	} else if _, ok := f.exits[src]; ok && f.self.IsValid() && dnsAsked(p) {
		return true
	}
	if binary.BigEndian.Uint16(p[6:8])&0x1fff != 0 {
		return set.All() // a later fragment carries no ports
	}
	l4 := p[ihl:]
	switch p[9] {
	case 6: // TCP
		if len(l4) < 14 {
			return false
		}
		syn, ack := l4[13]&0x02 != 0, l4[13]&0x10 != 0
		if !syn || ack {
			return true
		}
		return set.Allows("tcp", binary.BigEndian.Uint16(l4[2:4]))
	case 17: // UDP
		if len(l4) < 8 {
			return false
		}
		sport, dport := binary.BigEndian.Uint16(l4[0:2]), binary.BigEndian.Uint16(l4[2:4])
		if flows.answers(src, sport, dport) {
			return true
		}
		return set.Allows("udp", dport)
	case 1: // ICMP
		if len(l4) < 1 {
			return false
		}
		if l4[0] == 8 {
			return set.Allows("icmp", 0)
		}
		return true
	}
	return set.All()
}

func exitBlockedAddr(a netip.Addr) bool {
	return slices.ContainsFunc(exitBlocked, func(n netip.Prefix) bool { return n.Contains(a) })
}

// dnsAsked reports whether an IPv4 packet (checked by passes) is UDP or TCP to port 53.
func dnsAsked(p []byte) bool {
	ihl := int(p[0]&0x0f) * 4
	if binary.BigEndian.Uint16(p[6:8])&0x1fff != 0 || len(p) < ihl+4 || p[9] != 6 && p[9] != 17 {
		return false
	}
	return binary.BigEndian.Uint16(p[ihl+2:ihl+4]) == 53
}

// udpFlows remembers the UDP datagrams this device sent (to whom, from which port), so that their
// answers pass for a while (2 minutes after the last datagram).
type udpFlows struct {
	mu   sync.Mutex
	seen map[flowKey]time.Time
	now  func() time.Time // for tests
}

type flowKey struct {
	remote       netip.Addr
	rport, lport uint16
}

const udpFlowTimeout = 2 * time.Minute

func (u *udpFlows) clock() time.Time {
	if u.now != nil {
		return u.now()
	}
	return time.Now()
}

// outbound records a packet this device sends, if it is UDP over IPv4.
func (u *udpFlows) outbound(p []byte) {
	if len(p) < 20 || p[0]>>4 != 4 || p[9] != 17 {
		return
	}
	ihl := int(p[0]&0x0f) * 4
	if ihl < 20 || len(p) < ihl+8 || binary.BigEndian.Uint16(p[6:8])&0x1fff != 0 {
		return
	}
	l4 := p[ihl:]
	k := flowKey{remote: netip.AddrFrom4([4]byte(p[16:20])), rport: binary.BigEndian.Uint16(l4[2:4]),
		lport: binary.BigEndian.Uint16(l4[0:2])}
	now := u.clock()
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.seen == nil {
		u.seen = map[flowKey]time.Time{}
	}
	if len(u.seen) > 4096 { // forget what has expired
		for key, t := range u.seen {
			if now.Sub(t) > udpFlowTimeout {
				delete(u.seen, key)
			}
		}
	}
	u.seen[k] = now
}

// answers reports whether a datagram from remote:rport to local port lport answers one this device
// sent.
func (u *udpFlows) answers(remote netip.Addr, rport, lport uint16) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	t, ok := u.seen[flowKey{remote: remote, rport: rport, lport: lport}]
	return ok && u.clock().Sub(t) <= udpFlowTimeout
}

// dropLogRate is how many refused connections a minute are logged at most (and the burst), by the
// kernel (filter_linux.go) and by the filter in the packet path alike.
const dropLogRate = 20

// dropLog writes a line for each new connection the filter in the packet path refuses, at most
// dropLogRate a minute, in the format of the kernel's lines for the same drops (filter_linux.go):
//
//	ento-filter drop: IN=ento0 SRC=100.64.1.5 DST=100.64.1.3 PROTO=TCP SPT=40312 DPT=22
type dropLog struct {
	logf  func(format string, args ...any)
	iface string

	mu     sync.Mutex
	tokens float64
	last   time.Time
}

// allow takes a token from the bucket (dropLogRate a minute, as many at once).
func (d *dropLog) allow(now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.last.IsZero() {
		d.tokens = dropLogRate
	} else {
		d.tokens = min(dropLogRate, d.tokens+now.Sub(d.last).Minutes()*dropLogRate)
	}
	d.last = now
	if d.tokens < 1 {
		return false
	}
	d.tokens--
	return true
}

// note logs a refused packet (IPv4), if the rate allows.
func (d *dropLog) note(p []byte) {
	if d == nil || len(p) < 20 || p[0]>>4 != 4 || !d.allow(time.Now()) {
		return
	}
	d.logf("%s", dropLine(d.iface, p))
}

// dropLine describes a refused IPv4 packet as the kernel's log does.
func dropLine(iface string, p []byte) string {
	src, dst := netip.AddrFrom4([4]byte(p[12:16])), netip.AddrFrom4([4]byte(p[16:20]))
	line := fmt.Sprintf("ento-filter drop: IN=%s SRC=%s DST=%s", iface, src, dst)
	ihl := int(p[0]&0x0f) * 4
	l4 := p[min(ihl, len(p)):]
	fragment := binary.BigEndian.Uint16(p[6:8])&0x1fff != 0
	switch proto := p[9]; {
	case (proto == 6 || proto == 17) && !fragment && len(l4) >= 4:
		return fmt.Sprintf("%s PROTO=%s SPT=%d DPT=%d", line, map[byte]string{6: "TCP", 17: "UDP"}[proto],
			binary.BigEndian.Uint16(l4[0:2]), binary.BigEndian.Uint16(l4[2:4]))
	case proto == 1 && !fragment && len(l4) >= 2:
		return fmt.Sprintf("%s PROTO=ICMP TYPE=%d CODE=%d", line, l4[0], l4[1])
	default:
		return fmt.Sprintf("%s PROTO=%d", line, proto)
	}
}
