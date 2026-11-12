//go:build linux

package agent

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/ports"
)

// inboundFilterTable is the nftables table the agent owns for the inbound filter, in the namespace
// of its kernel WireGuard interface. It only judges what arrives on that interface:
//
//	table inet ento-filter {
//	  chain prerouting { type filter hook prerouting priority mangle; policy accept;
//	                iifname != "ento0" accept
//	                ct state established,related accept
//	                ip saddr <control node> accept                    (each one)
//	                ip saddr <peer> ip daddr <self> accept            (a peer allowed everything)
//	                ip saddr <peer> ip daddr <self> tcp dport 22 accept   (a peer's rules)
//	                ip saddr <peer> ip daddr <self> udp dport 8000-8100 accept
//	                ip saddr <peer> ip daddr <self> icmp type echo-request accept
//	                ip saddr <peer> ip daddr <self> udp dport 53 accept          (a device using it as an exit)
//	                ip saddr <peer> ip daddr <network served> tcp dport 445 accept   (a gateway)
//	                ip daddr 10.0.0.0/8 drop                       (an exit: each of exitBlocked)
//	                fib daddr type local drop                      (an exit: the gateway's own addresses)
//	                ip saddr <peer> accept                         (an exit: a device using it)
//	                drop }
//	  (a gateway, forwarding to the networks it serves, or an exit, to the internet:)
//	  chain postrouting { type nat hook postrouting priority srcnat;
//	                ip saddr <overlay> ip daddr <network served> oifname != "ento0" masquerade
//	                ip saddr <overlay> oifname != "ento0" masquerade }   (an exit)
//	  chain forward { type filter hook forward priority filter; policy accept;
//	                oifname "ento0" ct state established,related accept
//	                oifname "ento0" drop }                           (the LAN only answers)
//	}
//
// The chain runs in prerouting after conntrack (priority -200) and before the system's DNAT
// (-100), so ports are the ones the peer connected to even where the system redirects them (a
// firewall that sends 443 to a proxy's port: the policy names what the peer opens). Not at the input
// hook with conntrack's original destination: rules with `ct original` cannot be read back by
// google/nftables (the kernel gives the direction as one byte), which made the agent's own firewall
// fact unknown (0.19.3, 0.20.0). An input-hook chain would also count in the firewall fact; this one
// does not. Other tables still apply: a packet this table accepts can be dropped by the system's
// firewall.
//
// A network the device joined besides the first (networks.go) has its own table on its interface,
// ento-filter-<interface>, and every network's forward chain then also drops what would pass
// between its interface and another network's, in both directions:
//
//	chain forward { ...
//	              iifname "ento0" oifname "ento1" drop
//	              iifname "ento1" oifname "ento0" drop }
const inboundFilterTable = "ento-filter"

// filterTable is the table of the inbound filter on interface ifName: ento-filter for the first
// network's (and in a linked network's namespace), ento-filter-<name> for a joined network's
// interfaces (ento1, ento2, ...), which share the device's namespace with the first.
func filterTable(ifName string) string {
	if memberInterface(ifName) {
		return inboundFilterTable + "-" + ifName
	}
	return inboundFilterTable
}

// SetFilter applies the network map's inbound filter (nil removes it). It is called with every
// application of the map (every few seconds): an unchanged filter is left alone, but its table is
// looked for each time and put back if something removed it (`nft flush ruleset`, which Debian's
// /etc/nftables.conf starts with; before 0.51 once a minute, so up to a minute without a filter:
// 2026-11-03 review, D2).
func (i *Iface) SetFilter(f *inboundFilter) error {
	if i.filter.sameAs(f) && i.filterSet {
		if f == nil {
			return nil
		}
		if present, err := filterTablePresent(i.ns, filterTable(i.Name)); err != nil || present {
			return err
		}
	}
	if err := applyInboundFilter(i.ns, i.Name, f); err != nil {
		return err
	}
	if f != nil && (len(f.serves) > 0 || len(f.exits) > 0) && !i.ns.IsOpen() {
		// A gateway forwards (in the device's own namespace; gateways of linked networks are none).
		if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o644); err != nil {
			return fmt.Errorf("enable forwarding for the routes this device serves: %w", err)
		}
	}
	i.filter, i.filterSet = f, true
	return nil
}

func nftIn(ns netns.NsHandle) (*nftables.Conn, error) {
	if ns.IsOpen() {
		return nftables.New(nftables.WithNetNSFd(int(ns)))
	}
	return nftables.New()
}

func filterTablePresent(ns netns.NsHandle, table string) (bool, error) {
	c, err := nftIn(ns)
	if err != nil {
		return false, err
	}
	defer c.CloseLasting()
	tables, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(tables, func(t *nftables.Table) bool { return t.Name == table }), nil
}

func applyInboundFilter(ns netns.NsHandle, ifName string, f *inboundFilter) error {
	c, err := nftIn(ns)
	if err != nil {
		return err
	}
	defer c.CloseLasting()
	tables, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return err
	}
	table := filterTable(ifName)
	for _, t := range tables {
		if t.Name == table {
			c.DelTable(t)
		}
	}
	if f == nil {
		return c.Flush()
	}
	t := c.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: table})
	accept := nftables.ChainPolicyAccept
	pre := c.AddChain(&nftables.Chain{Name: "prerouting", Table: t, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityMangle, Policy: &accept})
	rule := func(exprs ...expr.Any) { c.AddRule(&nftables.Rule{Table: t, Chain: pre, Exprs: exprs}) }
	ok := &expr.Verdict{Kind: expr.VerdictAccept}
	onIface := func(op expr.CmpOp) []expr.Any {
		return []expr.Any{&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: op, Register: 1, Data: ifname(ifName)}}
	}
	rule(append(onIface(expr.CmpOpNeq), ok)...)
	rule(&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
			Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
			Xor:  binaryutil.NativeEndian.PutUint32(0)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)}, ok)
	from := func(a netip.Addr) []expr.Any {
		return []expr.Any{&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: a.AsSlice()}}
	}
	// to matches the destination address against a network (masked comparison).
	to := func(n netip.Prefix) []expr.Any {
		return []expr.Any{&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: net.CIDRMask(n.Bits(), 32), Xor: []byte{0, 0, 0, 0}},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: n.Masked().Addr().AsSlice()}}
	}
	toSelf := func() []expr.Any {
		if !f.self.IsValid() {
			return nil
		}
		return to(netip.PrefixFrom(f.self, 32))
	}
	controls := make([]netip.Addr, 0, len(f.controls))
	for a := range f.controls {
		controls = append(controls, a)
	}
	slices.SortFunc(controls, func(a, b netip.Addr) int { return a.Compare(b) })
	for _, a := range controls {
		rule(append(from(a), ok)...)
	}
	peers := make([]netip.Addr, 0, len(f.accept))
	for a := range f.accept {
		peers = append(peers, a)
	}
	slices.SortFunc(peers, func(a, b netip.Addr) int { return a.Compare(b) })
	allow := func(match []expr.Any, set ports.Set) {
		if set.All() {
			rule(append(slices.Clone(match), ok)...)
			return
		}
		for _, r := range set {
			if m, known := portMatch(r); known {
				rule(append(slices.Clone(match), m...)...)
			}
		}
	}
	for _, a := range peers {
		allow(append(from(a), toSelf()...), f.accept[a])
	}
	exiting := make([]netip.Addr, 0, len(f.exits))
	for a := range f.exits {
		exiting = append(exiting, a)
	}
	slices.SortFunc(exiting, func(a, b netip.Addr) int { return a.Compare(b) })
	if f.self.IsValid() {
		for _, a := range exiting {
			allow(append(from(a), toSelf()...), dnsPorts)
		}
	}
	routed := make([]netip.Addr, 0, len(f.routes))
	for a := range f.routes {
		routed = append(routed, a)
	}
	slices.SortFunc(routed, func(a, b netip.Addr) int { return a.Compare(b) })
	for _, a := range routed {
		for _, rr := range f.routes[a] {
			allow(append(from(a), to(rr.network)...), rr.set)
		}
	}
	drop := &expr.Verdict{Kind: expr.VerdictDrop}
	if len(exiting) > 0 {
		// An exit forwards to public addresses only: not into private ranges (routes of their own),
		// nor to the gateway itself (its public address, its services).
		for _, n := range exitBlocked {
			rule(append(to(n), drop)...)
		}
		rule(&expr.Fib{Register: 1, FlagDADDR: true, ResultADDRTYPE: true},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(unix.RTN_LOCAL)}, drop)
		for _, a := range exiting {
			allow(from(a), f.exits[a])
		}
	}
	if f.logDrops != nil {
		// New connections only (what reaches here is neither established nor related): TCP with
		// SYN and no ACK, anything else; at most dropLogRate a minute each, in the kernel's log.
		logged := func() []expr.Any {
			return []expr.Any{
				&expr.Limit{Type: expr.LimitTypePkts, Rate: dropLogRate, Unit: expr.LimitTimeMinute, Burst: dropLogRate},
				&expr.Log{Key: 1<<unix.NFTA_LOG_PREFIX | 1<<unix.NFTA_LOG_LEVEL, Level: expr.LogLevelInfo, Data: []byte("ento-filter drop: ")},
			}
		}
		l4 := func(op expr.CmpOp) []expr.Any {
			return []expr.Any{&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: op, Register: 1, Data: []byte{unix.IPPROTO_TCP}}}
		}
		syn := []expr.Any{&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 13, Len: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1, Mask: []byte{0x12}, Xor: []byte{0}},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x02}}}
		rule(slices.Concat(onIface(expr.CmpOpEq), l4(expr.CmpOpEq), syn, logged())...)
		rule(slices.Concat(onIface(expr.CmpOpEq), l4(expr.CmpOpNeq), logged())...)
	}
	rule(append(onIface(expr.CmpOpEq), drop)...)
	if f.person != nil {
		addPersonChain(c, t, ifName, f, to)
	}
	var fwd *nftables.Chain
	forward := func() *nftables.Chain {
		if fwd == nil {
			fwd = c.AddChain(&nftables.Chain{Name: "forward", Table: t, Type: nftables.ChainTypeFilter,
				Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter, Policy: &accept})
		}
		return fwd
	}
	// Nothing passes between this network and the device's others, before anything else.
	for _, other := range f.isolate {
		for _, dir := range [][2]string{{ifName, other}, {other, ifName}} {
			c.AddRule(&nftables.Rule{Table: t, Chain: forward(), Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(dir[0])},
				&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(dir[1])},
				&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop}}})
		}
	}
	// Nothing the device forwards (from containers, virtual machines, a network behind it) reaches
	// its control nodes' sign-in port: a person signed in there is signed in on this device, so only
	for _, a := range controls {
		c.AddRule(&nftables.Rule{Table: t, Chain: forward(), Exprs: slices.Concat(
			[]expr.Any{&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(ifName)},
				&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}}},
			to(netip.PrefixFrom(a, 32)),
			[]expr.Any{&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}}},
			[]expr.Any{&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(api.SignInPort)},
				&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop}})})
	}
	if (len(f.serves) > 0 || len(exiting) > 0) && f.overlay.IsValid() {
		// Forwarded traffic leaves with the gateway's own LAN address, so the LAN needs no route back;
		// the LAN only answers, it opens nothing into the network.
		nat := c.AddChain(&nftables.Chain{Name: "postrouting", Table: t, Type: nftables.ChainTypeNAT,
			Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityNATSource})
		masq := slices.Clone(f.serves)
		if len(exiting) > 0 {
			masq = []netip.Prefix{exitNetwork} // everything leaving the tunnel
		}
		for _, n := range masq {
			exprs := []expr.Any{&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
				&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: net.CIDRMask(f.overlay.Bits(), 32), Xor: []byte{0, 0, 0, 0}},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: f.overlay.Masked().Addr().AsSlice()}}
			if n.Bits() > 0 {
				exprs = append(exprs, to(n)...)
			}
			exprs = append(exprs, &expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
				&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: ifname(ifName)}, &expr.Masq{})
			c.AddRule(&nftables.Rule{Table: t, Chain: nat, Exprs: exprs})
		}
		fw := forward()
		out := func() []expr.Any {
			return []expr.Any{&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(ifName)}}
		}
		c.AddRule(&nftables.Rule{Table: t, Chain: fw, Exprs: append(out(),
			&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
				Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
				Xor:  binaryutil.NativeEndian.PutUint32(0)},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)}, ok)})
		c.AddRule(&nftables.Rule{Table: t, Chain: fw, Exprs: append(out(), &expr.Verdict{Kind: expr.VerdictDrop})})
	}
	return c.Flush()
}

// portMatch is the match of one port rule, ending in accept (false: a rule this agent cannot express,
// which then allows nothing).
func portMatch(r ports.Rule) ([]expr.Any, bool) {
	ok := &expr.Verdict{Kind: expr.VerdictAccept}
	proto := func(p byte) []expr.Any {
		return []expr.Any{&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{p}}}
	}
	switch r.Proto {
	case "icmp":
		return append(proto(unix.IPPROTO_ICMP),
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{8}}, ok), true
	case "tcp", "udp":
		p := byte(unix.IPPROTO_TCP)
		if r.Proto == "udp" {
			p = unix.IPPROTO_UDP
		}
		m := proto(p)
		if r.From != 0 {
			m = append(m, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2})
			if r.From == r.To {
				m = append(m, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(r.From)})
			} else {
				m = append(m, &expr.Range{Op: expr.CmpOpEq, Register: 1,
					FromData: binaryutil.BigEndian.PutUint16(r.From), ToData: binaryutil.BigEndian.PutUint16(r.To)})
			}
		}
		return append(m, ok), true
	}
	return nil, false
}

// personChain is the chain that counts the person's traffic (person.go) among what the device sends
// into the interface:
//
//	chain person { type filter hook output priority filter; policy accept;
//	              oifname != "ento0" accept
//	              ct direction reply accept                  (answers: the device opened nothing)
//	              ip daddr <control node> accept             (each)
//	              ip daddr <peer> tcp dport 1514 accept      (what the machine layer alone may open)
//	              ip daddr <network> tcp dport 445 accept    (the same, behind a gateway)
//	              ip daddr <overlay> counter accept          (the person's, to peers)
//	              ip daddr <network> counter accept          (each network behind a gateway)
//	              counter }                                  (only with an exit only the person may use)
//
// It accepts everything: it only counts. Its counters start over when the table is made again.
const personChain = "person"

func addPersonChain(c *nftables.Conn, t *nftables.Table, ifName string, f *inboundFilter, to func(netip.Prefix) []expr.Any) {
	accept := nftables.ChainPolicyAccept
	ch := c.AddChain(&nftables.Chain{Name: personChain, Table: t, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityFilter, Policy: &accept})
	ok := &expr.Verdict{Kind: expr.VerdictAccept}
	rule := func(exprs ...expr.Any) { c.AddRule(&nftables.Rule{Table: t, Chain: ch, Exprs: exprs}) }
	ipv4 := []expr.Any{&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}}}
	rule(&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1}, &expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: ifname(ifName)}, ok)
	rule(&expr.Ct{Register: 1, Key: expr.CtKeyDIRECTION}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1}}, ok)
	r := f.person
	dst := func(n netip.Prefix) []expr.Any { return append(slices.Clone(ipv4), to(n)...) }
	sorted := func(m map[netip.Addr]bool) []netip.Addr {
		out := make([]netip.Addr, 0, len(m))
		for a := range m {
			out = append(out, a)
		}
		slices.SortFunc(out, func(a, b netip.Addr) int { return a.Compare(b) })
		return out
	}
	for _, a := range sorted(r.controls) {
		rule(append(dst(netip.PrefixFrom(a, 32)), ok)...)
	}
	counted := &expr.Counter{}
	if r.all {
		rule(counted)
		return
	}
	machine := func(match []expr.Any, set ports.Set) {
		if set.All() {
			rule(append(slices.Clone(match), ok)...)
			return
		}
		for _, pr := range set {
			if m, known := portMatch(pr); known {
				rule(append(slices.Clone(match), m...)...)
			}
		}
	}
	peers := map[netip.Addr]bool{}
	for a := range r.peers {
		peers[a] = true
	}
	for _, a := range sorted(peers) {
		machine(dst(netip.PrefixFrom(a, 32)), r.peers[a])
	}
	for _, rr := range r.routes {
		machine(dst(rr.network), rr.set)
	}
	if r.overlay.IsValid() {
		rule(append(dst(r.overlay), &expr.Counter{}, ok)...)
	}
	for _, rr := range r.routes {
		rule(append(dst(rr.network), &expr.Counter{}, ok)...)
	}
	if r.exit {
		rule(&expr.Counter{})
	}
}

// PersonTraffic adds up the person chain's counters (0 without the chain).
func (i *Iface) PersonTraffic() (uint64, error) {
	if i.filter == nil || i.filter.person == nil {
		return 0, nil
	}
	c, err := nftIn(i.ns)
	if err != nil {
		return 0, err
	}
	defer c.CloseLasting()
	t := &nftables.Table{Family: nftables.TableFamilyINet, Name: filterTable(i.Name)}
	rules, err := c.GetRules(t, &nftables.Chain{Name: personChain, Table: t})
	if err != nil {
		return 0, err
	}
	var n uint64
	for _, r := range rules {
		for _, e := range r.Exprs {
			if ctr, ok := e.(*expr.Counter); ok {
				n += ctr.Bytes
			}
		}
	}
	return n, nil
}
