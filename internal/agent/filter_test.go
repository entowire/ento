package agent

import (
	"encoding/binary"
	"fmt"
	"slices"
	"testing"
	"time"

	"entowire.com/ento/internal/api"
)

// ipv4 builds an IPv4 packet from src to dst: proto 6 with TCP flags, 17 with ports, 1 with ICMP type.
func ipv4(src, dst string, proto byte, sport, dport uint16, flags byte) []byte {
	p := make([]byte, 20+20)
	p[0] = 0x45
	p[9] = proto
	copy(p[12:16], ip4(src))
	copy(p[16:20], ip4(dst))
	l4 := p[20:]
	switch proto {
	case 6, 17:
		binary.BigEndian.PutUint16(l4[0:2], sport)
		binary.BigEndian.PutUint16(l4[2:4], dport)
		l4[13] = flags
	case 1:
		l4[0] = flags // ICMP type
	}
	return p
}

func ip4(s string) []byte {
	var b [4]byte
	var n, i int
	for _, c := range s + "." {
		if c == '.' {
			b[i] = byte(n)
			i, n = i+1, 0
			continue
		}
		n = n*10 + int(c-'0')
	}
	return b[:]
}

const (
	tcpSYN    = 0x02
	tcpSYNACK = 0x12
	tcpACK    = 0x10
)

func TestInboundFilter(t *testing.T) {
	nm := api.NetMap{Filter: true, Controls: []api.Control{{Address: "100.64.0.1"}},
		Peers: []api.Peer{
			{Address: "100.64.1.2", Accept: []string{"tcp/22", "icmp"}}, // may open SSH and ping
			{Address: "100.64.1.3"}, // answers only
			{Address: "100.64.1.4", Accept: []string{"all"}},
		}}
	f := filterFromMap(nm)
	flows := &udpFlows{}
	me := "100.64.1.1"
	for _, c := range []struct {
		name string
		p    []byte
		want bool
	}{
		{"ssh opened by an allowed peer", ipv4("100.64.1.2", me, 6, 40000, 22, tcpSYN), true},
		{"another port opened by it", ipv4("100.64.1.2", me, 6, 40000, 80, tcpSYN), false},
		{"its ping", ipv4("100.64.1.2", me, 1, 0, 0, 8), true},
		{"a peer that only answers opens ssh", ipv4("100.64.1.3", me, 6, 40000, 22, tcpSYN), false},
		{"it answers this device's connection", ipv4("100.64.1.3", me, 6, 443, 40000, tcpSYNACK), true},
		{"and the data after", ipv4("100.64.1.3", me, 6, 443, 40000, tcpACK), true},
		{"its ping", ipv4("100.64.1.3", me, 1, 0, 0, 8), false},
		{"its echo reply", ipv4("100.64.1.3", me, 1, 0, 0, 0), true},
		{"its unasked UDP", ipv4("100.64.1.3", me, 17, 53, 5353, 0), false},
		{"a peer allowed everything", ipv4("100.64.1.4", me, 17, 1, 9, 0), true},
		{"a control node", ipv4("100.64.0.1", me, 17, 3479, 3479, 0), true},
		{"an address not in the map", ipv4("100.64.9.9", me, 6, 1, 22, tcpSYN), false},
		{"a truncated packet", ipv4("100.64.1.4", me, 6, 1, 22, tcpSYN)[:10], false},
	} {
		if got := f.passes(c.p, flows); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}

	// UDP answers pass for 2 minutes after this device's last datagram.
	now := time.Unix(1000, 0)
	flows.now = func() time.Time { return now }
	flows.outbound(ipv4(me, "100.64.1.3", 17, 5353, 53, 0))
	if !f.passes(ipv4("100.64.1.3", me, 17, 53, 5353, 0), flows) {
		t.Error("a DNS answer did not pass")
	}
	if f.passes(ipv4("100.64.1.3", me, 17, 53, 5354, 0), flows) {
		t.Error("a datagram to another local port passed")
	}
	now = now.Add(3 * time.Minute)
	if f.passes(ipv4("100.64.1.3", me, 17, 53, 5353, 0), flows) {
		t.Error("an answer passed after the flow expired")
	}

	if filterFromMap(api.NetMap{}) != nil {
		t.Error("a map without a filter made one")
	}
	g := filterFromMap(nm)
	if !f.sameAs(g) || f.sameAs(nil) || !(*inboundFilter)(nil).sameAs(nil) {
		t.Error("sameAs")
	}
}

// A gateway judges where a packet goes: its own address by the peer's device rules, a network it
// serves by the peer's rules there, anything else not at all.
func TestInboundFilterRoutes(t *testing.T) {
	nm := api.NetMap{Filter: true, Network: "100.64.0.0/16", Self: api.Self{Address: "100.64.1.9", Routes: []string{"192.168.10.0/24"}},
		Controls: []api.Control{{Address: "100.64.0.1"}},
		Peers: []api.Peer{
			{Address: "100.64.1.2", Accept: []string{"tcp/22"}, RouteAccept: []api.RouteRule{{Network: "192.168.10.0/24", Ports: []string{"tcp/445"}}}},
			{Address: "100.64.1.3", RouteAccept: []api.RouteRule{{Network: "10.9.9.0/24"}}}, // not served here
		}}
	f := filterFromMap(nm)
	flows := &udpFlows{}
	gw, lan := "100.64.1.9", "192.168.10.20"
	for _, c := range []struct {
		name string
		p    []byte
		want bool
	}{
		{"ssh on the gateway", ipv4("100.64.1.2", gw, 6, 40000, 22, tcpSYN), true},
		{"smb on the gateway", ipv4("100.64.1.2", gw, 6, 40000, 445, tcpSYN), false},
		{"smb in the office", ipv4("100.64.1.2", lan, 6, 40000, 445, tcpSYN), true},
		{"ssh in the office", ipv4("100.64.1.2", lan, 6, 40000, 22, tcpSYN), false},
		{"another network", ipv4("100.64.1.2", "10.1.1.1", 6, 40000, 445, tcpSYN), false},
		{"a network the map names but this device does not serve", ipv4("100.64.1.3", "10.9.9.5", 6, 1, 80, tcpSYN), false},
		{"a peer without a route in the office", ipv4("100.64.1.3", lan, 6, 1, 445, tcpSYN), false},
	} {
		if got := f.passes(c.p, flows); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// An exit forwards a device's traffic to public addresses only (a route of its own reaches a
// private network), answers its DNS, and forwards nothing for a device that does not use it.
func TestInboundFilterExit(t *testing.T) {
	nm := api.NetMap{Filter: true, Network: "100.64.0.0/16", Self: api.Self{Address: "100.64.1.9", Exit: true, Routes: []string{"192.168.10.0/24"}},
		Peers: []api.Peer{
			{Address: "100.64.1.2", RouteAccept: []api.RouteRule{{Network: "0.0.0.0/0", Ports: []string{"all"}},
				{Network: "192.168.10.0/24", Ports: []string{"tcp/445"}}}},
			{Address: "100.64.1.3", RouteAccept: []api.RouteRule{{Network: "0.0.0.0/0", Ports: []string{"tcp/443"}}}},
			{Address: "100.64.1.4"},
		}}
	f := filterFromMap(nm)
	flows := &udpFlows{}
	gw := "100.64.1.9"
	for _, c := range []struct {
		name string
		p    []byte
		want bool
	}{
		{"the web", ipv4("100.64.1.2", "1.1.1.1", 6, 40000, 443, tcpSYN), true},
		{"DNS on the internet", ipv4("100.64.1.2", "9.9.9.9", 17, 40000, 53, 0), true},
		{"DNS of the gateway", ipv4("100.64.1.2", gw, 17, 40000, 53, 0), true},
		{"DNS of the gateway over TCP", ipv4("100.64.1.2", gw, 6, 40000, 53, tcpSYN), true},
		{"ssh on the gateway", ipv4("100.64.1.2", gw, 6, 40000, 22, tcpSYN), false},
		{"the office through its route", ipv4("100.64.1.2", "192.168.10.20", 6, 40000, 445, tcpSYN), true},
		{"the office beyond its route", ipv4("100.64.1.2", "192.168.10.20", 6, 40000, 22, tcpSYN), false},
		{"another private network", ipv4("100.64.1.2", "10.0.0.1", 6, 40000, 443, tcpSYN), false},
		{"a cloud's metadata", ipv4("100.64.1.2", "169.254.169.254", 6, 40000, 80, tcpSYN), false},
		{"another device of the network", ipv4("100.64.1.2", "100.64.1.4", 6, 40000, 22, tcpSYN), false},
		{"multicast", ipv4("100.64.1.2", "239.1.1.1", 17, 40000, 5353, 0), false},
		{"only the web, the web", ipv4("100.64.1.3", "1.1.1.1", 6, 40000, 443, tcpSYN), true},
		{"only the web, ssh", ipv4("100.64.1.3", "1.1.1.1", 6, 40000, 22, tcpSYN), false},
		{"no exit for it", ipv4("100.64.1.4", "1.1.1.1", 6, 40000, 443, tcpSYN), false},
		{"no exit for it, DNS of the gateway", ipv4("100.64.1.4", gw, 17, 40000, 53, 0), false},
	} {
		if got := f.passes(c.p, flows); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	// Not an exit (the map says no): 0.0.0.0/0 in RouteAccept forwards nothing.
	nm.Self.Exit = false
	if f := filterFromMap(nm); len(f.exits) != 0 || f.passes(ipv4("100.64.1.2", "1.1.1.1", 6, 40000, 443, tcpSYN), flows) {
		t.Fatal("a device that is no exit forwards to the internet")
	}
}

func TestDropLog(t *testing.T) {
	var lines []string
	d := &dropLog{logf: func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }, iface: "ento0"}
	syn := make([]byte, 40)
	syn[0], syn[9] = 0x45, 6
	copy(syn[12:16], []byte{100, 64, 1, 5})
	copy(syn[16:20], []byte{100, 64, 1, 3})
	binary.BigEndian.PutUint16(syn[20:22], 40312)
	binary.BigEndian.PutUint16(syn[22:24], 22)
	syn[33] = 0x02
	d.note(syn)
	if len(lines) != 1 || lines[0] != "ento-filter drop: IN=ento0 SRC=100.64.1.5 DST=100.64.1.3 PROTO=TCP SPT=40312 DPT=22" {
		t.Fatalf("line: %q", lines)
	}
	icmp := slices.Clone(syn)
	icmp[9], icmp[20], icmp[21] = 1, 8, 0
	if got := dropLine("ento0", icmp); got != "ento-filter drop: IN=ento0 SRC=100.64.1.5 DST=100.64.1.3 PROTO=ICMP TYPE=8 CODE=0" {
		t.Errorf("icmp: %q", got)
	}
	// At most dropLogRate at once, then about dropLogRate a minute.
	now := time.Now()
	r := &dropLog{}
	n := 0
	for i := 0; i < 100; i++ {
		if r.allow(now) {
			n++
		}
	}
	if n != dropLogRate {
		t.Errorf("burst: %d", n)
	}
	if r.allow(now.Add(time.Second)) || !r.allow(now.Add(3*time.Second+time.Millisecond)) {
		t.Error("refill: one every 3 seconds")
	}
}
