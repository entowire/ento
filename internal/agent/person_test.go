package agent

import (
	"net/netip"
	"testing"

	"entowire.com/ento/internal/api"
)

// What the device sends counts as its person's when the machine layer alone would not send it: to a
// peer beyond the ports the machine may open there, into a network behind a gateway likewise, and
// through an exit only the person may use; never to control nodes, nor answers.
func TestPersonTraffic(t *testing.T) {
	nm := api.NetMap{Filter: true, Network: "100.64.0.0/16", Self: api.Self{Address: "100.64.1.9", PersonActive: true},
		Controls: []api.Control{{Address: "100.64.0.1"}},
		Peers: []api.Peer{
			{Address: "100.64.1.2", Machine: []string{"tcp/1514", "tcp/1515"}, Accept: []string{"tcp/8080"}}, // a server: the SIEM's ports
			{Address: "100.64.1.3", Machine: []string{"all"}},                                                // the machine reaches everything
			{Address: "100.64.1.4"}, // only the person
			{Address: "100.64.1.5", Routes: []string{"192.168.10.0/24"}, RouteMachine: []api.RouteRule{{Network: "192.168.10.0/24", Ports: []string{"udp/53"}}}},
		}}
	f := filterFromMap(nm)
	if f.person == nil {
		t.Fatal("no person rules with the person layer open")
	}
	self := "100.64.1.9"
	for _, c := range []struct {
		name string
		p    []byte
		want bool
	}{
		{"the SIEM agent's port", ipv4(self, "100.64.1.2", 6, 40000, 1514, tcpSYN), false},
		{"ssh to the server", ipv4(self, "100.64.1.2", 6, 40000, 22, tcpSYN), true},
		{"an answer from the server's service on the device", ipv4(self, "100.64.1.2", 6, 8080, 40000, 0x10), false},
		{"anything to a peer the machine reaches entirely", ipv4(self, "100.64.1.3", 6, 40000, 22, tcpSYN), false},
		{"a peer only the person reaches", ipv4(self, "100.64.1.4", 17, 40000, 51000, 0), true},
		{"a ping", ipv4(self, "100.64.1.4", 1, 0, 0, 8), true},
		{"an echo reply", ipv4(self, "100.64.1.4", 1, 0, 0, 0), false},
		{"the control plane", ipv4(self, "100.64.0.1", 6, 40000, 80, tcpSYN), false},
		{"the office's DNS (the machine's)", ipv4(self, "192.168.10.1", 17, 40000, 53, 0), false},
		{"the office's file server", ipv4(self, "192.168.10.20", 6, 40000, 445, tcpSYN), true},
		{"the internet without an exit of the person's", ipv4(self, "1.1.1.1", 6, 40000, 443, tcpSYN), false},
	} {
		if got := f.person.counts(c.p, f.accept); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	r := *f.person
	r.exit = true
	if !r.counts(ipv4(self, "1.1.1.1", 6, 40000, 443, tcpSYN), f.accept) {
		t.Error("the internet through an exit only the person may use is not counted")
	}
	all := &personRules{all: true, controls: map[netip.Addr]bool{netip.MustParseAddr("100.66.0.1"): true}}
	if !all.counts(ipv4("100.66.1.9", "100.66.1.2", 6, 40000, 1514, tcpSYN), nil) || all.counts(ipv4("100.66.1.9", "100.66.0.1", 6, 40000, 80, tcpSYN), nil) {
		t.Error("a linked network: everything but its control nodes counts")
	}
	// The person layer closed: nothing counts, and the filter changes with it.
	nm.Self.PersonActive = false
	if g := filterFromMap(nm); g.person != nil || g.key == f.key {
		t.Error("person rules without the person layer, or the filter unchanged")
	}
}
