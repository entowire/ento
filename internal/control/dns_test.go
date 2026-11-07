package control

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/ipam"
	"entowire.com/ento/internal/store"
)

// Internal DNS: each device's map names itself, the devices of its map and the administrators'
// names it can reach (through a route, or outside the network); forwarded zones likewise.
func TestDNS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, st := startTestNetwork(t, ctx, "100.64.0.0/16")
	admin := adminOf(t, ctx, srv, st, "ops-laptop", "admins")
	device := func(name string, groups ...string) (*testClient, store.Peer) {
		tok, _, _ := IssueToken(ctx, st, TokenOptions{Approve: true, Groups: groups, Name: name})
		srv.checkVersion(ctx)
		c, res := enroll(t, tok, name)
		p, _ := st.PeerByAddress(ctx, netip.MustParseAddr(res.Address))
		return c, p
	}
	_, gp := device("office-gw", "gateways")
	staff, _ := device("laptop-1", "staff")
	other, op := device("laptop-2", "guests")
	netmap := func(c *testClient) api.NetMap {
		var nm api.NetMap
		c.do(t, "GET", api.PathNetMap, nil, &nm)
		return nm
	}

	// Without a domain: no DNS in maps, and nothing to add.
	if nm := netmap(staff); nm.DNS != nil {
		t.Fatalf("DNS without a domain: %+v", nm.DNS)
	}
	if code := admin.do(t, "POST", api.PathDNSRecords, api.DNSRecord{Name: "nas", Address: "192.168.10.5"}, nil); code != http.StatusConflict {
		t.Fatalf("a name without a domain: HTTP %d", code)
	}
	srv.cfg.DNSDomain = "example.internal"

	admin.do(t, "POST", api.PathRoutes, api.Route{Name: "office", Networks: []string{"192.168.10.0/24"}, Via: "office-gw"}, nil)
	admin.do(t, "POST", api.PathPolicies, api.Policy{Source: "staff", Destination: "route:office"}, nil)
	admin.do(t, "POST", api.PathPolicies, api.Policy{Source: "*", Destination: "admins"}, nil)
	for _, bad := range []api.DNSRecord{
		{Name: "bad_name", Address: "192.168.10.5"},
		{Name: "nas", Address: "fd00::1"},
		{Name: "example.internal", Address: "192.168.10.5"},
	} {
		if code := admin.do(t, "POST", api.PathDNSRecords, bad, nil); code != http.StatusBadRequest {
			t.Errorf("record %+v: HTTP %d", bad, code)
		}
	}
	var rec api.DNSRecord
	if code := admin.do(t, "POST", api.PathDNSRecords, api.DNSRecord{Name: "NAS.Office.example.internal.", Address: "192.168.10.5"}, &rec); code != http.StatusCreated || rec.Name != "nas.office" {
		t.Fatalf("add a full name: HTTP %d %+v", code, rec)
	}
	if code := admin.do(t, "POST", api.PathDNSRecords, api.DNSRecord{Name: "nas.office", Address: "192.168.10.6"}, nil); code != http.StatusConflict {
		t.Fatalf("a name twice: HTTP %d", code)
	}
	admin.do(t, "POST", api.PathDNSRecords, api.DNSRecord{Name: "web", Address: "203.0.113.10"}, nil)
	admin.do(t, "POST", api.PathDNSRecords, api.DNSRecord{Name: "guest-alias", Address: op.Address.String()}, nil)
	admin.do(t, "POST", api.PathDNSRecords, api.DNSRecord{Name: "laptop-1", Address: "192.168.10.9"}, nil) // a device's name
	for _, bad := range []api.DNSForward{
		{Zone: "example.internal", Servers: []string{"192.168.10.1"}},
		{Zone: "corp.example.com", Servers: []string{"1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4", "1.1.1.5"}},
		{Zone: "corp.example.com", Servers: []string{"office-dns"}},
	} {
		if code := admin.do(t, "POST", api.PathDNSForwards, bad, nil); code != http.StatusBadRequest {
			t.Errorf("forward %+v: HTTP %d", bad, code)
		}
	}
	admin.do(t, "POST", api.PathDNSForwards, api.DNSForward{Zone: "corp.example.com", Servers: []string{"192.168.10.1"}}, nil)
	admin.do(t, "POST", api.PathDNSForwards, api.DNSForward{Zone: "ext.example", Servers: []string{"9.9.9.9"}}, nil)
	var listed api.DNSAdmin
	admin.do(t, "GET", api.PathDNS, nil, &listed)
	if i := slices.IndexFunc(listed.Records, func(r api.DNSRecord) bool { return r.Name == "laptop-1" }); i < 0 || len(listed.Records[i].Warnings) == 0 ||
		listed.Domain != "example.internal" || len(listed.Forwards) != 2 {
		t.Fatalf("the list: %+v", listed)
	}
	srv.checkVersion(ctx)

	names := func(d *api.DNSConfig) map[string]string {
		out := map[string]string{}
		for _, r := range d.Records {
			out[r.Name] = r.Address
		}
		return out
	}
	zones := func(d *api.DNSConfig) []string {
		var out []string
		for _, f := range d.Forwards {
			out = append(out, f.Zone)
		}
		return out
	}
	nm := netmap(staff)
	if nm.DNS == nil || nm.DNS.Domain != "example.internal" {
		t.Fatalf("the staff laptop's DNS: %+v", nm.DNS)
	}
	got := names(nm.DNS)
	// The record named like a device answers for the name (0.50, A2: before, the device did).
	want := map[string]string{"laptop-1": "192.168.10.9", "office-gw": gp.Address.String(), "nas.office": "192.168.10.5", "web": "203.0.113.10"}
	for n, a := range want {
		if got[n] != a {
			t.Errorf("staff: %s is %q, want %q (%v)", n, got[n], a, got)
		}
	}
	if _, ok := got["guest-alias"]; ok {
		t.Errorf("staff resolves a device it does not reach: %v", got)
	}
	if z := zones(nm.DNS); !slices.Equal(z, []string{"corp.example.com", "ext.example"}) {
		t.Errorf("staff zones %v", z)
	}
	got = names(netmap(other).DNS)
	if _, ok := got["nas.office"]; ok {
		t.Errorf("a guest resolves a name in an office it does not reach: %v", got)
	}
	if got["web"] != "203.0.113.10" || got["laptop-2"] != op.Address.String() || got["guest-alias"] != op.Address.String() {
		t.Errorf("guest names %v", got)
	}
	if z := zones(netmap(other).DNS); !slices.Equal(z, []string{"ext.example"}) {
		t.Errorf("guest zones %v", z)
	}
	if code := admin.do(t, "DELETE", api.PathDNSRecords+"/web", nil, nil); code != http.StatusNoContent {
		t.Fatalf("delete a name: HTTP %d", code)
	}
	if code := admin.do(t, "DELETE", api.PathDNSForwards+"/ext.example", nil, nil); code != http.StatusNoContent {
		t.Fatalf("delete a zone: HTTP %d", code)
	}
	if code := staff.do(t, "POST", api.PathDNSRecords, api.DNSRecord{Name: "mine", Address: "192.168.10.7"}, nil); code != http.StatusForbidden {
		t.Fatalf("a device that is no admin added a name: HTTP %d", code)
	}
}

// The names the control nodes serve on their overlay addresses (the identity provider's when they
// forward it, the admin interface's) go to every device, approved or not, with every control node's
// address: a device must reach them to sign in, whatever the DNS of its network makes of them.
func TestFixedNames(t *testing.T) {
	ctx := context.Background()
	space, _ := ipam.New(netip.MustParsePrefix("100.75.0.0/16"))
	nm := api.NetMap{Self: api.Self{Approved: false, Hostname: "phone", Address: "100.75.1.9"},
		Controls: []api.Control{{Name: "a", Address: "100.75.0.1"}, {Name: "b", Address: "100.75.0.2"}}}
	want := []api.Host{{Name: "id.example.com", Address: "100.75.0.1"}, {Name: "id.example.com", Address: "100.75.0.2"},
		{Name: "net.example.com", Address: "100.75.0.1"}, {Name: "net.example.com", Address: "100.75.0.2"}}
	s := &Server{cfg: Config{Space: space, Store: store.NewMemory(space), AdminUI: "Net.Example.com",
		OIDC: &OIDCConfig{Issuer: "https://ID.example.com/realms/team", ConnectTo: []string{"10.90.0.1:8443"}}}}
	dns, err := s.dnsConfig(ctx, nm)
	if err != nil || dns == nil || dns.Domain != "" || dns.Records != nil || !slices.Equal(dns.Fixed, want) {
		t.Fatalf("not approved, no domain: %+v %v", dns, err)
	}
	s.cfg.DNSDomain = "example.internal"
	nm.Self.Approved = true
	if dns, err = s.dnsConfig(ctx, nm); err != nil || dns == nil || dns.Domain != "example.internal" || !slices.Equal(dns.Fixed, want) {
		t.Fatalf("approved, with a domain: %+v %v", dns, err)
	}
	nm.Self.Approved = false
	if dns, err = s.dnsConfig(ctx, nm); err != nil || dns == nil || dns.Domain != "" || len(dns.Records) != 0 || !slices.Equal(dns.Fixed, want) {
		t.Fatalf("not approved, with a domain: %+v %v", dns, err)
	}
	// An identity provider the devices reach directly (no forward) keeps its own addresses.
	s.cfg.OIDC.ConnectTo, s.cfg.AdminUI = nil, ""
	if dns, err = s.dnsConfig(ctx, nm); err != nil || dns != nil {
		t.Fatalf("no forward, no admin interface: %+v %v", dns, err)
	}
	s.cfg.OIDC = &OIDCConfig{Issuer: "https://192.0.2.7/realms/team", ConnectTo: []string{"10.90.0.1:8443"}}
	if names := s.fixedNames(nm); len(names) != 0 {
		t.Fatalf("an issuer by address: %+v", names)
	}
}

// Service names resolve with the control node's DNS; only addresses inside the network are given,
// and a name that does not resolve for a moment keeps its addresses.
func TestServiceNames(t *testing.T) {
	network := netip.MustParsePrefix("100.75.0.0/16")
	answers := map[string][]netip.Addr{
		"chat.example.com":  {netip.MustParseAddr("100.75.1.4"), netip.MustParseAddr("100.75.1.3"), netip.MustParseAddr("100.75.1.3")},
		"www.example.com":   {netip.MustParseAddr("192.0.2.10")},                                    // outside: left out
		"mixed.example.com": {netip.MustParseAddr("192.0.2.11"), netip.MustParseAddr("100.75.1.9")}, // only the inside one
	}
	failing := map[string]bool{}
	lookup := func(_ context.Context, name string) ([]netip.Addr, error) {
		if failing[name] {
			return nil, errors.New("timeout")
		}
		return answers[name], nil
	}
	names := []string{"chat.example.com", "www.example.com", "mixed.example.com"}
	hosts, notes := resolveServiceNames(context.Background(), lookup, names, network, nil)
	want := []api.Host{{Name: "chat.example.com", Address: "100.75.1.3"}, {Name: "chat.example.com", Address: "100.75.1.4"},
		{Name: "mixed.example.com", Address: "100.75.1.9"}}
	if !slices.Equal(hosts, want) || len(notes) != 3 || !strings.Contains(notes[1], "no address inside") {
		t.Fatalf("hosts %+v notes %q", hosts, notes)
	}
	failing["chat.example.com"] = true
	again, notes := resolveServiceNames(context.Background(), lookup, names, network, &hosts)
	if !slices.Equal(again, want) || !strings.Contains(notes[0], "keeping 2") {
		t.Fatalf("after a failed lookup: %+v %q", again, notes)
	}

	// In the network map, after the names the control nodes serve (which keep their addresses).
	s := &Server{cfg: Config{AdminUI: "chat.example.com"}}
	s.services.Store(&hosts)
	nm := api.NetMap{Controls: []api.Control{{Address: "100.75.0.1"}}}
	got := s.fixedNames(nm)
	if !slices.Equal(got, []api.Host{{Name: "chat.example.com", Address: "100.75.0.1"}, {Name: "mixed.example.com", Address: "100.75.1.9"}}) {
		t.Fatalf("fixed names %+v", got)
	}
}
