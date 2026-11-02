package control

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"testing"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/store"
)

// A route to an office network: devices a policy lets reach "route:office" get the gateway as a peer
// carrying the network; the gateway gets, for each of them, what they may open there; a device
// without such a policy gets neither, and a policy between groups never reaches a route.
func TestRoutes(t *testing.T) {
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
	gw, gp := device("office-gw", "gateways")
	staff, sp := device("laptop-1", "staff")
	other, _ := device("laptop-2", "guests")
	netmap := func(c *testClient) api.NetMap {
		var nm api.NetMap
		c.do(t, "GET", api.PathNetMap, nil, &nm)
		return nm
	}
	peer := func(nm api.NetMap, addr netip.Addr) *api.Peer {
		for i := range nm.Peers {
			if nm.Peers[i].Address == addr.String() {
				return &nm.Peers[i]
			}
		}
		return nil
	}

	// Validation.
	for _, bad := range []api.Route{
		{Name: "office", Networks: []string{"192.168.10.1/24"}, Via: "office-gw"},  // host bits
		{Name: "office", Networks: []string{"100.64.5.0/24"}, Via: "office-gw"},    // the overlay
		{Name: "office", Networks: []string{"0.0.0.0/0"}, Via: "office-gw"},        // an exit
		{Name: "Office!", Networks: []string{"192.168.10.0/24"}, Via: "office-gw"}, // the name
	} {
		if code := admin.do(t, "POST", api.PathRoutes, bad, nil); code != http.StatusBadRequest {
			t.Errorf("route %+v: HTTP %d", bad, code)
		}
	}
	var created api.Route
	if code := admin.do(t, "POST", api.PathRoutes, api.Route{Name: "office", Networks: []string{"192.168.10.0/24"}, Via: "office-gw"}, &created); code != http.StatusCreated {
		t.Fatalf("add route: HTTP %d", code)
	}
	if code := admin.do(t, "POST", api.PathRoutes, api.Route{Name: "lab", Networks: []string{"192.168.10.128/25"}, Via: "office-gw"}, nil); code != http.StatusBadRequest {
		t.Fatalf("an overlapping route: HTTP %d", code)
	}
	if code := admin.do(t, "POST", api.PathPolicies, api.Policy{Source: "staff", Destination: "route:nowhere"}, nil); code != http.StatusBadRequest {
		t.Fatalf("a policy to a route that does not exist: HTTP %d", code)
	}
	if code := admin.do(t, "POST", api.PathPolicies, api.Policy{Source: "route:office", Destination: "staff"}, nil); code != http.StatusBadRequest {
		t.Fatalf("a route as a source: HTTP %d", code)
	}

	// No policy to the route yet: nobody reaches it, even with "*" between groups.
	admin.do(t, "POST", api.PathPolicies, api.Policy{Source: "*", Destination: "admins"}, nil)
	srv.checkVersion(ctx)
	if p := peer(netmap(staff), gp.Address); p != nil && len(p.Routes) > 0 {
		t.Fatalf("a route without a policy: %+v", p)
	}
	var pol api.Policy
	if code := admin.do(t, "POST", api.PathPolicies, api.Policy{Source: "staff", Destination: "route:office", Ports: []string{"tcp/445", "tcp/3389"}}, &pol); code != http.StatusCreated {
		t.Fatalf("policy to the route: HTTP %d", code)
	}
	srv.checkVersion(ctx)
	nm := netmap(staff)
	if p := peer(nm, gp.Address); p == nil || !slices.Equal(p.Routes, []string{"192.168.10.0/24"}) || len(p.Accept) != 0 {
		t.Fatalf("the staff laptop's map: %+v", nm.Peers)
	}
	gnm := netmap(gw)
	if !slices.Equal(gnm.Self.Routes, []string{"192.168.10.0/24"}) {
		t.Fatalf("the gateway serves %v", gnm.Self.Routes)
	}
	if p := peer(gnm, sp.Address); p == nil || len(p.RouteAccept) != 1 || p.RouteAccept[0].Network != "192.168.10.0/24" ||
		!slices.Equal(p.RouteAccept[0].Ports, []string{"tcp/3389", "tcp/445"}) || len(p.Accept) != 0 {
		t.Fatalf("the gateway's map: %+v", gnm.Peers)
	}
	if p := peer(netmap(other), gp.Address); p != nil && len(p.Routes) > 0 {
		t.Fatalf("a device outside the policy reaches the route: %+v", p)
	}
	// The relay carries what the route allows.
	peers, _ := st.Peers(ctx)
	policies, _ := st.Policies(ctx)
	routes, _ := st.Routes(ctx)
	table := newRelayTable(peers, policies, nil, routes)
	if !table.permits(sp, gp) || !table.permits(gp, sp) {
		t.Fatal("the relay refuses a route's traffic")
	}
	// A route a policy leads to is not deleted.
	if code := admin.do(t, "DELETE", api.PathRoutes+"/office", nil, nil); code != http.StatusConflict {
		t.Fatalf("delete a route in use: HTTP %d", code)
	}
	admin.do(t, "DELETE", fmt.Sprintf("%s/%d", api.PathPolicies, pol.ID), nil, nil)
	if code := admin.do(t, "DELETE", api.PathRoutes+"/office", nil, nil); code != http.StatusNoContent {
		t.Fatalf("delete the route: HTTP %d", code)
	}

	// An exit: no networks, offered to the devices a policy lets use it, 0.0.0.0/0 in the gateway's
	// RouteAccept for them; "default" only for an exit.
	for _, bad := range []api.Route{
		{Name: "internet", Networks: []string{"192.168.20.0/24"}, Via: "office-gw", Exit: true},
		{Name: "lan", Networks: []string{"192.168.20.0/24"}, Via: "office-gw", Default: true},
	} {
		if code := admin.do(t, "POST", api.PathRoutes, bad, nil); code != http.StatusBadRequest {
			t.Errorf("route %+v: HTTP %d", bad, code)
		}
	}
	if code := admin.do(t, "POST", api.PathRoutes, api.Route{Name: "internet", Via: "office-gw", Exit: true, Default: true}, &created); code != http.StatusCreated || !created.Exit || !created.Default {
		t.Fatalf("add an exit: HTTP %d %+v", code, created)
	}
	if code := admin.do(t, "POST", api.PathPolicies, api.Policy{Source: "staff", Destination: "route:internet"}, &pol); code != http.StatusCreated {
		t.Fatalf("policy to the exit: HTTP %d", code)
	}
	srv.checkVersion(ctx)
	if p := peer(netmap(staff), gp.Address); p == nil || len(p.Routes) != 0 ||
		!slices.Equal(p.Exits, []api.ExitOffer{{Route: "internet", Default: true}}) {
		t.Fatalf("the staff laptop is not offered the exit: %+v", p)
	}
	if p := peer(netmap(other), gp.Address); p != nil && len(p.Exits) > 0 {
		t.Fatalf("a device outside the policy is offered the exit: %+v", p)
	}
	gnm = netmap(gw)
	if !gnm.Self.Exit || len(gnm.Self.Routes) != 0 {
		t.Fatalf("the gateway's self: %+v", gnm.Self)
	}
	if p := peer(gnm, sp.Address); p == nil || len(p.RouteAccept) != 1 || p.RouteAccept[0].Network != "0.0.0.0/0" || !slices.Equal(p.RouteAccept[0].Ports, []string{"all"}) {
		t.Fatalf("the gateway's map for the exit: %+v", p)
	}
	if code := admin.do(t, "DELETE", api.PathRoutes+"/internet", nil, nil); code != http.StatusConflict {
		t.Fatalf("delete an exit in use: HTTP %d", code)
	}
}

func TestNoGateways(t *testing.T) {
	peers := []store.Peer{
		{Hostname: "node-a", Approved: true, Groups: []string{"servers"}},
		{Hostname: "office", Approved: true, Groups: []string{"offices"}},
		{Hostname: "laptop", Approved: true, Machine: store.Rights{Groups: []string{"servers"}}},
	}
	routes := []store.Route{{Name: "lan", Via: "office"}, {Name: "exit", Via: "node-a", Exit: true}, {Name: "x", Via: "laptop"}}
	got := usableRoutes(routes, peers, []string{"servers"})
	if len(got) != 1 || got[0].Name != "lan" {
		t.Fatalf("usable routes: %+v", got)
	}
	if len(usableRoutes(routes, peers, nil)) != 3 {
		t.Fatal("without --no-gateways every route stays")
	}
	if neverGateway(peers[0], []string{"servers"}) != "servers" || neverGateway(peers[1], []string{"servers"}) != "" {
		t.Fatal("neverGateway")
	}
}
