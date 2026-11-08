package control

import (
	"context"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"testing"
	"time"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/store"
)

// they are signed in there; the laptop alone does not, nor an engineer on another device. Every
// change is in the network's audit (7.1), which the API lists newest first.
func TestPeopleOnDevicesAndAudit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, st := startTestNetwork(t, ctx, "100.64.0.0/16")
	admin := adminOf(t, ctx, srv, st, "ops-laptop")
	enrollIn := func(host string, groups ...string) (*testClient, store.Peer) {
		tok, _, _ := IssueToken(ctx, st, TokenOptions{Approve: true, Groups: groups})
		srv.checkVersion(ctx)
		c, res := enroll(t, tok, host)
		p, _ := st.PeerByAddress(ctx, netip.MustParseAddr(res.Address))
		return c, p
	}
	server, serverPeer := enrollIn("web-1", "servers")
	laptop, laptopPeer := enrollIn("lap-1", "laptops")
	_, desktopPeer := enrollIn("desk-1", "desktops")
	var pol api.Policy
	if code := admin.do(t, "POST", api.PathPolicies, api.Policy{Source: "engineers", On: "laptops", Destination: "servers",
		Ports: []string{"tcp/22"}}, &pol); code != http.StatusCreated {
		t.Fatalf("add: HTTP %d", code)
	}
	if pol.Source != "engineers on device:laptops" || pol.Who != "engineers" || pol.On != "device:laptops" || pol.Destination != "device:servers" {
		t.Fatalf("the rule: %+v", pol)
	}
	for _, bad := range []api.Policy{
		{Source: "device:servers", On: "laptops", Destination: "servers"},
		{Source: "engineers", On: "laptops", Destination: "*nobody"},
		{Source: "engineers", Destination: "service:nothing.example.com"},
	} {
		if code := admin.do(t, "POST", api.PathPolicies, bad, nil); code != http.StatusBadRequest {
			t.Errorf("%+v: HTTP %d", bad, code)
		}
	}
	reaches := func(c *testClient, addr netip.Addr) bool {
		srv.checkVersion(ctx)
		var nm api.NetMap
		c.do(t, "GET", api.PathNetMap, nil, &nm)
		return slices.ContainsFunc(nm.Peers, func(p api.Peer) bool { return p.Address == addr.String() })
	}
	if reaches(laptop, serverPeer.Address) {
		t.Fatal("the laptop reaches the server with nobody signed in")
	}
	signIn := func(p store.Peer, groups ...string) {
		on, sub, now := true, "sub-"+p.Hostname, time.Now()
		if _, err := st.UpdatePeer(ctx, p.ID, store.PeerUpdate{User: &sub, LoginAt: &now, PersonActive: &on, PersonApproved: &on,
			PersonSince: &now, PersonGroups: &groups}); err != nil {
			t.Fatal(err)
		}
	}
	signIn(laptopPeer, "engineers")
	signIn(desktopPeer, "engineers")
	if !reaches(laptop, serverPeer.Address) {
		t.Fatal("an engineer on a laptop does not reach the server")
	}
	if !reaches(server, laptopPeer.Address) || reaches(server, desktopPeer.Address) {
		t.Fatal("the server's map: it answers the laptop with an engineer, not the desktop with one")
	}

	// The audit: the rule, the refusals, the enrollments; by whom, newest first.
	var page api.AuditPage
	if code := admin.do(t, "GET", api.PathAudit+"?action=policy_added", nil, &page); code != 200 || len(page.Entries) != 1 {
		t.Fatalf("the audit: HTTP %d %+v", code, page)
	}
	e := page.Entries[0]
	if e.Device != "z-ops-laptop" || e.Node != "c1" || e.Result != "ok" || e.Target != "policy "+itoa(pol.ID)+" engineers on device:laptops -> device:servers ports=tcp/22" {
		t.Fatalf("the entry: %+v", e)
	}
	if code := admin.do(t, "GET", api.PathAudit+"?limit=2", nil, &page); code != 200 || len(page.Entries) != 2 || !page.More ||
		page.Entries[0].ID <= page.Entries[1].ID {
		t.Fatalf("a page: HTTP %d %+v", code, page)
	}
	older := page.Entries[1].ID
	if code := admin.do(t, "GET", api.PathAudit+"?limit=1&before="+itoa(older), nil, &page); code != 200 || len(page.Entries) != 1 || page.Entries[0].ID >= older {
		t.Fatalf("the next page: HTTP %d %+v", code, page)
	}
	if code := admin.do(t, "GET", api.PathAudit+"?q=LAP-1", nil, &page); code != 200 || len(page.Entries) == 0 {
		t.Fatalf("a search: HTTP %d %+v", code, page)
	}
	if code := admin.do(t, "GET", api.PathAudit+"?limit=0", nil, nil); code != http.StatusBadRequest {
		t.Fatalf("a bad limit: HTTP %d", code)
	}
	// Devices that do not administer do not read it.
	if code := laptop.do(t, "GET", api.PathAudit, nil, nil); code != http.StatusForbidden {
		t.Fatalf("an ordinary device: HTTP %d", code)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
