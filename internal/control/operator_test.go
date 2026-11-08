package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/store"
)

// TestOperatorLimits checks that operator devices administer ordinary devices, tokens and policies,
// and nothing that cannot be undone.
func TestOperatorLimits(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	srv, st := startTestNetwork(t, ctx, "100.70.0.0/16")
	admin := adminOf(t, ctx, srv, st, "admin")

	enrollPeer := func(host string) (*testClient, store.Peer) {
		tok, _, err := IssueToken(ctx, st, TokenOptions{Approve: true, Groups: []string{"staff"}})
		if err != nil {
			t.Fatal(err)
		}
		srv.checkVersion(ctx)
		c, res := enroll(t, tok, host)
		p, err := st.PeerByAddress(ctx, netip.MustParseAddr(res.Address))
		if err != nil {
			t.Fatal(err)
		}
		return c, p
	}
	op, opPeer := enrollPeer("op")
	if _, err := st.UpdatePeer(ctx, opPeer.ID, store.PeerUpdate{Operator: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	signInRoles(t, st)
	_, plain := enrollPeer("plain")
	var adminPeer store.Peer
	peers, _ := st.Peers(ctx)
	for _, p := range peers {
		if p.Admin {
			adminPeer = p
		}
	}
	peerPath := func(p store.Peer) string { return fmt.Sprintf("%s/%d", api.PathPeers, p.ID) }

	cases := []struct {
		name   string
		method string
		path   string
		body   any
		want   int
	}{
		{"list devices", "GET", api.PathPeers, nil, http.StatusOK},
		{"info", "GET", api.PathInfo, nil, http.StatusOK},
		{"list links", "GET", api.PathAdminLinks, nil, http.StatusOK},
		{"list authorities", "GET", api.PathAuthorities, nil, http.StatusOK},
		{"rename an ordinary device", "PATCH", peerPath(plain), api.UpdatePeerRequest{Hostname: ptr("renamed")}, http.StatusOK},
		{"regroup an ordinary device", "PATCH", peerPath(plain), api.UpdatePeerRequest{Groups: &[]string{"lab"}}, http.StatusOK},
		{"suspend an ordinary device", "PATCH", peerPath(plain), api.UpdatePeerRequest{Suspended: ptr(true)}, http.StatusOK},
		{"resume it", "PATCH", peerPath(plain), api.UpdatePeerRequest{Suspended: ptr(false)}, http.StatusOK},
		{"make a device admin", "PATCH", peerPath(plain), api.UpdatePeerRequest{Admin: ptr(true)}, http.StatusForbidden},
		{"make a device operator", "PATCH", peerPath(plain), api.UpdatePeerRequest{Operator: ptr(true)}, http.StatusForbidden},
		{"suspend the admin", "PATCH", peerPath(adminPeer), api.UpdatePeerRequest{Suspended: ptr(true)}, http.StatusForbidden},
		{"regroup itself", "PATCH", peerPath(opPeer), api.UpdatePeerRequest{Groups: &[]string{"x"}}, http.StatusForbidden},
		{"delete a device", "DELETE", peerPath(plain), nil, http.StatusForbidden},
		{"ordinary token", "POST", api.PathTokens, api.CreateTokenRequest{Groups: []string{"lab"}, TTLSeconds: 600}, http.StatusCreated},
		{"admin token", "POST", api.PathTokens, api.CreateTokenRequest{Admin: true, TTLSeconds: 600}, http.StatusForbidden},
		// A role group in the invitation gives the role as the flag does (A1).
		{"token into admin", "POST", api.PathTokens, api.CreateTokenRequest{Groups: []string{"admin"}, TTLSeconds: 600}, http.StatusForbidden},
		{"token into device:admin", "POST", api.PathTokens, api.CreateTokenRequest{Groups: []string{"device:admin"}, TTLSeconds: 600}, http.StatusForbidden},
		{"token into operator", "POST", api.PathTokens, api.CreateTokenRequest{Groups: []string{"lab", "operator"}, TTLSeconds: 600}, http.StatusForbidden},
		{"words into admin", "POST", api.PathTokens, api.CreateTokenRequest{Groups: []string{"admin"}, Words: true, TTLSeconds: 600}, http.StatusForbidden},
		{"replacing token", "POST", api.PathTokens, api.CreateTokenRequest{Name: "renamed", Replace: true, TTLSeconds: 600}, http.StatusForbidden},
		{"add a policy", "POST", api.PathPolicies, api.Policy{Source: "lab", Destination: "lab"}, http.StatusCreated},
		{"create a link", "POST", api.PathAdminLinks, api.CreateLinkRequest{Name: "x", Groups: []string{"lab"}}, http.StatusForbidden},
		{"delete an authority", "DELETE", api.PathAuthorities + "/x", nil, http.StatusForbidden},
	}
	for _, c := range cases {
		if got := op.do(t, c.method, c.path, c.body, nil); got != c.want {
			t.Errorf("operator: %s: HTTP %d, want %d", c.name, got, c.want)
		}
	}

	// Admins may give a role through an invitation's groups.
	for _, g := range [][]string{{"admin"}, {"device:admin"}, {"operator"}} {
		if code := admin.do(t, "POST", api.PathTokens, api.CreateTokenRequest{Groups: g, TTLSeconds: 600}, nil); code != http.StatusCreated {
			t.Errorf("admin: token into %v: HTTP %d, want 201", g, code)
		}
	}

	// Admins give and take the role; the device keeps working as an ordinary one.
	if code := admin.do(t, "PATCH", peerPath(opPeer), api.UpdatePeerRequest{Operator: ptr(false)}, nil); code != http.StatusOK {
		t.Fatalf("admin removes the operator role: HTTP %d", code)
	}
	if code := op.do(t, "GET", api.PathPeers, nil, nil); code != http.StatusOK {
		t.Errorf("former operator device lists devices: HTTP %d, want 200 (viewing)", code)
	}
	if code := op.do(t, "PATCH", peerPath(plain), api.UpdatePeerRequest{Approved: ptr(false)}, nil); code != http.StatusForbidden {
		t.Errorf("former operator device changes a device: HTTP %d, want 403", code)
	}
}

// TestLoginRoles checks the roles a sign-in gives on a device in admin: admin wins over operator,
// both are approved.
func TestLoginRoles(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, st := startTestNetwork(t, ctx, "100.71.0.0/16")
	if _, _, err := IssueToken(ctx, st, TokenOptions{Admin: true}); err != nil {
		t.Fatal(err)
	}
	toks, _ := st.ActiveTokens(ctx, time.Now())
	key, _ := wgtypes.GeneratePrivateKey()
	p, err := st.Redeem(ctx, toks[0].TempAddress, key.PublicKey(), "laptop", "linux", time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := OIDCConfig{GroupsClaim: "groups", ApproveGroups: []string{"staff"}, OperatorGroups: []string{"engineers"},
		AdminGroups: []string{"admins"}}
	for _, c := range []struct {
		groups                    string
		approved, operator, admin bool
	}{
		{`["staff"]`, true, false, false},
		{`["engineers"]`, true, true, false},
		{`["engineers","admins"]`, true, false, true},
		{`["guests"]`, false, false, false},
	} {
		claims := idClaims{Subject: "u1", Email: "u@example.test", raw: map[string]json.RawMessage{"groups": json.RawMessage(c.groups)}}
		got, err := applyLogin(ctx, st, cfg, p.ID, claims)
		if err != nil {
			t.Fatal(err)
		}
		if got.Approved != c.approved || got.Operator != c.operator || got.Admin != c.admin {
			t.Errorf("%s: approved=%v operator=%v admin=%v, want %v %v %v", c.groups, got.Approved, got.Operator, got.Admin,
				c.approved, c.operator, c.admin)
		}
	}
}

// An admin person signed in on an isolated device administers nothing (constitution 4.3, A3): the
// device has no rights at all while it is isolated.
func TestIsolatedDeviceAdministersNothing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	srv, st := startTestNetwork(t, ctx, "100.72.0.0/16")
	dev := adminOf(t, ctx, srv, st, "suspect")
	if code := dev.do(t, "GET", api.PathPeers, nil, nil); code != http.StatusOK {
		t.Fatalf("before: HTTP %d", code)
	}
	var p store.Peer
	peers, _ := st.Peers(ctx)
	for _, q := range peers {
		if q.ReportedHostname == "suspect" {
			p = q
		}
	}
	on, off, sub := true, false, "sub-1"
	if _, err := st.UpdatePeer(ctx, p.ID, store.PeerUpdate{Groups: &[]string{IsolatedGroup, DeviceAdminGroup}, Approved: &off}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpdatePeer(ctx, p.ID, store.PeerUpdate{User: &sub, PersonActive: &on, PersonApproved: &on, PersonAdmin: &on,
		PersonGroups: &[]string{"admins"}}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"GET", api.PathPeers, nil},
		{"POST", api.PathTokens, api.CreateTokenRequest{Admin: true, TTLSeconds: 600}},
	} {
		if code := dev.do(t, c.method, c.path, c.body, nil); code != http.StatusForbidden {
			t.Errorf("isolated, admin person signed in: %s %s: HTTP %d, want 403", c.method, c.path, code)
		}
	}
}

// Operators neither take a route's gateway nor a DNS record's name by renaming devices or naming a
// new one (A2, constitution 4.7); an admin may, audited; a record always wins over a device's name.
func TestOperatorRenames(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	srv, st := startTestNetwork(t, ctx, "100.73.0.0/16")
	srv.cfg.DNSDomain = "example.internal"
	admin := adminOf(t, ctx, srv, st, "admin")
	device := func(name string) (*testClient, store.Peer) {
		tok, _, _ := IssueToken(ctx, st, TokenOptions{Approve: true, Groups: []string{"staff"}, Name: name})
		srv.checkVersion(ctx)
		c, res := enroll(t, tok, name)
		p, _ := st.PeerByAddress(ctx, netip.MustParseAddr(res.Address))
		return c, p
	}
	_, gw := device("office-gw")
	_, box := device("box")
	laptop, _ := device("laptop")
	op, opPeer := device("op")
	if _, err := st.UpdatePeer(ctx, opPeer.ID, store.PeerUpdate{Operator: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	signInRoles(t, st)
	admin.do(t, "POST", api.PathRoutes, api.Route{Name: "office", Networks: []string{"192.168.10.0/24"}, Via: "office-gw"}, nil)
	admin.do(t, "POST", api.PathPolicies, api.Policy{Source: "staff", Destination: "route:office"}, nil)
	admin.do(t, "POST", api.PathPolicies, api.Policy{Source: "staff", Destination: "staff"}, nil)
	if code := admin.do(t, "POST", api.PathDNSRecords, api.DNSRecord{Name: "intranet", Address: "192.168.10.5"}, nil); code >= 300 {
		t.Fatalf("record: HTTP %d", code)
	}
	rename := func(c *testClient, p store.Peer, name string) int {
		return c.do(t, "PATCH", fmt.Sprintf("%s/%d", api.PathPeers, p.ID), api.UpdatePeerRequest{Hostname: &name}, nil)
	}
	for _, c := range []struct {
		p    store.Peer
		name string
	}{{gw, "old-gw"}, {box, "office-gw"}, {box, "intranet"}} {
		if code := rename(op, c.p, c.name); code != http.StatusForbidden {
			t.Errorf("operator renames %s to %s: HTTP %d, want 403", c.p.Hostname, c.name, code)
		}
	}
	if code := op.do(t, "POST", api.PathTokens, api.CreateTokenRequest{Name: "intranet", TTLSeconds: 600}, nil); code != http.StatusForbidden {
		t.Errorf("operator names an invitation after a record: HTTP %d, want 403", code)
	}
	if code := rename(op, box, "box-2"); code != http.StatusOK {
		t.Errorf("operator renames an ordinary device: HTTP %d", code)
	}
	// An admin's rename to a record's name: the record still answers for it.
	if code := rename(admin, box, "intranet"); code != http.StatusOK {
		t.Fatalf("admin renames to a record's name: HTTP %d", code)
	}
	var nm api.NetMap
	if code := laptop.do(t, "GET", api.PathNetMap, nil, &nm); code != 200 || nm.DNS == nil {
		t.Fatalf("map: HTTP %d %+v", code, nm.DNS)
	}
	found := false
	for _, h := range nm.DNS.Records {
		if h.Name == "intranet" {
			found = true
			if h.Address != "192.168.10.5" {
				t.Errorf("the device's name won over the record: intranet -> %s", h.Address)
			}
		}
	}
	if !found {
		t.Errorf("the record is not in the map: %+v", nm.DNS.Records)
	}
}
