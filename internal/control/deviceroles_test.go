package control

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/ipam"
	"entowire.com/ento/internal/store"
)

// A device's own role is its groups (0.47), and a role takes a person too (0.54): an admin token
// puts the device in the admin group, an old admin flag without the group is moved into it, and an
// admin person signing in on the device leaves it there: the two together administer, neither alone.
func TestDeviceRolesAreGroups(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	space, _ := ipam.New(netip.MustParsePrefix("100.64.0.0/16"))
	st := store.NewMemory(space)
	key, _ := wgtypes.GeneratePrivateKey()
	port := freeUDPPort(t)
	srv, err := Start(ctx, Config{Name: "c1", PrivateKey: key, ListenPort: port, Endpoint: fmt.Sprintf("127.0.0.1:%d", port),
		Space: space, Store: st, Logf: (&logLines{t: t}).logf})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	// The first administrator's token, naming a group too: the device is in the admin group, and
	// with nobody signed in it does not administer.
	tok, _, _ := IssueToken(ctx, st, TokenOptions{Admin: true, Approve: true, Groups: []string{"laptops"}})
	_, res := enroll(t, tok, "first-laptop")
	p, _ := st.PeerByAddress(ctx, netip.MustParseAddr(res.Address))
	if !slices.Contains(p.Machine.Groups, DeviceAdminGroup) || !slices.Contains(p.Machine.Groups, "device:laptops") || !p.Machine.Admin || p.Admin {
		t.Fatalf("admin token: groups %v in admin %v admin %v", p.Machine.Groups, p.Machine.Admin, p.Admin)
	}

	// An admin person signs in on it: full administration; the device keeps its groups.
	on, sub, now := true, "sub-1", time.Now()
	if p, err = st.UpdatePeer(ctx, p.ID, store.PeerUpdate{User: &sub, LoginAt: &now, PersonActive: &on, PersonApproved: &on,
		PersonAdmin: &on, PersonGroups: &[]string{"admins"}}); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(p.Machine.Groups, DeviceAdminGroup) || !p.Admin || p.Operator {
		t.Fatalf("signed in as an admin: groups %v admin %v", p.Machine.Groups, p.Admin)
	}
	if m := p.MachineOnly(); m.Admin || !m.Approved {
		t.Fatalf("after the session: admin %v approved %v", m.Admin, m.Approved)
	}
	// An operator person on it operates; an admin person on a device outside admin views only.
	off := false
	if q, _ := st.UpdatePeer(ctx, p.ID, store.PeerUpdate{PersonAdmin: &off, PersonOperator: &on}); q.Admin || !q.Operator {
		t.Fatalf("an operator on an admin device: admin %v operator %v", q.Admin, q.Operator)
	}
	if q, _ := st.UpdatePeer(ctx, p.ID, store.PeerUpdate{PersonAdmin: &on, PersonOperator: &off, Groups: &[]string{"device:laptops"}, Admin: &off}); q.Admin || q.Operator || !srv.isViewer(q) {
		t.Fatalf("an admin on a laptop: admin %v operator %v viewer %v", q.Admin, q.Operator, srv.isViewer(q))
	}

	// A device made an admin before 0.47 by its flag alone is put in the admin group at start.
	tok, _, _ = IssueToken(ctx, st, TokenOptions{Approve: true, Groups: []string{"laptops"}})
	_, res = enroll(t, tok, "old-admin")
	q, _ := st.PeerByAddress(ctx, netip.MustParseAddr(res.Address))
	yes := true
	if _, err := st.UpdatePeer(ctx, q.ID, store.PeerUpdate{Admin: &yes}); err != nil {
		t.Fatal(err)
	}
	srv.rolesFromGroups(ctx)
	q, _ = st.PeerByAddress(ctx, q.Address)
	if !slices.Contains(q.Machine.Groups, DeviceAdminGroup) || !q.Machine.Admin {
		t.Fatalf("old admin flag: groups %v admin %v", q.Machine.Groups, q.Admin)
	}
	// Taken out of the admin group (as the dashboard, the API and `ento control groups` do: groups and
	// role together), it is no admin, and the start-up step does not put it back.
	groups, no := []string{"device:laptops"}, false
	if _, err := st.UpdatePeer(ctx, q.ID, store.PeerUpdate{Groups: &groups, Admin: &no}); err != nil {
		t.Fatal(err)
	}
	srv.rolesFromGroups(ctx)
	if q, _ = st.PeerByAddress(ctx, q.Address); q.Machine.Admin || slices.Contains(q.Machine.Groups, DeviceAdminGroup) {
		t.Fatalf("out of the admin group: groups %v admin %v", q.Machine.Groups, q.Admin)
	}
}

// Roles that 0.47 to 0.53 gave a person on any device stay where they were (0.54): once, each
// device whose person has a role is put in that role's device group; isolated devices, devices
// without a person and a removal made afterwards are left alone.
func TestRolesBothLayers(t *testing.T) {
	ctx := context.Background()
	space, _ := ipam.New(netip.MustParsePrefix("100.64.0.0/16"))
	st := store.NewMemory(space)
	s := &Server{cfg: Config{Store: st, Logf: t.Logf}}
	on, now := true, time.Now()
	device := func(name string, groups []string, admin, operator bool) store.Peer {
		temp, _ := wgtypes.GeneratePrivateKey()
		k, _ := wgtypes.GeneratePrivateKey()
		tok, err := st.CreateToken(ctx, store.Token{PublicKey: temp.PublicKey(), Name: name, Approve: true, Groups: groups, ExpiresAt: now.Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		p, err := st.Redeem(ctx, tok.TempAddress, k.PublicKey(), name, "linux", now, nil)
		if err != nil {
			t.Fatal(err)
		}
		sub := "sub-" + name
		p, err = st.UpdatePeer(ctx, p.ID, store.PeerUpdate{User: &sub, LoginAt: &now, PersonApproved: &on, PersonAdmin: &admin, PersonOperator: &operator})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	adminLaptop := device("a", []string{"device:laptops"}, true, false)
	operatorLaptop := device("o", []string{"device:laptops"}, false, true)
	plain := device("p", []string{"device:laptops"}, false, false)
	isolatedDev := device("i", []string{"device:isolated"}, true, false)
	if err := s.rolesBothLayers(ctx); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		p    store.Peer
		want []string
	}{
		{adminLaptop, []string{"device:laptops", DeviceAdminGroup}},
		{operatorLaptop, []string{"device:laptops", DeviceOperatorGroup}},
		{plain, []string{"device:laptops"}},
		{isolatedDev, []string{"device:isolated"}},
	} {
		got, _ := st.PeerByAddress(ctx, c.p.Address)
		if !slices.Equal(got.Machine.Groups, c.want) {
			t.Errorf("%s: groups %v, want %v", c.p.Hostname, got.Machine.Groups, c.want)
		}
	}
	got, _ := st.PeerByAddress(ctx, adminLaptop.Address)
	if !got.Machine.Admin || !got.Approved {
		t.Fatalf("the admin's laptop: in admin %v approved %v", got.Machine.Admin, got.Approved)
	}
	groups, off := []string{"device:laptops"}, false
	if _, err := st.UpdatePeer(ctx, got.ID, store.PeerUpdate{Groups: &groups, Admin: &off}); err != nil {
		t.Fatal(err)
	}
	if err := s.rolesBothLayers(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ = st.PeerByAddress(ctx, adminLaptop.Address); got.Machine.Admin {
		t.Fatal("a device taken out of admin afterwards was put back")
	}
}

// Without an identity provider nobody signs in, so a device in admin administers alone; with one,
// it takes its person too.
func TestRolesWithoutPeople(t *testing.T) {
	dev := testDevice(1, []string{DeviceAdminGroup})
	dev.Machine.Admin = true
	if p := (&Server{}).withRoles(dev); !p.Admin || p.Operator {
		t.Fatalf("no identity provider: admin %v operator %v", p.Admin, p.Operator)
	}
	if p := (&Server{cfg: Config{OIDC: &OIDCConfig{}}}).withRoles(dev); p.Admin {
		t.Fatal("with an identity provider, a device in admin administered with nobody signed in")
	}
	dev.Groups, dev.Machine.Groups = []string{"device:isolated"}, []string{"device:isolated"}
	if p := (&Server{}).withRoles(dev); p.Admin {
		t.Fatal("an isolated device administered")
	}
}
