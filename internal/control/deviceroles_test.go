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

// A device's own role is its groups (0.47): an admin token puts the device in the admin group, an
// old admin flag without the group is moved into it, and an admin person signing in on the device
// takes it out, so the device's admin rights end with their session.
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

	// The first administrator's token, naming a group too: the device is in the admin group.
	tok, _, _ := IssueToken(ctx, st, TokenOptions{Admin: true, Approve: true, Groups: []string{"laptops"}})
	_, res := enroll(t, tok, "first-laptop")
	p, _ := st.PeerByAddress(ctx, netip.MustParseAddr(res.Address))
	if !slices.Contains(p.Machine.Groups, DeviceAdminGroup) || !slices.Contains(p.Machine.Groups, "device:laptops") || !p.Admin {
		t.Fatalf("admin token: groups %v admin %v", p.Machine.Groups, p.Admin)
	}

	// An admin person signs in on it: the device leaves the admin group, keeps laptops and its approval.
	on, sub, now := true, "sub-1", time.Now()
	if p, err = st.UpdatePeer(ctx, p.ID, store.PeerUpdate{User: &sub, LoginAt: &now, PersonActive: &on, PersonApproved: &on,
		PersonAdmin: &on, PersonGroups: &[]string{"admins"}}); err != nil {
		t.Fatal(err)
	}
	p = srv.dropDeviceAdmin(ctx, p)
	if slices.Contains(p.Machine.Groups, DeviceAdminGroup) || !slices.Contains(p.Machine.Groups, "device:laptops") || !p.Admin {
		t.Fatalf("signed in as an admin: groups %v admin %v", p.Machine.Groups, p.Admin)
	}
	if m := p.MachineOnly(); m.Admin || !m.Approved {
		t.Fatalf("after the session: admin %v approved %v", m.Admin, m.Approved)
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
	if !slices.Contains(q.Machine.Groups, DeviceAdminGroup) || !q.Admin {
		t.Fatalf("old admin flag: groups %v admin %v", q.Machine.Groups, q.Admin)
	}
	// Taken out of the admin group (as the dashboard, the API and `ento control groups` do: groups and
	// role together), it is no admin, and the start-up step does not put it back.
	groups, no := []string{"device:laptops"}, false
	if _, err := st.UpdatePeer(ctx, q.ID, store.PeerUpdate{Groups: &groups, Admin: &no}); err != nil {
		t.Fatal(err)
	}
	srv.rolesFromGroups(ctx)
	if q, _ = st.PeerByAddress(ctx, q.Address); q.Admin || slices.Contains(q.Machine.Groups, DeviceAdminGroup) {
		t.Fatalf("out of the admin group: groups %v admin %v", q.Machine.Groups, q.Admin)
	}
}
