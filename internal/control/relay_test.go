package control

import (
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/store"
)

func TestRelayPermits(t *testing.T) {
	peer := func(id int64, approved bool, groups ...string) store.Peer {
		k, _ := wgtypes.GeneratePrivateKey()
		return store.Peer{ID: id, PublicKey: k.PublicKey(), Approved: approved, Groups: groups,
			Address: netip.AddrFrom4([4]byte{100, 64, 1, byte(id)})}
	}
	admin := peer(1, true, "admins")
	server := peer(2, true, "servers")
	pending := peer(3, false, "servers")
	laptop := peer(4, true, "laptops")
	table := newRelayTable([]store.Peer{admin, server, pending, laptop},
		[]store.Policy{{Source: "admins", Destination: "servers"}}, nil, nil)

	cases := []struct {
		name     string
		src, dst store.Peer
		want     bool
	}{
		{"policy allows", admin, server, true},
		{"policies are symmetric", server, admin, true},
		{"no policy", laptop, server, false},
		{"unapproved destination", admin, pending, false},
		{"unapproved source", pending, admin, false},
		{"no self relay", admin, admin, false},
	}
	for _, c := range cases {
		if got := table.permits(c.src, c.dst); got != c.want {
			t.Errorf("%s: permits = %v, want %v", c.name, got, c.want)
		}
	}
}
