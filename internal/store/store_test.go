package store

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/ipam"
)

var testSpace = func() ipam.Space {
	s, err := ipam.New(netip.MustParsePrefix("100.64.0.0/16"))
	if err != nil {
		panic(err)
	}
	return s
}()

// backends returns every store implementation to test. PostgreSQL is included when
// ENTO_TEST_POSTGRES holds a DSN of a database the test may wipe.
func backends(t *testing.T) map[string]func(t *testing.T) Store {
	b := map[string]func(t *testing.T) Store{
		"memory": func(*testing.T) Store { return NewMemory(testSpace) },
	}
	if dsn := os.Getenv("ENTO_TEST_POSTGRES"); dsn != "" {
		b["postgres"] = func(t *testing.T) Store {
			ctx := context.Background()
			conn, err := pgx.Connect(ctx, dsn)
			if err != nil {
				t.Fatal(err)
			}
			_, err = conn.Exec(ctx, `DROP TABLE IF EXISTS ento_settings, ento_state, ento_control_nodes,
				ento_peers, ento_tokens, ento_policies, ento_authorities, ento_links, ento_link_keys, ento_ui_sessions, ento_admin_sessions, ento_sso_tokens,
				ento_posture, ento_posture_checks, ento_link_posture, ento_approvals, ento_checkins, ento_hwkeys, ento_routes, ento_dns_records, ento_dns_forwards, ento_signin_codes, ento_signin_use, ento_update_policy, ento_release_offers, ento_audit`)
			conn.Close(ctx)
			if err != nil {
				t.Fatal(err)
			}
			s, err := OpenPostgres(ctx, dsn, testSpace)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { s.Close() })
			return s
		}
	}
	return b
}

func key(t *testing.T) wgtypes.Key {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey()
}

func TestStore(t *testing.T) {
	for name, open := range backends(t) {
		t.Run(name, func(t *testing.T) {
			t.Run("control nodes", func(t *testing.T) { testControlNodes(t, open(t)) })
			t.Run("enrollment", func(t *testing.T) { testEnrollment(t, open(t)) })
			t.Run("reserved keys", func(t *testing.T) { testReservedKeys(t, open(t)) })
			t.Run("asked-for enrollment addresses", func(t *testing.T) { testTokenAddress(t, open(t)) })
			t.Run("names", func(t *testing.T) { testNames(t, open(t)) })
			t.Run("concurrent redeem", func(t *testing.T) { testConcurrentRedeem(t, open(t)) })
			t.Run("authorities", func(t *testing.T) { testAuthorities(t, open(t)) })
			t.Run("links", func(t *testing.T) { testLinks(t, open(t)) })
			t.Run("sessions", func(t *testing.T) { testSessions(t, open(t)) })
			t.Run("peers and policies", func(t *testing.T) { testPeersAndPolicies(t, open(t)) })
			t.Run("memberships", func(t *testing.T) { testMemberships(t, open(t)) })
			t.Run("link keys", func(t *testing.T) { testLinkKeys(t, open(t)) })
			t.Run("admin interface", func(t *testing.T) { testUISessions(t, open(t)) })
			t.Run("isolation", func(t *testing.T) { testIsolation(t, open(t)) })
			t.Run("device sign-in", func(t *testing.T) { testSignIn(t, open(t)) })
			t.Run("sso tokens", func(t *testing.T) { testSSOTokens(t, open(t)) })
			t.Run("posture", func(t *testing.T) { testPosture(t, open(t)) })
			t.Run("link posture", func(t *testing.T) { testLinkPosture(t, open(t)) })
		})
	}
}

// A token may ask for its enrollment address (enrollment by words derives it): it gets it when it
// is free, ErrAddressInUse when a usable token holds it or it is no enrollment address.
func testTokenAddress(t *testing.T, s Store) {
	ctx := context.Background()
	want := netip.MustParseAddr("100.64.255.77")
	a, err := s.CreateToken(ctx, Token{PublicKey: key(t), TempAddress: want, ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil || a.TempAddress != want {
		t.Fatalf("asked for %s: %v %s", want, err, a.TempAddress)
	}
	if _, err := s.CreateToken(ctx, Token{PublicKey: key(t), TempAddress: want, ExpiresAt: time.Now().Add(time.Hour)}); !errors.Is(err, ErrAddressInUse) {
		t.Fatalf("the same address again: %v", err)
	}
	if _, err := s.CreateToken(ctx, Token{PublicKey: key(t), TempAddress: netip.MustParseAddr("100.64.1.77"), ExpiresAt: time.Now().Add(time.Hour)}); !errors.Is(err, ErrAddressInUse) {
		t.Fatalf("a peer address: %v", err)
	}
	if b, err := s.CreateToken(ctx, Token{PublicKey: key(t), ExpiresAt: time.Now().Add(time.Hour)}); err != nil || b.TempAddress == want {
		t.Fatalf("an allocated address: %v %s", err, b.TempAddress)
	}
	if err := s.DeleteToken(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateToken(ctx, Token{PublicKey: key(t), TempAddress: want, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("the address once its token is gone: %v", err)
	}
}

func testControlNodes(t *testing.T, s Store) {
	ctx := context.Background()
	k1, k2 := key(t), key(t)
	a, err := s.RegisterControlNode(ctx, ControlNode{Name: "c1", PublicKey: k1, Endpoint: "1.2.3.4:51821", LastSeen: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.RegisterControlNode(ctx, ControlNode{Name: "c2", PublicKey: k2, Endpoint: "1.2.3.5:51821", LastSeen: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if a.Address != netip.MustParseAddr("100.64.0.1") || b.Address != netip.MustParseAddr("100.64.0.2") {
		t.Fatalf("unexpected addresses %s %s", a.Address, b.Address)
	}
	v1, _ := s.Version(ctx)
	// Re-registering with the same data keeps the address and does not change the version.
	again, err := s.RegisterControlNode(ctx, ControlNode{Name: "c1", PublicKey: k1, Endpoint: "1.2.3.4:51821", LastSeen: time.Now()})
	if err != nil || again.Address != a.Address {
		t.Fatalf("re-register: %v %s", err, again.Address)
	}
	if v2, _ := s.Version(ctx); v2 != v1 {
		t.Fatalf("version changed on a no-op registration: %d -> %d", v1, v2)
	}
	if _, err := s.RegisterControlNode(ctx, ControlNode{Name: "c3", PublicKey: k1, Endpoint: "x:1", LastSeen: time.Now()}); !errors.Is(err, ErrKeyInUse) {
		t.Fatalf("expected ErrKeyInUse, got %v", err)
	}
	nodes, _ := s.ControlNodes(ctx)
	if len(nodes) != 2 || nodes[0].Name != "c1" {
		t.Fatalf("unexpected nodes %+v", nodes)
	}
}

// A device never enrolls with a control node's or a token's key (it would take that peer's place
// in the control nodes' WireGuard), and a control node never registers with a device's or token's.
func testReservedKeys(t *testing.T, s Store) {
	ctx := context.Background()
	now := time.Now()
	ctl := key(t)
	if _, err := s.RegisterControlNode(ctx, ControlNode{Name: "c1", PublicKey: ctl, Endpoint: "1.2.3.4:51821", LastSeen: now}); err != nil {
		t.Fatal(err)
	}
	tok, err := s.CreateToken(ctx, Token{PublicKey: key(t), PresharedKey: key(t), ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.CreateToken(ctx, Token{PublicKey: key(t), PresharedKey: key(t), ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Redeem(ctx, tok.TempAddress, ctl, "h", "linux", now, nil); !errors.Is(err, ErrKeyInUse) {
		t.Fatalf("redeem with a control node's key: expected ErrKeyInUse, got %v", err)
	}
	if _, err := s.Redeem(ctx, tok.TempAddress, other.PublicKey, "h", "linux", now, nil); !errors.Is(err, ErrKeyInUse) {
		t.Fatalf("redeem with a token's key: expected ErrKeyInUse, got %v", err)
	}
	dev := key(t)
	if _, err := s.Redeem(ctx, tok.TempAddress, dev, "h", "linux", now, nil); err != nil {
		t.Fatalf("the token stays usable after refused keys: %v", err)
	}
	if _, err := s.RegisterControlNode(ctx, ControlNode{Name: "c2", PublicKey: dev, Endpoint: "1.2.3.5:51821", LastSeen: now}); !errors.Is(err, ErrKeyInUse) {
		t.Fatalf("control node with a device's key: expected ErrKeyInUse, got %v", err)
	}
	if _, err := s.RegisterControlNode(ctx, ControlNode{Name: "c2", PublicKey: other.PublicKey, Endpoint: "1.2.3.5:51821", LastSeen: now}); !errors.Is(err, ErrKeyInUse) {
		t.Fatalf("control node with a token's key: expected ErrKeyInUse, got %v", err)
	}
}

func testEnrollment(t *testing.T, s Store) {
	ctx := context.Background()
	now := time.Now()
	tok, err := s.CreateToken(ctx, Token{PublicKey: key(t), PresharedKey: key(t), Groups: []string{"servers"},
		Approve: true, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if !testSpace.IsEnrollment(tok.TempAddress) {
		t.Fatalf("temporary address %s outside the enrollment range", tok.TempAddress)
	}
	expired, err := s.CreateToken(ctx, Token{PublicKey: key(t), PresharedKey: key(t), ExpiresAt: now.Add(-time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	active, _ := s.ActiveTokens(ctx, now)
	if len(active) != 1 || active[0].ID != tok.ID {
		t.Fatalf("unexpected active tokens %+v", active)
	}
	if _, err := s.Redeem(ctx, expired.TempAddress, key(t), "h", "linux", now, nil); !errors.Is(err, ErrTokenUnusable) {
		t.Fatalf("expired token: expected ErrTokenUnusable, got %v", err)
	}

	pk := key(t)
	peer, err := s.Redeem(ctx, tok.TempAddress, pk, "host-a", "linux", now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !peer.Approved || len(peer.Groups) != 1 || peer.Groups[0] != "servers" || peer.PublicKey != pk {
		t.Fatalf("peer does not carry the token's authorisation: %+v", peer)
	}
	if peer.Address != netip.MustParseAddr("100.64.1.1") {
		t.Fatalf("unexpected peer address %s", peer.Address)
	}
	if _, err := s.Redeem(ctx, tok.TempAddress, key(t), "h", "linux", now, nil); !errors.Is(err, ErrTokenUnusable) {
		t.Fatalf("second redeem: expected ErrTokenUnusable, got %v", err)
	}
	if active, _ := s.ActiveTokens(ctx, now); len(active) != 0 {
		t.Fatalf("redeemed token still active: %+v", active)
	}
	got, err := s.PeerByAddress(ctx, peer.Address)
	if err != nil || got.ID != peer.ID {
		t.Fatalf("PeerByAddress: %v %+v", err, got)
	}
}

func testNames(t *testing.T, s Store) {
	ctx := context.Background()
	now := time.Now()
	newToken := func(name string, replace bool) (Token, error) {
		return s.CreateToken(ctx, Token{PublicKey: key(t), PresharedKey: key(t), Name: name, Replace: replace, ExpiresAt: now.Add(time.Hour)})
	}
	token := func(name string, replace bool) Token {
		t.Helper()
		tok, err := newToken(name, replace)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	redeem := func(tok Token, hostname string) (Peer, error) {
		return s.Redeem(ctx, tok.TempAddress, key(t), hostname, "linux", now, nil)
	}

	// Devices named after their host names: cleaned up, after the prefix, a counter on conflicts.
	a, err := redeem(token("", false), "Laptop.local")
	b, err2 := redeem(token("", false), "LAPTOP")
	if err != nil || err2 != nil || a.Hostname != "z-laptop" || b.Hostname != "z-laptop-1" || a.ReportedHostname != "Laptop.local" {
		t.Fatalf("named after host names: %+v %+v %v %v", a, b, err, err2)
	}

	// A token's name is reserved: no other token gets it, no rename takes it.
	web := token("web-1", false)
	if _, err := newToken("web-1", false); !takenBy(err, 0, web.ID) {
		t.Fatalf("second token for web-1: %v", err)
	}
	if _, err := s.UpdatePeer(ctx, a.ID, PeerUpdate{Hostname: ptr("web-1")}); !takenBy(err, 0, web.ID) {
		t.Fatalf("rename to a reserved name: %v", err)
	}
	w, err := redeem(web, "ip-10-0-0-7")
	if err != nil || w.Hostname != "web-1" || w.ReportedHostname != "ip-10-0-0-7" {
		t.Fatalf("named token: %+v %v", w, err)
	}

	// Renames: to a free name only.
	if _, err := s.UpdatePeer(ctx, b.ID, PeerUpdate{Hostname: ptr("z-laptop")}); !takenBy(err, a.ID, 0) {
		t.Fatalf("rename to a taken name: %v", err)
	}
	if p, err := s.UpdatePeer(ctx, b.ID, PeerUpdate{Hostname: ptr("laptop")}); err != nil || p.Hostname != "laptop" {
		t.Fatalf("rename: %+v %v", p, err)
	}

	// A token for a name a device has needs Replace; its device then takes the old one's place.
	if _, err := newToken("web-1", false); !takenBy(err, w.ID, 0) {
		t.Fatalf("token for a taken name: %v", err)
	}
	w2, err := redeem(token("web-1", true), "ip-10-0-0-8")
	if err != nil || w2.Hostname != "web-1" || w2.Address != w.Address || w2.ID == w.ID {
		t.Fatalf("replacing web-1: %+v %v", w2, err)
	}
	if _, err := s.PeerByPublicKey(ctx, w.PublicKey); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the replaced device is still there: %v", err)
	}
	peers, err := s.Peers(ctx)
	seen := map[string]bool{}
	for _, p := range peers {
		if seen[p.Hostname] {
			t.Fatalf("two devices named %s", p.Hostname)
		}
		seen[p.Hostname] = true
	}
	if err != nil || len(peers) != 3 {
		t.Fatalf("peers: %d, %v", len(peers), err)
	}
}

func takenBy(err error, peer, token int64) bool {
	var e *NameTakenError
	return errors.As(err, &e) && e.PeerID == peer && e.TokenID == token
}

func ptr[T any](v T) *T { return &v }

// TestPostgresNameMigration: devices enrolled before names were managed keep their names, cleaned
// up and made unique, as administrators' names.
func TestPostgresNameMigration(t *testing.T) {
	open, ok := backends(t)["postgres"]
	if !ok {
		t.Skip("ENTO_TEST_POSTGRES not set")
	}
	ctx := context.Background()
	s := open(t).(*Postgres)
	if _, err := s.pool.Exec(ctx, `DROP INDEX ento_peers_hostname_key`); err != nil {
		t.Fatal(err)
	}
	legacy := []string{"Laptop.local", "laptop", "web\n01", "acme-core-node-a", "z-box"}
	for i, h := range legacy {
		if _, err := s.pool.Exec(ctx, `INSERT INTO ento_peers (public_key, address, hostname, os, approved, admin, groups, created_at)
			VALUES ($1, $2, $3, 'linux', true, false, '{}', now())`, key(t).String(), fmt.Sprintf("100.64.1.%d", i+1), h); err != nil {
			t.Fatal(err)
		}
	}
	before, _ := s.Version(ctx)
	s2, err := OpenPostgres(ctx, os.Getenv("ENTO_TEST_POSTGRES"), testSpace)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	peers, err := s2.Peers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"laptop", "laptop-1", "web-01", "acme-core-node-a", "box"}
	for i, p := range peers {
		if p.Hostname != want[i] || p.ReportedHostname != strings.ReplaceAll(legacy[i], "\n", "?") {
			t.Errorf("device %d: %q (reported %q), want %q", i, p.Hostname, p.ReportedHostname, want[i])
		}
	}
	if after, _ := s2.Version(ctx); after <= before {
		t.Error("renamed devices without a new version: agents would keep the old names")
	}
	// Once only: a device named later keeps its name when a control node starts again.
	if _, err := s2.UpdatePeer(ctx, peers[0].ID, PeerUpdate{Hostname: ptr("renamed")}); err != nil {
		t.Fatal(err)
	}
	s3, err := OpenPostgres(ctx, os.Getenv("ENTO_TEST_POSTGRES"), testSpace)
	if err != nil {
		t.Fatal(err)
	}
	defer s3.Close()
	if p, _ := s3.PeerByPublicKey(ctx, peers[0].PublicKey); p.Hostname != "renamed" {
		t.Errorf("migrated again: %q", p.Hostname)
	}
}

func testConcurrentRedeem(t *testing.T, s Store) {
	ctx := context.Background()
	tok, err := s.CreateToken(ctx, Token{PublicKey: key(t), PresharedKey: key(t), ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.Redeem(ctx, tok.TempAddress, key(t), fmt.Sprintf("h%d", i), "linux", time.Now(), nil)
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)
	ok := 0
	for err := range results {
		if err == nil {
			ok++
		} else if !errors.Is(err, ErrTokenUnusable) {
			t.Fatalf("unexpected error %v", err)
		}
	}
	if ok != 1 {
		t.Fatalf("a one-time token was redeemed %d times", ok)
	}
}

func testPeersAndPolicies(t *testing.T, s Store) {
	ctx := context.Background()
	tok, _ := s.CreateToken(ctx, Token{PublicKey: key(t), PresharedKey: key(t), ExpiresAt: time.Now().Add(time.Hour)})
	pk := key(t)
	peer, err := s.Redeem(ctx, tok.TempAddress, pk, "h", "linux", time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if peer.Approved {
		t.Fatal("peer approved although the token did not pre-authorise it")
	}
	yes, groups, user, userName := true, []string{"laptops"}, "sub-123", "alice@example.com"
	up, err := s.UpdatePeer(ctx, peer.ID, PeerUpdate{Approved: &yes, Groups: &groups, User: &user, UserName: &userName})
	if err != nil || !up.Approved || up.Groups[0] != "laptops" || up.User != user || up.UserName != userName {
		t.Fatalf("UpdatePeer: %v %+v", err, up)
	}
	if got, _ := s.PeerByAddress(ctx, peer.Address); got.User != user || got.UserName != userName {
		t.Fatalf("user identity not persisted: %+v", got)
	}
	if _, err := s.UpdatePeer(ctx, peer.ID, PeerUpdate{Operator: &yes}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.PeerByAddress(ctx, peer.Address); !got.Machine.Operator || got.Machine.Admin || got.Operator || !got.Approved {
		t.Fatalf("operator role not persisted (the device's alone, no role without its person): %+v", got)
	}

	v1, _ := s.Version(ctx)
	if _, changed, err := s.ObservePeer(ctx, pk, "", time.Now()); err != nil || changed {
		t.Fatal(err, changed)
	}
	if v2, _ := s.Version(ctx); v2 != v1 {
		t.Fatal("a seen timestamp must not change the version")
	}
	if prev, changed, err := s.ObservePeer(ctx, pk, "198.51.100.7:40000", time.Now()); err != nil || !changed || prev != "" {
		t.Fatal(err, changed, prev)
	}
	v3, _ := s.Version(ctx)
	if v3 == v1 {
		t.Fatal("an endpoint change must change the version")
	}
	if _, changed, err := s.ObservePeer(ctx, pk, "198.51.100.7:40000", time.Now()); err != nil || changed {
		t.Fatal(err, changed)
	}
	if v4, _ := s.Version(ctx); v4 != v3 {
		t.Fatal("an unchanged endpoint must not change the version")
	}
	if prev, changed, err := s.ObservePeer(ctx, pk, "203.0.113.9:40000", time.Now()); err != nil || !changed || prev != "198.51.100.7:40000" {
		t.Fatal(err, changed, prev)
	}
	if p, err := s.PeerByPublicKey(ctx, pk); err != nil || p.Endpoint != "203.0.113.9:40000" {
		t.Fatalf("peer by key: %+v, %v", p, err)
	}
	if v5, _ := s.Version(ctx); v5 == v3 {
		t.Fatal("an endpoint change must change the version")
	}

	pol, err := s.AddPolicy(ctx, Policy{Source: "laptops", Destination: "servers"})
	if err != nil {
		t.Fatal(err)
	}
	again, _ := s.AddPolicy(ctx, Policy{Source: "laptops", Destination: "servers", Posture: []string{"other"}})
	if again.ID != pol.ID || again.Posture != nil {
		t.Fatalf("duplicate policy created, or the existing one changed: %+v", again)
	}
	// Direction and ports: kept, read back, changed.
	ssh, err := s.AddPolicy(ctx, Policy{Source: "ops", Destination: "servers", OneWay: true, Ports: []string{"tcp/22"}})
	if err != nil || !ssh.OneWay || !slices.Equal(ssh.Ports, []string{"tcp/22"}) {
		t.Fatalf("one-way policy: %+v %v", ssh, err)
	}
	if pols, _ := s.Policies(ctx); len(pols) != 2 || !pols[1].OneWay || !slices.Equal(pols[1].Ports, []string{"tcp/22"}) || pols[0].OneWay || pols[0].Ports != nil {
		t.Fatalf("policies read back: %+v", pols)
	}
	v6, _ := s.Version(ctx)
	if got, err := s.SetPolicyRules(ctx, ssh.ID, false, nil); err != nil || got.OneWay || got.Ports != nil {
		t.Fatalf("rules changed: %+v %v", got, err)
	}
	if v7, _ := s.Version(ctx); v7 == v6 {
		t.Fatal("a change of a policy's rules must change the version")
	}
	if _, err := s.SetPolicyRules(ctx, 9999, true, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rules of a missing policy: %v", err)
	}
	if err := s.DeletePolicy(ctx, ssh.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeletePolicy(ctx, pol.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeletePeer(ctx, peer.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PeerByAddress(ctx, peer.Address); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted peer still found: %v", err)
	}
}

func testAuthorities(t *testing.T, s Store) {
	ctx := context.Background()
	now := time.Now()
	pub := make([]byte, 32)
	a, tok, err := s.CreateAuthority(ctx, Authority{Name: "home", PublicKey: pub, Groups: []string{"operators"}, MaxTTL: time.Hour},
		Token{PublicKey: key(t), ExpiresAt: now.Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateAuthority(ctx, Authority{Name: "home", PublicKey: pub}, Token{PublicKey: key(t), ExpiresAt: now.Add(time.Hour)}); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate authority: %v", err)
	}
	got, err := s.Authority(ctx, "home")
	if err != nil || got.TokenID != tok.ID || got.MaxTTL != time.Hour || len(got.PublicKey) != 32 || a.TokenID != tok.ID {
		t.Fatalf("authority = %+v, %v", got, err)
	}

	if _, err := s.Redeem(ctx, tok.TempAddress, key(t), "h", "linux", now, nil); !errors.Is(err, ErrTokenUnusable) {
		t.Fatalf("authority token redeemed without a grant: %v", err)
	}
	if _, err := s.Redeem(ctx, tok.TempAddress, key(t), "h", "linux", now, &Grant{Authority: "other"}); !errors.Is(err, ErrTokenUnusable) {
		t.Fatalf("authority token redeemed with another authority's grant: %v", err)
	}
	grant := &Grant{Authority: "home", Groups: []string{"home:operators"}, UserName: "home:alice", Hostname: "laptop", Until: now.Add(time.Minute)}
	p1, err := s.Redeem(ctx, tok.TempAddress, key(t), "h", "linux", now, grant)
	if err != nil {
		t.Fatal(err)
	}
	if !p1.Approved || p1.Admin || p1.Authority != "home" || p1.Hostname != "home-laptop" || p1.ReportedHostname != "laptop" ||
		p1.Groups[0] != "home:operators" {
		t.Fatalf("peer = %+v", p1)
	}
	// The token is reusable.
	grant.Until = now.Add(time.Hour)
	p2, err := s.Redeem(ctx, tok.TempAddress, key(t), "h", "linux", now, grant)
	if err != nil {
		t.Fatalf("second device: %v", err)
	}
	if p2.Hostname != "home-laptop-1" {
		t.Fatalf("second device named %q", p2.Hostname)
	}
	if active, _ := s.ActiveTokens(ctx, now); len(active) != 1 {
		t.Fatalf("active tokens = %d, want the authority token", len(active))
	}

	// Approval ends when it expires.
	if n, err := s.ExpirePeers(ctx, now.Add(2*time.Minute)); err != nil || n != 1 {
		t.Fatalf("expired %d, %v", n, err)
	}
	peers, _ := s.Peers(ctx)
	for _, p := range peers {
		if p.ID == p1.ID && p.Approved || p.ID == p2.ID && !p.Approved {
			t.Fatalf("after expiry: %+v", p)
		}
	}
	later := now.Add(3 * time.Hour)
	approved := true
	if _, err := s.UpdatePeer(ctx, p1.ID, PeerUpdate{Approved: &approved, ApprovedUntil: &later}); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.PeerByAddress(ctx, p1.Address); !p.Approved || !p.ApprovedUntil.Equal(later.Truncate(time.Microsecond)) && !p.ApprovedUntil.Equal(later) {
		t.Fatalf("renewed peer = %+v", p)
	}

	// Deleting the authority removes its token and every device it admitted.
	if err := s.DeleteAuthority(ctx, "home"); err != nil {
		t.Fatal(err)
	}
	if peers, _ := s.Peers(ctx); len(peers) != 0 {
		t.Fatalf("peers left after deleting the authority: %d", len(peers))
	}
	if active, _ := s.ActiveTokens(ctx, now); len(active) != 0 {
		t.Fatalf("authority token left: %d", len(active))
	}
	if err := s.DeleteAuthority(ctx, "home"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
}

func testLinks(t *testing.T, s Store) {
	ctx := context.Background()
	priv := make([]byte, 64)
	priv[0] = 7
	if _, err := s.CreateLink(ctx, Link{Name: "acme", PrivateKey: priv, Groups: []string{"operators"}, Grant: []string{"operators"}, TTL: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateLink(ctx, Link{Name: "acme", PrivateKey: priv}); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate link: %v", err)
	}
	if err := s.SetLinkToken(ctx, "acme", "ento1:x"); err != nil {
		t.Fatal(err)
	}
	l, err := s.Link(ctx, "acme")
	if err != nil || l.Token != "ento1:x" || l.TTL != time.Hour || l.PrivateKey[0] != 7 || l.Grant[0] != "operators" {
		t.Fatalf("link = %+v, %v", l, err)
	}
	if ls, _ := s.Links(ctx); len(ls) != 1 {
		t.Fatalf("links = %d", len(ls))
	}
	if err := s.DeleteLink(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Link(ctx, "acme"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted link: %v", err)
	}
}

func testSessions(t *testing.T, s Store) {
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)
	enroll := func(name string) Peer {
		// Devices in admin: their person's role counts while the person is signed in (0.54).
		tok, err := s.CreateToken(ctx, Token{PublicKey: key(t), Approve: true, Admin: true, Groups: []string{"laptops"}, ExpiresAt: now.Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		p, err := s.Redeem(ctx, tok.TempAddress, key(t), name, "linux", now, nil)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	server := enroll("server")         // no person: nothing ends
	fresh := enroll("fresh")           // the person's traffic now
	idle := enroll("idle")             // opened 10 h ago, last traffic 9 h ago
	legacy := enroll("legacy")         // an agent that does not report, seen now
	legacyIdle := enroll("legacy-off") // an agent that does not report, not seen for 9 h
	aged := enroll("aged")             // opened 13 h ago, in use now
	user, yes := "u", true
	groups := []string{"admins", "staff"}
	open := func(p Peer, since, activity, seen time.Time, reports bool) {
		u := PeerUpdate{User: &user, LoginAt: &since, PersonApproved: &yes, PersonAdmin: &yes, PersonGroups: &groups,
			PersonActive: &yes, PersonSince: &since, PersonReports: &reports}
		if !activity.IsZero() {
			u.PersonActivityAt = &activity
		}
		if _, err := s.UpdatePeer(ctx, p.ID, u); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.ObservePeer(ctx, p.PublicKey, "", seen); err != nil {
			t.Fatal(err)
		}
	}
	h := time.Hour
	open(fresh, now.Add(-h), now, now, true)
	open(idle, now.Add(-10*h), now.Add(-9*h), now, true)
	open(legacy, now.Add(-10*h), time.Time{}, now, false)
	open(legacyIdle, now.Add(-10*h), time.Time{}, now.Add(-9*h), false)
	open(aged, now.Add(-13*h), now, now, true)
	if p, _ := s.PeerByAddress(ctx, fresh.Address); !p.Person.Admin || !slices.Contains(p.Groups, "staff") || !slices.Contains(p.Groups, "laptops") {
		t.Fatalf("an open person layer: %+v", p)
	}

	ended, err := s.EndIdleSessions(ctx, now, 8*h, 0)
	if err != nil || len(ended) != 2 || ended[0].ID != idle.ID || ended[1].ID != legacyIdle.ID {
		t.Fatalf("ended %v, %v; want idle and legacy-off", ended, err)
	}
	open1 := map[int64]bool{fresh.ID: true, legacy.ID: true, aged.ID: true}
	peers, _ := s.Peers(ctx)
	for _, p := range peers {
		if p.ID == server.ID || p.Hostname == "" {
			continue
		}
		if p.Person.Active != open1[p.ID] {
			t.Errorf("%s: person layer open = %v", p.Hostname, p.Person.Active)
		}
		// The machine layer stays whatever happens to the person's; the person's rights count only
		// while open, and are kept for the next time.
		if !p.Approved || !slices.Contains(p.Groups, "laptops") || p.Admin != open1[p.ID] || slices.Contains(p.Groups, "staff") != open1[p.ID] ||
			!slices.Equal(p.Person.Groups, groups) {
			t.Errorf("%s after the sweep: approved %v admin %v groups %v person %v", p.Hostname, p.Approved, p.Admin, p.Groups, p.Person.Groups)
		}
	}
	if ended, _ := s.EndIdleSessions(ctx, now, 8*h, 0); len(ended) != 0 {
		t.Fatalf("second sweep ended %d", len(ended))
	}
	// Only a configured maximum ends a layer in use for its age.
	if ended, _ := s.EndIdleSessions(ctx, now, 8*h, 12*h); len(ended) != 1 || ended[0].ID != aged.ID {
		t.Fatalf("with a maximum: ended %v", ended)
	}
	// Activity is recorded without a new version, and only moves forward.
	before, _ := s.Version(ctx)
	if err := s.RecordPersonActivity(ctx, fresh.ID, now.Add(-2*h), true, "boot-1"); err != nil {
		t.Fatal(err)
	}
	if after, _ := s.Version(ctx); after != before {
		t.Fatal("recording activity bumped the version")
	}
	if p, _ := s.PeerByAddress(ctx, fresh.Address); !p.Person.ActivityAt.Equal(now) || p.BootID != "boot-1" {
		t.Fatalf("activity %v (want %v), boot %q", p.Person.ActivityAt, now, p.BootID)
	}
}

// A suspended device stays unapproved whatever else changes, until it is resumed; revoking a token
// removes it once, and never an authority's.
func TestSuspendAndRevoke(t *testing.T) {
	for name, open := range backends(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s := open(t)
			tok, err := s.CreateToken(ctx, Token{PublicKey: key(t), PresharedKey: key(t), Approve: true,
				ExpiresAt: time.Now().Add(time.Hour), CreatedBy: "admin-laptop"})
			if err != nil {
				t.Fatal(err)
			}
			active, _ := s.ActiveTokens(ctx, time.Now())
			if len(active) != 1 || active[0].CreatedBy != "admin-laptop" {
				t.Fatalf("active tokens %+v", active)
			}
			p, err := s.Redeem(ctx, tok.TempAddress, key(t), "phone", "test", time.Now(), nil)
			if err != nil || !p.Approved {
				t.Fatalf("redeem: %v %+v", err, p)
			}
			yes, no := true, false
			if p, _ = s.UpdatePeer(ctx, p.ID, PeerUpdate{Suspended: &yes}); p.Approved || !p.Suspended {
				t.Fatalf("suspended: %+v", p)
			}
			if p, _ = s.UpdatePeer(ctx, p.ID, PeerUpdate{Approved: &yes}); p.Approved {
				t.Fatalf("approved while suspended: %+v", p)
			}
			if p, _ = s.PeerByAddress(ctx, p.Address); !p.Suspended || p.Approved {
				t.Fatalf("stored: %+v", p)
			}
			if p, _ = s.UpdatePeer(ctx, p.ID, PeerUpdate{Suspended: &no, Approved: &yes}); !p.Approved || p.Suspended {
				t.Fatalf("resumed: %+v", p)
			}

			other, _ := s.CreateToken(ctx, Token{PublicKey: key(t), PresharedKey: key(t), ExpiresAt: time.Now().Add(time.Hour)})
			if err := s.DeleteToken(ctx, other.ID); err != nil {
				t.Fatal(err)
			}
			if err := s.DeleteToken(ctx, other.ID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("second revoke: %v", err)
			}
			if err := s.DeleteToken(ctx, tok.ID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("revoked a used token: %v", err)
			}
			_, at, err := s.CreateAuthority(ctx, Authority{Name: "partner", PublicKey: make([]byte, 32), MaxTTL: time.Hour},
				Token{PublicKey: key(t), PresharedKey: key(t), ExpiresAt: time.Now().Add(time.Hour)})
			if err != nil {
				t.Fatal(err)
			}
			if err := s.DeleteToken(ctx, at.ID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("revoked an authority's token: %v", err)
			}
		})
	}
}

// enrolled redeems a fresh ordinary token and returns the device.
func enrolled(t *testing.T, s Store, host string) Peer {
	t.Helper()
	ctx := context.Background()
	tok, err := s.CreateToken(ctx, Token{PublicKey: key(t), PresharedKey: key(t), Approve: true, ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Redeem(ctx, tok.TempAddress, key(t), host, "linux", time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// An authority's device has one membership: a grant for the same home device replaces it (name and
// address kept); the authority's devices can be capped; its token can be replaced.
func testMemberships(t *testing.T, s Store) {
	ctx := context.Background()
	now := time.Now()
	_, tok, err := s.CreateAuthority(ctx, Authority{Name: "home", PublicKey: make([]byte, 32), Groups: []string{"operators"},
		MaxTTL: time.Hour, MaxDevices: 2}, Token{PublicKey: key(t), ExpiresAt: now.Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := s.Authority(ctx, "home"); a.MaxDevices != 2 {
		t.Fatalf("authority limit = %d", a.MaxDevices)
	}
	grant := func(device string) *Grant {
		a, _ := s.Authority(ctx, "home")
		return &Grant{Authority: "home", Groups: []string{"home:operators"}, UserName: "home:alice", Hostname: "laptop-" + device,
			Until: now.Add(time.Hour), DeviceID: device, MaxDevices: a.MaxDevices}
	}
	first, err := s.Redeem(ctx, tok.TempAddress, key(t), "x", "linux", now, grant("7"))
	if err != nil {
		t.Fatal(err)
	}
	k := key(t)
	again, err := s.Redeem(ctx, tok.TempAddress, k, "x", "linux", now, grant("7"))
	if err != nil {
		t.Fatal(err)
	}
	if again.Address != first.Address || again.Hostname != first.Hostname || again.AuthorityDevice != "7" || again.ID == first.ID {
		t.Fatalf("replacing membership: %+v (was %+v)", again, first)
	}
	if peers, _ := s.Peers(ctx); len(peers) != 1 || peers[0].PublicKey != k || peers[0].AuthorityDevice != "7" {
		t.Fatalf("memberships after replacing: %+v", peers)
	}
	// A retried redeem with the same key is refused, and replaces nothing.
	if _, err := s.Redeem(ctx, tok.TempAddress, k, "x", "linux", now, grant("7")); !errors.Is(err, ErrKeyInUse) {
		t.Fatalf("the same key again: %v", err)
	}
	if peers, _ := s.Peers(ctx); len(peers) != 1 || peers[0].ID != again.ID {
		t.Fatalf("memberships after a retried redeem: %+v", peers)
	}
	// A suspended membership stays suspended: the same home device with a new key is refused.
	yes := true
	if _, err := s.UpdatePeer(ctx, again.ID, PeerUpdate{Suspended: &yes}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Redeem(ctx, tok.TempAddress, key(t), "x", "linux", now, grant("7")); !errors.Is(err, ErrMemberSuspended) {
		t.Fatalf("a suspended device joined again with a new key: %v", err)
	}
	if p, _ := s.PeerByAddress(ctx, again.Address); p.ID != again.ID || !p.Suspended {
		t.Fatalf("the suspended membership changed: %+v", p)
	}
	no := false
	if _, err := s.UpdatePeer(ctx, again.ID, PeerUpdate{Suspended: &no}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Redeem(ctx, tok.TempAddress, key(t), "x", "linux", now, grant("8")); err != nil {
		t.Fatalf("second device within the limit: %v", err)
	}
	var full *AuthorityFullError
	if _, err := s.Redeem(ctx, tok.TempAddress, key(t), "x", "linux", now, grant("9")); !errors.As(err, &full) || full.Max != 2 {
		t.Fatalf("third device beyond the limit: %v", err)
	}
	// A device already in replaces itself even at the limit.
	if _, err := s.Redeem(ctx, tok.TempAddress, key(t), "x", "linux", now, grant("8")); err != nil {
		t.Fatalf("replacing at the limit: %v", err)
	}
	if err := s.SetAuthorityLimit(ctx, "home", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Redeem(ctx, tok.TempAddress, key(t), "x", "linux", now, grant("9")); err != nil {
		t.Fatalf("third device without a limit: %v", err)
	}
	if err := s.SetAuthorityLimit(ctx, "nobody", 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("limit of a missing authority: %v", err)
	}

	// A new token replaces the old one, which can no longer be redeemed.
	nt, err := s.RotateAuthorityToken(ctx, "home", Token{PublicKey: key(t), ExpiresAt: now.Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := s.Authority(ctx, "home"); a.TokenID != nt.ID || nt.Authority != "home" {
		t.Fatalf("authority after rotation: %+v, token %+v", a, nt)
	}
	active, _ := s.ActiveTokens(ctx, now)
	if len(active) != 1 || active[0].ID != nt.ID {
		t.Fatalf("active tokens after rotation: %+v", active)
	}
	if nt.TempAddress != tok.TempAddress { // a freed address may come back: only check the old one fails when it moved
		if _, err := s.Redeem(ctx, tok.TempAddress, key(t), "x", "linux", now, grant("10")); !errors.Is(err, ErrTokenUnusable) {
			t.Fatalf("redeem with the replaced token: %v", err)
		}
	}
	if _, err := s.Redeem(ctx, nt.TempAddress, key(t), "x", "linux", now, grant("10")); err != nil {
		t.Fatalf("redeem with the new token: %v", err)
	}
	if _, err := s.RotateAuthorityToken(ctx, "nobody", Token{PublicKey: key(t), ExpiresAt: now.Add(time.Hour)}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rotation of a missing authority: %v", err)
	}
}

func testLinkKeys(t *testing.T, s Store) {
	ctx := context.Background()
	if _, err := s.CreateLink(ctx, Link{Name: "acme", PrivateKey: make([]byte, 64), Groups: []string{"operators"}, TTL: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateLink(ctx, Link{Name: "beta", PrivateKey: make([]byte, 64), Groups: []string{"operators"}, TTL: time.Hour}); err != nil {
		t.Fatal(err)
	}
	p := enrolled(t, s, "laptop")
	if _, err := s.LinkKey(ctx, "acme", p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("key before any: %v", err)
	}
	k1, k2 := key(t), key(t)
	if err := s.SetLinkKey(ctx, "acme", p.ID, k1); err != nil {
		t.Fatal(err)
	}
	if err := s.SetLinkKey(ctx, "acme", p.ID, k2); err != nil {
		t.Fatal(err)
	}
	if err := s.SetLinkKey(ctx, "beta", p.ID, k1); err != nil {
		t.Fatal(err)
	}
	if got, err := s.LinkKey(ctx, "acme", p.ID); err != nil || got != k2 {
		t.Fatalf("key = %s, %v (want the replacement)", got, err)
	}
	// Keys go with their link, and with their device.
	if err := s.DeleteLink(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateLink(ctx, Link{Name: "acme", PrivateKey: make([]byte, 64), Groups: []string{"operators"}, TTL: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LinkKey(ctx, "acme", p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("key of a deleted link: %v", err)
	}
	if err := s.DeletePeer(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LinkKey(ctx, "beta", p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("key of a deleted device: %v", err)
	}
}

// Codes of the device sign-in provider are used once and expire; its record of a device's last
// sign-in belongs to one person layer; deleting the device deletes both.
func testSignIn(t *testing.T, s Store) {
	ctx := context.Background()
	now := time.Now().Truncate(time.Microsecond)
	p := enrolled(t, s, "laptop")
	c := SignInCode{Hash: "h1", PeerID: p.ID, PersonSince: now.Add(-time.Hour), ClientID: "kc", RedirectURI: "https://id/cb", Nonce: "n",
		Challenge: "c", ExpiresAt: now.Add(time.Minute)}
	if err := s.CreateSignInCode(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSignInCode(ctx, c); !errors.Is(err, ErrExists) {
		t.Errorf("same hash again: %v, want ErrExists", err)
	}
	got, err := s.TakeSignInCode(ctx, "h1", now)
	if err != nil || got.PeerID != p.ID || !got.PersonSince.Equal(c.PersonSince) || got.Nonce != "n" || got.Challenge != "c" || got.RedirectURI != c.RedirectURI {
		t.Fatalf("take: %+v %v", got, err)
	}
	if _, err := s.TakeSignInCode(ctx, "h1", now); !errors.Is(err, ErrNotFound) {
		t.Errorf("taken twice: %v", err)
	}
	c.Hash, c.ExpiresAt = "h2", now.Add(-time.Second)
	s.CreateSignInCode(ctx, c)
	if _, err := s.TakeSignInCode(ctx, "h2", now); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired code taken: %v", err)
	}
	c.Hash, c.ExpiresAt = "h3", now.Add(-time.Second)
	s.CreateSignInCode(ctx, c)
	if err := s.ExpireSignInCodes(ctx, now); err != nil {
		t.Fatal(err)
	}

	since := now.Add(-2 * time.Hour)
	if at, err := s.LastSignIn(ctx, p.ID, since); err != nil || !at.IsZero() {
		t.Errorf("never signed in: %s %v", at, err)
	}
	s.RecordSignIn(ctx, p.ID, since, now.Add(-time.Minute))
	s.RecordSignIn(ctx, p.ID, since, now)
	if at, _ := s.LastSignIn(ctx, p.ID, since); !at.Equal(now) {
		t.Errorf("last sign-in %s, want %s", at, now)
	}
	if at, _ := s.LastSignIn(ctx, p.ID, now.Add(-time.Hour)); !at.IsZero() {
		t.Errorf("another person layer sees %s", at)
	}

	c.Hash, c.ExpiresAt = "h4", now.Add(time.Minute)
	s.CreateSignInCode(ctx, c)
	if err := s.DeletePeer(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TakeSignInCode(ctx, "h4", now); !errors.Is(err, ErrNotFound) {
		t.Errorf("code of a deleted device: %v", err)
	}
	if at, _ := s.LastSignIn(ctx, p.ID, since); !at.IsZero() {
		t.Errorf("record of a deleted device: %s", at)
	}
}

func testUISessions(t *testing.T, s Store) {
	ctx := context.Background()
	now := time.Now()
	p := enrolled(t, s, "laptop")
	other := enrolled(t, s, "desktop")
	pending := func(hash, code string, peer int64, exp time.Time) UISession {
		return UISession{Hash: hash, PeerID: peer, Code: code, Browser: "test", CreatedAt: now, ExpiresAt: exp, LastUsed: now}
	}
	if err := s.CreateUISession(ctx, pending("h1", "AAAA-BBBB", p.ID, now.Add(5*time.Minute))); err != nil {
		t.Fatal(err)
	}
	// A session opened by signing in (0.49): approved at once, with its person.
	signed := UISession{Hash: "hs", PeerID: p.ID, Browser: "test", Approved: true, CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastUsed: now, Person: "sub-1"}
	if err := s.CreateUISession(ctx, signed); err != nil {
		t.Fatal(err)
	}
	if u, err := s.UISession(ctx, "hs", now); err != nil || !u.Approved || u.Person != "sub-1" {
		t.Fatalf("signed-in session: %+v %v", u, err)
	}
	if err := s.DeleteUISession(ctx, "hs"); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUISession(ctx, pending("h1", "CCCC-DDDD", p.ID, now.Add(5*time.Minute))); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate hash: %v", err)
	}
	if err := s.CreateUISession(ctx, pending("h2", "AAAA-BBBB", p.ID, now.Add(5*time.Minute))); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate pending code of a device: %v", err)
	}
	if err := s.CreateUISession(ctx, pending("h3", "AAAA-BBBB", other.ID, now.Add(5*time.Minute))); err != nil {
		t.Fatalf("the same code for another device: %v", err)
	}
	if n, err := s.PendingUISessions(ctx, p.ID, now); err != nil || n != 1 {
		t.Fatalf("pending = %d, %v", n, err)
	}
	if u, err := s.UISession(ctx, "h1", now); err != nil || u.Approved || u.Code != "AAAA-BBBB" || u.PeerID != p.ID || u.Browser != "test" {
		t.Fatalf("pending session: %+v %v", u, err)
	}

	// Only the device the session belongs to approves it, by its code, before it expires.
	if _, err := s.ApproveUISession(ctx, p.ID, "XXXX-XXXX", now, now.Add(8*time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong code: %v", err)
	}
	if _, err := s.ApproveUISession(ctx, p.ID, "AAAA-BBBB", now.Add(6*time.Minute), now.Add(8*time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired pending session approved: %v", err)
	}
	u, err := s.ApproveUISession(ctx, p.ID, "AAAA-BBBB", now, now.Add(8*time.Hour))
	if err != nil || !u.Approved || u.Hash != "h1" {
		t.Fatalf("approve: %+v %v", u, err)
	}
	if _, err := s.ApproveUISession(ctx, p.ID, "AAAA-BBBB", now, now.Add(8*time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("approved twice: %v", err)
	}
	if got, _ := s.UISession(ctx, "h3", now); got.Approved {
		t.Fatal("another device's session with the same code was approved")
	}
	if got, err := s.UISession(ctx, "h1", now.Add(7*time.Hour)); err != nil || !got.Approved {
		t.Fatalf("approved session: %+v %v", got, err)
	}
	later := now.Add(time.Hour)
	if err := s.TouchUISession(ctx, "h1", later); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.UISession(ctx, "h1", now); !got.LastUsed.Equal(later) && !got.LastUsed.Equal(later.Truncate(time.Microsecond)) {
		t.Fatalf("last used = %s", got.LastUsed)
	}
	if _, err := s.UISession(ctx, "h1", now.Add(9*time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired session: %v", err)
	}

	// Expiry and signing out delete; deleting the device deletes its sessions.
	if err := s.ExpireUISessions(ctx, now.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UISession(ctx, "h3", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired pending session kept: %v", err)
	}
	if _, err := s.UISession(ctx, "h1", now); err != nil {
		t.Fatalf("live session expired: %v", err)
	}
	if err := s.DeleteUISession(ctx, "h1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UISession(ctx, "h1", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted session: %v", err)
	}
	s.CreateUISession(ctx, pending("h5", "GGGG-HHHH", p.ID, now.Add(time.Hour)))
	if err := s.DeleteUISessionsOf(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UISession(ctx, "h5", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("session of a device whose sessions were ended: %v", err)
	}
	s.CreateUISession(ctx, pending("h4", "EEEE-FFFF", p.ID, now.Add(time.Hour)))
	if err := s.DeletePeer(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UISession(ctx, "h4", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("session of a deleted device: %v", err)
	}
}

func testSSOTokens(t *testing.T, s Store) {
	ctx := context.Background()
	now := time.Now()
	a, b := enrolled(t, s, "laptop"), enrolled(t, s, "phone")
	if err := s.SetSSOToken(ctx, SSOToken{PeerID: a.ID, Subject: "u1", Encrypted: "x1", NextCheck: now.Add(-time.Second)}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSSOToken(ctx, SSOToken{PeerID: b.ID, Subject: "u2", Encrypted: "x2", NextCheck: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSSOToken(ctx, SSOToken{PeerID: 999999, Subject: "u", Encrypted: "x", NextCheck: now}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("token for a missing device: %v", err)
	}
	// Due tokens are claimed once: a second control node asking right after gets none.
	got, err := s.ClaimSSOTokens(ctx, now, now.Add(2*time.Minute), 10)
	if err != nil || len(got) != 1 || got[0].PeerID != a.ID || got[0].Subject != "u1" || got[0].Encrypted != "x1" {
		t.Fatalf("claim: %+v %v", got, err)
	}
	if again, _ := s.ClaimSSOTokens(ctx, now, now.Add(2*time.Minute), 10); len(again) != 0 {
		t.Fatalf("claimed twice: %+v", again)
	}
	if later, _ := s.ClaimSSOTokens(ctx, now.Add(3*time.Minute), now.Add(5*time.Minute), 10); len(later) != 1 || later[0].PeerID != a.ID {
		t.Fatalf("claim when due again: %+v", later)
	}
	// Replaced by a new sign-in; gone with its device.
	if err := s.SetSSOToken(ctx, SSOToken{PeerID: a.ID, Subject: "u3", Encrypted: "x3", NextCheck: now}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ClaimSSOTokens(ctx, now, now.Add(time.Minute), 10); len(got) != 1 || got[0].Subject != "u3" || got[0].Encrypted != "x3" {
		t.Fatalf("replaced token: %+v", got)
	}
	// A check that started before that sign-in replaces and deletes nothing.
	if err := s.SetSSOToken(ctx, SSOToken{PeerID: a.ID, Subject: "u1", Encrypted: "x1b", NextCheck: now, Previous: "x1"}); !errors.Is(err, ErrChanged) {
		t.Fatalf("stale replacement: %v", err)
	}
	if err := s.DeleteSSOToken(ctx, a.ID, "x1"); !errors.Is(err, ErrChanged) {
		t.Fatalf("stale deletion: %v", err)
	}
	if err := s.SetSSOToken(ctx, SSOToken{PeerID: a.ID, Subject: "u3", Encrypted: "x4", NextCheck: now, Previous: "x3"}); err != nil {
		t.Fatalf("replacement of the current token: %v", err)
	}
	if got, _ := s.ClaimSSOTokens(ctx, now, now.Add(time.Minute), 10); len(got) != 1 || got[0].Encrypted != "x4" {
		t.Fatalf("after a conditional replacement: %+v", got)
	}
	if err := s.DeleteSSOToken(ctx, a.ID, "x4"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeletePeer(ctx, b.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ClaimSSOTokens(ctx, now.Add(24*time.Hour), now.Add(25*time.Hour), 10); len(got) != 0 {
		t.Fatalf("tokens left: %+v", got)
	}

	// The token key's canary: kept by the first, learnt by every later one; forgotten with the
	// tokens, which name their devices.
	if v, err := s.KeepSetting(ctx, SettingSSOTokenCanary, "c1"); err != nil || v != "c1" {
		t.Fatalf("first canary: %q %v", v, err)
	}
	if v, _ := s.KeepSetting(ctx, SettingSSOTokenCanary, "c2"); v != "c1" {
		t.Fatalf("a second canary replaced the first: %q", v)
	}
	if err := s.SetSSOToken(ctx, SSOToken{PeerID: a.ID, Subject: "u5", Encrypted: "x5", NextCheck: now}); err != nil {
		t.Fatal(err)
	}
	if ids, err := s.ForgetSSOTokens(ctx); err != nil || len(ids) != 1 || ids[0] != a.ID {
		t.Fatalf("forget: %v %v", ids, err)
	}
	if got, _ := s.ClaimSSOTokens(ctx, now.Add(24*time.Hour), now.Add(25*time.Hour), 10); len(got) != 0 {
		t.Fatalf("tokens left after forgetting: %+v", got)
	}
	if v, _ := s.KeepSetting(ctx, SettingSSOTokenCanary, "c3"); v != "c3" {
		t.Fatalf("the canary was not forgotten: %q", v)
	}

	// Updates conditional on the sign-in they were decided for.
	login := now.Add(-time.Hour).Truncate(time.Microsecond)
	if _, err := s.UpdatePeer(ctx, a.ID, PeerUpdate{LoginAt: &login}); err != nil {
		t.Fatal(err)
	}
	off, earlier := false, login.Add(-time.Minute)
	if _, err := s.UpdatePeer(ctx, a.ID, PeerUpdate{Approved: &off, IfLoginAt: &earlier}); !errors.Is(err, ErrChanged) {
		t.Fatalf("update after another sign-in: %v", err)
	}
	if p, err := s.UpdatePeer(ctx, a.ID, PeerUpdate{Approved: &off, IfLoginAt: &login}); err != nil || p.Approved {
		t.Fatalf("update of the same sign-in: %+v %v", p, err)
	}
}

// Posture checks, policies that require them, reports and their evaluations.
func testPosture(t *testing.T, s Store) {
	ctx := context.Background()
	c, err := s.AddPostureCheck(ctx, PostureCheck{Name: "baseline", DiskEncryption: true, Firewall: true,
		MinOS: map[string]string{"linux": "6.1", "windows": "10.0.22631"}, MaxAge: 30 * time.Minute})
	if err != nil || c.CreatedAt.IsZero() {
		t.Fatal(c, err)
	}
	if _, err := s.AddPostureCheck(ctx, PostureCheck{Name: "baseline"}); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate check: %v", err)
	}
	if _, err := s.AddPostureCheck(ctx, PostureCheck{Name: "boot", SecureBoot: true, Antimalware: true, MaxAge: time.Hour,
		MaxPatchAge: map[string]int{"android": 90}}); err != nil {
		t.Fatal(err)
	}
	checks, err := s.PostureChecks(ctx)
	if err != nil || len(checks) != 2 || checks[0].Name != "baseline" || !checks[0].DiskEncryption || !checks[0].Firewall ||
		checks[0].SecureBoot || checks[0].Antimalware || checks[0].MinOS["windows"] != "10.0.22631" || checks[0].MaxAge != 30*time.Minute ||
		checks[0].MaxPatchAge != nil || !checks[1].SecureBoot || !checks[1].Antimalware || checks[1].MinOS != nil ||
		len(checks[1].MaxPatchAge) != 1 || checks[1].MaxPatchAge["android"] != 90 {
		t.Fatalf("checks: %+v %v", checks, err)
	}

	var missing *NoSuchCheckError
	if _, err := s.AddPolicy(ctx, Policy{Source: "laptops", Destination: "servers", Posture: []string{"baseline", "gone"}}); !errors.As(err, &missing) || missing.Check != "gone" {
		t.Fatalf("policy requiring a check that does not exist: %v", err)
	}
	if pols, _ := s.Policies(ctx); len(pols) != 0 {
		t.Fatalf("policy added anyway: %+v", pols)
	}
	v0, _ := s.Version(ctx)
	pol, err := s.AddPolicy(ctx, Policy{Source: "laptops", Destination: "servers", Posture: []string{"baseline"}})
	if err != nil || len(pol.Posture) != 1 {
		t.Fatal(pol, err)
	}
	if v, _ := s.Version(ctx); v == v0 {
		t.Fatal("a policy must change the version")
	}
	plain, _ := s.AddPolicy(ctx, Policy{Source: "a", Destination: "b"})
	pols, _ := s.Policies(ctx)
	if len(pols) != 2 || !slices.Equal(pols[0].Posture, []string{"baseline"}) || pols[1].Posture != nil {
		t.Fatalf("policies: %+v", pols)
	}
	var inUse *CheckInUseError
	if err := s.DeletePostureCheck(ctx, "baseline"); !errors.As(err, &inUse) || !slices.Equal(inUse.Policies, []int64{pol.ID}) {
		t.Fatalf("deleted a check a policy requires: %v", err)
	}
	v1, _ := s.Version(ctx)
	if got, err := s.SetPolicyPosture(ctx, plain.ID, []string{"boot", "baseline"}); err != nil || len(got.Posture) != 2 || got.Source != "a" {
		t.Fatal(got, err)
	}
	v2, _ := s.Version(ctx)
	if v2 == v1 {
		t.Fatal("changing a policy's checks must change the version")
	}
	if _, err := s.SetPolicyPosture(ctx, plain.ID, []string{"boot", "baseline"}); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.Version(ctx); v != v2 {
		t.Fatal("setting the same checks must not change the version")
	}
	if _, err := s.SetPolicyPosture(ctx, plain.ID, []string{"gone"}); !errors.As(err, &missing) {
		t.Fatalf("policy changed to require a check that does not exist: %v", err)
	}
	if _, err := s.SetPolicyPosture(ctx, 999999, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown policy: %v", err)
	}
	if _, err := s.SetPolicyPosture(ctx, plain.ID, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.DeletePostureCheck(ctx, "boot"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeletePostureCheck(ctx, "boot"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted twice: %v", err)
	}

	p := enrolled(t, s, "laptop")
	if err := s.SetPostureReport(ctx, 999999, []byte(`{}`), time.Now(), 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("report of an unknown device: %v", err)
	}
	v3, _ := s.Version(ctx)
	at := time.Now().Add(-time.Minute).Truncate(time.Microsecond)
	if err := s.SetPostureReport(ctx, p.ID, []byte(`{"format":1,"os":"linux","disk_encryption":true}`), at, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	// Reports closer together than the gap are refused, and change nothing.
	if err := s.SetPostureReport(ctx, p.ID, []byte(`{"format":1,"os":"linux"}`), at.Add(29*time.Second), 30*time.Second); !errors.Is(err, ErrTooSoon) {
		t.Fatalf("report too soon: %v", err)
	}
	if v, _ := s.Version(ctx); v != v3 {
		t.Fatal("a report must not change the version")
	}
	reports, err := s.PostureReports(ctx)
	if err != nil || len(reports) != 1 || reports[0].PeerID != p.ID || !reports[0].ReportedAt.Equal(at) || reports[0].Results != nil ||
		!strings.Contains(string(reports[0].Facts), `"disk_encryption": true`) && !strings.Contains(string(reports[0].Facts), `"disk_encryption":true`) {
		t.Fatalf("reports: %+v %v", reports, err)
	}

	// Evaluations are conditional on the stored one, and change the version only when they differ.
	failing := map[string]string{"baseline": "firewall off"}
	if ok, err := s.SetPostureResults(ctx, p.ID, map[string]string{}, failing); err != nil || ok {
		t.Fatalf("applied over a different evaluation: %v %v", ok, err)
	}
	if ok, err := s.SetPostureResults(ctx, p.ID, nil, failing); err != nil || !ok {
		t.Fatalf("first evaluation: %v %v", ok, err)
	}
	reports, _ = s.PostureReports(ctx)
	firstAt := reports[0].ResultsAt
	if firstAt.IsZero() || time.Since(firstAt) > time.Minute || time.Until(firstAt) > time.Minute {
		t.Fatalf("time of the evaluation: %v", firstAt)
	}
	if ok, err := s.SetPostureResults(ctx, p.ID, failing, failing); err != nil || !ok {
		t.Fatalf("same evaluation: %v %v", ok, err)
	}
	if reports, _ = s.PostureReports(ctx); !reports[0].ResultsAt.Equal(firstAt) {
		t.Fatalf("the same evaluation moved its time: %v, was %v", reports[0].ResultsAt, firstAt)
	}
	v4, _ := s.Version(ctx)
	if v4 == v3 {
		t.Fatal("a new evaluation must change the version")
	}
	if ok, _ := s.SetPostureResults(ctx, p.ID, nil, failing); ok {
		t.Fatal("applied although the stored evaluation is no longer none")
	}
	if ok, err := s.SetPostureResults(ctx, p.ID, failing, map[string]string{"baseline": ""}); err != nil || !ok {
		t.Fatalf("second evaluation: %v %v", ok, err)
	}
	if v, _ := s.Version(ctx); v == v4 {
		t.Fatal("a changed evaluation must change the version")
	}
	reports, _ = s.PostureReports(ctx)
	if r, ok := reports[0].Results["baseline"]; !ok || r != "" || reports[0].Facts == nil {
		t.Fatalf("evaluation not stored, or the report lost: %+v", reports[0])
	}
	// A report keeps the evaluation; a device without a report can be evaluated too.
	if err := s.SetPostureReport(ctx, p.ID, []byte(`{"format":1}`), time.Now(), 30*time.Second); err != nil {
		t.Fatal(err)
	}
	q := enrolled(t, s, "phone")
	if ok, err := s.SetPostureResults(ctx, q.ID, nil, map[string]string{"baseline": "no report"}); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if _, err := s.SetPostureResults(ctx, 999999, nil, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("evaluation of an unknown device: %v", err)
	}
	reports, _ = s.PostureReports(ctx)
	if len(reports) != 2 || reports[0].Results["baseline"] != "" || reports[1].Facts != nil || !reports[1].ReportedAt.IsZero() ||
		reports[1].Results["baseline"] != "no report" {
		t.Fatalf("reports: %+v", reports)
	}
	// Deleting a device deletes its report.
	if err := s.DeletePeer(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	if reports, _ = s.PostureReports(ctx); len(reports) != 1 || reports[0].PeerID != q.ID {
		t.Fatalf("report of a deleted device kept: %+v", reports)
	}
}

func testLinkPosture(t *testing.T, s Store) {
	ctx := context.Background()
	priv := make([]byte, 64)
	for _, name := range []string{"enc", "boot"} {
		if _, err := s.AddPostureCheck(ctx, PostureCheck{Name: name, DiskEncryption: true, MaxAge: time.Hour}); err != nil {
			t.Fatal(err)
		}
	}
	var missing *NoSuchCheckError
	if _, err := s.CreateLink(ctx, Link{Name: "acme", PrivateKey: priv, Groups: []string{"ops"}, Grant: []string{"ops"},
		TTL: time.Hour, Posture: []string{"enc", "gone"}}); !errors.As(err, &missing) || missing.Check != "gone" {
		t.Fatalf("link requiring a check that does not exist: %v", err)
	}
	if _, err := s.Link(ctx, "acme"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("link created anyway: %v", err)
	}
	v0, _ := s.Version(ctx)
	l, err := s.CreateLink(ctx, Link{Name: "acme", PrivateKey: priv, Groups: []string{"ops"}, Grant: []string{"ops"},
		TTL: time.Hour, Posture: []string{"enc"}})
	if err != nil || !slices.Equal(l.Posture, []string{"enc"}) {
		t.Fatal(l, err)
	}
	if _, err := s.CreateLink(ctx, Link{Name: "plain", PrivateKey: priv, Groups: []string{"ops"}, Grant: []string{"ops"}, TTL: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.Version(ctx); v != v0 {
		t.Fatal("links are not in the network map: creating one must not change the version")
	}
	links, _ := s.Links(ctx)
	if len(links) != 2 || !slices.Equal(links[0].Posture, []string{"enc"}) || links[1].Posture != nil {
		t.Fatalf("links: %+v", links)
	}
	// Importing the token (the one change an older control node makes) keeps the checks.
	if err := s.SetLinkToken(ctx, "acme", "ento1:x"); err != nil {
		t.Fatal(err)
	}
	if l, _ := s.Link(ctx, "acme"); l.Token != "ento1:x" || !slices.Equal(l.Posture, []string{"enc"}) {
		t.Fatalf("token import changed the checks: %+v", l)
	}

	// A check a link requires cannot be deleted.
	var inUse *CheckInUseError
	if err := s.DeletePostureCheck(ctx, "enc"); !errors.As(err, &inUse) || !slices.Equal(inUse.Links, []string{"acme"}) ||
		len(inUse.Policies) != 0 || !strings.Contains(err.Error(), "link acme") {
		t.Fatalf("deleted a check a link requires: %v", err)
	}

	// Results are swapped atomically; "" (passes) is what a device without a record has.
	p := enrolled(t, s, "laptop")
	if prev, err := s.SwapLinkPosture(ctx, "acme", p.ID, ""); err != nil || prev != "" {
		t.Fatal(prev, err)
	}
	if prev, err := s.SwapLinkPosture(ctx, "acme", p.ID, "enc: no report"); err != nil || prev != "" {
		t.Fatal(prev, err)
	}
	if prev, err := s.SwapLinkPosture(ctx, "acme", p.ID, "enc: no report"); err != nil || prev != "enc: no report" {
		t.Fatal(prev, err)
	}
	if prev, err := s.SwapLinkPosture(ctx, "plain", p.ID, "enc: disk not encrypted"); err != nil || prev != "" {
		t.Fatal("results are per link: ", prev, err)
	}
	if prev, err := s.SwapLinkPosture(ctx, "acme", p.ID, ""); err != nil || prev != "enc: no report" {
		t.Fatal(prev, err)
	}
	if prev, _ := s.SwapLinkPosture(ctx, "acme", p.ID, "enc: disk not encrypted"); prev != "" {
		t.Fatalf("a pass was not recorded: %q", prev)
	}
	if _, err := s.SwapLinkPosture(ctx, "gone", p.ID, "enc: x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("result for a link that does not exist: %v", err)
	}
	if _, err := s.SwapLinkPosture(ctx, "acme", 999999, "enc: x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("result for a device that does not exist: %v", err)
	}
	v1, _ := s.Version(ctx)

	// Changing the checks: they must exist, the version stays, and the results recorded are forgotten.
	if _, err := s.SetLinkPosture(ctx, "acme", []string{"enc", "gone"}); !errors.As(err, &missing) {
		t.Fatalf("link changed to require a check that does not exist: %v", err)
	}
	if _, err := s.SetLinkPosture(ctx, "nope", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown link: %v", err)
	}
	if prev, _ := s.SwapLinkPosture(ctx, "acme", p.ID, "enc: disk not encrypted"); prev != "enc: disk not encrypted" {
		t.Fatalf("setting the same checks: %q", prev)
	}
	if l, err := s.SetLinkPosture(ctx, "acme", []string{"enc"}); err != nil || !slices.Equal(l.Posture, []string{"enc"}) {
		t.Fatal(l, err)
	}
	if prev, _ := s.SwapLinkPosture(ctx, "acme", p.ID, "enc: disk not encrypted"); prev != "enc: disk not encrypted" {
		t.Fatalf("setting the same checks forgot the results: %q", prev)
	}
	l, err = s.SetLinkPosture(ctx, "acme", []string{"enc", "boot"})
	if err != nil || !slices.Equal(l.Posture, []string{"enc", "boot"}) || l.Token != "ento1:x" || l.TTL != time.Hour {
		t.Fatal(l, err)
	}
	if prev, _ := s.SwapLinkPosture(ctx, "acme", p.ID, "boot: no report"); prev != "" {
		t.Fatalf("new checks kept the results of the old ones: %q", prev)
	}
	if v, _ := s.Version(ctx); v != v1 {
		t.Fatal("changing a link's checks must not change the version")
	}
	if l, err := s.SetLinkPosture(ctx, "acme", []string{}); err != nil || l.Posture != nil {
		t.Fatal(l, err)
	}
	if l, _ := s.Link(ctx, "acme"); l.Posture != nil {
		t.Fatalf("checks not removed: %+v", l)
	}
	if err := s.DeletePostureCheck(ctx, "enc"); err != nil {
		t.Fatalf("a check no link requires any more: %v", err)
	}

	// Results go with the device and with the link.
	if _, err := s.SwapLinkPosture(ctx, "plain", p.ID, "boot: no report"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeletePeer(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	q := enrolled(t, s, "phone")
	if _, err := s.SwapLinkPosture(ctx, "plain", q.ID, "boot: no report"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteLink(ctx, "plain"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateLink(ctx, Link{Name: "plain", PrivateKey: priv, Groups: []string{"ops"}, Grant: []string{"ops"}, TTL: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if prev, _ := s.SwapLinkPosture(ctx, "plain", q.ID, ""); prev != "" {
		t.Fatalf("a link created again kept the results of the deleted one: %q", prev)
	}
}

// TestPostgresLinkPostureUpgrade: links made by an older control node (no posture column yet) get
// none, and the statements an older node runs on links leave the checks alone.
func TestPostgresLinkPostureUpgrade(t *testing.T) {
	open, ok := backends(t)["postgres"]
	if !ok {
		t.Skip("ENTO_TEST_POSTGRES not set")
	}
	ctx := context.Background()
	s := open(t).(*Postgres)
	if _, err := s.pool.Exec(ctx, `DROP TABLE ento_link_posture; ALTER TABLE ento_links DROP COLUMN posture`); err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString(make([]byte, 64))
	if _, err := s.pool.Exec(ctx, `INSERT INTO ento_links (name, private_key, token, groups, grant_groups, ttl_seconds, created_at)
		VALUES ('old', $1, '', '{ops}', '{ops}', 3600, now())`, key); err != nil {
		t.Fatal(err)
	}
	s2, err := OpenPostgres(ctx, os.Getenv("ENTO_TEST_POSTGRES"), testSpace)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if l, err := s2.Link(ctx, "old"); err != nil || l.Posture != nil || l.TTL != time.Hour {
		t.Fatalf("link of an older control node: %+v %v", l, err)
	}
	if _, err := s2.AddPostureCheck(ctx, PostureCheck{Name: "enc", DiskEncryption: true, MaxAge: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.SetLinkPosture(ctx, "old", []string{"enc"}); err != nil {
		t.Fatal(err)
	}
	// What an older control node runs: its own insert (without the column) and the token import.
	if _, err := s2.pool.Exec(ctx, `INSERT INTO ento_links (name, private_key, token, groups, grant_groups, ttl_seconds, created_at)
		VALUES ('older', $1, '', '{ops}', '{ops}', 3600, now())`, key); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.pool.Exec(ctx, `UPDATE ento_links SET token = $2 WHERE name = $1`, "old", "ento1:y"); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.pool.Exec(ctx, `SELECT name, private_key, token, groups, grant_groups, ttl_seconds, created_at FROM ento_links`); err != nil {
		t.Fatal(err)
	}
	links, err := s2.Links(ctx)
	if err != nil || len(links) != 2 || !slices.Equal(links[0].Posture, []string{"enc"}) || links[0].Token != "ento1:y" || links[1].Posture != nil {
		t.Fatalf("links: %+v %v", links, err)
	}
}

// TestPostgresLayersMigration: before 0.27 a device bound to a person kept its person's rights in
// approved, admin, operator and groups (a session's); they move to its person layer once, and other
// devices keep theirs as their machine layer.
func TestPostgresLayersMigration(t *testing.T) {
	open, ok := backends(t)["postgres"]
	if !ok {
		t.Skip("ENTO_TEST_POSTGRES not set")
	}
	ctx := context.Background()
	s := open(t).(*Postgres)
	insert := func(addr, host, user string, approved, admin bool, groups []string) {
		if _, err := s.pool.Exec(ctx, `INSERT INTO ento_peers (public_key, address, hostname, os, approved, admin, groups, created_at,
			user_id, login_at, last_seen, layered) VALUES ($1, $2, $3, 'linux', $4, $5, $6, now(), $7, now() - interval '1 hour', now(), false)`,
			key(t).String(), addr, host, approved, admin, groups, user); err != nil {
			t.Fatal(err)
		}
	}
	insert("100.64.1.1", "laptop", "sub-ana", true, true, []string{"admins"})
	insert("100.64.1.2", "phone", "sub-ana", false, false, []string{}) // its session had ended
	insert("100.64.1.3", "server", "", true, false, []string{"servers"})
	s2, err := OpenPostgres(ctx, os.Getenv("ENTO_TEST_POSTGRES"), testSpace)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	at := func(a string) Peer {
		p, err := s2.PeerByAddress(ctx, netip.MustParseAddr(a))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	if p := at("100.64.1.1"); p.Machine.Approved || p.Machine.Admin || len(p.Machine.Groups) != 0 || !p.Person.Active ||
		!p.Person.Approved || !p.Person.Admin || !slices.Equal(p.Person.Groups, []string{"admins"}) || p.Admin || p.Person.Since.IsZero() {
		t.Fatalf("the laptop after the migration: %+v", p)
	}
	if p := at("100.64.1.2"); p.Approved || p.Person.Active || p.Machine.Approved {
		t.Fatalf("the phone after the migration: %+v", p)
	}
	if p := at("100.64.1.3"); !p.Machine.Approved || !slices.Equal(p.Machine.Groups, []string{"servers"}) || !p.Approved {
		t.Fatalf("the server after the migration: %+v", p)
	}
	// Once: a later start leaves the new form alone.
	yes := true
	if _, err := s2.UpdatePeer(ctx, at("100.64.1.1").ID, PeerUpdate{Approved: &yes}); err != nil {
		t.Fatal(err)
	}
	s3, err := OpenPostgres(ctx, os.Getenv("ENTO_TEST_POSTGRES"), testSpace)
	if err != nil {
		t.Fatal(err)
	}
	defer s3.Close()
	if p := at("100.64.1.1"); !p.Machine.Approved || !p.Person.Admin {
		t.Fatalf("a second start migrated again: %+v", p)
	}
}

// A device's hardware key: bound once, updated under the device's lock, released by deleting it;
// its WireGuard key changes only from the key it has, to one nobody else has, and the change is a
// new network map version.
func TestHWKeyAndRotation(t *testing.T) {
	for name, open := range backends(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s := open(t)
			p := enrolled(t, s, "laptop")
			other := enrolled(t, s, "other")
			if ks, _ := s.HWKeys(ctx); len(ks) != 0 {
				t.Fatalf("keys before binding: %+v", ks)
			}
			k, err := s.UpdateHWKey(ctx, p.ID, func(k HWKey, found bool) (HWKey, error) {
				if found {
					t.Error("found before binding")
				}
				k.Kind, k.PublicKey = "tpm", "pk"
				return k, nil
			})
			if err != nil || k.Kind != "tpm" || k.BoundAt.IsZero() {
				t.Fatalf("bind: %v %+v", err, k)
			}
			now := time.Now().Truncate(time.Second)
			if _, err := s.UpdateHWKey(ctx, p.ID, func(k HWKey, found bool) (HWKey, error) {
				if !found || k.PublicKey != "pk" {
					t.Errorf("not found again: %+v", k)
				}
				k.SeenAt, k.Rotate = now, true
				return k, nil
			}); err != nil {
				t.Fatal(err)
			}
			ks, err := s.HWKeys(ctx)
			if err != nil || len(ks) != 1 || !ks[0].SeenAt.Equal(now) || !ks[0].Rotate || !ks[0].UnsignedSince.IsZero() {
				t.Fatalf("keys: %v %+v", err, ks)
			}
			if _, err := s.UpdateHWKey(ctx, 999999, func(k HWKey, _ bool) (HWKey, error) { return k, nil }); !errors.Is(err, ErrNotFound) {
				t.Fatalf("unknown device: %v", err)
			}

			v0, _ := s.Version(ctx)
			newKey := key(t)
			if err := s.RotatePeerKey(ctx, p.ID, other.PublicKey, newKey); !errors.Is(err, ErrNotFound) {
				t.Fatalf("from a key it does not have: %v", err)
			}
			if err := s.RotatePeerKey(ctx, p.ID, p.PublicKey, other.PublicKey); !errors.Is(err, ErrExists) {
				t.Fatalf("to another device's key: %v", err)
			}
			if err := s.RotatePeerKey(ctx, p.ID, p.PublicKey, newKey); err != nil {
				t.Fatal(err)
			}
			if v1, _ := s.Version(ctx); v1 <= v0 {
				t.Fatalf("version %d after %d", v1, v0)
			}
			got, err := s.PeerByAddress(ctx, p.Address)
			if err != nil || got.PublicKey != newKey || got.Address != p.Address || got.Hostname != p.Hostname || !got.Approved {
				t.Fatalf("after rotating: %v %+v", err, got)
			}
			if _, err := s.PeerByPublicKey(ctx, p.PublicKey); !errors.Is(err, ErrNotFound) {
				t.Fatalf("the old key still names the device: %v", err)
			}
			if k, err := s.HWKey(ctx, p.ID); err != nil || k.Rotate || k.RotatedAt.IsZero() {
				t.Fatalf("the change did not clear the request: %v %+v", err, k)
			}
			if _, err := s.HWKey(ctx, other.ID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("a device without a key: %v", err)
			}
			// Asking for a change is a new map version (the device's map says so); seeing a check-in is not.
			v2, _ := s.Version(ctx)
			s.UpdateHWKey(ctx, p.ID, func(k HWKey, _ bool) (HWKey, error) { k.SeenAt = time.Now(); return k, nil })
			if v, _ := s.Version(ctx); v != v2 {
				t.Fatal("a check-in made a new version")
			}
			s.UpdateHWKey(ctx, p.ID, func(k HWKey, _ bool) (HWKey, error) { k.Rotate = true; return k, nil })
			if v, _ := s.Version(ctx); v <= v2 {
				t.Fatal("a change request made no new version")
			}

			if err := s.DeleteHWKey(ctx, p.ID); err != nil {
				t.Fatal(err)
			}
			if err := s.DeleteHWKey(ctx, p.ID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("released twice: %v", err)
			}
		})
	}
}

func TestUpdatePolicy(t *testing.T) {
	for name, open := range backends(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s := open(t)
			p, err := s.UpdatePolicy(ctx)
			if err != nil || p.Mode != "auto" {
				t.Fatalf("default %+v %v", p, err)
			}
			v0, _ := s.Version(ctx)
			set := UpdatePolicy{Mode: "approve", Approved: "0.37.0", FirstGroup: "canaries", FirstHours: 24, SetBy: "peer 1", SetAt: time.Now().UTC().Truncate(time.Second)}
			if err := s.SetUpdatePolicy(ctx, set); err != nil {
				t.Fatal(err)
			}
			if v1, _ := s.Version(ctx); v1 == v0 {
				t.Fatal("setting the policy did not change the state version (maps are not sent again)")
			}
			got, _ := s.UpdatePolicy(ctx)
			if got.Mode != set.Mode || got.Approved != set.Approved || got.FirstGroup != set.FirstGroup || got.FirstHours != 24 || !got.SetAt.Equal(set.SetAt) {
				t.Fatalf("got %+v", got)
			}
			first := time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)
			if at, err := s.ReleaseOffered(ctx, "0.37.0", first); err != nil || !at.Equal(first) {
				t.Fatalf("offered %v %v", at, err)
			}
			if at, _ := s.ReleaseOffered(ctx, "0.37.0", first.Add(time.Hour)); !at.Equal(first) {
				t.Fatalf("the first offer must win: %v", at)
			}
		})
	}
}

// An isolated device has no rights, whoever is signed in on it (constitution 4.3, A3): not approved,
// no role, none of its person's groups; isolating it ends the person's session there.
func testIsolation(t *testing.T, s Store) {
	ctx := context.Background()
	p := enrolled(t, s, "laptop")
	on, sub := true, "sub-1"
	p, err := s.UpdatePeer(ctx, p.ID, PeerUpdate{Admin: &on, User: &sub, PersonActive: &on, PersonApproved: &on, PersonAdmin: &on,
		PersonGroups: &[]string{"admins"}})
	if err != nil || !p.Admin || !p.Approved {
		t.Fatalf("an admin person signed in: %+v %v", p, err)
	}
	// Isolated with the person signed in (an old row, or the layer opened again afterwards).
	off := false
	if p, err = s.UpdatePeer(ctx, p.ID, PeerUpdate{Groups: &[]string{"device:isolated"}, Approved: &off}); err != nil {
		t.Fatal(err)
	}
	if p.Person.Active {
		t.Fatal("isolating the device left its person's session open")
	}
	if p, err = s.UpdatePeer(ctx, p.ID, PeerUpdate{PersonActive: &on}); err != nil {
		t.Fatal(err)
	}
	for _, q := range []Peer{p, func() Peer { q, _ := s.PeerByAddress(ctx, p.Address); return q }()} {
		if q.Approved || q.Admin || q.Operator || slices.Contains(q.Groups, "admins") {
			t.Fatalf("isolated with an admin person: approved %v admin %v operator %v groups %v", q.Approved, q.Admin, q.Operator, q.Groups)
		}
	}
}

// The audit (0.53): entries come back newest first, by page, filtered; the database refuses to
func TestAudit(t *testing.T) {
	for name, open := range backends(t) {
		t.Run(name, func(t *testing.T) {
			s := open(t)
			ctx := context.Background()
			base := time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond)
			for i, a := range []string{"enrolled", "policy_added", "policy_added", "forward_connection", "policy_deleted"} {
				result := "ok"
				if a == "forward_connection" {
					result = "denied"
				}
				if err := s.AddAudit(ctx, AuditEntry{At: base.Add(time.Duration(i) * time.Minute), Node: "c1", Action: a, Device: "lap-1",
					Person: "ana@example.com", From: "100.64.1.1", Target: fmt.Sprintf("entry %d 100%%_done", i), Result: result}); err != nil {
					t.Fatal(err)
				}
			}
			all, err := s.Audit(ctx, AuditQuery{})
			if err != nil || len(all) != 5 || all[0].Action != "policy_deleted" || all[4].Action != "enrolled" || !all[0].At.Equal(base.Add(4*time.Minute)) {
				t.Fatalf("all: %+v %v", all, err)
			}
			page, _ := s.Audit(ctx, AuditQuery{Limit: 2, Before: all[1].ID})
			if len(page) != 2 || page[0].ID != all[2].ID || page[1].ID != all[3].ID {
				t.Fatalf("a page: %+v", page)
			}
			if got, _ := s.Audit(ctx, AuditQuery{Action: "policy_added"}); len(got) != 2 {
				t.Fatalf("by action: %+v", got)
			}
			if got, _ := s.Audit(ctx, AuditQuery{Result: "denied"}); len(got) != 1 || got[0].Action != "forward_connection" {
				t.Fatalf("by result: %+v", got)
			}
			if got, _ := s.Audit(ctx, AuditQuery{Text: "ANA@"}); len(got) != 5 {
				t.Fatalf("by text: %d", len(got))
			}
			if got, _ := s.Audit(ctx, AuditQuery{Text: "entry 3 100%_"}); len(got) != 1 {
				t.Fatalf("by text with %% and _: %+v", got)
			}
			if got, _ := s.Audit(ctx, AuditQuery{Text: "entry 3 100_"}); len(got) != 0 {
				t.Fatalf("_ is no wildcard: %+v", got)
			}
			if got, _ := s.Audit(ctx, AuditQuery{Since: base.Add(3 * time.Minute)}); len(got) != 2 {
				t.Fatalf("since: %+v", got)
			}
			if pg, ok := s.(*Postgres); ok {
				for _, q := range []string{`UPDATE ento_audit SET result = 'ok'`, `DELETE FROM ento_audit`, `TRUNCATE ento_audit`} {
					if _, err := pg.pool.Exec(ctx, q); err == nil {
						t.Errorf("%s: allowed", q)
					}
				}
				if got, _ := s.Audit(ctx, AuditQuery{}); len(got) != 5 {
					t.Fatalf("after the attempts: %d entries", len(got))
				}
			}
		})
	}
}

// Setting reads what KeepSetting stored, and says when nothing is.
func TestSetting(t *testing.T) {
	for name, open := range backends(t) {
		t.Run(name, func(t *testing.T) {
			s := open(t)
			ctx := context.Background()
			if v, ok, err := s.Setting(ctx, "k"); err != nil || ok || v != "" {
				t.Fatalf("none: %q %v %v", v, ok, err)
			}
			if _, err := s.KeepSetting(ctx, "k", "v1"); err != nil {
				t.Fatal(err)
			}
			if v, ok, err := s.Setting(ctx, "k"); err != nil || !ok || v != "v1" {
				t.Fatalf("stored: %q %v %v", v, ok, err)
			}
		})
	}
}
