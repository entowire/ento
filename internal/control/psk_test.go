package control

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/psk"
	"entowire.com/ento/internal/store"
	"entowire.com/ento/internal/token"
)

// reachesAPI reports whether c gets a connection to the control API within d (a handshake that
// fails gets none).
func reachesAPI(c *testClient, d time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	conn, err := c.net.DialContext(ctx, "tcp", net.JoinHostPort(c.ctl.String(), "80"))
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// Constitution 9.1 between a device and its control nodes: a device that joins with an
// encapsulation key has a preshared key from its first handshake, and a device without it gets no
// tunnel; a new key agreed over the tunnel changes nothing until the device confirms it, then the
// control node sets it in place (the session carries on), without moving the network map's
// version; a reset (after a restore) leaves the device's tunnel without one.
func TestPresharedKeyExchange(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, st := startTestNetwork(t, ctx, "100.64.0.0/16")
	tokStr, _, err := IssueToken(ctx, st, TokenOptions{Approve: true, Groups: []string{"staff"}, Name: "laptop"})
	if err != nil {
		t.Fatal(err)
	}
	srv.checkVersion(ctx)
	tok, _ := token.Parse(tokStr)
	creds, _ := token.Derive(tok.Secret)
	temp := newTestClient(t, creds.PrivateKey, creds.PresharedKey, tok.TempAddress, tok.Controls[0])
	perm, _ := wgtypes.GeneratePrivateKey()
	req, err := psk.NewRequest()
	if err != nil {
		t.Fatal(err)
	}
	var res api.RedeemResponse
	if code := temp.do(t, "POST", api.PathRedeem, api.RedeemRequest{PublicKey: perm.PublicKey().String(), Hostname: "laptop", OS: "test",
		PSKEncapsulationKey: req.EncapsulationKey()}, &res); code != 200 {
		t.Fatalf("redeem: HTTP %d", code)
	}
	temp.dev.Close()
	if res.PSKCiphertext == "" || len(res.Controls) != 1 || !res.Controls[0].PresharedKeys {
		t.Fatalf("redeem answered no exchange: %+v", res)
	}
	first, err := req.Finish(res.PSKCiphertext, perm.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	addr := netip.MustParseAddr(res.Address)
	peer, err := st.PeerByAddress(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	if got := presharedKeyOf(t, srv.wg, perm.PublicKey()); got != hexKey(first.Key) {
		t.Fatalf("the control node set %s on the new device's tunnel, not the agreed key", got)
	}

	// Without the key there is no tunnel, with it there is.
	without := newTestClient(t, perm, wgtypes.Key{}, addr, tok.Controls[0])
	if reachesAPI(without, 3*time.Second) {
		t.Fatal("a device without the preshared key reached the control node")
	}
	without.dev.Close()
	c := newTestClient(t, perm, first.Key, addr, tok.Controls[0])
	var nm api.NetMap
	if code := c.do(t, "GET", api.PathNetMap, nil, &nm); code != 200 {
		t.Fatalf("netmap with the key: HTTP %d", code)
	}
	if len(nm.Controls) != 1 || !nm.Controls[0].PresharedKeys {
		t.Fatalf("the map does not say the control node sets preshared keys: %+v", nm.Controls)
	}

	// A new key over the tunnel: kept as next until confirmed.
	mapVersion, _ := st.Version(ctx)
	req2, _ := psk.NewRequest()
	var pr api.PSKResponse
	if code := c.do(t, "POST", api.PathPSK, api.PSKRequest{EncapsulationKey: req2.EncapsulationKey()}, &pr); code != 200 {
		t.Fatalf("exchange: HTTP %d", code)
	}
	second, err := req2.Finish(pr.Ciphertext, perm.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	srv.checkVersion(ctx)
	if got := presharedKeyOf(t, srv.wg, perm.PublicKey()); got != hexKey(first.Key) {
		t.Fatal("a key not confirmed was set")
	}
	if code := c.do(t, "POST", api.PathPSK, api.PSKRequest{EncapsulationKey: "nonsense"}, nil); code != http.StatusBadRequest {
		t.Fatalf("a malformed exchange: HTTP %d, want 400", code)
	}
	if code := c.do(t, "POST", api.PathPSKConfirm, api.PSKConfirm{Tag: first.Tag}, nil); code != http.StatusConflict {
		t.Fatalf("confirming a key other than the next one: HTTP %d, want 409", code)
	}

	// The agent sets it on its end first, then confirms over the session that carries on.
	if err := c.dev.IpcSet("public_key=" + hexKey(c.ctlKey) + "\npreshared_key=" + hexKey(second.Key) + "\n"); err != nil {
		t.Fatal(err)
	}
	if code := c.do(t, "POST", api.PathPSKConfirm, api.PSKConfirm{Tag: second.Tag}, nil); code != 200 {
		t.Fatalf("confirm: HTTP %d", code)
	}
	if got := presharedKeyOf(t, srv.wg, perm.PublicKey()); got != hexKey(second.Key) {
		t.Fatal("the confirmed key was not set")
	}
	if code := c.do(t, "POST", api.PathPSKConfirm, api.PSKConfirm{Tag: second.Tag}, nil); code != 200 {
		t.Fatalf("a repeated confirmation (its answer lost): HTTP %d", code)
	}
	if v, _ := st.Version(ctx); v != mapVersion {
		t.Fatalf("a preshared key change moved the network map's version: %d -> %d", mapVersion, v)
	}
	if ks, _ := st.PresharedKeys(ctx); ks[peer.ID].Current != second.Key || ks[peer.ID].Next != (wgtypes.Key{}) {
		t.Fatalf("stored %+v", ks[peer.ID])
	}
	if es, _ := st.Audit(ctx, store.AuditQuery{Action: "psk_changed"}); len(es) != 1 {
		t.Fatalf("audited %d changes, want 1", len(es))
	}
	c.dev.Close()
	// A fresh handshake takes the new key.
	c = newTestClient(t, perm, second.Key, addr, tok.Controls[0])
	if !reachesAPI(c, 10*time.Second) {
		t.Fatal("no tunnel with the new key")
	}
	c.dev.Close()

	// Reset: the control nodes forget the keys and set none.
	if _, err := st.ResetPresharedKeys(ctx); err != nil {
		t.Fatal(err)
	}
	srv.checkVersion(ctx)
	if got := presharedKeyOf(t, srv.wg, perm.PublicKey()); got != hexKey(wgtypes.Key{}) {
		t.Fatalf("after a reset the control node still sets %s", got)
	}
	c = newTestClient(t, perm, wgtypes.Key{}, addr, tok.Controls[0])
	if !reachesAPI(c, 10*time.Second) {
		t.Fatal("no tunnel without a key after the reset")
	}
}

// enrollWithPSK enrolls a device in group staff that agrees on a preshared key with its control
// node (a 0.62 agent), or none (an older one).
func enrollWithPSK(t *testing.T, ctx context.Context, srv *Server, st store.Store, name string, withPSK bool) (*testClient, store.Peer) {
	t.Helper()
	tokStr, _, err := IssueToken(ctx, st, TokenOptions{Approve: true, Groups: []string{"staff"}, Name: name})
	if err != nil {
		t.Fatal(err)
	}
	srv.checkVersion(ctx)
	tok, _ := token.Parse(tokStr)
	creds, _ := token.Derive(tok.Secret)
	temp := newTestClient(t, creds.PrivateKey, creds.PresharedKey, tok.TempAddress, tok.Controls[0])
	perm, _ := wgtypes.GeneratePrivateKey()
	req := api.RedeemRequest{PublicKey: perm.PublicKey().String(), Hostname: name, OS: "test"}
	var x *psk.Request
	if withPSK {
		x, _ = psk.NewRequest()
		req.PSKEncapsulationKey = x.EncapsulationKey()
	}
	var res api.RedeemResponse
	if code := temp.do(t, "POST", api.PathRedeem, req, &res); code != 200 {
		t.Fatalf("redeem: HTTP %d", code)
	}
	temp.dev.Close()
	var key wgtypes.Key
	if withPSK {
		a, err := x.Finish(res.PSKCiphertext, perm.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		key = a.Key
	}
	p, err := st.PeerByAddress(ctx, netip.MustParseAddr(res.Address))
	if err != nil {
		t.Fatal(err)
	}
	return newTestClient(t, perm, key, p.Address, tok.Controls[0]), p
}

// peerIn returns the entry for p in nm.
func peerIn(t *testing.T, nm api.NetMap, p store.Peer) api.Peer {
	t.Helper()
	for _, e := range nm.Peers {
		if e.PublicKey == p.PublicKey.String() {
			return e
		}
	}
	t.Fatalf("%s not in the map", p.Hostname)
	return api.Peer{}
}

// Constitution 9.1 between two devices: the control nodes make a pair's key and put it in both
// devices' maps, first as the next key with the time both switch to it; only devices that set
// preshared keys get them; the daily batch gives every pair a next key at once, and a device whose
// WireGuard key changed gets new ones at once.
func TestPairKeys(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, st := startTestNetwork(t, ctx, "100.64.0.0/16")
	if _, err := st.AddPolicy(ctx, store.Policy{Source: "staff", Destination: "staff"}); err != nil {
		t.Fatal(err)
	}
	ca, a := enrollWithPSK(t, ctx, srv, st, "a", true)
	cb, b := enrollWithPSK(t, ctx, srv, st, "b", true)
	cc, c := enrollWithPSK(t, ctx, srv, st, "c", false)
	srv.checkVersion(ctx)
	get := func(cl *testClient) api.NetMap {
		t.Helper()
		var nm api.NetMap
		if code := cl.do(t, "GET", api.PathNetMap, nil, &nm); code != 200 {
			t.Fatalf("netmap: HTTP %d", code)
		}
		return nm
	}
	before := time.Now()
	nmA := get(ca)
	if nmA.Time < before.Add(-time.Second).UnixMilli() || nmA.Time > time.Now().Add(time.Second).UnixMilli() {
		t.Fatalf("the map's time %d is not the control node's clock", nmA.Time)
	}
	ab := peerIn(t, nmA, b)
	if ab.PresharedKey != "" || ab.PresharedKeyNext == "" || ab.PresharedKeyAt < before.Add(pairKeyLead-time.Second).Unix() {
		t.Fatalf("a's entry for b: %+v, want a next key switching in %s", ab, pairKeyLead)
	}
	ba := peerIn(t, get(cb), a)
	if ba.PresharedKeyNext != ab.PresharedKeyNext || ba.PresharedKeyAt != ab.PresharedKeyAt {
		t.Fatalf("a and b disagree: %+v %+v", ab, ba)
	}
	// c sets no preshared keys: none for it, and none for its peers' tunnels with it.
	if e := peerIn(t, nmA, c); e.PresharedKey != "" || e.PresharedKeyNext != "" {
		t.Fatalf("a key for a device that sets none: %+v", e)
	}
	if e := peerIn(t, get(cc), a); e.PresharedKey != "" || e.PresharedKeyNext != "" {
		t.Fatalf("a device that sets none got a key: %+v", e)
	}

	// The first batch ever runs at once (none before it): it leaves a pair with a change under way.
	if n, err := st.RotatePairKeys(ctx, time.Now(), 24*time.Hour, pairKeyLead, newKey); err != nil || n != 0 {
		t.Fatalf("first batch: %d, %v", n, err)
	}
	// Its time passed: in use, in both maps alike.
	later := time.Now().Add(pairKeyLead + time.Second)
	if _, err := st.RotatePairKeys(ctx, later, 24*time.Hour, pairKeyLead, newKey); err != nil {
		t.Fatal(err)
	}
	ab, ba = peerIn(t, get(ca), b), peerIn(t, get(cb), a)
	if ab.PresharedKey != ba.PresharedKey || ab.PresharedKey == "" || ab.PresharedKeyNext != "" {
		t.Fatalf("after its time: %+v %+v", ab, ba)
	}
	first := ab.PresharedKey
	// The next day's batch: a next key in both maps, the current one kept until then.
	v, _ := st.Version(ctx)
	if n, err := st.RotatePairKeys(ctx, later.Add(24*time.Hour), 24*time.Hour, pairKeyLead, newKey); err != nil || n != 1 {
		t.Fatalf("batch: %d, %v", n, err)
	}
	if nv, _ := st.Version(ctx); nv == v {
		t.Fatal("the batch did not change the maps")
	}
	ab = peerIn(t, get(ca), b)
	if ab.PresharedKey != first || ab.PresharedKeyNext == "" || ab.PresharedKeyNext == first {
		t.Fatalf("after the batch: %+v", ab)
	}
	// a's WireGuard key changes: its pairs' keys are replaced at once.
	if err := st.ReplacePairKeys(ctx, a.ID, newKey); err != nil {
		t.Fatal(err)
	}
	if ab2 := peerIn(t, get(ca), b); ab2.PresharedKey == first || ab2.PresharedKey == "" || ab2.PresharedKeyNext != "" {
		t.Fatalf("after a's key changed: %+v", ab2)
	}
}
