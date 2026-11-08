package control

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/hwsig"
	"entowire.com/ento/internal/ipam"
	"entowire.com/ento/internal/store"
	"entowire.com/ento/internal/token"
)

// softHW stands for a TPM in tests.
type softHW struct{ k *ecdsa.PrivateKey }

func newSoftHW(t *testing.T) softHW {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return softHW{k}
}
func (s softHW) Kind() string                        { return hwsig.KindTPM }
func (s softHW) Public() *ecdsa.PublicKey            { return &s.k.PublicKey }
func (s softHW) SignDigest(d []byte) ([]byte, error) { return ecdsa.SignASN1(rand.Reader, s.k, d) }

// Hardware-bound identities: the first key binds, another is a copy; check-ins without its signature
// are refused, then suspended after hwGrace; with it, a token mismatch makes the original change its
// key instead of suspending it; key changes need its certificate; only admins release a binding.
func TestHWKeys(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	space, _ := ipam.New(netip.MustParsePrefix("100.64.0.0/16"))
	st := store.NewMemory(space)
	key, _ := wgtypes.GeneratePrivateKey()
	port := freeUDPPort(t)
	logs := &logLines{t: t}
	srv, err := Start(ctx, Config{Name: "c1", PrivateKey: key, ListenPort: port, Endpoint: fmt.Sprintf("127.0.0.1:%d", port),
		Space: space, Store: st, Logf: logs.logf})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	admin := adminOf(t, ctx, srv, st, "ops-laptop", "staff")
	tok, _, _ := IssueToken(ctx, st, TokenOptions{Approve: true, Groups: []string{"staff"}, Name: "laptop-1"})
	srv.checkVersion(ctx)
	laptop, res := enroll(t, tok, "laptop-1")
	lp, _ := st.PeerByAddress(ctx, netip.MustParseAddr(res.Address))
	sub, now := "sub-1", time.Now()
	if lp, err = st.UpdatePeer(ctx, lp.ID, store.PeerUpdate{User: &sub, LoginAt: &now}); err != nil { // a person's device
		t.Fatal(err)
	}
	tpm := newSoftHW(t)
	hwPub, _ := hwsig.EncodePublic(tpm.Public())

	bind := func(c *testClient, hw softHW) int {
		pub, _ := hwsig.EncodePublic(hw.Public())
		now := time.Now().Unix()
		sig, _ := hwsig.Sign(hw, hwsig.BindMessage(c.key.PublicKey().String(), pub, now))
		return c.do(t, "POST", api.PathHWKey, api.HWKeyRequest{Kind: hwsig.KindTPM, PublicKey: pub, Time: now, Signature: sig}, nil)
	}
	checkIn := func(c *testClient, tok string, hw *softHW) (api.CheckInResponse, int) {
		req := api.CheckInRequest{Token: tok, Fingerprint: fmt.Sprintf("fp%x", c.key.PublicKey().String()[:6])} // salted with the key, as agents do
		if hw != nil {
			req.HWTime = time.Now().Unix()
			req.HWSignature, _ = hwsig.Sign(*hw, hwsig.CheckInMessage(c.key.PublicKey().String(), tok, req.HWTime))
		}
		var res api.CheckInResponse
		code := c.do(t, "POST", api.PathCheckIn, req, &res)
		return res, code
	}
	rotate := func(c *testClient, hw softHW) (wgtypes.Key, int) {
		next, _ := wgtypes.GeneratePrivateKey()
		now := time.Now().Unix()
		sig, _ := hwsig.Sign(hw, hwsig.RotateMessage(c.key.PublicKey().String(), next.PublicKey().String(), now))
		return next, c.do(t, "POST", api.PathRotate, api.RotateRequest{PublicKey: next.PublicKey().String(), Time: now, Signature: sig}, nil)
	}
	suspended := func() bool {
		time.Sleep(1500 * time.Millisecond)
		q, _ := st.PeerByAddress(ctx, lp.Address)
		return q.Suspended
	}
	// The device again, with a WireGuard session for a new key (as the agent after changing it).
	reconnect := func(c *testClient, k wgtypes.Key) *testClient {
		c.dev.Close()
		return newTestClient(t, k, wgtypes.Key{}, lp.Address, token.Control{PublicKey: key.PublicKey(),
			Endpoint: fmt.Sprintf("127.0.0.1:%d", port), Address: c.ctl})
	}

	// Not bound yet: check-ins as before; a key change is refused.
	t1, code := checkIn(laptop, "", nil)
	if code != 200 || t1.Token == "" {
		t.Fatalf("check-in before binding: HTTP %d", code)
	}
	if _, code := rotate(laptop, tpm); code != http.StatusConflict {
		t.Fatalf("a key change without a binding: HTTP %d", code)
	}
	// A binding signed by another key than the one it names: refused.
	pub := hwPub
	stamp := time.Now().Unix()
	badSig, _ := hwsig.Sign(newSoftHW(t), hwsig.BindMessage(laptop.key.PublicKey().String(), pub, stamp))
	if code := laptop.do(t, "POST", api.PathHWKey, api.HWKeyRequest{Kind: hwsig.KindTPM, PublicKey: pub, Time: stamp, Signature: badSig}, nil); code != http.StatusBadRequest {
		t.Fatalf("a binding not signed by its key: HTTP %d", code)
	}
	if code := bind(laptop, tpm); code != http.StatusCreated || logs.count("action=hwkey_bound") != 1 {
		t.Fatalf("bind: HTTP %d", code)
	}
	if code := bind(laptop, tpm); code != http.StatusOK || logs.count("action=hwkey_bound") != 1 {
		t.Fatalf("bind again: HTTP %d", code)
	}
	// A copy with a TPM of its own: refused, and the device is to change its key.
	if code := bind(laptop, newSoftHW(t)); code != http.StatusConflict || logs.count("action=hwkey_conflict") != 1 {
		t.Fatalf("another hardware key: HTTP %d", code)
	}
	t2, code := checkIn(laptop, t1.Token, &tpm)
	if code != 200 || !t2.RotateKey {
		t.Fatalf("signed check-in after a conflict: HTTP %d, rotate %v", code, t2.RotateKey)
	}

	// The device changes its key, certified by its hardware key; a certificate from another key is
	// refused.
	if _, code := rotate(laptop, newSoftHW(t)); code != http.StatusForbidden {
		t.Fatalf("a key change certified by another key: HTTP %d", code)
	}
	next, code := rotate(laptop, tpm)
	if code != 200 {
		t.Fatalf("key change: HTTP %d", code)
	}
	// The control plane changes the key just after its answer.
	for i := 0; i < 50 && logs.countAll("action=key_rotated", "result=ok") == 0; i++ {
		time.Sleep(100 * time.Millisecond)
	}
	if logs.countAll("action=key_rotated", "result=ok") != 1 {
		t.Fatal("the key change is not audited")
	}
	if q, _ := st.PeerByAddress(ctx, lp.Address); q.PublicKey != next.PublicKey() || q.Hostname != lp.Hostname || !q.Approved {
		t.Fatalf("after the key change: %+v", q)
	}
	srv.checkVersion(ctx)
	laptop = reconnect(laptop, next)
	t3, code := checkIn(laptop, t2.Token, &tpm)
	if code != 200 || t3.RotateKey {
		t.Fatalf("signed check-in with the new key: HTTP %d, rotate %v", code, t3.RotateKey)
	}
	var peers []api.PeerInfo
	admin.do(t, "GET", api.PathPeers, nil, &peers)
	for _, p := range peers {
		if p.ID == lp.ID && (p.HardwareKey != hwsig.KindTPM || p.HardwareKeyAt == "" || p.KeyRotatedAt == "") {
			t.Fatalf("the peer list: %+v", p)
		}
	}

	// A copy without the TPM: refused, not suspended, the token chain untouched; the original's next
	// signed check-in (with its token) passes and is asked to change its key.
	if _, code := checkIn(laptop, t3.Token, nil); code != http.StatusConflict || suspended() ||
		logs.count("no hardware signature") != 1 {
		t.Fatalf("an unsigned check-in: HTTP %d", code)
	}
	t4, code := checkIn(laptop, t3.Token, &tpm)
	if code != 200 || !t4.RotateKey {
		t.Fatalf("the original after a copy's check-in: HTTP %d, rotate %v", code, t4.RotateKey)
	}
	// State restored from an older copy on the original machine (its TPM signs): a token already
	// replaced, but no suspension: the key changes.
	t5, code := checkIn(laptop, t2.Token, &tpm) // t3 is the previous token (a lost answer), t2 older
	if code != 200 || !t5.RotateKey || suspended() || logs.count("action=rotated") != 1 {
		t.Fatalf("a signed check-in with a replaced token: HTTP %d, rotate %v", code, t5.RotateKey)
	}
	// Unsigned for longer than hwGrace (the original gone, a copy left): suspended.
	if _, err := st.UpdateHWKey(ctx, lp.ID, func(k store.HWKey, _ bool) (store.HWKey, error) {
		k.UnsignedSince = time.Now().Add(-hwGrace - time.Minute)
		return k, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, code := checkIn(laptop, t5.Token, nil); code != http.StatusConflict || !suspended() {
		t.Fatalf("unsigned past the grace: HTTP %d", code)
	}

	// Only admins release a binding.
	opTok, _, _ := IssueToken(ctx, st, TokenOptions{Approve: true, Groups: []string{"staff"}})
	srv.checkVersion(ctx)
	op, opRes := enroll(t, opTok, "op-laptop")
	opPeer, _ := st.PeerByAddress(ctx, netip.MustParseAddr(opRes.Address))
	yes := true
	if _, err := st.UpdatePeer(ctx, opPeer.ID, store.PeerUpdate{Operator: &yes}); err != nil {
		t.Fatal(err)
	}
	signInRoles(t, st)
	srv.checkVersion(ctx)
	if code := op.do(t, "PATCH", fmt.Sprintf("%s/%d", api.PathPeers, lp.ID), api.UpdatePeerRequest{UnbindHardwareKey: true}, nil); code != http.StatusForbidden {
		t.Fatalf("an operator released the binding: HTTP %d", code)
	}
	if code := admin.do(t, "PATCH", fmt.Sprintf("%s/%d", api.PathPeers, lp.ID), api.UpdatePeerRequest{UnbindHardwareKey: true}, nil); code != 200 ||
		logs.count("action=hwkey_unbound") != 2 { // the operator's denied attempt and the admin's
		t.Fatalf("release: HTTP %d", code)
	}
	if keys, _ := st.HWKeys(ctx); len(keys) != 0 {
		t.Fatalf("still bound: %+v", keys)
	}
}
