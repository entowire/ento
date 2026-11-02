package control

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/ipam"
	"entowire.com/ento/internal/store"
	"entowire.com/ento/internal/token"
)

// Check-ins notice a copied identity: a token one copy already spent, or another machine's
// fingerprint. A device bound to a person is suspended (and starts over once resumed); a server is
// reported and keeps working. Lost answers and the first check-in are not suspicious.
func TestCheckIns(t *testing.T) {
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
	device := func(name string, person bool) (*testClient, store.Peer) {
		tok, _, _ := IssueToken(ctx, st, TokenOptions{Approve: true, Groups: []string{"staff"}, Name: name})
		srv.checkVersion(ctx)
		c, res := enroll(t, tok, name)
		p, _ := st.PeerByAddress(ctx, netip.MustParseAddr(res.Address))
		if person {
			sub, now := "sub-"+name, time.Now()
			if p, err = st.UpdatePeer(ctx, p.ID, store.PeerUpdate{User: &sub, LoginAt: &now}); err != nil {
				t.Fatal(err)
			}
		}
		return c, p
	}
	checkIn := func(c *testClient, tok, fp string) (string, int) {
		var res api.CheckInResponse
		code := c.do(t, "POST", api.PathCheckIn, api.CheckInRequest{Token: tok, Fingerprint: fp}, &res)
		return res.Token, code
	}
	suspended := func(p store.Peer) bool { // the suspension follows the answer within a second or two
		for i := 0; i < 40; i++ {
			if q, _ := st.PeerByAddress(ctx, p.Address); q.Suspended {
				return true
			}
			time.Sleep(100 * time.Millisecond)
		}
		return false
	}
	notSuspended := func(p store.Peer) bool {
		time.Sleep(1500 * time.Millisecond)
		q, _ := st.PeerByAddress(ctx, p.Address)
		return !q.Suspended
	}

	laptop, lp := device("laptop-1", true)
	t1, code := checkIn(laptop, "", "fp-a")
	if code != 200 || t1 == "" {
		t.Fatalf("first check-in: HTTP %d", code)
	}
	t2, _ := checkIn(laptop, t1, "fp-a")
	// The answer carrying t3 is lost: t2 again is no copy, and gets a fresh token.
	if _, code := checkIn(laptop, t2, "fp-a"); code != 200 {
		t.Fatalf("a check-in after a lost answer: HTTP %d", code)
	}
	t4, code := checkIn(laptop, t2, "fp-a")
	if code != 200 || logs.count("device_clone_suspected") != 0 {
		t.Fatalf("lost answers counted as a copy: HTTP %d", code)
	}
	// Two copies hold t4: A spends it (t5), B presents it again (t6, voiding t5), A presents t5.
	t5, _ := checkIn(laptop, t4, "fp-a")
	if _, code := checkIn(laptop, t4, "fp-a"); code != 200 {
		t.Fatalf("copy B: HTTP %d", code)
	}
	if _, code := checkIn(laptop, t5, "fp-a"); code != http.StatusConflict || !suspended(lp) ||
		logs.count("action=device_clone_suspected") != 1 || logs.count("action=suspended") != 1 {
		t.Fatalf("copy A with a voided token: HTTP %d, suspended %v", code, suspended(lp))
	}
	var peers []api.PeerInfo
	admin.do(t, "GET", api.PathPeers, nil, &peers)
	for _, p := range peers {
		if p.ID == lp.ID && (p.CloneSuspected == "" || p.CheckedInAt == "" || !p.Suspended) {
			t.Fatalf("the peer list: %+v", p)
		}
	}
	// Resumed: its check-ins start over (any token, the current machine's fingerprint).
	no := false
	if code := admin.do(t, "PATCH", fmt.Sprintf("%s/%d", api.PathPeers, lp.ID), api.UpdatePeerRequest{Suspended: &no}, nil); code != 200 {
		t.Fatalf("resume: HTTP %d", code)
	}
	srv.checkVersion(ctx)
	// A new WireGuard session, as the agent makes one (the control node dropped the old one).
	laptop.dev.Close()
	laptop = newTestClient(t, laptop.key, wgtypes.Key{}, lp.Address, token.Control{PublicKey: key.PublicKey(),
		Endpoint: fmt.Sprintf("127.0.0.1:%d", port), Address: laptop.ctl})
	if _, code := checkIn(laptop, "whatever-it-had", "fp-b"); code != 200 || !notSuspended(lp) {
		t.Fatalf("the first check-in after resuming: HTTP %d", code)
	}

	// Another machine (fingerprint) for a person's device: suspended.
	phone, pp := device("phone-1", true)
	f1, _ := checkIn(phone, "", "fp-phone")
	if _, code := checkIn(phone, f1, "fp-other"); code != http.StatusConflict || !suspended(pp) {
		t.Fatalf("another fingerprint: HTTP %d", code)
	}
	// The answer to the very first check-in lost (a phone's app restarted its agent at once): no token
	// again, from the same machine, is no copy and gets a fresh token; a copy holding the replaced
	// one is caught at its next check-in.
	pad, padp := device("pad-1", true)
	lost, _ := checkIn(pad, "", "fp-pad")
	p1, code := checkIn(pad, "", "fp-pad")
	if code != 200 || p1 == "" || !notSuspended(padp) {
		t.Fatalf("a check-in after the first answer was lost: HTTP %d", code)
	}
	if _, code := checkIn(pad, lost, "fp-pad"); code != http.StatusConflict || !suspended(padp) {
		t.Fatalf("a copy holding the replaced first token: HTTP %d", code)
	}
	// No token although it checked in before (twice: its first answer arrived): state older than its
	// last check-in.
	tablet, tp := device("tablet-1", true)
	c1, _ := checkIn(tablet, "", "fp-t")
	checkIn(tablet, c1, "fp-t")
	if _, code := checkIn(tablet, "", "fp-t"); code != http.StatusConflict || !suspended(tp) {
		t.Fatalf("no token: HTTP %d", code)
	}

	// A server (bound to nobody): reported, once an hour, and it keeps working; the machine that
	// checked in becomes the one expected.
	server, sp := device("server-1", false)
	s1, _ := checkIn(server, "", "fp-s")
	s2, _ := checkIn(server, s1, "fp-s")
	s3, _ := checkIn(server, s1, "fp-s") // copy B with s1 (prev): fresh token, s2 voided
	before := logs.count("action=reported")
	s4, code := checkIn(server, s2, "fp-s")
	if code != 200 || s4 == "" || !notSuspended(sp) || logs.count("action=reported") != before+1 {
		t.Fatalf("a server's copy: HTTP %d", code)
	}
	if _, code := checkIn(server, s3, "fp-rebuilt"); code != 200 || logs.count("action=reported") != before+1 {
		t.Fatalf("a second suspicion within the hour: HTTP %d, %d lines", code, logs.count("action=reported"))
	}
}
