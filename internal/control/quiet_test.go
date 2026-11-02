package control

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/store"
	"entowire.com/ento/internal/token"
)

// enrollAs enrolls like enroll, reporting the system os.
func enrollAs(t *testing.T, tokStr, hostname, os string) (*testClient, api.RedeemResponse) {
	t.Helper()
	tok, err := token.Parse(tokStr)
	if err != nil {
		t.Fatal(err)
	}
	creds, _ := token.Derive(tok.Secret)
	temp := newTestClient(t, creds.PrivateKey, creds.PresharedKey, tok.TempAddress, tok.Controls[0])
	perm, _ := wgtypes.GeneratePrivateKey()
	var res api.RedeemResponse
	if code := temp.do(t, "POST", api.PathRedeem, api.RedeemRequest{PublicKey: perm.PublicKey().String(), Hostname: hostname, OS: os}, &res); code != 200 {
		t.Fatalf("redeem: HTTP %d", code)
	}
	temp.dev.Close()
	return newTestClient(t, perm, wgtypes.Key{}, netip.MustParseAddr(res.Address), tok.Controls[0]), res
}

// Phones are quiet (0.34): their peers' maps say so (no keepalives to them), and the control node
// sends them none itself; other devices are as before.
func TestQuietPeers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, st := startTestNetwork(t, ctx, "100.64.0.0/16")
	if _, err := st.AddPolicy(ctx, store.Policy{Source: "staff", Destination: "staff"}); err != nil {
		t.Fatal(err)
	}
	enrollWith := func(name, os string) *testClient {
		tok, _, err := IssueToken(ctx, st, TokenOptions{Approve: true, Groups: []string{"staff"}, Name: name})
		if err != nil {
			t.Fatal(err)
		}
		srv.checkVersion(ctx)
		c, _ := enrollAs(t, tok, name, os)
		return c
	}
	laptop := enrollWith("laptop-1", "linux")
	enrollWith("phone-1", "android")
	srv.checkVersion(ctx)
	var nm api.NetMap
	if code := laptop.do(t, "GET", api.PathNetMap, nil, &nm); code != 200 {
		t.Fatalf("netmap: HTTP %d", code)
	}
	quiet := map[string]bool{}
	for _, p := range nm.Peers {
		quiet[p.Hostname] = p.Quiet
	}
	if q, ok := quiet["phone-1"]; !ok || !q {
		t.Fatalf("the phone is not quiet in the laptop's map: %+v", nm.Peers)
	}
	// The control node's own keepalives: none towards the phone, every 25 s towards the laptop.
	phoneKey, laptopKey := mustKey(t), mustKey(t)
	if err := srv.wg.Sync(map[wgtypes.Key]wgPeer{
		phoneKey:  {AllowedIP: netip.MustParseAddr("100.64.9.1"), Endpoint: "192.0.2.1:51820", Quiet: true},
		laptopKey: {AllowedIP: netip.MustParseAddr("100.64.9.2"), Endpoint: "192.0.2.2:51820"},
	}); err != nil {
		t.Fatal(err)
	}
	cfg, err := srv.wg.dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	keepalive := map[string]string{}
	for _, block := range strings.Split(cfg, "public_key=")[1:] {
		k, _, _ := strings.Cut(block, "\n")
		for _, line := range strings.Split(block, "\n") {
			if v, ok := strings.CutPrefix(line, "persistent_keepalive_interval="); ok {
				keepalive[k] = v
			}
		}
	}
	if got := keepalive[hexKey(phoneKey)]; got != "0" {
		t.Errorf("keepalive towards the phone = %q, want 0", got)
	}
	if got := keepalive[hexKey(laptopKey)]; got != "25" {
		t.Errorf("keepalive towards the laptop = %q, want 25", got)
	}
}

func mustKey(t *testing.T) wgtypes.Key {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey()
}

// A quiet device's map comes early when the approvals waiting for its person change (0.34), with
// their number, so the phone keeps no approvals poll of its own.
func TestApprovalsInMap(t *testing.T) {
	approvalPoll = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, st := startTestNetwork(t, ctx, "100.64.0.0/16")
	enrollApproved := func(name, os string) (*testClient, store.Peer) {
		tok, _, err := IssueToken(ctx, st, TokenOptions{Approve: true, Groups: []string{"staff"}, Name: name})
		if err != nil {
			t.Fatal(err)
		}
		srv.checkVersion(ctx)
		c, res := enrollAs(t, tok, name, os)
		p, _ := st.PeerByAddress(ctx, netip.MustParseAddr(res.Address))
		return c, p
	}
	laptop, lp := enrollApproved("laptop-1", "linux")
	phone, pp := enrollApproved("phone-1", "android")
	for _, p := range []store.Peer{lp, pp} {
		now, yes, sub, login, name, groups := time.Now(), true, "sub-ana", "ana", "ana@example.com", []string{"staff"}
		if _, err := st.UpdatePeer(ctx, p.ID, store.PeerUpdate{User: &sub, UserLogin: &login, UserName: &name, LoginAt: &now,
			PersonApproved: &yes, PersonGroups: &groups}); err != nil {
			t.Fatal(err)
		}
	}
	if code := phone.do(t, "POST", api.PathPosture, api.Posture{Format: 1, OS: "android", OSVersion: "14", Agent: "0.34.0"}, nil); code != 200 {
		t.Fatalf("posture: HTTP %d", code)
	}
	srv.checkVersion(ctx)
	var first api.NetMap
	if code := phone.do(t, "GET", api.PathNetMap, nil, &first); code != 200 {
		t.Fatalf("netmap: HTTP %d", code)
	}
	if first.Approvals {
		t.Fatal("approvals reported to a device that did not ask for them")
	}
	// Waiting with nothing pending: the map comes when an approval is asked for, not at the timeout.
	type answer struct {
		nm   api.NetMap
		code int
		took time.Duration
	}
	poll := func(known int) chan answer {
		ch := make(chan answer, 1)
		go func() {
			var nm api.NetMap
			start := time.Now()
			code := phone.do(t, "GET", fmt.Sprintf("%s?since=%d&approvals=%d", api.PathNetMap, first.Version, known), nil, &nm)
			ch <- answer{nm, code, time.Since(start)}
		}()
		return ch
	}
	waiting := poll(0)
	time.Sleep(300 * time.Millisecond)
	var res api.ApprovalResponse
	if code := laptop.do(t, "POST", api.PathApprovals, api.ApprovalRequest{User: "ana", Service: "sudo"}, &res); code != http.StatusCreated && code != 200 {
		t.Fatalf("ask: HTTP %d", code)
	}
	select {
	case a := <-waiting:
		if a.code != 200 || !a.nm.Approvals || a.nm.Self.PendingApprovals != 1 || a.took > 10*time.Second {
			t.Fatalf("map after an approval was asked: HTTP %d, approvals %v, pending %d, after %s", a.code, a.nm.Approvals, a.nm.Self.PendingApprovals, a.took)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the map did not come when an approval was asked")
	}
	// Knowing of it, the device waits again; the map comes when it is answered (here: denied).
	waiting = poll(1)
	time.Sleep(300 * time.Millisecond)
	var st2 api.ApprovalStatus
	if code := phone.do(t, "POST", api.PathApprovals+"/"+res.ID, api.ApprovalAnswer{Number: 0, Approve: false}, &st2); code != 200 {
		t.Fatalf("answer: HTTP %d", code)
	}
	select {
	case a := <-waiting:
		if a.code != 200 || a.nm.Self.PendingApprovals != 0 || a.took > 10*time.Second {
			t.Fatalf("map after the answer: HTTP %d, pending %d, after %s", a.code, a.nm.Self.PendingApprovals, a.took)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the map did not come when the approval was answered")
	}
}
