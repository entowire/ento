package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/store"
)

// Sign-in approvals: a laptop asks; the person's phone, bound to them by sign-in, sees three
// numbers and must pick the one the laptop shows. Wrong number or declined: denied. Single use,
// expiry, rate limits, and devices that may not approve.
func TestSignInApprovals(t *testing.T) {
	approvalPoll = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, st := startTestNetwork(t, ctx, "100.64.0.0/16")
	enrollApproved := func(name string) (*testClient, store.Peer) {
		tok, _, err := IssueToken(ctx, st, TokenOptions{Approve: true, Groups: []string{"staff"}, Name: name})
		if err != nil {
			t.Fatal(err)
		}
		srv.checkVersion(ctx)
		c, res := enroll(t, tok, name)
		p, _ := st.PeerByAddress(ctx, netip.MustParseAddr(res.Address))
		return c, p
	}
	bind := func(p store.Peer, sub, login string) { // as a sign-in leaves it (its person layer closed since)
		now, yes := time.Now(), true
		name, groups := login+"@example.com", []string{"staff"}
		if _, err := st.UpdatePeer(ctx, p.ID, store.PeerUpdate{User: &sub, UserLogin: &login, UserName: &name, LoginAt: &now,
			PersonApproved: &yes, PersonGroups: &groups}); err != nil {
			t.Fatal(err)
		}
	}
	report := func(c *testClient, agent string) {
		if code := c.do(t, "POST", api.PathPosture, api.Posture{Format: 1, OS: "android", OSVersion: "14", Agent: agent}, nil); code != 200 {
			t.Fatalf("posture report: HTTP %d", code)
		}
	}
	laptop, lp := enrollApproved("laptop-1")
	phone, pp := enrollApproved("phone-1")
	bind(lp, "sub-ana", "ana")
	bind(pp, "sub-ana", "ana")
	report(phone, "0.21.0")
	other, op := enrollApproved("phone-2")
	bind(op, "sub-bob", "bob")
	report(other, "0.21.0")

	ask := func(user, service string) (api.ApprovalResponse, int) {
		var res api.ApprovalResponse
		code := laptop.do(t, "POST", api.PathApprovals, api.ApprovalRequest{User: user, Service: service}, &res)
		return res, code
	}
	pending := func(c *testClient) []api.PendingApproval {
		var list []api.PendingApproval
		if code := c.do(t, "GET", api.PathApprovals, nil, &list); code != 200 {
			t.Fatalf("pending: HTTP %d", code)
		}
		return list
	}
	answer := func(c *testClient, id string, n int, approve bool) (string, int) {
		var st api.ApprovalStatus
		code := c.do(t, "POST", api.PathApprovals+"/"+id, api.ApprovalAnswer{Number: n, Approve: approve}, &st)
		return st.State, code
	}
	status := func(id string) string {
		var st api.ApprovalStatus
		if code := laptop.do(t, "GET", api.PathApprovals+"/"+id+"?wait=1", nil, &st); code != 200 {
			t.Fatalf("status: HTTP %d", code)
		}
		return st.State
	}

	if _, code := ask("nobody", "sudo"); code != http.StatusNotFound {
		t.Fatalf("an unknown person: HTTP %d", code)
	}
	if _, code := ask("ana", "sudo; rm"); code != http.StatusBadRequest {
		t.Fatalf("a bad service: HTTP %d", code)
	}

	// A wrong number denies.
	a, code := ask("ana", "gdm-password")
	if code != http.StatusCreated || a.Number < 10 || a.Number > 99 {
		t.Fatalf("ask: HTTP %d %+v", code, a)
	}
	list := pending(phone)
	if len(list) != 1 || list[0].Device != "laptop-1" || list[0].User != "ana" || list[0].Service != "gdm-password" ||
		len(list[0].Choices) != 3 || !slices.Contains(list[0].Choices, a.Number) {
		t.Fatalf("the phone sees %+v (number %d)", list, a.Number)
	}
	if len(pending(other)) != 0 || len(pending(laptop)) != 0 {
		t.Fatal("another person's phone, or the asking device itself, sees the approval")
	}
	if _, code := answer(other, a.ID, a.Number, true); code != http.StatusNotFound {
		t.Fatalf("another person answers: HTTP %d", code)
	}
	wrong := list[0].Choices[0]
	if wrong == a.Number {
		wrong = list[0].Choices[1]
	}
	if state, code := answer(phone, a.ID, wrong, true); code != 200 || state != "denied" || status(a.ID) != "denied" {
		t.Fatalf("a wrong number: HTTP %d %s", code, state)
	}

	// The right number approves, once.
	a, _ = ask("ANA", "sudo") // the username in any case
	if state, code := answer(phone, a.ID, a.Number, true); code != 200 || state != "approved" || status(a.ID) != "approved" {
		t.Fatalf("the right number: HTTP %d %s", code, state)
	}
	if _, code := answer(phone, a.ID, a.Number, true); code != http.StatusGone {
		t.Fatalf("a second answer: HTTP %d", code)
	}
	// Declined, with the right number: denied.
	a, _ = ask("ana@example.com", "sudo") // the readable name works too
	if state, _ := answer(phone, a.ID, a.Number, false); state != "denied" {
		t.Fatalf("declined: %s", state)
	}

	// Waiting for an answer: the laptop's call returns when the phone answers.
	a, _ = ask("ana", "sudo")
	done := make(chan string, 1)
	go func() {
		var s api.ApprovalStatus
		laptop.do(t, "GET", api.PathApprovals+"/"+a.ID+"?wait=10", nil, &s)
		done <- s.State
	}()
	time.Sleep(100 * time.Millisecond)
	answer(phone, a.ID, a.Number, true)
	select {
	case s := <-done:
		if s != "approved" {
			t.Fatalf("waited for %s", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the waiting call did not return on the answer")
	}

	// An approved sign-in to the desktop reopens the laptop's closed person layer (its machine is
	// approved, its person's last full sign-in on it recent), for the boot it asked from; one to
	// anything else does not; after store.PersonReopen it takes a full sign-in.
	personOf := func() store.PersonLayer {
		p, _ := st.PeerByAddress(ctx, lp.Address)
		return p.Person
	}
	askDesktop := func(service string) {
		var res api.ApprovalResponse
		if code := laptop.do(t, "POST", api.PathApprovals, api.ApprovalRequest{User: "ana", Service: service, BootID: "boot-1"}, &res); code != http.StatusCreated {
			t.Fatalf("ask: HTTP %d", code)
		}
		if state, code := answer(phone, res.ID, res.Number, true); code != 200 || state != "approved" {
			t.Fatalf("approve: HTTP %d %s", code, state)
		}
	}
	askDesktop("sudo")
	if personOf().Active {
		t.Fatal("an approved sudo opened the person layer")
	}
	askDesktop("gdm-password")
	if pl := personOf(); !pl.Active || pl.Since.IsZero() {
		t.Fatalf("an approved desktop sign-in did not reopen the person layer: %+v", pl)
	}
	if p, _ := st.PeerByAddress(ctx, lp.Address); p.BootID != "boot-1" || !slices.Contains(p.Groups, "staff") {
		t.Fatalf("after reopening: boot %q, groups %v", p.BootID, p.Groups)
	}
	off, old := false, time.Now().Add(-store.PersonReopen-time.Hour)
	if _, err := st.UpdatePeer(ctx, lp.ID, store.PeerUpdate{PersonActive: &off, LoginAt: &old}); err != nil {
		t.Fatal(err)
	}
	askDesktop("gdm-password")
	if personOf().Active {
		t.Fatal("a desktop sign-in reopened the person layer a week after the last full sign-in")
	}
	recent := time.Now()
	if _, err := st.UpdatePeer(ctx, lp.ID, store.PeerUpdate{LoginAt: &recent}); err != nil {
		t.Fatal(err)
	}

	// Expired: neither answerable nor approved.
	past := time.Now().Add(-time.Minute)
	if err := st.CreateApproval(ctx, store.Approval{ID: "expired-approval-1", Requester: lp.ID, User: "sub-ana", Login: "ana",
		Service: "sudo", Number: 42, Choices: []int{42, 43, 44}, CreatedAt: past.Add(-time.Minute), ExpiresAt: past}); err != nil {
		t.Fatal(err)
	}
	if status("expired-approval-1") != "expired" {
		t.Fatal("an approval past its time is not expired")
	}
	if _, code := answer(phone, "expired-approval-1", 42, true); code != http.StatusGone {
		t.Fatalf("answering an expired approval: HTTP %d", code)
	}

	// A device that may not approve: suspended, not bound by sign-in, or an agent too old.
	yes := true
	if _, err := st.UpdatePeer(ctx, pp.ID, store.PeerUpdate{Suspended: &yes}); err != nil {
		t.Fatal(err)
	}
	if _, code := ask("ana", "sudo"); code != http.StatusNotFound {
		t.Fatalf("the only approver suspended: HTTP %d", code)
	}
	setAgent := func(p store.Peer, agent string) { // a later report, without the endpoint's minimum gap
		b, _ := json.Marshal(api.Posture{Format: 1, OS: "android", OSVersion: "14", Agent: agent})
		if err := st.SetPostureReport(ctx, p.ID, b, time.Now(), 0); err != nil {
			t.Fatal(err)
		}
	}
	setAgent(op, "0.20.1")
	if _, code := ask("bob", "sudo"); code != http.StatusNotFound {
		t.Fatalf("an approver with an older agent: HTTP %d", code)
	}

	// Rate limit per asking device.
	setAgent(op, "0.21.0")
	for i := 0; i < approvalsPerDev; i++ {
		_ = st.CreateApproval(ctx, store.Approval{ID: "flood-" + strings.Repeat("x", i+1), Requester: lp.ID, User: "sub-x",
			Login: "x", Service: "sudo", Number: 11, Choices: []int{11, 12, 13}, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)})
	}
	if _, code := ask("bob", "sudo"); code != http.StatusTooManyRequests {
		t.Fatalf("too many requests: HTTP %d", code)
	}
}
