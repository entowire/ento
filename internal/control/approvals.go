package control

// Sign-in approvals: a device asks that a person approve a sign-in on it (a PAM service: the login
// screen, sudo) from another of their devices, e.g. their phone. The asking device shows a number;
// the approving device offers three and the person picks that one (number matching: a request they
// did not start has no number in front of them). Both calls are signed with the devices' keys.
// Approving devices are the person's own, bound to them by single sign-on (so a leaver loses them
// when the SSO refresh withdraws access), approved, not suspended and passing the posture checks
// their policies require. An approval is good for one answer, for at most two minutes. It does not
// decide who may sign in: the asking system still does, after this step.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/store"
)

const (
	approvalDefault  = 60 * time.Second
	approvalMax      = 120 * time.Second
	approvalWindow   = 10 * time.Minute
	approvalsPerDev  = 10 // asked by one device per window
	approvalsPerUser = 20 // asked for one person per window
	approvingAgents  = "0.21.0"
)

// approvalPoll is how often a waiting call looks at the store (another control node may hold the
// other side).
var approvalPoll = time.Second

func validLogin(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._@+-", r)) {
			return false
		}
	}
	return true
}

func validService(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-", r)) {
			return false
		}
	}
	return true
}

// approvers returns the devices of a person that may approve their sign-ins, but the asking one.
func (s *Server) approvers(ctx context.Context, user string, except int64) ([]store.Peer, error) {
	peers, err := s.cfg.Store.Peers(ctx)
	if err != nil {
		return nil, err
	}
	policies, err := s.cfg.Store.Policies(ctx)
	if err != nil {
		return nil, err
	}
	ps, err := loadPosture(ctx, s.cfg.Store, time.Now())
	if err != nil {
		return nil, err
	}
	var out []store.Peer
	for _, p := range peers {
		if s.mayApprove(p, user, policies, ps) && p.ID != except {
			out = append(out, p)
		}
	}
	return out, nil
}

func (s *Server) mayApprove(p store.Peer, user string, policies []store.Policy, ps *postureState) bool {
	// The person's own device, bound by a full sign-in and still theirs (the identity provider keeps
	// their rights current): its person layer need not be open, so a phone that sat idle overnight
	// approves the morning's sign-in on the laptop.
	if user == "" || p.User != user || p.LoginAt.IsZero() || !p.Person.Approved || p.Suspended || p.Authority != "" {
		return false
	}
	if len(failingChecks(p, policies, ps)) > 0 {
		return false
	}
	f := ps.facts[p.ID]
	if f == nil {
		return false
	}
	c, ok := compareVersions(f.Agent, approvingAgents)
	return ok && c >= 0
}

// approvalUser finds the person an account name belongs to: the user of devices bound by single
// sign-on whose username (or readable name) it is. "" when nobody, or more than one person.
func approvalUser(peers []store.Peer, login string) (user string, ambiguous bool) {
	for _, p := range peers {
		if p.User == "" || p.LoginAt.IsZero() || p.Authority != "" {
			continue
		}
		if !strings.EqualFold(p.UserLogin, login) && !strings.EqualFold(p.UserName, login) {
			continue
		}
		if user != "" && user != p.User {
			return "", true
		}
		user = p.User
	}
	return user, false
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// approvalNumbers draws the number to show (10 to 99) and two others, in random order.
func approvalNumbers() (int, []int, error) {
	draw := func() (int, error) {
		n, err := rand.Int(rand.Reader, big.NewInt(90))
		return int(n.Int64()) + 10, err
	}
	number, err := draw()
	if err != nil {
		return 0, nil, err
	}
	choices := []int{number}
	for len(choices) < 3 {
		n, err := draw()
		if err != nil {
			return 0, nil, err
		}
		dup := false
		for _, c := range choices {
			dup = dup || c == n
		}
		if !dup {
			choices = append(choices, n)
		}
	}
	for i := len(choices) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return 0, nil, err
		}
		choices[i], choices[j.Int64()] = choices[j.Int64()], choices[i]
	}
	return number, choices, nil
}

func (s *Server) handleRequestApproval(w http.ResponseWriter, r *http.Request, self store.Peer) {
	var req api.ApprovalRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	if !validLogin(req.User) || !validService(req.Service) {
		writeErr(w, http.StatusBadRequest, "user: letters, digits and ._@+- (at most 128); service: letters, digits and ._- (at most 64)")
		return
	}
	// The machine's approval suffices (0.27): the login screen asks before any person layer is open.
	if !self.Approved || self.Suspended {
		writeErr(w, http.StatusForbidden, "this device is not approved")
		return
	}
	if !validCheckInValue(req.BootID, 64) {
		writeErr(w, http.StatusBadRequest, "invalid boot ID")
		return
	}
	timeout := approvalDefault
	if req.TimeoutSeconds > 0 {
		timeout = min(max(time.Duration(req.TimeoutSeconds)*time.Second, 10*time.Second), approvalMax)
	}
	ctx := r.Context()
	peers, err := s.cfg.Store.Peers(ctx)
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	user, ambiguous := approvalUser(peers, req.User)
	target := fmt.Sprintf("user=%s service=%s device=%s", req.User, req.Service, self.Hostname)
	switch {
	case ambiguous:
		s.audit(r, &self, "signin_approval_requested", target+" (the name belongs to more than one person)", "denied")
		writeErr(w, http.StatusConflict, "that name belongs to more than one person")
		return
	case user == "":
		writeErr(w, http.StatusNotFound, "nobody of that name has signed in on a device of this network")
		return
	}
	now := time.Now()
	byDev, byUser, err := s.cfg.Store.CountApprovals(ctx, self.ID, user, now.Add(-approvalWindow))
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	if byDev >= approvalsPerDev || byUser >= approvalsPerUser {
		s.audit(r, &self, "signin_approval_requested", target+" (too many requests)", "denied")
		writeErr(w, http.StatusTooManyRequests, "too many sign-in approvals asked: try again in a few minutes")
		return
	}
	approvers, err := s.approvers(ctx, user, self.ID)
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	if len(approvers) == 0 {
		writeErr(w, http.StatusNotFound, fmt.Sprintf("no device of %s can approve (signed in, approved, passing its checks, ento %s or later)", req.User, approvingAgents))
		return
	}
	id, err := randomID()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	number, choices, err := approvalNumbers()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	a := store.Approval{ID: id, Requester: self.ID, User: user, Login: req.User, Service: req.Service, Number: number,
		Choices: choices, CreatedAt: now, ExpiresAt: now.Add(timeout), BootID: req.BootID}
	if err := s.cfg.Store.CreateApproval(ctx, a); err != nil {
		s.respondStoreErr(w, err)
		return
	}
	s.audit(r, &self, "signin_approval_requested", fmt.Sprintf("%s id=%s approvers=%d", target, id[:8], len(approvers)), "ok")
	writeJSON(w, http.StatusCreated, api.ApprovalResponse{ID: id, Number: number, ExpiresAt: a.ExpiresAt.UTC().Format(time.RFC3339)})
}

// waitParam is how long a call may wait for a change (?wait=SECONDS, at most the long-poll timeout).
func waitParam(r *http.Request) time.Duration {
	n, err := strconv.Atoi(r.URL.Query().Get("wait"))
	if err != nil || n <= 0 {
		return 0
	}
	return min(time.Duration(n)*time.Second, longPollTimeout)
}

// finishExpired ends an approval whose time ran out, once (whichever control node sees it first).
func (s *Server) finishExpired(ctx context.Context, a store.Approval, now time.Time) store.Approval {
	if a.State != store.ApprovalPending || now.Before(a.ExpiresAt) {
		return a
	}
	done, err := s.cfg.Store.FinishApproval(ctx, a.ID, store.ApprovalExpired, 0, now)
	if err != nil {
		if b, err := s.cfg.Store.Approval(ctx, a.ID); err == nil {
			return b
		}
		return a
	}
	s.audit(nil, nil, "signin_approval_expired", fmt.Sprintf("user=%s service=%s device=%s id=%s", done.Login, done.Service,
		s.peerName(ctx, done.Requester), done.ID[:8]), "ok")
	return done
}

func (s *Server) peerName(ctx context.Context, id int64) string {
	if peers, err := s.cfg.Store.Peers(ctx); err == nil {
		for _, p := range peers {
			if p.ID == id {
				return p.Hostname
			}
		}
	}
	return fmt.Sprintf("peer-%d", id)
}

// handleApprovalStatus answers the asking device: the state of its approval, waiting for an answer
// with ?wait=.
func (s *Server) handleApprovalStatus(w http.ResponseWriter, r *http.Request, self store.Peer) {
	ctx := r.Context()
	deadline := time.Now().Add(waitParam(r))
	for {
		a, err := s.cfg.Store.Approval(ctx, r.PathValue("id"))
		if errors.Is(err, store.ErrNotFound) || err == nil && a.Requester != self.ID {
			writeErr(w, http.StatusNotFound, "no such approval")
			return
		}
		if err != nil {
			s.respondStoreErr(w, err)
			return
		}
		now := time.Now()
		a = s.finishExpired(ctx, a, now)
		if a.State != store.ApprovalPending || !now.Before(deadline) {
			writeJSON(w, http.StatusOK, api.ApprovalStatus{ID: a.ID, State: a.State})
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(approvalPoll):
		}
	}
}

// handlePendingApprovals answers an approving device: the approvals waiting for its person, waiting
// for one with ?wait=. Devices that may not approve get none.
func (s *Server) handlePendingApprovals(w http.ResponseWriter, r *http.Request, self store.Peer) {
	ctx := r.Context()
	deadline := time.Now().Add(waitParam(r))
	for {
		now := time.Now()
		out, err := s.pendingFor(ctx, self, now)
		if err != nil {
			s.respondStoreErr(w, err)
			return
		}
		if len(out) > 0 || !now.Before(deadline) {
			writeJSON(w, http.StatusOK, out)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * approvalPoll):
		}
	}
}

// pendingFor returns the approvals waiting for the person of the device to answer on it (none
// when the device may not approve). The store is asked the cheap question first: is anything
// pending at all.
func (s *Server) pendingFor(ctx context.Context, self store.Peer, now time.Time) ([]api.PendingApproval, error) {
	out := []api.PendingApproval{}
	if self.User == "" {
		return out, nil
	}
	any, err := s.cfg.Store.AnyPendingApproval(ctx, now)
	if err != nil || !any {
		return out, err
	}
	pending, err := s.cfg.Store.PendingApprovals(ctx, self.User, now)
	if err != nil || len(pending) == 0 {
		return out, err
	}
	ok, err := s.selfMayApprove(ctx, self)
	if err != nil || !ok {
		return out, err
	}
	for _, a := range pending {
		if a.Requester != self.ID {
			out = append(out, api.PendingApproval{ID: a.ID, Device: s.peerName(ctx, a.Requester), User: a.Login,
				Service: a.Service, Choices: a.Choices, ExpiresAt: a.ExpiresAt.UTC().Format(time.RFC3339)})
		}
	}
	return out, nil
}

// selfMayApprove reads the device again (its state may have changed since the call began).
func (s *Server) selfMayApprove(ctx context.Context, self store.Peer) (bool, error) {
	p, err := s.cfg.Store.PeerByAddress(ctx, self.Address)
	if err != nil || p.ID != self.ID {
		return false, err
	}
	policies, err := s.cfg.Store.Policies(ctx)
	if err != nil {
		return false, err
	}
	ps, err := loadPosture(ctx, s.cfg.Store, time.Now())
	if err != nil {
		return false, err
	}
	return s.mayApprove(p, p.User, policies, ps), nil
}

// handleAnswerApproval takes an approving device's answer: approved when it picked the number the
// asking device shows and approves, denied otherwise.
func (s *Server) handleAnswerApproval(w http.ResponseWriter, r *http.Request, self store.Peer) {
	var ans api.ApprovalAnswer
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&ans); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	ctx := r.Context()
	a, err := s.cfg.Store.Approval(ctx, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) || err == nil && (a.User != self.User || a.Requester == self.ID) {
		writeErr(w, http.StatusNotFound, "no such approval")
		return
	}
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	ok, err := s.selfMayApprove(ctx, self)
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	target := fmt.Sprintf("user=%s service=%s device=%s by=%s id=%s", a.Login, a.Service, s.peerName(ctx, a.Requester), self.Hostname, a.ID[:8])
	if !ok {
		s.audit(r, &self, "signin_approved", target+" (this device may not approve)", "denied")
		writeErr(w, http.StatusForbidden, "this device may not approve sign-ins (signed in, approved, passing its checks)")
		return
	}
	now := time.Now()
	if a = s.finishExpired(ctx, a, now); a.State != store.ApprovalPending {
		writeErr(w, http.StatusGone, "this approval has ended ("+a.State+")")
		return
	}
	state, action, why := store.ApprovalDenied, "signin_denied", "declined"
	switch {
	case ans.Approve && ans.Number == a.Number:
		state, action, why = store.ApprovalApproved, "signin_approved", ""
	case ans.Approve:
		why = "wrong number"
	}
	done, err := s.cfg.Store.FinishApproval(ctx, a.ID, state, self.ID, now)
	if errors.Is(err, store.ErrChanged) {
		writeErr(w, http.StatusGone, "this approval has ended")
		return
	}
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	if why != "" {
		target += " (" + why + ")"
	}
	s.audit(r, &self, action, target, "ok")
	s.reopenOnApproval(ctx, done)
	writeJSON(w, http.StatusOK, api.ApprovalStatus{ID: done.ID, State: done.State})
}
