package control

// The person layer of a device (0.27). A device's access has two layers: the machine's, which its
// enrollment token or an administrator gives it and which no session touches (a laptop in group
// laptops stays connected, its SIEM agent keeps sending, with nobody signed in), and the person's,
// which a single sign-on adds with the rights of the person's groups. The person layer:
//
//   - opens at a sign-in (ento agent login), and again, without one, when the device's person
//     approves a sign-in on it (a login screen: Config.ReopenServices) from another of their devices,
//     within store.PersonReopen of their last full sign-in on it;
//   - ends when nothing of theirs crossed the tunnel for Config.SessionIdle (the device counts its
//     traffic that the machine layer alone would not send and reports it in its check-ins; the
//     control plane adds the person's own administration), when they sign out (ento agent logout),
//     when the device starts again (a new boot ID), when the identity provider withdraws them, and,
//     only if one is configured, after Config.SessionMax. A running session is never cut for its
//     age by default.
//
// Its rights are kept current by the identity provider while the device is bound to the person,
// open or not (ssotoken.go), so a reopened layer has the person's groups of now.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/store"
)

// DefaultReopenServices are the sign-ins (PAM services) whose approval reopens a device's person
// layer: logging in to the desktop.
var DefaultReopenServices = []string{"gdm-password"}

// personActivityEvery limits how often the control plane records a person's administration as
// activity (a write per call would be wasted: the idle time is hours).
const personActivityEvery = time.Minute

// endPersonSessions closes the person layers that have been idle too long (or, with a maximum,
// are too old).
func (s *Server) endPersonSessions(ctx context.Context) bool {
	if s.cfg.SessionIdle <= 0 && s.cfg.SessionMax <= 0 {
		return false
	}
	now := time.Now()
	ended, err := s.cfg.Store.EndIdleSessions(ctx, now, s.cfg.SessionIdle, s.cfg.SessionMax)
	if err != nil {
		s.cfg.Logf("end idle sessions: %v", err)
		return false
	}
	for _, p := range ended {
		reason := "idle"
		if s.cfg.SessionMax > 0 && now.Sub(p.Person.Since) > s.cfg.SessionMax {
			reason = "too old"
		}
		s.personEnded(ctx, p, reason)
	}
	return len(ended) > 0
}

// personEnded records that a device's person layer ended (p as it was) and ends what came with it.
func (s *Server) personEnded(ctx context.Context, p store.Peer, reason string) {
	s.audit(nil, nil, "session_ended", fmt.Sprintf("%s reason=%s", userLabel(p), reason), "ok")
	if after, err := s.peerByID(ctx, p.ID); err == nil {
		s.endUISessionsIfLess(ctx, p, after)
	}
}

// closePerson closes a device's person layer, if it is still the one opened at since (zero: any).
// It reports whether it closed it.
func (s *Server) closePerson(ctx context.Context, p store.Peer, since time.Time, reason string) bool {
	if !p.Person.Active || !since.IsZero() && !since.Equal(p.Person.Since) {
		return false
	}
	off := false
	cur := p.Person.Since
	if _, err := s.cfg.Store.UpdatePeer(ctx, p.ID, store.PeerUpdate{PersonActive: &off, IfPersonSince: &cur}); err != nil {
		if !errors.Is(err, store.ErrChanged) {
			s.cfg.Logf("close the person layer of peer %d: %v", p.ID, err)
		}
		return false
	}
	s.personEnded(ctx, p, reason)
	s.checkVersion(ctx)
	return true
}

// handleLogout: the device's person signed out (ento agent logout). Idempotent: nothing open,
// another session open since, or no person at all answer as well.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, self store.Peer) {
	var req api.LogoutRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	var since time.Time
	if req.PersonSince != "" {
		t, err := time.Parse(time.RFC3339Nano, req.PersonSince)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "person_since: RFC 3339")
			return
		}
		since = t
	}
	s.closePerson(r.Context(), self, since, "logout")
	w.WriteHeader(http.StatusNoContent)
}

// personCheckIn applies what a check-in says about the person layer: a new boot closes it; the
// person's last traffic keeps it open.
func (s *Server) personCheckIn(ctx context.Context, p store.Peer, req api.CheckInRequest) {
	if p.User == "" || p.Authority != "" {
		if req.BootID != "" && req.BootID != p.BootID {
			_ = s.cfg.Store.RecordPersonActivity(ctx, p.ID, time.Time{}, false, req.BootID)
		}
		return
	}
	if req.BootID != "" && p.BootID != "" && req.BootID != p.BootID {
		s.closePerson(ctx, p, time.Time{}, "boot")
	}
	var at time.Time
	if req.PersonIdle != nil && *req.PersonIdle >= 0 {
		at = time.Now().Add(-time.Duration(*req.PersonIdle) * time.Second)
	}
	if err := s.cfg.Store.RecordPersonActivity(ctx, p.ID, at, req.PersonIdle != nil, req.BootID); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.cfg.Logf("person activity of peer %d: %v", p.ID, err)
	}
}

// personAdministers notes a call that used rights of the device's open person layer (its admin or
// operator role, the admin interface) as the person's activity.
func (s *Server) personAdministers(ctx context.Context, p store.Peer) {
	if !p.Person.Active || p.Machine.Admin || p.Machine.Operator {
		return
	}
	now := time.Now()
	s.activityMu.Lock()
	if s.activityNoted == nil {
		s.activityNoted = map[int64]time.Time{}
	}
	if now.Sub(s.activityNoted[p.ID]) < personActivityEvery {
		s.activityMu.Unlock()
		return
	}
	s.activityNoted[p.ID] = now
	s.activityMu.Unlock()
	if err := s.cfg.Store.RecordPersonActivity(ctx, p.ID, now, false, ""); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.cfg.Logf("person activity of peer %d: %v", p.ID, err)
	}
}

// reopenServices are the sign-ins whose approval reopens a person layer.
func (s *Server) reopenServices() []string {
	if s.cfg.ReopenServices != nil {
		return s.cfg.ReopenServices
	}
	return DefaultReopenServices
}

// reopenOnApproval reopens the person layer of the device that asked for an approved sign-in to
// its desktop, when the sign-in is its person's and their last full sign-in on it is recent
// enough (store.PersonReopen). An open layer counts it as activity.
func (s *Server) reopenOnApproval(ctx context.Context, a store.Approval) {
	if a.State != store.ApprovalApproved || !slices.Contains(s.reopenServices(), a.Service) {
		return
	}
	p, err := s.peerByID(ctx, a.Requester)
	if err != nil || p.User != a.User {
		return
	}
	now := time.Now()
	if p.Person.Active {
		_ = s.cfg.Store.RecordPersonActivity(ctx, p.ID, now, false, a.BootID)
		return
	}
	if !p.Reopenable(now) {
		s.audit(nil, nil, "session_opened", fmt.Sprintf("%s reason=approval service=%s (last full sign-in %s: ento agent login)", userLabel(p),
			a.Service, p.LoginAt.UTC().Format(time.RFC3339)), "denied")
		return
	}
	on := true
	u := store.PeerUpdate{PersonActive: &on, PersonSince: &now, PersonActivityAt: &now, IfLoginAt: &p.LoginAt}
	if a.BootID != "" {
		u.BootID = &a.BootID
	}
	if _, err := s.cfg.Store.UpdatePeer(ctx, p.ID, u); err != nil {
		if !errors.Is(err, store.ErrChanged) {
			s.cfg.Logf("reopen the person layer of peer %d: %v", p.ID, err)
		}
		return
	}
	s.audit(nil, nil, "session_opened", fmt.Sprintf("%s reason=approval service=%s", userLabel(p), a.Service), "ok")
	s.checkVersion(ctx)
}
