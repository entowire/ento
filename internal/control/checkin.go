package control

// Check-ins: noticing a device identity that was copied to another machine. A device's identity is
// its key in the agent's state; copied, the copy is that device. Every check-in (signed with the
// device's key) presents the token the previous one handed out and gets a new one, which the agent
// saves before it uses it. The control plane keeps the token it expects (Cur, issued) and the last
// one it accepted (Prev), as hashes:
//
//   - Cur presented: accepted; it becomes Prev and a new Cur is issued.
//   - Prev presented: the answer that carried Cur was lost (or the agent stopped before saving it):
//     a fresh Cur replaces the unused one, never Cur again, so two copies cannot trade one token.
//   - No token, after only the first check-in (no Prev yet) and from the same machine: the answer to
//     that first check-in was lost the same way (a phone's app starts its agent again moments after
//     the first map arrives, which can stop the agent before it saves the token): as above.
//   - Anything else: two holders. Copies A and B both hold T0; A gets T1; B presents T0 (Prev) and
//     gets T2, which voids T1; A presents T1 and is caught.
//
// The device also reports a fingerprint of the machine (a hash of its machine ID salted with its own
// key), kept from its first check-in: another one means another machine. Root can fake it; it is a
// tripwire, as the tokens are: a copy whose original stays off for good, with the fingerprint faked,
// goes unnoticed (hardware-held keys are the later step).
//
// What happens then depends on the device (Config.CloneResponse): a device bound to a person by
// single sign-on is suspended (as an administrator's suspension: it survives sign-ins; resuming it
// starts its check-ins over); other devices, such as servers whose state survives a rebuild on a new
// machine ID, are reported but keep working, and the machine that checked in becomes the one
// expected. Either way an audit line (device_clone_suspected) names the reason and both endpoints.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/store"
)

// CloneResponse values (Config.CloneResponse).
const (
	CloneAuto    = "auto"    // suspend devices bound to a person by single sign-on, report the others
	CloneSuspend = "suspend" // suspend every device
	CloneReport  = "report"  // suspend none
)

// cloneAuditEvery limits how often one device's suspicion is audited when it is not suspended (two
// copies that keep running would raise it at every check-in).
const cloneAuditEvery = time.Hour

func hashToken(t string) string {
	h := sha256.Sum256([]byte("ento-checkin-v1\n" + t))
	return hex.EncodeToString(h[:])
}

func validCheckInValue(s string, max int) bool {
	if len(s) > max {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// suspendsClones reports whether a device suspected of being copied is suspended.
func (s *Server) suspendsClones(p store.Peer) bool {
	switch s.cfg.CloneResponse {
	case CloneSuspend:
		return true
	case CloneReport:
		return false
	}
	return p.User != "" && p.Authority == ""
}

func (s *Server) handleCheckIn(w http.ResponseWriter, r *http.Request, self store.Peer) {
	var req api.CheckInRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048)).Decode(&req); err != nil ||
		!validCheckInValue(req.Token, 64) || !validCheckInValue(req.Fingerprint, 64) || !validCheckInValue(req.BootID, 64) {
		writeErr(w, http.StatusBadRequest, "invalid check-in")
		return
	}
	if req.FilterFailed != "" {
		// The device has only its control nodes as peers until its filter applies (D2): say so where
		// administrators look, at every check-in while it lasts.
		s.audit(r, &self, "filter_failed", fmt.Sprintf("%s: %s; only the control nodes are its peers", peerLabel(self), printable(req.FilterFailed, 200)), "failed")
	}
	s.noteHereGuard(r.Context(), self, req.HereGuard)
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	next := base64.RawURLEncoding.EncodeToString(raw)
	now := time.Now()
	suspend := s.suspendsClones(self)
	// A device with a bound hardware key (hwkey.go): a check-in without its signature comes from a
	// copy (or a failing TPM) and counts for nothing; with it, the device is the original whatever
	// the tokens say, so it is never suspended, and changes its key instead.
	hw, err := s.checkInHW(r.Context(), self, req, now)
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	if hw.bound && !hw.signed {
		s.unsignedCheckIn(w, r, self, hw)
		return
	}
	if hw.signed {
		suspend = false
	}
	var why, lastEndpoint, lastFailed string
	failed := printable(req.UpdateFailed, 200)
	_, err = s.cfg.Store.UpdateCheckIn(r.Context(), self.ID, func(c store.CheckIn, found bool) (store.CheckIn, error) {
		why, lastEndpoint, lastFailed = "", c.Endpoint, c.UpdateFailed
		c.UpdateFailed = failed
		presented := ""
		if req.Token != "" {
			presented = hashToken(req.Token)
		}
		switch {
		case !found: // the first check-in (enrolled before 0.23, or started over)
		case presented != "" && presented == c.Cur:
			c.Prev = c.Cur
		case presented != "" && presented == c.Prev: // the answer was lost: a fresh token, below
		case presented == "" && c.Prev == "" && (c.Fingerprint == "" || req.Fingerprint == c.Fingerprint):
			// The answer to the first check-in was lost: a fresh token, below (a copy that holds the
			// replaced one is caught at its next check-in).
		case presented == "":
			why = "no token (its state is older than its last check-in)"
		default:
			why = "a token already replaced (another machine checked in with this identity)"
		}
		if found && c.Fingerprint != "" && req.Fingerprint != "" && req.Fingerprint != c.Fingerprint {
			why = strings.TrimPrefix(why+"; another machine (its fingerprint changed)", "; ")
		}
		if why != "" {
			c.Suspected, c.SuspectedAt = why, now
			if suspend {
				return c, nil // nothing issued: the device is suspended
			}
			c.Fingerprint = "" // the machine that checked in becomes the one expected
		}
		if c.Fingerprint == "" {
			c.Fingerprint = req.Fingerprint
		}
		c.Cur, c.Endpoint, c.At = hashToken(next), self.Endpoint, now
		return c, nil
	})
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	if failed != "" && failed != lastFailed {
		// A self-update that failed, once per reason: administrators see it beside the version too.
		s.audit(r, &self, "update_failed", peerLabel(self)+": "+failed, "failed")
	}
	if why == "" {
		writeJSON(w, http.StatusOK, api.CheckInResponse{Token: next, RotateKey: hw.rotate})
		s.personCheckIn(r.Context(), self, req)
		return
	}
	target := fmt.Sprintf("%s reason=%q endpoint=%s last=%s", peerLabel(self), why, self.Endpoint, orDash(lastEndpoint))
	if hw.signed {
		// The original, with its hardware key: a copy checked in before it. Its key changes now.
		s.markRotate(r.Context(), self.ID)
		s.audit(r, &self, "device_clone_suspected", target+" action=rotated (the original signed with its hardware key)", "ok")
		writeJSON(w, http.StatusOK, api.CheckInResponse{Token: next, RotateKey: true})
		s.personCheckIn(r.Context(), self, req)
		return
	}
	if !suspend {
		if s.cloneAuditDue(self.ID, now) {
			s.audit(r, &self, "device_clone_suspected", target+" action=reported", "ok")
		}
		writeJSON(w, http.StatusOK, api.CheckInResponse{Token: next})
		s.personCheckIn(r.Context(), self, req)
		return
	}
	s.audit(r, &self, "device_clone_suspected", target+" action=suspended", "ok")
	s.suspendAfterAnswer(w, self.ID, "this device's identity seems to be in use on another machine ("+why+"): it is suspended until an administrator resumes it")
}

// unsignedCheckIn answers a bound device's check-in that its hardware key did not sign: refused
// (no token: the original's chain of tokens is untouched), and after hwGrace without a signed one,
// suspended.
func (s *Server) unsignedCheckIn(w http.ResponseWriter, r *http.Request, self store.Peer, hw hwCheckIn) {
	why := hw.why
	if !strings.HasPrefix(why, "no hardware signature") {
		why = "no hardware signature: " + why
	}
	target := fmt.Sprintf("%s reason=%q endpoint=%s", peerLabel(self), why, self.Endpoint)
	if hw.suspend {
		s.audit(r, &self, "device_clone_suspected", target+" action=suspended (none signed for "+hwGrace.String()+")", "ok")
		s.suspendAfterAnswer(w, self.ID, "this device's check-ins have not been signed by its hardware key for "+hwGrace.String()+": it is suspended until an administrator resumes it")
		return
	}
	if s.cloneAuditDue(self.ID, time.Now()) {
		s.audit(r, &self, "device_clone_suspected", target+" action=refused (the original changes its key at once)", "denied")
	}
	writeErr(w, http.StatusConflict, "this check-in is not signed by the device's hardware key ("+hw.why+")")
}

// suspendAfterAnswer answers with msg, then suspends the device: suspending removes it from the
// control nodes' WireGuard, and with it the way back for the answer. Should this node stop in
// between, nothing is lost: no token was issued, so the device's next check-in is caught again.
func (s *Server) suspendAfterAnswer(w http.ResponseWriter, peerID int64, msg string) {
	writeErr(w, http.StatusConflict, msg)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	go func(id int64) {
		time.Sleep(time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		yes := true
		if _, err := s.cfg.Store.UpdatePeer(ctx, id, store.PeerUpdate{Suspended: &yes}); err != nil {
			s.cfg.Logf("suspend peer %d: %v", id, err)
		}
		s.checkVersion(ctx)
	}(peerID)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// cloneAuditDue reports whether a device's reported (not suspended) suspicion is worth an audit
// line: the first in cloneAuditEvery on this control node.
func (s *Server) cloneAuditDue(id int64, now time.Time) bool {
	s.cloneMu.Lock()
	defer s.cloneMu.Unlock()
	if s.cloneAudited == nil {
		s.cloneAudited = map[int64]time.Time{}
	}
	if t, ok := s.cloneAudited[id]; ok && now.Sub(t) < cloneAuditEvery {
		return false
	}
	s.cloneAudited[id] = now
	return true
}

// restartCheckIns forgets a resumed device's check-ins: its next one starts over (new token, its
// current machine's fingerprint).
func (s *Server) restartCheckIns(ctx context.Context, id int64) {
	if err := s.cfg.Store.DeleteCheckIn(ctx, id); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.cfg.Logf("check-ins of peer %d: %v", id, err)
	}
}

// checkInInfo adds what the peer list shows of each device's check-ins.
func checkInInfo(out []api.PeerInfo, checkIns []store.CheckIn) {
	byID := map[int64]store.CheckIn{}
	for _, c := range checkIns {
		byID[c.PeerID] = c
	}
	for i := range out {
		c, ok := byID[out[i].ID]
		if !ok {
			continue
		}
		if !c.At.IsZero() {
			out[i].CheckedInAt = c.At.UTC().Format(time.RFC3339)
		}
		out[i].UpdateFailed = c.UpdateFailed
		if c.Suspected != "" {
			out[i].CloneSuspected = c.Suspected
			out[i].CloneSuspectedAt = c.SuspectedAt.UTC().Format(time.RFC3339)
		}
	}
}
