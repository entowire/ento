package control

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/credential"
	"entowire.com/ento/internal/store"
	"entowire.com/ento/internal/token"
)

// Linked networks (see docs/design.md). This file holds both sides:
//
//   - in a linked network, authorities: other networks whose credentials admit their devices;
//   - in a home network, links: the authority keys it signs its devices' credentials with.

// validName restricts link and authority names: they end up in group names, network namespace
// and interface names (at most 15 bytes, "enl-" included).
var validName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,9}$`)

const (
	defaultCredentialTTL = 12 * time.Hour
	// authorityTokenLifetime: an authority's enrollment token lives as long as the authority.
	authorityTokenLifetime = 100 * 365 * 24 * time.Hour
)

// --- linked network: authorities -----------------------------------------------------------------

// grantFor turns verified claims into what the device is admitted with: the requested groups the
// authority may assign, prefixed with its name, until the credential expires, and never longer than
// MaxTTL after the credential was issued (a credential cannot be presented again and again for
// fresh MaxTTLs).
func grantFor(a store.Authority, c credential.Claims) store.Grant {
	g := store.Grant{Authority: a.Name, Groups: []string{}, UserName: a.Name + ":" + c.User, Hostname: c.Device,
		DeviceID: c.DeviceID, MaxDevices: a.MaxDevices}
	for _, grp := range c.Groups {
		if slices.Contains(a.Groups, grp) && !slices.Contains(g.Groups, a.Name+":"+grp) {
			g.Groups = append(g.Groups, a.Name+":"+grp)
		}
	}
	g.Until = c.Expires()
	if max := c.Issued().Add(a.MaxTTL); a.MaxTTL > 0 && g.Until.After(max) {
		g.Until = max
	}
	return g
}

// verifyGrant checks a credential presented for key against the named authority, and returns its
// claims too (for the record: their identifier).
func (s *Server) verifyGrant(ctx context.Context, authority, cred string, key wgtypes.Key) (store.Grant, credential.Claims, error) {
	a, err := s.cfg.Store.Authority(ctx, authority)
	if err != nil {
		return store.Grant{}, credential.Claims{}, err
	}
	if a.Suspended {
		return store.Grant{}, credential.Claims{}, fmt.Errorf("%w: authority %s is suspended", credential.ErrInvalid, authority)
	}
	now := time.Now()
	c, err := credential.Verify(a.PublicKey, cred, now)
	if err != nil {
		return store.Grant{}, c, err
	}
	if c.Key != key.String() {
		return store.Grant{}, c, fmt.Errorf("%w: issued for another key", credential.ErrInvalid)
	}
	g := grantFor(a, c)
	if !now.Before(g.Until) {
		return store.Grant{}, c, fmt.Errorf("%w: issued more than %s ago (the authority's limit)", credential.ErrInvalid, a.MaxTTL)
	}
	return g, c, nil
}

// credentialLabel describes a credential in audit lines: its identifier and the home device.
func credentialLabel(c credential.Claims) string {
	id, dev := c.ID, c.DeviceID
	if id == "" {
		id = "-"
	}
	if dev == "" {
		dev = "-"
	}
	return "credential=" + id + " home_device=" + dev
}

func (s *Server) handleCreateAuthority(w http.ResponseWriter, r *http.Request, self store.Peer) {
	var req api.CreateAuthorityRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	if !validName.MatchString(req.Name) {
		writeErr(w, http.StatusBadRequest, "name: 1 to 10 lowercase letters, digits or dashes")
		return
	}
	pub, err := credential.ParsePublicKey(req.PublicKey)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.Groups) == 0 {
		writeErr(w, http.StatusBadRequest, "at least one group is required")
		return
	}
	if err := checkGroups(req.Groups, false); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ttl := time.Duration(req.MaxTTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = defaultCredentialTTL
	}
	if req.MaxDevices < 0 {
		writeErr(w, http.StatusBadRequest, "max_devices: 0 (no limit) or more")
		return
	}
	tok, err := IssueAuthorityToken(r.Context(), s.cfg.Store, store.Authority{Name: req.Name, PublicKey: pub, Groups: req.Groups,
		MaxTTL: ttl, MaxDevices: req.MaxDevices})
	switch {
	case errors.Is(err, store.ErrExists):
		writeErr(w, http.StatusConflict, "an authority with this name exists")
		return
	case err != nil:
		s.cfg.Logf("create authority: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.cfg.Logf("authority %s registered (groups %v, credentials up to %s, devices up to %d)", req.Name, req.Groups, ttl, req.MaxDevices)
	s.audit(r, &self, "authority_added", fmt.Sprintf("authority %s groups=%s max_ttl=%s max_devices=%d", req.Name,
		strings.Join(req.Groups, ","), ttl, req.MaxDevices), "ok")
	s.checkVersion(r.Context()) // register the enrollment key right away
	writeJSON(w, http.StatusCreated, api.CreateAuthorityResponse{Token: tok})
}

// IssueAuthorityToken stores an authority with a fresh reusable enrollment token and returns the
// token's text, the only copy of its secret. Used by the admin API and, for bootstrapping, directly
// on the database (ento control authority).
func IssueAuthorityToken(ctx context.Context, st store.Store, a store.Authority) (string, error) {
	if !validName.MatchString(a.Name) {
		return "", fmt.Errorf("authority name: 1 to 10 lowercase letters, digits or dashes")
	}
	if a.MaxTTL <= 0 {
		a.MaxTTL = defaultCredentialTTL
	}
	return authorityToken(ctx, st, func(t store.Token) (store.Token, error) {
		_, t, err := st.CreateAuthority(ctx, a, t)
		return t, err
	})
}

// RotateAuthorityToken gives an authority a new enrollment token in place of its current one and
// returns its text. Used by the admin API and on the database (ento control authority token).
func RotateAuthorityToken(ctx context.Context, st store.Store, name string) (string, error) {
	return authorityToken(ctx, st, func(t store.Token) (store.Token, error) {
		return st.RotateAuthorityToken(ctx, name, t)
	})
}

// authorityToken makes a reusable enrollment token, stores it with save and returns its text.
func authorityToken(ctx context.Context, st store.Store, save func(store.Token) (store.Token, error)) (string, error) {
	nodes, err := st.ControlNodes(ctx)
	if err != nil {
		return "", err
	}
	if len(nodes) == 0 {
		return "", fmt.Errorf("no control node registered yet")
	}
	secret, err := token.NewSecret()
	if err != nil {
		return "", err
	}
	creds, err := token.Derive(secret)
	if err != nil {
		return "", err
	}
	t, err := save(store.Token{PublicKey: creds.PublicKey, PresharedKey: creds.PresharedKey,
		ExpiresAt: time.Now().Add(authorityTokenLifetime)})
	if err != nil {
		return "", err
	}
	tok := token.Token{Secret: secret, TempAddress: t.TempAddress}
	for _, n := range nodes {
		tok.Controls = append(tok.Controls, token.Control{PublicKey: n.PublicKey, Endpoint: n.Endpoint, Address: n.Address})
	}
	return tok.Encode()
}

func (s *Server) handleListAuthorities(w http.ResponseWriter, r *http.Request, _ store.Peer) {
	auths, err := s.cfg.Store.Authorities(r.Context())
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	peers, err := s.cfg.Store.Peers(r.Context())
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	devices := map[string]int{}
	for _, p := range peers {
		devices[p.Authority]++
	}
	out := make([]api.AuthorityInfo, 0, len(auths))
	for _, a := range auths {
		out = append(out, api.AuthorityInfo{Name: a.Name, PublicKey: credential.EncodePublicKey(a.PublicKey), Groups: a.Groups,
			MaxTTLSeconds: int(a.MaxTTL / time.Second), Devices: devices[a.Name], CreatedAt: a.CreatedAt.UTC().Format(time.RFC3339),
			Suspended: a.Suspended, MaxDevices: a.MaxDevices})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleDeleteAuthority(w http.ResponseWriter, r *http.Request, self store.Peer) {
	name := r.PathValue("name")
	if err := s.cfg.Store.DeleteAuthority(r.Context(), name); err != nil {
		s.respondStoreErr(w, err)
		return
	}
	s.cfg.Logf("authority %s deleted with all its devices", name)
	s.audit(r, &self, "authority_deleted", "authority "+name, "ok")
	s.checkVersion(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleUpdateAuthority(w http.ResponseWriter, r *http.Request, self store.Peer) {
	var req api.UpdateAuthorityRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	name := r.PathValue("name")
	if req.Suspended == nil {
		writeErr(w, http.StatusBadRequest, "suspended: true or false")
		return
	}
	if self.Authority == name && *req.Suspended {
		writeErr(w, http.StatusBadRequest, "a device cannot suspend the authority that admitted it")
		return
	}
	if err := s.cfg.Store.SuspendAuthority(r.Context(), name, *req.Suspended); err != nil {
		s.respondStoreErr(w, err)
		return
	}
	action := "authority_resumed"
	if *req.Suspended {
		action = "authority_suspended"
	}
	s.audit(r, &self, action, "authority "+name, "ok")
	s.checkVersion(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

// handleAuthorityLimit changes how many devices an authority may have; devices already in stay.
func (s *Server) handleAuthorityLimit(w http.ResponseWriter, r *http.Request, self store.Peer) {
	var req api.AuthorityLimitRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil || req.MaxDevices < 0 {
		writeErr(w, http.StatusBadRequest, "max_devices: 0 (no limit) or more")
		return
	}
	name := r.PathValue("name")
	if err := s.cfg.Store.SetAuthorityLimit(r.Context(), name, req.MaxDevices); err != nil {
		s.respondStoreErr(w, err)
		return
	}
	s.audit(r, &self, "authority_limit", fmt.Sprintf("authority %s max_devices=%d", name, req.MaxDevices), "ok")
	w.WriteHeader(http.StatusNoContent)
}

// handleRotateAuthorityToken replaces an authority's enrollment token: the previous one stops
// working (devices already admitted stay), the new one goes to the home network's link.
func (s *Server) handleRotateAuthorityToken(w http.ResponseWriter, r *http.Request, self store.Peer) {
	name := r.PathValue("name")
	tok, err := RotateAuthorityToken(r.Context(), s.cfg.Store, name)
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	s.audit(r, &self, "authority_token_rotated", "authority "+name, "ok")
	s.checkVersion(r.Context()) // withdraw the old enrollment key, register the new one
	writeJSON(w, http.StatusOK, api.RotateAuthorityTokenResponse{Token: tok})
}

// handleRenewCredential extends the approval of a device admitted by an authority.
func (s *Server) handleRenewCredential(w http.ResponseWriter, r *http.Request, self store.Peer) {
	if self.Authority == "" {
		writeErr(w, http.StatusForbidden, "this device was not admitted by an authority")
		return
	}
	var req api.RenewCredentialRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	g, c, err := s.verifyGrant(r.Context(), self.Authority, req.Credential, self.PublicKey)
	if err == nil && self.AuthorityDevice != "" && c.DeviceID != self.AuthorityDevice {
		err = fmt.Errorf("%w: issued for another device of the authority", credential.ErrInvalid)
	}
	if err != nil {
		s.audit(r, &self, "credential_renewed", "authority "+self.Authority+" "+credentialLabel(c)+": "+err.Error(), "denied")
	}
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusForbidden, "authority no longer registered")
		return
	case errors.Is(err, credential.ErrInvalid):
		writeErr(w, http.StatusForbidden, err.Error())
		return
	case err != nil:
		s.respondStoreErr(w, err)
		return
	}
	approved := true
	u := store.PeerUpdate{Approved: &approved, Groups: &g.Groups, UserName: &g.UserName, ApprovedUntil: &g.Until}
	if self.AuthorityDevice == "" && g.DeviceID != "" {
		// A membership from before credentials named the home device: from now on it is that
		// device's one membership (a new key replaces it, the authority's limit counts it once).
		u.AuthorityDevice = &g.DeviceID
	}
	p, err := s.cfg.Store.UpdatePeer(r.Context(), self.ID, u)
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	s.audit(r, &p, "credential_renewed", fmt.Sprintf("%s authority=%s %s until=%s", peerLabel(p), p.Authority, credentialLabel(c),
		p.ApprovedUntil.UTC().Format(time.RFC3339)), "ok")
	writeJSON(w, http.StatusOK, api.RenewCredentialResponse{ApprovedUntil: p.ApprovedUntil.UTC().Format(time.RFC3339), Groups: p.Groups})
}

// expire withdraws approvals whose credentials were not renewed in time, and closes the person
// layers whose person was idle too long.
func (s *Server) expire(ctx context.Context) {
	changed := false
	n, err := s.cfg.Store.ExpirePeers(ctx, time.Now())
	if err != nil {
		s.cfg.Logf("expire approvals: %v", err)
	} else if n > 0 {
		s.cfg.Logf("%d device(s) admitted by an authority expired", n)
		s.audit(nil, nil, "approval_expired", fmt.Sprintf("%d device(s) admitted by an authority", n), "ok")
		changed = true
	}
	// Also without SSO configured (any more): person layers opened before must still end.
	if s.endPersonSessions(ctx) {
		changed = true
	}
	if changed {
		s.checkVersion(ctx)
	}
	if time.Since(s.uiSwept) > time.Minute {
		s.uiSwept = time.Now()
		if err := s.cfg.Store.ExpireUISessions(ctx, time.Now()); err != nil {
			s.cfg.Logf("expire admin interface sessions: %v", err)
		}
		if err := s.cfg.Store.ExpireSignInCodes(ctx, time.Now()); err != nil {
			s.cfg.Logf("expire device sign-in codes: %v", err)
		}
	}
	if time.Since(s.approvalsSwept) > time.Hour {
		s.approvalsSwept = time.Now()
		// The audit lines are their record; the rows only serve the requests and the rate limits.
		if err := s.cfg.Store.DeleteApprovalsBefore(ctx, time.Now().Add(-24*time.Hour)); err != nil {
			s.cfg.Logf("delete old sign-in approvals: %v", err)
		}
	}
}

// --- home network: links -----------------------------------------------------------------------

func linkInfo(l store.Link) api.LinkInfo {
	info := api.LinkInfo{Name: l.Name, PublicKey: credential.EncodePublicKey(l.PrivateKey.Public().(ed25519.PublicKey)),
		Groups: l.Groups, Grant: l.Grant, TTLSeconds: int(l.TTL / time.Second), HasToken: l.Token != "",
		CreatedAt: l.CreatedAt.UTC().Format(time.RFC3339), Posture: l.Posture}
	if l.Token != "" {
		info.Controls, info.Network = linkedNetwork(l.Token)
	}
	return info
}

func (s *Server) handleCreateLink(w http.ResponseWriter, r *http.Request, self store.Peer) {
	var req api.CreateLinkRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	if !validName.MatchString(req.Name) {
		writeErr(w, http.StatusBadRequest, "name: 1 to 10 lowercase letters, digits or dashes")
		return
	}
	if len(req.Groups) == 0 || len(req.Grant) == 0 {
		writeErr(w, http.StatusBadRequest, "groups (who may join) and grant (what they request) are required")
		return
	}
	if err := checkGroups(append(slices.Clone(req.Groups), req.Grant...), false); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	checks, err := postureNames(req.Posture)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = defaultCredentialTTL
	}
	_, priv, err := credential.NewKey()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	l, err := s.cfg.Store.CreateLink(r.Context(), store.Link{Name: req.Name, PrivateKey: priv, Groups: req.Groups, Grant: req.Grant,
		TTL: ttl, Posture: checks})
	if errors.Is(err, store.ErrExists) {
		writeErr(w, http.StatusConflict, "a link with this name exists")
		return
	}
	if noSuchCheck(w, err) {
		return
	}
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	s.cfg.Logf("link %s created (groups %v may join, requesting %v, posture %v)", l.Name, l.Groups, l.Grant, l.Posture)
	s.audit(r, &self, "link_created", fmt.Sprintf("link %s groups=%s grant=%s ttl=%s posture=%s", l.Name, strings.Join(l.Groups, ","),
		strings.Join(l.Grant, ","), l.TTL, checkList(l.Posture)), "ok")
	writeJSON(w, http.StatusCreated, linkInfo(l))
}

// checkList names posture checks for audit lines ("none" for none).
func checkList(checks []string) string {
	if len(checks) == 0 {
		return "none"
	}
	return strings.Join(checks, ",")
}

// handleUpdateLink changes the posture checks a link requires of the devices that ask for its
// credentials. Credentials issued before stay valid until they expire.
func (s *Server) handleUpdateLink(w http.ResponseWriter, r *http.Request, self store.Peer) {
	var req api.UpdateLinkRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.Posture == nil {
		writeErr(w, http.StatusBadRequest, "posture: the checks the link requires (an empty list: none)")
		return
	}
	checks, err := postureNames(*req.Posture)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	name := r.PathValue("name")
	before, err := s.cfg.Store.Link(r.Context(), name)
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	l, err := s.cfg.Store.SetLinkPosture(r.Context(), name, checks)
	if noSuchCheck(w, err) {
		return
	}
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	s.audit(r, &self, "link_posture", fmt.Sprintf("link %s posture=%s (was %s)", l.Name, checkList(l.Posture), checkList(before.Posture)), "ok")
	writeJSON(w, http.StatusOK, linkInfo(l))
}

// linkPostureFailing lists the checks a link requires that a device fails now. The evaluation is
// the one policies get: a report recent enough for each check, with the facts it requires (fail
// closed: no report, an old one, an unknown fact or a check that is gone all fail). Where a policy
// requires the same check of the device, a failure over its facts that the stored evaluation still
// holds (postureHoldDown) counts too, so that both agree.
func (s *Server) linkPostureFailing(ctx context.Context, p store.Peer, l store.Link) ([]api.PostureFailure, error) {
	ps, err := loadPosture(ctx, s.cfg.Store, time.Now())
	if err != nil {
		return nil, err
	}
	var out []api.PostureFailure
	for _, name := range l.Posture {
		why := ps.live(p, name)
		if stored := ps.reports[p.ID].Results[name]; why == "" && stored != "" && !staleReason(stored) {
			why = stored
		}
		if why != "" {
			out = append(out, api.PostureFailure{Check: name, Reason: why})
		}
	}
	return out, nil
}

// failingSummary describes failing checks in one line: "enc (disk not encrypted), boot (no report)".
func failingSummary(f []api.PostureFailure) string {
	parts := make([]string, len(f))
	for i, x := range f {
		parts[i] = x.Check + " (" + x.Reason + ")"
	}
	return strings.Join(parts, ", ")
}

// linkOutcomes is what is recorded of a device on a link's checks (SwapLinkPosture): the outcome
// of each check it does not pass, "enc=failed,fw=stale" ("" when it passes them all). Outcomes, not
// reasons, so that a device whose reason changes within one outcome is not audited again (as for
// policies).
func linkOutcomes(failing []api.PostureFailure) string {
	parts := make([]string, len(failing))
	for i, f := range failing {
		parts[i] = f.Check + "=" + outcome(f.Reason)
	}
	return strings.Join(parts, ",")
}

// parseLinkOutcomes reads what linkOutcomes recorded: check name -> failed or stale.
func parseLinkOutcomes(rec string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(rec, ",") {
		if name, o, ok := strings.Cut(part, "="); ok {
			out[name] = o
		}
	}
	return out
}

// linkPostureAllows decides whether a device passes the checks a link requires, records how it does
// on each and audits every check whose outcome changed, as policies do: link_posture_failed
// (denied) over the device's facts, link_posture_stale (ok) when the report is missing or too old
// (asleep, or a device asking right after it started, before its first report), link_posture_passed.
// Once per change, whichever control node the device asks, not at every renewal. A refusal answers
// the device with the checks it fails. False when the request is answered.
func (s *Server) linkPostureAllows(w http.ResponseWriter, r *http.Request, self store.Peer, l store.Link) bool {
	if len(l.Posture) == 0 {
		return true
	}
	failing, err := s.linkPostureFailing(r.Context(), self, l)
	if err != nil {
		s.cfg.Logf("posture for link %s: %v", l.Name, err)
		writeErr(w, http.StatusServiceUnavailable, "temporarily unavailable")
		return false
	}
	record := linkOutcomes(failing)
	previous, err := s.cfg.Store.SwapLinkPosture(r.Context(), l.Name, self.ID, record)
	if err != nil {
		// The decision stands; only the record of it is missing (the link or device just went).
		s.cfg.Logf("posture for link %s: record: %v", l.Name, err)
	} else if previous != record {
		before := parseLinkOutcomes(previous)
		reasons := map[string]string{}
		for _, f := range failing {
			reasons[f.Check] = f.Reason
		}
		for _, name := range l.Posture {
			now, old := outcome(reasons[name]), before[name]
			if old == "" {
				old = "passed"
			}
			if now == old {
				continue
			}
			switch now {
			case "failed":
				s.audit(r, &self, "link_posture_failed", fmt.Sprintf("%s link=%s check=%s reason=%s", peerLabel(self), l.Name, name, reasons[name]), "denied")
			case "stale":
				s.audit(r, &self, "link_posture_stale", fmt.Sprintf("%s link=%s check=%s reason=%s", peerLabel(self), l.Name, name, reasons[name]), "ok")
			default:
				s.audit(r, &self, "link_posture_passed", fmt.Sprintf("%s link=%s check=%s", peerLabel(self), l.Name, name), "ok")
			}
		}
	}
	if len(failing) == 0 {
		return true
	}
	writeJSON(w, http.StatusForbidden, api.Error{Error: fmt.Sprintf("this device fails the posture checks link %s requires: %s",
		l.Name, failingSummary(failing)), PostureFailing: failing})
	return false
}

func (s *Server) handleListLinks(w http.ResponseWriter, r *http.Request, _ store.Peer) {
	links, err := s.cfg.Store.Links(r.Context())
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	out := make([]api.LinkInfo, 0, len(links))
	for _, l := range links {
		out = append(out, linkInfo(l))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleSetLinkToken(w http.ResponseWriter, r *http.Request, self store.Peer) {
	var req api.SetLinkTokenRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	if _, err := token.Parse(req.Token); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.cfg.Store.SetLinkToken(r.Context(), r.PathValue("name"), req.Token); err != nil {
		s.respondStoreErr(w, err)
		return
	}
	s.audit(r, &self, "link_token_set", "link "+r.PathValue("name"), "ok")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteLink(w http.ResponseWriter, r *http.Request, self store.Peer) {
	if err := s.cfg.Store.DeleteLink(r.Context(), r.PathValue("name")); err != nil {
		s.respondStoreErr(w, err)
		return
	}
	s.audit(r, &self, "link_deleted", "link "+r.PathValue("name"), "ok")
	w.WriteHeader(http.StatusNoContent)
}

// handleLinkCredential gives an approved device of an allowed group a credential for its key in
// the linked network, and when it joins, the linked network's enrollment token. A device holds
// one key per linked network: renewals are for that key only, and joining again replaces it (the
// linked network then replaces the device's membership too, see store.Grant.DeviceID). Only the
// agent can ask: the call is signed with the device's key (keyHolder).
func (s *Server) handleLinkCredential(w http.ResponseWriter, r *http.Request, self store.Peer) {
	if !self.Approved {
		writeErr(w, http.StatusForbidden, "device not approved")
		return
	}
	l, err := s.cfg.Store.Link(r.Context(), r.PathValue("name"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no such link")
		return
	}
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	inLink := func(g string) bool { return slices.ContainsFunc(l.Groups, func(lg string) bool { return hasGroup([]string{g}, lg) }) }
	if !slices.ContainsFunc(self.Groups, inLink) {
		// A device whose person may join but has no session open on it (it ended: idle, logout,
		// a new boot) asks as its agent keeps the link up; said so, since that is routine and a
		// device that may never join is not.
		target := "link " + l.Name
		if !self.Person.Active && slices.ContainsFunc(self.Person.Groups, inLink) {
			target += ": no person signed in on this device (their session ended)"
		}
		s.audit(r, &self, "link_credential", target, "denied")
		writeErr(w, http.StatusForbidden, "this device's groups may not join "+l.Name)
		return
	}
	if l.Token == "" {
		writeErr(w, http.StatusConflict, "the linked network's token has not been imported yet")
		return
	}
	var req api.LinkCredentialRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	key, err := wgtypes.ParseKey(req.PublicKey)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid public key")
		return
	}
	// Posture: neither a credential nor, joining, the linked network's token while the device fails
	// a check the link requires. Credentials issued before simply expire (renewals are refused).
	if !s.linkPostureAllows(w, r, self, l) {
		return
	}
	held, err := s.cfg.Store.LinkKey(r.Context(), l.Name, self.ID)
	switch {
	case errors.Is(err, store.ErrNotFound): // the first credential for this device (or since 0.11)
	case err != nil:
		s.respondStoreErr(w, err)
		return
	case held == key:
	case !req.Join:
		s.audit(r, &self, "link_credential", fmt.Sprintf("link %s key=%s: the device holds key %s there", l.Name, key, held), "denied")
		writeErr(w, http.StatusConflict, "this device holds another key in "+l.Name+": only joining again replaces it")
		return
	default:
		s.audit(r, &self, "link_key_replaced", fmt.Sprintf("link %s key=%s (was %s)", l.Name, key, held), "ok")
	}
	if held != key {
		if err := s.cfg.Store.SetLinkKey(r.Context(), l.Name, self.ID, key); err != nil {
			s.respondStoreErr(w, err)
			return
		}
	}
	user := self.UserName
	if user == "" {
		user = self.Hostname
	}
	now := time.Now()
	ttl := s.linkTTL(self, l.TTL)
	c := credential.Claims{Key: key.String(), User: user, Device: self.Hostname, Groups: l.Grant,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(ttl).Unix(), ID: credential.NewID(), DeviceID: strconv.FormatInt(self.ID, 10)}
	cred, err := credential.Sign(l.PrivateKey, c)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.audit(r, &self, "link_credential", fmt.Sprintf("link %s key=%s %s join=%v until=%s", l.Name, key, credentialLabel(c), req.Join,
		c.Expires().UTC().Format(time.RFC3339)), "ok")
	res := api.LinkCredentialResponse{Credential: cred, ExpiresAt: c.Expires().UTC().Format(time.RFC3339)}
	if req.Join {
		res.Token = l.Token // the linked network's enrollment token: needed to join, never to renew
	}
	writeJSON(w, http.StatusOK, res)
}

// ssoLinkTTL caps the credentials of signed-in devices while their users are checked with the
// identity provider every few minutes (OIDCConfig.TokenKey): a user disabled there loses their
// memberships in linked networks within this too, not only at home.
const ssoLinkTTL = 10 * time.Minute

// linkTTL is how long a device's credential for a linked network lasts. A device on an SSO session
// may lose it after SessionIdle, or at its next check: its access to linked networks must not
// outlive that (it is renewed at half its lifetime while the session lasts).
func (s *Server) linkTTL(self store.Peer, ttl time.Duration) time.Duration {
	if self.User == "" {
		return ttl
	}
	if s.cfg.SessionIdle > 0 && s.cfg.SessionIdle < ttl {
		ttl = s.cfg.SessionIdle
	}
	if s.oidc != nil && len(s.oidc.cfg.TokenKey) > 0 && ssoLinkTTL < ttl {
		ttl = ssoLinkTTL
	}
	return ttl
}

// handleEndCredential withdraws, at its device's request, the approval of a membership admitted
// through a linked network: its home network refused to renew its credential (its person's
// session there ended, or it may no longer join), and the credential it holds would otherwise keep
// it in until it expires. The membership stays; the next credential approves it again.
func (s *Server) handleEndCredential(w http.ResponseWriter, r *http.Request, self store.Peer) {
	if self.Authority == "" {
		writeErr(w, http.StatusForbidden, "this device was not admitted by an authority")
		return
	}
	off, now := false, time.Now()
	p, err := s.cfg.Store.UpdatePeer(r.Context(), self.ID, store.PeerUpdate{Approved: &off, ApprovedUntil: &now})
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	s.audit(r, &p, "credential_ended", peerLabel(p)+" authority="+p.Authority+": its home network refused to renew it", "ok")
	s.checkVersion(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

// handleLeave deletes a membership admitted through a linked network at its device's request (it
// left the network: ento agent unlink, or unused for a week), so that it no longer counts against
// its authority's devices. Answered first: deleting it removes the device from the control nodes'
// WireGuard, and with it the way back for the answer.
func (s *Server) handleLeave(w http.ResponseWriter, r *http.Request, self store.Peer) {
	if self.Authority == "" {
		writeErr(w, http.StatusForbidden, "only memberships admitted through a linked network leave this way; an administrator deletes a device")
		return
	}
	s.audit(r, &self, "link_left", peerLabel(self), "ok")
	w.WriteHeader(http.StatusNoContent)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	go func(id int64) {
		time.Sleep(time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := s.cfg.Store.DeletePeer(ctx, id); err != nil && !errors.Is(err, store.ErrNotFound) {
			s.cfg.Logf("leave: delete peer %d: %v", id, err)
		}
		s.checkVersion(ctx)
	}(self.ID)
}
