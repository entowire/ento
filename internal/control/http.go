package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/credential"
	"entowire.com/ento/internal/names"
	"entowire.com/ento/internal/reqsig"
	"entowire.com/ento/internal/store"
	"entowire.com/ento/internal/token"
)

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+api.PathRedeem, s.handleRedeem)
	mux.HandleFunc("GET "+api.PathNetMap, s.peerOnly(s.handleNetMap))
	mux.HandleFunc("POST "+api.PathTokens, s.operatorOnly(s.handleCreateToken))
	mux.HandleFunc("GET "+api.PathTokens, s.operatorOnly(s.handleListTokens))
	mux.HandleFunc("DELETE "+api.PathTokens+"/{id}", s.operatorOnly(s.handleDeleteToken))
	mux.HandleFunc("GET "+api.PathRecord, s.operatorOnly(s.handleRecord))
	mux.HandleFunc("POST "+api.PathCheckIn, s.keyHolder(false, s.handleCheckIn))
	mux.HandleFunc("POST "+api.PathLogout, s.keyHolder(false, s.handleLogout))
	mux.HandleFunc("POST "+api.PathLeave, s.keyHolder(false, s.handleLeave))
	mux.HandleFunc("POST "+api.PathCredentialEnd, s.keyHolder(false, s.handleEndCredential))
	mux.HandleFunc("POST "+api.PathHWKey, s.keyHolder(false, s.handleHWKey))
	mux.HandleFunc("POST "+api.PathRotate, s.keyHolder(false, s.handleRotate))
	mux.HandleFunc("GET "+api.PathRoutes, s.operatorOnly(s.handleListRoutes))
	mux.HandleFunc("POST "+api.PathRoutes, s.adminOnly(s.handleAddRoute))
	mux.HandleFunc("DELETE "+api.PathRoutes+"/{name}", s.adminOnly(s.handleDeleteRoute))
	mux.HandleFunc("GET "+api.PathDNS, s.operatorOnly(s.handleListDNS))
	mux.HandleFunc("POST "+api.PathDNSRecords, s.adminOnly(s.handleAddDNSRecord))
	mux.HandleFunc("DELETE "+api.PathDNSRecords+"/{name}", s.adminOnly(s.handleDeleteDNSRecord))
	mux.HandleFunc("POST "+api.PathDNSForwards, s.adminOnly(s.handleAddDNSForward))
	mux.HandleFunc("DELETE "+api.PathDNSForwards+"/{zone}", s.adminOnly(s.handleDeleteDNSForward))
	mux.HandleFunc("POST "+api.PathApprovals, s.keyHolder(false, s.handleRequestApproval))
	mux.HandleFunc("GET "+api.PathApprovals, s.keyHolder(false, s.handlePendingApprovals))
	mux.HandleFunc("GET "+api.PathApprovals+"/{id}", s.keyHolder(false, s.handleApprovalStatus))
	mux.HandleFunc("POST "+api.PathApprovals+"/{id}", s.keyHolder(false, s.handleAnswerApproval))
	mux.HandleFunc("GET "+api.PathInfo, s.operatorOnly(s.handleInfo))
	mux.HandleFunc("GET "+api.PathPeers, s.operatorOnly(s.handleListPeers))
	mux.HandleFunc("PATCH "+api.PathPeers+"/{id}", s.operatorOnly(s.handleUpdatePeer))
	mux.HandleFunc("DELETE "+api.PathPeers+"/{id}", s.adminOnly(s.handleDeletePeer))
	mux.HandleFunc("POST "+api.PathUserSuspension, s.operatorOnly(s.handleSuspendUser))
	mux.HandleFunc("GET "+api.PathPolicies, s.operatorOnly(s.handleListPolicies))
	mux.HandleFunc("POST "+api.PathPolicies, s.operatorOnly(s.handleAddPolicy))
	mux.HandleFunc("DELETE "+api.PathPolicies+"/{id}", s.operatorOnly(s.handleDeletePolicy))
	mux.HandleFunc("PATCH "+api.PathPolicies+"/{id}", s.adminOnly(s.handleUpdatePolicy))
	mux.HandleFunc("PUT "+api.PathPolicies+"/{id}/rules", s.operatorOnly(s.handleSetPolicyRules))
	mux.HandleFunc("POST "+api.PathPosture, s.keyHolder(false, s.handlePostureReport))
	mux.HandleFunc("GET "+api.PathUpdate+"/{version}/{name}", s.peerOnly(s.handleUpdateFile))
	mux.HandleFunc("GET "+api.PathAdminUpdates, s.operatorOnly(s.handleGetUpdates))
	mux.HandleFunc("PUT "+api.PathAdminUpdates, s.adminOnly(s.handleSetUpdates))
	mux.HandleFunc("GET "+api.PathPostureChecks, s.operatorOnly(s.handleListPostureChecks))
	mux.HandleFunc("POST "+api.PathPostureChecks, s.adminOnly(s.handleAddPostureCheck))
	mux.HandleFunc("DELETE "+api.PathPostureChecks+"/{name}", s.adminOnly(s.handleDeletePostureCheck))
	mux.HandleFunc("POST "+api.PathLogin, s.keyHolder(false, s.handleLoginStart))
	mux.HandleFunc("GET "+api.PathLogin, s.keyHolder(false, s.handleLoginStatus))
	mux.HandleFunc("GET "+api.PathAdminUI, s.keyHolder(false, s.operatorRole(s.handleAdminUI)))
	mux.HandleFunc("POST "+api.PathAdminUI, s.keyHolder(false, s.operatorRole(s.handleApproveAdminUI)))
	mux.HandleFunc("POST "+api.PathAuthorities, s.adminOnly(s.handleCreateAuthority))
	mux.HandleFunc("GET "+api.PathAuthorities, s.operatorOnly(s.handleListAuthorities))
	mux.HandleFunc("DELETE "+api.PathAuthorities+"/{name}", s.adminOnly(s.handleDeleteAuthority))
	mux.HandleFunc("PATCH "+api.PathAuthorities+"/{name}", s.adminOnly(s.handleUpdateAuthority))
	mux.HandleFunc("POST "+api.PathAuthorities+"/{name}/token", s.adminOnly(s.handleRotateAuthorityToken))
	mux.HandleFunc("PUT "+api.PathAuthorities+"/{name}/limit", s.adminOnly(s.handleAuthorityLimit))
	mux.HandleFunc("POST "+api.PathCredential, s.peerOnly(s.handleRenewCredential))
	mux.HandleFunc("POST "+api.PathAdminLinks, s.adminOnly(s.handleCreateLink))
	mux.HandleFunc("GET "+api.PathAdminLinks, s.operatorOnly(s.handleListLinks))
	mux.HandleFunc("PUT "+api.PathAdminLinks+"/{name}/token", s.adminOnly(s.handleSetLinkToken))
	mux.HandleFunc("DELETE "+api.PathAdminLinks+"/{name}", s.adminOnly(s.handleDeleteLink))
	mux.HandleFunc("PATCH "+api.PathAdminLinks+"/{name}", s.adminOnly(s.handleUpdateLink))
	mux.HandleFunc("GET "+api.PathPeople, s.adminOnly(s.handleListPeople))
	mux.HandleFunc("POST "+api.PathPeople, s.adminOnly(s.handleAddPerson))
	mux.HandleFunc("GET "+api.PathPeople+"/{id}", s.adminOnly(s.handleGetPerson))
	mux.HandleFunc("PATCH "+api.PathPeople+"/{id}", s.adminOnly(s.handleUpdatePerson))
	mux.HandleFunc("DELETE "+api.PathPeople+"/{id}", s.adminOnly(s.handleDeletePerson))
	mux.HandleFunc("DELETE "+api.PathPeople+"/{id}/passkeys/{name}", s.adminOnly(s.handleDeletePasskey))
	mux.HandleFunc("POST "+api.PathPeople+"/{id}/setup", s.adminOnly(s.handlePersonSetup))
	mux.HandleFunc("GET "+api.PathSignin, s.adminOnly(s.handleGetSignin))
	mux.HandleFunc("PUT "+api.PathSignin, s.adminOnly(s.handleSetSignin))
	mux.HandleFunc("POST "+api.PathGroups, s.adminOnly(s.handleAddGroup))
	mux.HandleFunc("DELETE "+api.PathGroups+"/{name}", s.adminOnly(s.handleDeleteGroup))
	mux.HandleFunc("POST "+api.PathLinks+"/{name}/credential", s.keyHolder(false, s.handleLinkCredential))
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, api.Error{Error: msg})
}

// caller returns the overlay address of the request. The API only listens inside WireGuard, so
// this address is authenticated by the peer's key: it proves the device, not the program on it
// (see keyHolder).
func caller(r *http.Request) (netip.Addr, bool) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, false
	}
	return ap.Addr(), true
}

type peerHandler func(w http.ResponseWriter, r *http.Request, self store.Peer)

func (s *Server) peerOnly(h peerHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		addr, ok := caller(r)
		if !ok {
			writeErr(w, http.StatusForbidden, "unknown caller")
			return
		}
		self, err := s.cfg.Store.PeerByAddress(r.Context(), addr)
		if errors.Is(err, store.ErrNotFound) {
			s.audit(r, nil, "api", r.Method+" "+r.URL.Path, "denied")
			writeErr(w, http.StatusForbidden, "not an enrolled peer")
			return
		}
		if err != nil {
			writeErr(w, http.StatusServiceUnavailable, "temporarily unavailable")
			return
		}
		h(w, r, self)
	}
}

// maxSignedBody bounds the body of a signed request (read before the handler, for the signature).
const maxSignedBody = 64 << 10

// uiSessionKey marks a request that came through a session of the admin interface (adminui.go):
// its value is the device the session belongs to. Only that handler sets it, never the plain API.
type uiSessionKey struct{}

// keyHolder admits a call only when it proves possession of the device's private key, not just its
// address: every process on a device shares the address, but only the agent, root or an
// administrator reads the key. The proof is a signature over the request (package reqsig), or, for
// administration only (sessions), a session of the admin interface, which only such a signature
// opens. Sign-in and credentials for linked networks always need the signature.
func (s *Server) keyHolder(sessions bool, h peerHandler) http.HandlerFunc {
	return s.peerOnly(func(w http.ResponseWriter, r *http.Request, self store.Peer) {
		if id, ok := r.Context().Value(uiSessionKey{}).(int64); ok {
			if sessions && id == self.ID {
				h(w, r, self)
				return
			}
			writeErr(w, http.StatusForbidden, "this needs the device's key, not a session of the admin interface")
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxSignedBody))
		if err != nil {
			writeErr(w, http.StatusRequestEntityTooLarge, "request too large")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		now := time.Now()
		key, err := reqsig.ControlKey(s.cfg.PrivateKey, self.PublicKey)
		var nonce string
		if err == nil {
			nonce, err = reqsig.Verify(r, key, body, now)
		}
		if err == nil {
			err = s.nonces.Check(self.PublicKey.String(), nonce, now)
		}
		if err != nil {
			// A program on the device that is not the agent tried to act with its rights (or an
			// agent older than signed requests): worth an alert where the device is an admin's.
			// Recorded once a minute per device at most, so it cannot flood the record.
			// A replay carries the device's own valid signature: the same request sent twice, as an
			// HTTP client resends one on a dropped connection (a phone changing networks), not a
			// program without the key.
			action := "unsigned_call"
			if errors.Is(err, reqsig.ErrReplayed) {
				action = "signed_call_repeated"
			}
			if s.unsignedSeen(self.ID, now) {
				s.audit(r, &self, action, fmt.Sprintf("%s %s role=%s: %v", r.Method, r.URL.Path, roleName(self), err), "denied")
			}
			msg := "this call must be signed with the device's key (ento 0.11 or later, run as root or administrator)"
			if !errors.Is(err, reqsig.ErrUnsigned) {
				msg = err.Error()
			}
			writeErr(w, http.StatusUnauthorized, msg)
			return
		}
		h(w, r, self)
	})
}

// unsignedSeen reports whether a refused unsigned call of a device is worth an audit line: the
// first in a minute.
func (s *Server) unsignedSeen(id int64, now time.Time) bool {
	s.unsignedMu.Lock()
	defer s.unsignedMu.Unlock()
	if s.unsigned == nil || len(s.unsigned) > 10000 {
		s.unsigned = map[int64]time.Time{}
	}
	if now.Sub(s.unsigned[id]) < time.Minute {
		return false
	}
	s.unsigned[id] = now
	return true
}

func (s *Server) adminOnly(h peerHandler) http.HandlerFunc {
	return s.keyHolder(true, func(w http.ResponseWriter, r *http.Request, self store.Peer) {
		if !self.Admin || !self.Approved {
			s.audit(r, &self, "admin_api", r.Method+" "+r.URL.Path, "denied")
			writeErr(w, http.StatusForbidden, "admin only")
			return
		}
		s.personAdministers(r.Context(), self)
		h(w, r, self)
	})
}

// operatorOnly admits admin and operator devices. Handlers of operator routes limit operators to
// what can be undone (mayOperate); everything else stays adminOnly: deleting devices, roles, links
// and authorities.
func (s *Server) operatorOnly(h peerHandler) http.HandlerFunc {
	return s.keyHolder(true, s.operatorRole(h))
}

// operatorRole admits approved admin and operator devices (the caller is already authenticated).
func (s *Server) operatorRole(h peerHandler) peerHandler {
	return func(w http.ResponseWriter, r *http.Request, self store.Peer) {
		readOnly := r.Method == http.MethodGet || r.URL.Path == api.PathAdminUI
		if !(self.Admin || self.Operator) && readOnly && s.isViewer(self) {
			h(w, r, self)
			return
		}
		if !(self.Admin || self.Operator) || !self.Approved {
			s.audit(r, &self, "admin_api", r.Method+" "+r.URL.Path, "denied")
			writeErr(w, http.StatusForbidden, "admins and operators only")
			return
		}
		s.personAdministers(r.Context(), self)
		h(w, r, self)
	}
}

// roleName is a device's role, for audit lines.
func roleName(p store.Peer) string {
	switch {
	case p.Admin:
		return "admin"
	case p.Operator:
		return "operator"
	}
	return "none"
}

// mayOperate reports whether self may change target: admins any device, operators only devices
// that are neither admins nor operators (their own included).
func mayOperate(self, target store.Peer) bool {
	return self.Admin || !(target.Admin || target.Operator)
}

func (s *Server) handleRedeem(w http.ResponseWriter, r *http.Request) {
	addr, ok := caller(r)
	if !ok || !s.cfg.Space.IsEnrollment(addr) {
		writeErr(w, http.StatusForbidden, "redeem is only possible from an enrollment address")
		return
	}
	var req api.RedeemRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	key, err := wgtypes.ParseKey(req.PublicKey)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid public key")
		return
	}
	var grant *store.Grant
	var claims credential.Claims
	var replaces *store.Peer // the device a named token (or a new membership) takes over from, for the record
	if tokens, err := s.cfg.Store.ActiveTokens(r.Context(), time.Now()); err == nil {
		for _, t := range tokens {
			if t.TempAddress != addr {
				continue
			}
			if t.Name != "" && t.Replace {
				if old, err := s.peerNamed(r.Context(), t.Name); err == nil {
					replaces = &old
				}
			}
			if t.Authority != "" {
				// An authority's enrollment key is shared by its devices: each one proves with
				// a credential that the authority admits it, and the key stays configured.
				g, c, err := s.verifyGrant(r.Context(), t.Authority, req.Credential, key)
				if err != nil {
					s.audit(r, nil, "enrolled", "authority "+t.Authority+" "+credentialLabel(c)+": "+err.Error(), "denied")
					writeErr(w, http.StatusForbidden, "credential rejected: "+err.Error())
					return
				}
				grant, claims = &g, c
				if g.DeviceID != "" {
					if old, err := s.findPeer(r.Context(), func(p store.Peer) bool {
						return p.Authority == g.Authority && p.AuthorityDevice == g.DeviceID
					}); err == nil {
						replaces = &old
					}
				}
				continue
			}
			// Keep the temporary key reachable after redemption (see Server.grace).
			s.graceMu.Lock()
			s.grace[t.PublicKey] = gracePeer{
				peer:    wgPeer{AllowedIP: t.TempAddress, PresharedKey: t.PresharedKey},
				expires: time.Now().Add(redeemGrace),
			}
			s.graceMu.Unlock()
		}
	}
	peer, err := s.cfg.Store.Redeem(r.Context(), addr, key, req.Hostname, cleanOS(req.OS), time.Now(), grant)
	var taken *store.NameTakenError
	var full *store.AuthorityFullError
	switch {
	case errors.As(err, &full):
		s.audit(r, nil, "enrolled", fmt.Sprintf("authority %s key=%s %s: %v", grant.Authority, key, credentialLabel(claims), err), "denied")
		writeErr(w, http.StatusConflict, err.Error())
		return
	case errors.Is(err, store.ErrTokenUnusable):
		writeErr(w, http.StatusGone, err.Error())
		return
	case errors.Is(err, store.ErrMemberSuspended):
		s.audit(r, nil, "enrolled", fmt.Sprintf("authority %s key=%s %s: %v", grant.Authority, key, credentialLabel(claims), err), "denied")
		writeErr(w, http.StatusForbidden, err.Error())
		return
	case errors.Is(err, store.ErrKeyInUse):
		writeErr(w, http.StatusConflict, err.Error())
		return
	case errors.As(err, &taken):
		// The token's name was taken after it was issued (a rename); an administrator decides.
		s.audit(r, nil, "enrolled", "named token: "+err.Error(), "denied")
		writeErr(w, http.StatusConflict, "the name reserved for this device is taken: "+err.Error())
		return
	case err != nil:
		s.cfg.Logf("redeem: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if placed, err := s.placeNewDevice(r.Context(), peer); err != nil {
		s.cfg.Logf("place new device %s: %v", peer.Hostname, err)
	} else {
		peer = placed
	}
	// Add the permanent key before answering, so the agent can switch keys immediately. The other
	// control nodes pick it up on their next reconciliation.
	if err := s.reconcile(r.Context()); err != nil {
		s.cfg.Logf("reconcile after redeem: %v", err)
	}
	nodes, err := s.cfg.Store.ControlNodes(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.cfg.Logf("enrolled peer %d %s (reported %q, %s) at %s, approved=%v", peer.ID, peer.Hostname, peer.ReportedHostname,
		peer.PublicKey, peer.Address, peer.Approved)
	target := fmt.Sprintf("%s approved=%v groups=%s", peerLabel(peer), peer.Approved, strings.Join(peer.Groups, ","))
	if peer.Authority != "" {
		target += " authority=" + peer.Authority + " user=" + peer.UserName + " key=" + peer.PublicKey.String() + " " + credentialLabel(claims)
	}
	s.audit(r, &peer, "enrolled", target, "ok")
	if replaces != nil && replaces.ID != peer.ID {
		s.audit(r, &peer, "peer_replaced", peerLabel(*replaces), "ok")
	}
	writeJSON(w, http.StatusOK, api.RedeemResponse{
		Address: peer.Address.String(), Network: s.cfg.Space.Prefix.String(),
		Approved: peer.Approved, Controls: apiControls(nodes),
	})
}

func (s *Server) handleNetMap(w http.ResponseWriter, r *http.Request, self store.Peer) {
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	// A quiet device (a phone) learns of approvals waiting for its person from its map (0.34):
	// ?approvals=N is how many it knows of, and the map comes early when that changes.
	knownApprovals, aerr := strconv.Atoi(r.URL.Query().Get("approvals"))
	watchApprovals := aerr == nil && knownApprovals >= 0
	var version int64
	pending := 0
	if watchApprovals {
		version, pending = s.waitChangeOrApprovals(r.Context(), self, since, knownApprovals, longPollTimeout)
	} else {
		version = s.waitChange(r.Context(), since, longPollTimeout)
	}
	// Re-read the caller: the change we woke up for may concern it.
	self, err := s.cfg.Store.PeerByAddress(r.Context(), self.Address)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusForbidden, "not an enrolled peer")
		return
	}
	if err != nil { // e.g. shutting down, database unavailable: the agent fails over
		writeErr(w, http.StatusServiceUnavailable, "temporarily unavailable")
		return
	}
	nm, err := buildNetMap(r.Context(), s.cfg.Store, s.cfg.Space, self, version, s.cfg.NoGateways)
	nm.Hosts = s.cfg.Hosts
	nm.LinkForwards = s.cfg.LinkForwards
	nm.RecordDomain = s.cfg.RecordDomain
	nm.Update = s.offerUpdate(r.Context(), self)
	if watchApprovals {
		nm.Approvals, nm.Self.PendingApprovals = true, pending
	}
	if k, found, herr := s.hwKey(r.Context(), self.ID); herr == nil && found && k.Rotate {
		nm.Self.RotateKey = true
	}
	if err == nil {
		nm.DNS, err = s.dnsConfig(r.Context(), nm)
	}
	if err != nil {
		s.cfg.Logf("netmap: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, nm)
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request, self store.Peer) {
	var req api.CreateTokenRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	req.Groups = deviceGroups(req.Groups) // an invitation's groups are device groups
	if err := checkGroups(req.Groups, false); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.checkDeviceGroups(r.Context(), req.Groups); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.keepGroups(r.Context(), req.Groups)
	if req.Name != "" {
		if err := names.Check(req.Name); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	} else if req.Replace {
		writeErr(w, http.StatusBadRequest, "replacing a device needs its name")
		return
	}
	if !self.Admin && (req.Admin || req.Replace) {
		s.audit(r, &self, "token_created", fmt.Sprintf("admin=%v replace=%v", req.Admin, req.Replace), "denied")
		writeErr(w, http.StatusForbidden, "only admins create admin tokens or tokens that replace a device")
		return
	}
	if req.Words && time.Duration(req.TTLSeconds)*time.Second > maxWordsTTL {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("words are good for at most %s", maxWordsTTL))
		return
	}
	qrDomain := req.QRDomain
	if qrDomain != "" {
		var err error
		if qrDomain, err = token.JoinDomain(qrDomain); err != nil || !req.Words {
			writeErr(w, http.StatusBadRequest, "qr_domain: a domain, for words")
			return
		}
	} else if req.Words {
		qrDomain = s.cfg.RecordDomain
	}
	tok, t, err := IssueToken(r.Context(), s.cfg.Store, TokenOptions{Groups: req.Groups, Approve: req.Approve,
		Admin: req.Admin, TTL: time.Duration(req.TTLSeconds) * time.Second, CreatedBy: peerLabel(self),
		Name: req.Name, Replace: req.Replace, Words: req.Words, Network: s.cfg.Space.Prefix})
	var taken *store.NameTakenError
	if errors.As(err, &taken) {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		s.cfg.Logf("create token: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.checkVersion(r.Context()) // register the temporary peer right away
	action := "token_created"
	if req.Admin {
		action = "admin_token_created"
	}
	target := fmt.Sprintf("approve=%v groups=%s ttl=%ds", req.Approve, strings.Join(req.Groups, ","), req.TTLSeconds)
	if req.Name != "" {
		target += fmt.Sprintf(" name=%s replace=%v", req.Name, req.Replace)
	}
	if req.Words {
		target += " words=true"
	}
	s.audit(r, &self, action, target, "ok")
	res := api.CreateTokenResponse{Token: tok, ExpiresAt: t.ExpiresAt.UTC().Format(time.RFC3339)}
	if req.Words {
		res.Token, res.Words = "", tok
		if rec, err := NetworkRecord(r.Context(), s.cfg.Store, s.cfg.Space.Prefix); err == nil {
			res.Fingerprint = rec.Fingerprint()
		}
		// For phones to scan: the domain, the fingerprint and the words.
		if j, err := token.NewJoinCode(qrDomain, res.Fingerprint, tok); err == nil {
			res.JoinCode = j.String()
			if res.QRSVG, err = qrSVG(res.JoinCode); err != nil {
				s.cfg.Logf("enrollment QR code: %v", err)
			}
		}
	}
	writeJSON(w, http.StatusCreated, res)
}

// handleRecord returns the network record to publish for enrollment by words. It names nothing an
// enrolled device does not know already.
func (s *Server) handleRecord(w http.ResponseWriter, r *http.Request, _ store.Peer) {
	rec, err := NetworkRecord(r.Context(), s.cfg.Store, s.cfg.Space.Prefix)
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, api.NetworkRecordResponse{Record: rec.String(), Fingerprint: rec.Fingerprint()})
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request, _ store.Peer) {
	toks, err := s.cfg.Store.ActiveTokens(r.Context(), time.Now())
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	out := make([]api.TokenInfo, 0, len(toks))
	for _, t := range toks {
		out = append(out, api.TokenInfo{ID: t.ID, Groups: nonNilStrings(t.Groups), Approve: t.Approve, Admin: t.Admin,
			CreatedAt: t.CreatedAt.UTC().Format(time.RFC3339), ExpiresAt: t.ExpiresAt.UTC().Format(time.RFC3339),
			CreatedBy: t.CreatedBy, Authority: t.Authority, Name: t.Name, Replace: t.Replace})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleDeleteToken(w http.ResponseWriter, r *http.Request, self store.Peer) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.cfg.Store.DeleteToken(r.Context(), id); err != nil {
		s.respondStoreErr(w, err)
		return
	}
	s.audit(r, &self, "token_revoked", fmt.Sprintf("token %d", id), "ok")
	s.checkVersion(r.Context()) // withdraw its temporary peer right away
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request, self store.Peer) {
	nodes, err := s.cfg.Store.ControlNodes(r.Context())
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	out := api.AdminInfo{Network: s.cfg.Space.Prefix.String(), Node: s.cfg.Name, Version: s.cfg.Version,
		Self: peerInfo(self), SSO: s.cfg.OIDC != nil, People: s.people != nil, NoGateways: s.cfg.NoGateways, Viewer: !(self.Admin || self.Operator) && s.isViewer(self), PersonRoles: s.personRoles(), Controls: []api.ControlInfo{}}
	for _, n := range nodes {
		out.Controls = append(out.Controls, api.ControlInfo{Name: n.Name, Address: n.Address.String(),
			Endpoint: n.Endpoint, LastSeen: n.LastSeen.UTC().Format(time.RFC3339)})
	}
	writeJSON(w, http.StatusOK, out)
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func peerInfo(p store.Peer) api.PeerInfo {
	info := api.PeerInfo{ID: p.ID, PublicKey: p.PublicKey.String(), Address: p.Address.String(), Hostname: p.Hostname,
		ReportedHostname: p.ReportedHostname, OS: p.OS, Approved: p.Approved, Admin: p.Admin, Operator: p.Operator, Groups: p.Groups,
		Endpoint: p.Endpoint, User: p.UserName}
	if !p.LastSeen.IsZero() {
		info.LastSeen = p.LastSeen.UTC().Format(time.RFC3339)
	}
	info.Authority = p.Authority
	if !p.ApprovedUntil.IsZero() {
		info.ApprovedUntil = p.ApprovedUntil.UTC().Format(time.RFC3339)
	}
	info.Suspended = p.Suspended
	info.Groups = nonNilStrings(info.Groups)
	if !p.CreatedAt.IsZero() {
		info.CreatedAt = p.CreatedAt.UTC().Format(time.RFC3339)
	}
	if !p.LoginAt.IsZero() {
		info.LoginAt = p.LoginAt.UTC().Format(time.RFC3339)
	}
	info.MachineApproved, info.MachineGroups = p.Machine.Approved, p.Machine.Groups
	if p.User != "" && p.Authority == "" {
		info.PersonApproved, info.PersonGroups, info.PersonActive = p.Person.Approved, p.Person.Groups, p.Person.Active
		switch {
		case p.Person.Admin:
			info.PersonRole = "admin"
		case p.Person.Operator:
			info.PersonRole = "operator"
		}
		if p.Person.Active && !p.Person.Since.IsZero() {
			info.PersonSince = p.Person.Since.UTC().Format(time.RFC3339)
		}
		if !p.Person.ActivityAt.IsZero() {
			info.PersonActivityAt = p.Person.ActivityAt.UTC().Format(time.RFC3339)
		}
	}
	return info
}

func (s *Server) handleListPeers(w http.ResponseWriter, r *http.Request, _ store.Peer) {
	peers, err := s.cfg.Store.Peers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	policies, err := s.cfg.Store.Policies(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	ps, err := loadPosture(r.Context(), s.cfg.Store, time.Now())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	out := make([]api.PeerInfo, 0, len(peers))
	for _, p := range peers {
		out = append(out, peerInfo(p))
	}
	devicePosture(out, peers, policies, ps)
	if checkIns, err := s.cfg.Store.CheckIns(r.Context()); err == nil {
		checkInInfo(out, checkIns)
	}
	if keys, err := s.cfg.Store.HWKeys(r.Context()); err == nil {
		hwKeyInfo(out, keys)
	}
	writeJSON(w, http.StatusOK, out)
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return 0, false
	}
	return id, true
}

// peerByID and peerNamed find a device for administrative actions (small lists, rare calls).
func (s *Server) peerByID(ctx context.Context, id int64) (store.Peer, error) {
	return s.findPeer(ctx, func(p store.Peer) bool { return p.ID == id })
}

func (s *Server) peerNamed(ctx context.Context, name string) (store.Peer, error) {
	return s.findPeer(ctx, func(p store.Peer) bool { return p.Hostname == name })
}

func (s *Server) findPeer(ctx context.Context, match func(store.Peer) bool) (store.Peer, error) {
	peers, err := s.cfg.Store.Peers(ctx)
	if err != nil {
		return store.Peer{}, err
	}
	for _, p := range peers {
		if match(p) {
			return p, nil
		}
	}
	return store.Peer{}, store.ErrNotFound
}

// cleanOS keeps what an agent reports as its system to a short identifier (runtime.GOOS values).
func cleanOS(s string) string {
	s = names.Label(s)
	if len(s) > 16 {
		s = s[:16]
	}
	return s
}

func (s *Server) respondStoreErr(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	var taken *store.NameTakenError
	if errors.As(err, &taken) {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	s.cfg.Logf("store: %v", err)
	writeErr(w, http.StatusInternalServerError, "internal error")
}

func (s *Server) handleUpdatePeer(w http.ResponseWriter, r *http.Request, self store.Peer) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req api.UpdatePeerRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	// Everything is checked before anything is written.
	current, err := s.peerByID(r.Context(), id)
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	if !self.Admin {
		if req.Admin != nil || req.Operator != nil {
			s.audit(r, &self, "peer_role", peerLabel(current), "denied")
			writeErr(w, http.StatusForbidden, "only admins change a device's role")
			return
		}
		if req.UnbindHardwareKey { // it weakens the device's identity: no operator undoes that
			s.audit(r, &self, "hwkey_unbound", peerLabel(current), "denied")
			writeErr(w, http.StatusForbidden, "only admins release a device's hardware key")
			return
		}
		if !mayOperate(self, current) {
			s.audit(r, &self, "peer_update", peerLabel(current), "denied")
			writeErr(w, http.StatusForbidden, "operators cannot change admin or operator devices")
			return
		}
	}
	if req.UseReportedHostname {
		if req.Hostname != nil {
			writeErr(w, http.StatusBadRequest, "give a new name or use the reported one, not both")
			return
		}
		if current.ReportedHostname == "" {
			writeErr(w, http.StatusBadRequest, "the device reported no host name")
			return
		}
		name := names.FromReported(current.ReportedHostname)
		req.Hostname = &name
	}
	if req.Hostname != nil {
		if err := names.Check(*req.Hostname); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	// Approving a device takes it out of isolated; withdrawing its approval puts it there.
	if req.Groups == nil && req.Approved != nil && current.Authority == "" {
		g := slices.DeleteFunc(slices.Clone(current.Machine.Groups), func(x string) bool { return x == IsolatedGroup })
		if !*req.Approved {
			g = append(g, IsolatedGroup)
		}
		req.Groups = &g
	}
	// Giving a device a role (ento admin role) puts it in that role's group, out of isolated.
	if self.Admin && req.Groups == nil && current.Authority == "" && (req.Admin != nil && *req.Admin || req.Operator != nil && *req.Operator) {
		g := slices.DeleteFunc(slices.Clone(current.Machine.Groups), func(x string) bool { return x == IsolatedGroup })
		role := s.operatorGroups()[0]
		if req.Admin != nil && *req.Admin {
			role = s.adminGroups()[0]
		}
		if !slices.Contains(g, role) {
			g = append(g, role)
		}
		req.Groups = &g
	}
	if req.Groups != nil && current.Authority == "" {
		g := deviceGroups(*req.Groups)
		req.Groups = &g
		if err := s.checkDeviceGroups(r.Context(), g); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if req.Groups != nil {
		if err := checkGroups(*req.Groups, false); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if current.Authority == "" {
			// A device's own groups decide its approval and roles: only admins move devices into or
			// out of the role groups, and nobody isolates or demotes the device they work from.
			old := current.Machine.Groups
			if !self.Admin && !slices.Equal(s.roleSet(*req.Groups), s.roleSet(old)) {
				s.audit(r, &self, "peer_role", peerLabel(current), "denied")
				writeErr(w, http.StatusForbidden, "only admins put devices in the admin or operator groups or take them out")
				return
			}
			approved, admin, operator := s.groupRights(*req.Groups)
			if req.Approved != nil && *req.Approved && !slices.Contains(*req.Groups, IsolatedGroup) {
				approved = true // approved explicitly, groups or not
			}
			if id == self.ID && (!approved || current.Admin && !admin && !current.Person.Admin) {
				writeErr(w, http.StatusBadRequest, "you cannot isolate this device or take away its admin group from it")
				return
			}
			admin = admin || current.Machine.Admin && !self.Admin // an operator never changes it
			if req.Approved == nil {
				req.Approved = &approved
			}
			if self.Admin {
				if req.Admin == nil {
					req.Admin = &admin
				}
				if req.Operator == nil {
					req.Operator = &operator
				}
			}
		}
		s.keepGroups(r.Context(), *req.Groups)
	}
	if id == self.ID && req.Admin != nil && !*req.Admin {
		writeErr(w, http.StatusBadRequest, "an admin cannot remove its own admin flag")
		return
	}
	if id == self.ID && ((req.Suspended != nil && *req.Suspended) || (req.Approved != nil && !*req.Approved)) {
		writeErr(w, http.StatusBadRequest, "an admin cannot suspend or unapprove itself")
		return
	}
	resumed := req.Suspended != nil && !*req.Suspended
	if req.Approved != nil && *req.Approved && (current.Suspended && !resumed || req.Suspended != nil && *req.Suspended) {
		writeErr(w, http.StatusConflict, "the device is suspended: resume it first")
		return
	}
	if req.SignOut && id == self.ID {
		writeErr(w, http.StatusBadRequest, "sign this device out on it (ento agent logout)")
		return
	}
	u := store.PeerUpdate{Hostname: req.Hostname, Approved: req.Approved, Admin: req.Admin, Operator: req.Operator,
		Groups: req.Groups, Suspended: req.Suspended}
	if req.SignOut {
		off := false
		u.PersonActive = &off
	}
	p, err := s.cfg.Store.UpdatePeer(r.Context(), id, u)
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	if req.SignOut && current.Person.Active {
		s.audit(r, &self, "session_ended", fmt.Sprintf("%s reason=signed out by an administrator", userLabel(current)), "ok")
	}
	if req.UnbindHardwareKey {
		switch err := s.cfg.Store.DeleteHWKey(r.Context(), p.ID); {
		case err == nil:
			s.audit(r, &self, "hwkey_unbound", peerLabel(p)+" (its next hardware key binds)", "ok")
		case !errors.Is(err, store.ErrNotFound):
			s.respondStoreErr(w, err)
			return
		}
	}
	if p.Hostname != current.Hostname {
		s.audit(r, &self, "peer_renamed", fmt.Sprintf("%s (was %s)", peerLabel(p), current.Hostname), "ok")
	}
	if req.Suspended != nil {
		action := "peer_suspended"
		if !*req.Suspended {
			action = "peer_resumed"
			s.restartCheckIns(r.Context(), p.ID)
		}
		s.audit(r, &self, action, peerLabel(p), "ok")
	}
	if req.Approved != nil {
		action := "peer_approved"
		if !*req.Approved {
			action = "peer_unapproved"
		}
		s.audit(r, &self, action, peerLabel(p), "ok")
	}
	if req.Groups != nil {
		s.audit(r, &self, "peer_groups", peerLabel(p)+" groups="+strings.Join(p.Machine.Groups, ","), "ok")
	}
	if req.Admin != nil || req.Operator != nil {
		s.audit(r, &self, "peer_role", fmt.Sprintf("%s admin=%v operator=%v", peerLabel(p), p.Admin, p.Operator), "ok")
	}
	s.endUISessionsIfLess(r.Context(), current, p)
	if p.Suspended { // the binding ends with it; the machine's approval alone does not touch it
		_ = s.cfg.Store.DeleteSSOToken(r.Context(), p.ID, "")
	}
	writeJSON(w, http.StatusOK, peerInfo(p))
}

// handleSuspendUser suspends (or resumes) every device a user signed in on, e.g. when they leave:
// all of them lose their access at once, and no sign-in restores it until resumed. Operators reach
// only the devices they may change; the caller's own device is never suspended. Only this network's
// own sign-ins count: a namesake admitted through a linked network is someone else (their authority,
// or the device itself, is suspended instead).
func (s *Server) handleSuspendUser(w http.ResponseWriter, r *http.Request, self store.Peer) {
	var req api.SuspendUserRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || strings.TrimSpace(req.User) == "" {
		writeErr(w, http.StatusBadRequest, "invalid request: name the user")
		return
	}
	if req.Suspended && self.UserName != "" && (strings.EqualFold(req.User, self.UserName) || req.User == self.User) {
		writeErr(w, http.StatusConflict, "not your own devices: another admin does that")
		return
	}
	peers, err := s.cfg.Store.Peers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	action := "user_suspended"
	if !req.Suspended {
		action = "user_resumed"
	}
	res := api.SuspendUserResult{User: req.User, Changed: []api.PeerInfo{}, Skipped: []api.SkippedDevice{}}
	var names []string
	for _, p := range peers {
		if p.Authority != "" || !(p.User == req.User || (p.UserName != "" && strings.EqualFold(p.UserName, req.User))) {
			continue
		}
		skip := func(reason string) {
			res.Skipped = append(res.Skipped, api.SkippedDevice{ID: p.ID, Hostname: p.Hostname, Reason: reason})
		}
		switch {
		case p.ID == self.ID:
			skip("the calling device")
			continue
		case !mayOperate(self, p):
			skip("an admin or operator device: only admins change it")
			continue
		case p.Suspended == req.Suspended:
			skip("already " + map[bool]string{true: "suspended", false: "not suspended"}[req.Suspended])
			continue
		}
		suspended := req.Suspended
		updated, err := s.cfg.Store.UpdatePeer(r.Context(), p.ID, store.PeerUpdate{Suspended: &suspended})
		if err != nil {
			skip("not changed: " + err.Error())
			continue
		}
		if req.Suspended {
			_ = s.cfg.Store.DeleteSSOToken(r.Context(), p.ID, "")
			s.endUISessionsIfLess(r.Context(), p, updated)
		}
		if !suspended {
			s.restartCheckIns(r.Context(), p.ID)
		}
		res.Changed = append(res.Changed, peerInfo(updated))
		names = append(names, updated.Hostname)
	}
	if len(res.Changed) == 0 && len(res.Skipped) == 0 {
		writeErr(w, http.StatusNotFound, "no device of that user")
		return
	}
	result := "ok"
	if len(res.Changed) == 0 {
		result = "denied"
	}
	s.audit(r, &self, action, fmt.Sprintf("user=%s devices=%s skipped=%d", req.User, strings.Join(names, ","), len(res.Skipped)), result)
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleDeletePeer(w http.ResponseWriter, r *http.Request, self store.Peer) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if id == self.ID {
		writeErr(w, http.StatusBadRequest, "an admin cannot delete itself")
		return
	}
	if err := s.cfg.Store.DeletePeer(r.Context(), id); err != nil {
		s.respondStoreErr(w, err)
		return
	}
	s.audit(r, &self, "peer_deleted", fmt.Sprintf("peer %d", id), "ok")
	s.checkVersion(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request, _ store.Peer) {
	pols, err := s.cfg.Store.Policies(r.Context())
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	out := make([]api.Policy, 0, len(pols))
	for _, p := range pols {
		out = append(out, apiPolicy(p))
	}
	writeJSON(w, http.StatusOK, out)
}

// handleAddPolicy adds a policy. Requiring posture checks is for admins: operators add policies
// without checks only.
func (s *Server) handleAddPolicy(w http.ResponseWriter, r *http.Request, self store.Peer) {
	var req api.Policy
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || req.Source == "" || req.Destination == "" {
		writeErr(w, http.StatusBadRequest, "source and destination are required")
		return
	}
	for _, g := range []*string{&req.Source, &req.Destination} {
		resolved, err := s.resolveRuleGroup(r.Context(), *g)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		*g = resolved
	}
	if err := checkGroups([]string{req.Source, req.Destination}, true); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.keepGroups(r.Context(), []string{req.Source, req.Destination})
	if err := s.checkPolicyRoute(r.Context(), store.Policy{Source: req.Source, Destination: req.Destination}); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	checks, err := postureNames(req.Posture)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	rules, err := policyPorts(req.Ports)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	candidate := store.Policy{Source: req.Source, Destination: req.Destination, Posture: checks, OneWay: req.OneWay, Ports: rules}
	if len(checks) > 0 && !self.Admin {
		s.audit(r, &self, "policy_added", policyLabel(candidate), "denied")
		writeErr(w, http.StatusForbidden, "only admins attach posture checks to policies")
		return
	}
	all, err := s.cfg.Store.Policies(r.Context())
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	if !self.Admin {
		// Operators cannot make an admin's checks moot with a policy of their own.
		for _, o := range all {
			if bypasses(candidate, o) {
				s.audit(r, &self, "policy_added", fmt.Sprintf("%s (would bypass policy %d)", policyLabel(candidate), o.ID), "denied")
				writeErr(w, http.StatusForbidden, fmt.Sprintf("policy %d requires posture checks (%s) of devices this policy would connect without them: only admins add it",
					o.ID, strings.Join(o.Posture, ",")))
				return
			}
		}
	}
	p, err := s.cfg.Store.AddPolicy(r.Context(), candidate)
	if noSuchCheck(w, err) {
		return
	}
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	if !slices.Equal(p.Posture, checks) {
		writeErr(w, http.StatusConflict, fmt.Sprintf("policy %d between these groups exists, requiring other posture checks (%s): change its checks instead",
			p.ID, strings.Join(p.Posture, ",")))
		return
	}
	if p.OneWay != candidate.OneWay || !slices.Equal(p.Ports, candidate.Ports) {
		writeErr(w, http.StatusConflict, fmt.Sprintf("%s exists with another direction or other ports: change its rules instead",
			policyLabel(p)))
		return
	}
	s.audit(r, &self, "policy_added", policyLabel(p), "ok")
	if len(checks) > 0 {
		s.postureChanged(r.Context())
	}
	out := apiPolicy(p)
	out.Warnings = append(policyWarnings(p, all), s.enforcementWarnings(r.Context(), p)...)
	writeJSON(w, http.StatusCreated, out)
}

// handleSetPolicyRules changes a policy's direction and ports. Operators may, as they may remove the
// policy and add it again, except for a policy that requires posture checks (as for removing it).
func (s *Server) handleSetPolicyRules(w http.ResponseWriter, r *http.Request, self store.Peer) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req api.PolicyRulesRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	rules, err := policyPorts(req.Ports)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	before, err := s.policyByID(r.Context(), id)
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	if len(before.Posture) > 0 && !self.Admin {
		s.audit(r, &self, "policy_rules", policyLabel(before), "denied")
		writeErr(w, http.StatusForbidden, "only admins change a policy that requires posture checks")
		return
	}
	p, err := s.cfg.Store.SetPolicyRules(r.Context(), id, req.OneWay, rules)
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	s.audit(r, &self, "policy_rules", fmt.Sprintf("%s (was %s)", policyLabel(p), policyLabel(before)), "ok")
	s.checkVersion(r.Context())
	out := apiPolicy(p)
	out.Warnings = s.enforcementWarnings(r.Context(), p)
	writeJSON(w, http.StatusOK, out)
}

// handleDeletePolicy removes a policy. One that requires posture checks only admins remove:
// operators could otherwise replace it with one without them.
func (s *Server) handleDeletePolicy(w http.ResponseWriter, r *http.Request, self store.Peer) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p, err := s.policyByID(r.Context(), id)
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	if len(p.Posture) > 0 && !self.Admin {
		s.audit(r, &self, "policy_deleted", policyLabel(p), "denied")
		writeErr(w, http.StatusForbidden, "only admins remove a policy that requires posture checks")
		return
	}
	if err := s.cfg.Store.DeletePolicy(r.Context(), id); err != nil {
		s.respondStoreErr(w, err)
		return
	}
	s.audit(r, &self, "policy_deleted", policyLabel(p), "ok")
	w.WriteHeader(http.StatusNoContent)
}

// loginInterval is the least time between two sign-ins started by one device. A variable for tests.
var loginInterval = 5 * time.Second

func (s *Server) loginAllowed(id int64, now time.Time) bool {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	if s.loginStarts == nil {
		s.loginStarts = map[int64]time.Time{}
	}
	if last, ok := s.loginStarts[id]; ok && now.Sub(last) < loginInterval {
		return false
	}
	for k, t := range s.loginStarts { // forget old starts, so the map stays small
		if now.Sub(t) > time.Hour {
			delete(s.loginStarts, k)
		}
	}
	s.loginStarts[id] = now
	return true
}

func (s *Server) handleLoginStart(w http.ResponseWriter, r *http.Request, self store.Peer) {
	if s.oidc == nil {
		writeErr(w, http.StatusNotImplemented, "SSO is not configured on this deployment")
		return
	}
	if self.Suspended { // unreachable while suspended devices are no WireGuard peers; kept as a guard
		writeErr(w, http.StatusForbidden, "the device is suspended")
		return
	}
	// Signing in opens the device's person layer with its person's rights, on top of what its
	// machine layer has (0.27: a laptop approved by its token, in group laptops, stays connected
	// without anyone signed in). A device admitted through a linked network has its rights from that
	// network's authority alone.
	if self.Authority != "" {
		writeErr(w, http.StatusForbidden, "devices admitted through a linked network do not sign in here")
		return
	}
	// Each start asks the identity provider for a device code: one every few seconds per device.
	if !s.loginAllowed(self.ID, time.Now()) {
		writeErr(w, http.StatusTooManyRequests, "a sign-in was started moments ago; wait a few seconds")
		return
	}
	start, err := s.oidc.start(r.Context(), self.ID, func(c idClaims, refreshToken string) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		p, err := applyLogin(ctx, s.cfg.Store, s.oidc.cfg, self.ID, c)
		if err != nil {
			s.cfg.Logf("sso login for peer %d: %v", self.ID, err)
			return
		}
		s.keepSSOToken(ctx, p.ID, c.Subject, refreshToken)
		s.cfg.Logf("sso: peer %d %s is now %q (approved=%v admin=%v operator=%v groups=%q)", p.ID, p.Hostname, p.UserName,
			p.Approved, p.Admin, p.Operator, p.Groups)
		// Whose device it was: a sign-in that binds a device to a person for the first time, or to
		// another person, and makes it an admin or operator device is how a phished sign-in (someone
		// signing in with a link another device asked for) shows; the SIEM raises it.
		binding := "same"
		switch {
		case self.User == "":
			binding = "new"
		case self.User != c.Subject:
			binding = "changed"
		}
		// The format is read by the SIEM (binding=... ends the line).
		s.audit(nil, &p, "login", fmt.Sprintf("%s approved=%v admin=%v operator=%v groups=%s binding=%s", peerLabel(p), p.Approved, p.Admin,
			p.Operator, strings.Join(p.Groups, ","), binding), "ok")
		s.checkVersion(ctx)
	})
	if err != nil {
		s.cfg.Logf("sso login start: %v", err)
		writeErr(w, http.StatusBadGateway, "identity provider unavailable")
		return
	}
	writeJSON(w, http.StatusOK, start)
}

func (s *Server) handleLoginStatus(w http.ResponseWriter, r *http.Request, self store.Peer) {
	if s.oidc == nil {
		writeErr(w, http.StatusNotImplemented, "SSO is not configured on this deployment")
		return
	}
	l, ok := s.oidc.status(self.ID)
	if !ok {
		writeJSON(w, http.StatusOK, api.LoginStatus{State: "none", Approved: self.Approved, User: self.UserName})
		return
	}
	writeJSON(w, http.StatusOK, api.LoginStatus{State: l.state, User: l.user, Error: l.errMsg, Approved: self.Approved})
}
