package control

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"entowire.com/ento/internal/store"
)

// Refresh tokens of signed-in devices (OIDCConfig.TokenKey): kept encrypted, used every
// RefreshInterval to learn from the identity provider whether the user still has access.

const (
	defaultRefreshInterval = 2 * time.Minute
	refreshBatch           = 100
	// unavailableReport: while the provider cannot be asked, an audit line this often (the first at
	// once), so the SIEM can tell a blip from an outage.
	unavailableReport = 10 * time.Minute
)

func (s *Server) refreshInterval() time.Duration {
	if s.cfg.OIDC != nil && s.cfg.OIDC.RefreshInterval > 0 {
		return s.cfg.OIDC.RefreshInterval
	}
	return defaultRefreshInterval
}

// sealToken encrypts a refresh token for one device (AES-256-GCM; the device's ID is bound in, so a
// token copied to another device's row does not open).
func sealToken(key []byte, peerID int64, token string) (string, error) {
	aead, err := tokenAEAD(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nonce, nonce, []byte(token), tokenAAD(peerID))
	return base64.RawStdEncoding.EncodeToString(sealed), nil
}

func openToken(key []byte, peerID int64, sealed string) (string, error) {
	aead, err := tokenAEAD(key)
	if err != nil {
		return "", err
	}
	b, err := base64.RawStdEncoding.DecodeString(sealed)
	if err != nil || len(b) < aead.NonceSize() {
		return "", errors.New("malformed sealed token")
	}
	plain, err := aead.Open(nil, b[:aead.NonceSize()], b[aead.NonceSize():], tokenAAD(peerID))
	if err != nil {
		return "", errors.New("the token does not open with this key")
	}
	return string(plain), nil
}

func tokenAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("the token key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func tokenAAD(peerID int64) []byte {
	return []byte("ento/v1/sso-token/" + strconv.FormatInt(peerID, 10))
}

// keepSSOToken stores the refresh token of a device's sign-in (or forgets the previous one when the
// provider gave none).
func (s *Server) keepSSOToken(ctx context.Context, peerID int64, subject, token string) {
	if s.oidc == nil || len(s.oidc.cfg.TokenKey) == 0 {
		return
	}
	if token == "" {
		_ = s.cfg.Store.DeleteSSOToken(ctx, peerID, "")
		s.cfg.Logf("sso: the identity provider gave peer %d no refresh token: its access ends only with the session limits", peerID)
		return
	}
	if err := s.storeSSOToken(ctx, peerID, subject, token, ""); err != nil {
		s.cfg.Logf("sso: keep refresh token of peer %d: %v", peerID, err)
	}
}

// storeSSOToken seals and stores a device's refresh token, if previous is set only in place of that
// (sealed) one.
func (s *Server) storeSSOToken(ctx context.Context, peerID int64, subject, token, previous string) error {
	sealed, err := sealToken(s.oidc.cfg.TokenKey, peerID, token)
	if err != nil {
		return err
	}
	return s.cfg.Store.SetSSOToken(ctx, store.SSOToken{PeerID: peerID, Subject: subject, Encrypted: sealed,
		NextCheck: time.Now().Add(s.refreshInterval()), Previous: previous})
}

// refreshLoop checks the signed-in devices that are due, a few times a minute.
func (s *Server) refreshLoop(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.refreshDue(ctx)
		}
	}
}

// refreshDue checks every device whose refresh token is due (claimed in the store, so that of
// several control nodes only one checks each device).
func (s *Server) refreshDue(ctx context.Context) {
	now := time.Now()
	due, err := s.cfg.Store.ClaimSSOTokens(ctx, now, now.Add(s.refreshInterval()), refreshBatch)
	if err != nil {
		s.cfg.Logf("sso: refresh tokens: %v", err)
		return
	}
	changed := false
	for _, t := range due {
		if s.refreshDevice(ctx, t) {
			changed = true
		}
	}
	if changed {
		s.checkVersion(ctx)
	}
}

// refreshDevice asks the identity provider about one device's user and applies the answer. It
// reports whether the device's access changed. Every change is conditional on the token and the
// sign-in it was decided for: a device signed in again meanwhile keeps what that sign-in gave it.
func (s *Server) refreshDevice(ctx context.Context, t store.SSOToken) bool {
	p, err := s.peerByID(ctx, t.PeerID)
	if errors.Is(err, store.ErrNotFound) {
		_ = s.cfg.Store.DeleteSSOToken(ctx, t.PeerID, "")
		return false
	}
	if err != nil {
		return false
	}
	// The binding ended (suspended, another person signed in since): nothing to check. A closed
	// person layer is still checked: its rights are kept current, and the refresh keeps the offline
	// token alive for the next time it opens.
	if p.Suspended || p.User != t.Subject {
		_ = s.cfg.Store.DeleteSSOToken(ctx, t.PeerID, t.Encrypted)
		return false
	}
	token, err := openToken(s.oidc.cfg.TokenKey, p.ID, t.Encrypted)
	if err != nil {
		s.cfg.Logf("sso: refresh token of peer %d: %v", p.ID, err)
		_ = s.cfg.Store.DeleteSSOToken(ctx, t.PeerID, t.Encrypted)
		return false
	}
	rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	claims, next, err := s.oidc.refresh(rctx, token)
	cancel()
	var refused *withdrawnError
	switch {
	case errors.As(err, &refused):
		s.providerAvailable()
		return s.withdraw(ctx, p, t, refused.reason)
	case err != nil:
		s.providerUnavailable(err)
		return false
	}
	s.providerAvailable()
	if claims != nil && claims.Subject != p.User {
		return s.withdraw(ctx, p, t, "the refresh token now belongs to another user")
	}
	if next != "" && next != token {
		if err := s.storeSSOToken(ctx, p.ID, p.User, next, t.Encrypted); err != nil {
			if !errors.Is(err, store.ErrChanged) {
				s.cfg.Logf("sso: keep refresh token of peer %d: %v", p.ID, err)
			}
			return false
		}
	}
	if claims == nil { // the provider sent no ID token: the groups are unknown, keep them
		return false
	}
	a := accessOf(s.oidc.cfg, *claims)
	if a.same(p) {
		if login := claims.PreferredUsername; login != p.UserLogin {
			// The username changed, or the device signed in before ento kept it (0.21): no access
			// changes, so no audit line and no withdrawal.
			if _, err := s.cfg.Store.UpdatePeer(ctx, p.ID, store.PeerUpdate{UserLogin: &login, IfLoginAt: &p.LoginAt}); err != nil &&
				!errors.Is(err, store.ErrChanged) {
				s.cfg.Logf("sso: update peer %d: %v", p.ID, err)
			}
		}
		return false
	}
	name, login := claims.name(), claims.PreferredUsername
	u := a.update()
	u.UserName, u.UserLogin, u.IfLoginAt = &name, &login, &p.LoginAt
	updated, err := s.cfg.Store.UpdatePeer(ctx, p.ID, u)
	if err != nil {
		if !errors.Is(err, store.ErrChanged) {
			s.cfg.Logf("sso: update peer %d: %v", p.ID, err)
		}
		return false
	}
	was, now := p.Person, updated.Person
	s.audit(nil, nil, "sso_changed", fmt.Sprintf("%s approved=%v admin=%v operator=%v groups=%s (were approved=%v admin=%v operator=%v groups=%s) session=%s",
		userLabel(updated), now.Approved, now.Admin, now.Operator, strings.Join(now.Groups, ","),
		was.Approved, was.Admin, was.Operator, strings.Join(was.Groups, ","), map[bool]string{true: "open", false: "closed"}[now.Active]), "ok")
	s.endUISessionsIfLess(ctx, p, updated)
	s.dropDeviceAdmin(ctx, updated) // their groups made them an admin while signed in
	return updated.Person.Active || p.Person.Active
}

// withdraw ends a device's session because the identity provider no longer lets its user in, unless
// the device was signed in again meanwhile (its token replaced, or its sign-in time changed): that
// sign-in stands.
func (s *Server) withdraw(ctx context.Context, p store.Peer, t store.SSOToken, reason string) bool {
	if err := s.cfg.Store.DeleteSSOToken(ctx, p.ID, t.Encrypted); err != nil {
		if !errors.Is(err, store.ErrChanged) {
			s.cfg.Logf("sso: withdraw peer %d: %v", p.ID, err)
		}
		return false
	}
	// The person's rights go, and their layer closes; the machine's stay.
	off, none := false, []string{}
	updated, err := s.cfg.Store.UpdatePeer(ctx, p.ID, store.PeerUpdate{PersonApproved: &off, PersonAdmin: &off, PersonOperator: &off,
		PersonGroups: &none, PersonActive: &off, IfLoginAt: &p.LoginAt})
	if err != nil {
		if !errors.Is(err, store.ErrChanged) {
			s.cfg.Logf("sso: withdraw peer %d: %v", p.ID, err)
			// Due again at once, so that the next round tries again.
			_ = s.cfg.Store.SetSSOToken(ctx, store.SSOToken{PeerID: p.ID, Subject: t.Subject, Encrypted: t.Encrypted, NextCheck: time.Now()})
		}
		return false
	}
	s.endUISessionsIfLess(ctx, p, updated)
	s.audit(nil, nil, "sso_withdrawn", fmt.Sprintf("%s (%s)", userLabel(updated), reason), "ok")
	return true
}

func (s *Server) providerUnavailable(err error) {
	now := time.Now()
	if s.idpDownSince.IsZero() {
		s.idpDownSince = now
	}
	if now.Sub(s.idpReported) < unavailableReport {
		return
	}
	s.idpReported = now
	s.cfg.Logf("sso: the identity provider cannot be asked about signed-in devices: %v", err)
	s.audit(nil, nil, "sso_refresh_unavailable", fmt.Sprintf("identity provider unavailable for %s, nothing cut (%v)",
		now.Sub(s.idpDownSince).Round(time.Second), err), "failed")
}

func (s *Server) providerAvailable() {
	if s.idpDownSince.IsZero() {
		return
	}
	s.audit(nil, nil, "sso_refresh_unavailable", fmt.Sprintf("identity provider available again after %s",
		time.Since(s.idpDownSince).Round(time.Second)), "ok")
	s.idpDownSince, s.idpReported = time.Time{}, time.Time{}
}

// userLabel names a device and the user signed in on it, for audit lines about the user.
func userLabel(p store.Peer) string { return fmt.Sprintf("%s user=%s", peerLabel(p), p.UserName) }

// endUISessionsIfLess ends a device's sessions of the admin interface once it lost rights it had: getting
// them back later does not bring an old session back.
func (s *Server) endUISessionsIfLess(ctx context.Context, before, after store.Peer) {
	if (before.Admin && !after.Admin) || (before.Operator && !after.Operator) || (before.Approved && !after.Approved) || after.Suspended {
		if err := s.cfg.Store.DeleteUISessionsOf(ctx, after.ID); err != nil {
			s.cfg.Logf("end admin interface sessions of peer %d: %v", after.ID, err)
		}
	}
}
