package control

import (
	"crypto/rand"
	"encoding/json"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"entowire.com/ento/internal/store"
)

// Signing in on the admin interface (0.49): besides approving the page's code from the device
// (ento admin ui), a person opens it by signing in with the network's identity provider, as for
// any web application (authorization code with PKCE, the control nodes' own client). It opens only
// for the person signed in on that device in ento right now, on a device that may administer, and
// lasts only while they stay signed in there: a program on the device that reaches the page from its
// address still lacks the browser's sign-in, and a new one takes the person's passkey.
const (
	uiSignInPath   = "/ui/signin"
	uiCallbackPath = "/ui/callback"
	// uiSignInCookie holds the sign-in's state and PKCE verifier while it runs: Lax, so the
	// provider's redirect back brings it; nothing kept on a control node, so either may finish it.
	uiSignInCookie   = "__Host-ento-admin-signin"
	uiSignInLifetime = 10 * time.Minute
)

// personSignedIn reports whether the person (the provider's subject) is signed in on the device in
// ento now, with an approved session.
func personSignedIn(p store.Peer, subject string) bool {
	return subject != "" && p.User == subject && p.Person.Active && p.Person.Approved && !p.Suspended
}

// personHasRole: the person signed in on the device administers, operates or views by their own
// groups (the device's role never counts for a sign-in).
func (s *Server) personHasRole(p store.Peer) bool {
	pl := p.Person
	return pl.Active && pl.Approved && (pl.Admin || pl.Operator || intersects(pl.Groups, s.viewerGroups()))
}

func (s *Server) withSignIn(st uiState, device store.Peer) uiState {
	if s.oidc == nil {
		return st
	}
	st.SignIn = true
	if device.User != "" && device.Person.Active {
		st.Person = device.UserName
	}
	return st
}

func uiRandom() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// uiPage answers a browser navigation with a short plain page (no script: the interface's own page
// shows the state).
func uiPage(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	io.WriteString(w, msg+"\n")
}

func (s *Server) uiSignIn(w http.ResponseWriter, r *http.Request, device store.Peer) {
	if s.oidc == nil {
		uiPage(w, http.StatusNotFound, "This network has no identity provider: approve the page from this device (sudo ento admin ui).")
		return
	}
	if device.User == "" || !device.Person.Active {
		uiPage(w, http.StatusForbidden, "Nobody is signed in on this device: sign in on it first (sudo ento agent login, or the app), then sign in here.")
		return
	}
	d, err := s.oidc.discover(r.Context())
	if err != nil || d.AuthorizationEndpoint == "" {
		s.cfg.Logf("admin interface sign-in: %v", err)
		uiPage(w, http.StatusBadGateway, "The sign-in cannot be reached now: try again in a moment.")
		return
	}
	if !s.personHasRole(device) {
		s.audit(r, &device, "admin_ui_signin", "the person signed in on the device has no role", "denied")
		uiPage(w, http.StatusForbidden, "The person signed in on this device is neither an admin, an operator nor a viewer.")
		return
	}
	// A fresh sign-in every time (prompt=login, max_age=0): the provider's open session does not
	// open the dashboard (constitution 2.5). The nonce and the start time come back in the ID token.
	state, verifier, nonce := uiRandom(), uiRandom(), uiRandom()
	start := strconv.FormatInt(time.Now().Unix(), 10)
	http.SetCookie(w, &http.Cookie{Name: uiSignInCookie, Value: state + "." + verifier + "." + nonce + "." + start, Path: "/", Secure: true,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(uiSignInLifetime / time.Second)})
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"response_type": {"code"}, "client_id": {s.oidc.cfg.ClientID}, "redirect_uri": {s.uiRedirect()},
		"scope": {"openid email profile"}, "state": {state}, "nonce": {nonce}, "prompt": {"login"}, "max_age": {"0"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	if device.UserLogin != "" {
		q.Set("login_hint", device.UserLogin)
	} else if strings.Contains(device.UserName, "@") {
		q.Set("login_hint", device.UserName)
	}
	sep := "?"
	if strings.Contains(d.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	http.Redirect(w, r, d.AuthorizationEndpoint+sep+q.Encode(), http.StatusFound)
}

func (s *Server) uiRedirect() string { return "https://" + s.cfg.AdminUI + uiCallbackPath }

func (s *Server) uiCallback(w http.ResponseWriter, r *http.Request, device store.Peer) {
	if s.oidc == nil {
		uiPage(w, http.StatusNotFound, "This network has no identity provider.")
		return
	}
	c, err := r.Cookie(uiSignInCookie)
	http.SetCookie(w, &http.Cookie{Name: uiSignInCookie, Value: "", Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: -1})
	q := r.URL.Query()
	var parts []string
	if err == nil {
		parts = strings.Split(c.Value, ".")
	}
	if len(parts) != 4 || parts[0] == "" || parts[1] == "" || parts[2] == "" || q.Get("state") != parts[0] {
		s.audit(r, &device, "admin_ui_signin", "state does not match: not started on this page, or expired", "denied")
		uiPage(w, http.StatusBadRequest, "This sign-in expired or did not start on this page: open the admin page again.")
		return
	}
	verifier, nonce := parts[1], parts[2]
	started, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		uiPage(w, http.StatusBadRequest, "This sign-in expired or did not start on this page: open the admin page again.")
		return
	}
	if e := q.Get("error"); e != "" {
		s.audit(r, &device, "admin_ui_signin", "the identity provider refused: "+e, "denied")
		uiPage(w, http.StatusForbidden, "The sign-in was refused ("+e+"): open the admin page again.")
		return
	}
	d, err := s.oidc.discover(r.Context())
	if err != nil {
		uiPage(w, http.StatusBadGateway, "The sign-in cannot be reached now: try again in a moment.")
		return
	}
	var tok struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
	}
	code, err := s.oidc.postForm(r.Context(), d.TokenEndpoint, url.Values{"grant_type": {"authorization_code"},
		"code": {q.Get("code")}, "redirect_uri": {s.uiRedirect()}, "code_verifier": {verifier}}, &tok)
	if err != nil || code != http.StatusOK || tok.IDToken == "" {
		s.audit(r, &device, "admin_ui_signin", fmt.Sprintf("token endpoint: HTTP %d %s", code, tok.Error), "failed")
		uiPage(w, http.StatusBadGateway, "The sign-in did not complete: open the admin page again.")
		return
	}
	claims, err := s.oidc.verifyIDToken(r.Context(), tok.IDToken, nonce)
	if err != nil {
		s.audit(r, &device, "admin_ui_signin", "invalid ID token: "+err.Error(), "denied")
		uiPage(w, http.StatusBadGateway, "The sign-in returned an invalid token.")
		return
	}
	// The person signed in for this page, not before it opened (an old session at the provider).
	var at struct {
		AuthTime *float64 `json:"auth_time"`
	}
	if raw, ok := claims.raw["auth_time"]; ok {
		_ = json.Unmarshal(raw, &at.AuthTime)
	}
	if at.AuthTime == nil || int64(*at.AuthTime) < started-int64(idTokenSkew/time.Second) {
		s.audit(r, &device, "admin_ui_signin", "the identity provider did not ask for a fresh sign-in (auth_time)", "denied")
		uiPage(w, http.StatusForbidden, "The sign-in was not fresh: open the admin page again and sign in.")
		return
	}
	if !personSignedIn(device, claims.Subject) || !s.personHasRole(device) {
		on := "nobody"
		if device.User != "" && device.Person.Active {
			on = device.UserName
		}
		s.audit(r, &device, "admin_ui_signin", fmt.Sprintf("signed in as %s, but %s is signed in on the device", claims.name(), on), "denied")
		uiPage(w, http.StatusForbidden, fmt.Sprintf("You signed in as %s, but the person signed in on this device is %s: "+
			"the admin page opens only for them.", claims.name(), on))
		return
	}
	secret, hash, err := uiSecret()
	if err != nil {
		uiPage(w, http.StatusInternalServerError, "internal error")
		return
	}
	now := time.Now()
	u := store.UISession{Hash: hash, PeerID: device.ID, Browser: browserName(r.UserAgent()), Approved: true,
		CreatedAt: now, ExpiresAt: now.Add(uiSessionLifetime), LastUsed: now, Person: claims.Subject}
	if err := s.cfg.Store.CreateUISession(r.Context(), u); err != nil {
		s.cfg.Logf("admin interface sign-in: %v", err)
		uiPage(w, http.StatusServiceUnavailable, "The session could not be opened: try again in a moment.")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: uiCookie, Value: secret, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteStrictMode})
	s.audit(r, &device, "admin_ui_session", peerLabel(device)+" signed in as "+claims.name(), "ok")
	http.Redirect(w, r, "/", http.StatusFound)
}
