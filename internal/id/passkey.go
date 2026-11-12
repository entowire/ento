package id

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"entowire.com/ento/internal/store"
)

// passkeyRecord is what store.IDPasskey.Credential holds: the verifier's record, and the user
// handle the passkey was made with (a person's ID for passkeys made here; another provider's
// handle for passkeys copied from it).
type passkeyRecord struct {
	Credential webauthn.Credential `json:"credential"`
	UserHandle []byte              `json:"user_handle"`
}

// user is a person as the verifier sees them: the handle and the passkeys of one sign-in.
type user struct {
	person store.IDPerson
	handle []byte
	creds  []webauthn.Credential
}

func (u *user) WebAuthnID() []byte                         { return u.handle }
func (u *user) WebAuthnName() string                       { return u.person.Email }
func (u *user) WebAuthnDisplayName() string                { return personName(u.person) }
func (u *user) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// ceremony is a passkey ceremony under way: what it is for and the verifier's session. A sign-in
// after a password names its person (and the password step); a discoverable one does not.
type ceremony struct {
	goal
	Purpose  string               `json:"purpose"`            // "signin", "setup" or "account" (a passkey added)
	Person   string               `json:"person,omitempty"`   // whose passkey (setup, account, after a password)
	Password string               `json:"password,omitempty"` // the password step it completes
	Setup    string               `json:"setup,omitempty"`    // setup: the link's key
	Session  webauthn.SessionData `json:"session"`
}

// errNoAccess: the passkey is unknown, or its person may not sign in.
var errNoAccess = errors.New("no access")

// signIn verifies a passkey assertion and returns the person, after recording the passkey's use. A
// disabled person's passkey is refused like an unknown one, and so is another's than the person
// a sign-in after a password names (c.Person).
func (p *Provider) signIn(ctx context.Context, c ceremony, raw json.RawMessage) (store.IDPerson, error) {
	parsed, err := protocol.ParseCredentialRequestResponseBytes(raw)
	if err != nil {
		return store.IDPerson{}, fmt.Errorf("unreadable passkey answer: %w", err)
	}
	var found store.IDPasskey
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		k, err := p.cfg.Store.IDPasskey(ctx, rawID)
		if err != nil {
			return nil, errNoAccess
		}
		var rec passkeyRecord
		if err := json.Unmarshal(k.Credential, &rec); err != nil {
			return nil, err
		}
		person, err := p.cfg.Store.IDPerson(ctx, k.PersonID)
		if err != nil || person.Disabled || c.Person != "" && person.ID != c.Person {
			return nil, errNoAccess
		}
		found = k
		return &user{person: person, handle: rec.UserHandle, creds: []webauthn.Credential{rec.Credential}}, nil
	}
	u, cred, err := p.wa.ValidatePasskeyLogin(handler, c.Session, parsed)
	if err != nil {
		return store.IDPerson{}, err
	}
	person := u.(*user).person
	if cred.Authenticator.CloneWarning {
		return person, fmt.Errorf("passkey %q of %s: its counter went back, so it may have been copied", found.Name, person.Email)
	}
	rec, err := json.Marshal(passkeyRecord{Credential: *cred, UserHandle: u.WebAuthnID()})
	if err != nil {
		return store.IDPerson{}, err
	}
	if err := p.cfg.Store.UseIDPasskey(ctx, found.CredentialID, rec, p.cfg.Now()); err != nil {
		return store.IDPerson{}, err
	}
	return person, nil
}

// passkeyBegin starts a passkey sign-in (discoverable: the passkey names its person) for a goal.
func (p *Provider) passkeyBegin(w http.ResponseWriter, r *http.Request) {
	var g goal
	if !readJSON(w, r, &g) {
		return
	}
	if !p.allow(r) {
		fail(w, http.StatusTooManyRequests, "Too many attempts. Wait a minute and try again.")
		return
	}
	if msg := p.checkGoal(r, &g); msg != "" {
		fail(w, http.StatusGone, msg)
		return
	}
	assertion, session, err := p.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		p.cfg.Logf("identity provider: passkey sign-in: %v", err)
		fail(w, http.StatusInternalServerError, "The sign-in could not start.")
		return
	}
	id := secret(24)
	if err := p.putState(r.Context(), "ceremony:"+id, kindCeremony, "", ceremony{goal: g, Purpose: "signin", Session: *session}, ceremonyLifetime); err != nil {
		fail(w, http.StatusServiceUnavailable, "The sign-in could not start. Try again in a moment.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ceremony": id, "publicKey": assertion.Response})
}

// passkeyFinish checks the passkey and goes on with the goal: a passkey alone where the person's
// groups allow it, or a passkey after their password.
func (p *Provider) passkeyFinish(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Ceremony   string          `json:"ceremony"`
		Credential json.RawMessage `json:"credential"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	var c ceremony
	if _, err := p.getState(r.Context(), "ceremony:"+in.Ceremony, true, &c); err != nil || c.Purpose != "signin" {
		fail(w, http.StatusGone, "This sign-in has expired. Start again.")
		return
	}
	person, err := p.signIn(r.Context(), c, in.Credential)
	if err != nil {
		who := person.Email
		if who == "" {
			who = "unknown passkey"
		}
		p.audit(r, "id_signin", who+": "+err.Error(), "denied")
		fail(w, http.StatusForbidden, "This passkey does not sign anyone in here.")
		return
	}
	a, err := p.access(r.Context(), person)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "Try again in a moment.")
		return
	}
	method := MethodPasskey
	if c.Password != "" {
		// The second step after a password: that step is used now.
		var ps passwordStep
		if _, err := p.getState(r.Context(), "password:"+c.Password, true, &ps); err != nil || ps.Person != person.ID {
			fail(w, http.StatusGone, "This sign-in has expired. Start again.")
			return
		}
		method = MethodPasswordPasskey
	}
	if !a.can(method) {
		p.audit(r, "id_signin", person.Email+": "+method+" is not allowed for this account", "denied")
		msg := "This way of signing in is not allowed for your account."
		if method == MethodPasskey && a.can(MethodPasswordPasskey) {
			msg = "Your account signs in with your password first, then this passkey."
		}
		fail(w, http.StatusForbidden, msg)
		return
	}
	p.complete(w, r, c.goal, person, method)
}

// passkeyName is a name for a new passkey, from what the browser says it runs on.
func passkeyName(ua string) string {
	ua = strings.ToLower(ua)
	switch {
	case strings.Contains(ua, "android"):
		return "Android"
	case strings.Contains(ua, "iphone"):
		return "iPhone"
	case strings.Contains(ua, "ipad"):
		return "iPad"
	case strings.Contains(ua, "windows"):
		return "Windows"
	case strings.Contains(ua, "mac os"):
		return "Mac"
	case strings.Contains(ua, "cros"):
		return "ChromeOS"
	case strings.Contains(ua, "linux"):
		return "Linux"
	}
	return "Passkey"
}
