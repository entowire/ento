package id

import (
	"errors"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"entowire.com/ento/internal/store"
)

// goal is what a sign-in is for: an application's authorization request, a device's code, the
// device the browser runs on (here.go), or the person's own account page.
type goal struct {
	Goal     string `json:"goal"`                // "authorize", "device", "here" or "account"
	Request  string `json:"request,omitempty"`   // authorize: the authorization request
	UserCode string `json:"user_code,omitempty"` // device: the device's code
	FromLink bool   `json:"from_link,omitempty"` // device: the code came in a link
	Then     string `json:"then,omitempty"`      // here: what signing in on the device is for (Here.HereSignedIn)
}

// checkGoal says why a sign-in for g cannot start ("": it can), and normalizes it.
func (p *Provider) checkGoal(r *http.Request, g *goal) string {
	switch g.Goal {
	case "authorize":
		var req authRequest
		if _, err := p.getState(r.Context(), "request:"+g.Request, false, &req); err != nil {
			return "This sign-in has expired. Go back to the application and start again."
		}
	case "device":
		g.UserCode = normalizeUserCode(g.UserCode)
		if d, _, err := p.deviceByUserCode(r, g.UserCode); err != nil || d.Status != "pending" {
			return "This code is not known, or has expired. Check it, or start the sign-in on the device again."
		}
	case "here":
		if !p.hereOn() {
			return "Unknown sign-in."
		}
		if _, why := p.cfg.Here.HereDevice(r); why != "" {
			return why
		}
	case "account":
	default:
		return "Unknown sign-in."
	}
	return ""
}

// complete goes on with a goal once the person has signed in with method.
func (p *Provider) complete(w http.ResponseWriter, r *http.Request, g goal, person store.IDPerson, method string) {
	switch g.Goal {
	case "authorize":
		p.finishAuthorize(w, r, g, person, method)
	case "device":
		p.finishDevice(w, r, g, person, method)
	case "here":
		p.finishHere(w, r, g, person, method)
	case "account":
		p.openAccount(w, r, person, method)
	default:
		fail(w, http.StatusBadRequest, "Unknown sign-in.")
	}
}

// passwordStep is a checked password waiting for its second step.
type passwordStep struct {
	goal
	Person string `json:"person"`
}

// passwordStep checks an address and password, and answers with the second steps the person may
// take: a passkey, a code from their app, or both.
func (p *Provider) passwordStep(w http.ResponseWriter, r *http.Request) {
	var in struct {
		goal
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if !p.allow(r) {
		fail(w, http.StatusTooManyRequests, "Too many attempts. Wait a minute and try again.")
		return
	}
	if msg := p.checkGoal(r, &in.goal); msg != "" {
		fail(w, http.StatusGone, msg)
		return
	}
	x, err := p.checkPassword(r.Context(), in.Email, in.Password)
	if err != nil {
		who := x.Email
		if who == "" {
			who = "unknown address"
		}
		p.audit(r, "id_signin", who+": "+err.Error(), "denied")
		fail(w, http.StatusForbidden, err.Error())
		return
	}
	a, err := p.access(r.Context(), x)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "Try again in a moment.")
		return
	}
	var next []string
	if a.can(MethodPasswordPasskey) {
		next = append(next, "passkey")
	}
	if a.can(MethodPasswordTOTP) {
		next = append(next, "totp")
	}
	if len(next) == 0 {
		p.audit(r, "id_signin", x.Email+": no second step this account may use after a password", "denied")
		msg := "This way of signing in is not allowed for your account."
		if a.can(MethodPasskey) {
			msg = "Your account signs in with its passkey: use Sign in with your passkey."
		}
		fail(w, http.StatusForbidden, msg)
		return
	}
	id := secret(24)
	if err := p.putState(r.Context(), "password:"+id, kindPassword, x.ID, passwordStep{goal: in.goal, Person: x.ID}, ceremonyLifetime); err != nil {
		fail(w, http.StatusServiceUnavailable, "Try again in a moment.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"step": id, "next": next})
}

// passwordPasskey starts the passkey that follows a password.
func (p *Provider) passwordPasskey(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Step string `json:"step"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	var ps passwordStep
	if _, err := p.getState(r.Context(), "password:"+in.Step, false, &ps); err != nil {
		fail(w, http.StatusGone, "This sign-in has expired. Start again.")
		return
	}
	assertion, session, err := p.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationPreferred))
	if err != nil {
		fail(w, http.StatusInternalServerError, "The sign-in could not start.")
		return
	}
	id := secret(24)
	c := ceremony{goal: ps.goal, Purpose: "signin", Person: ps.Person, Password: in.Step, Session: *session}
	if err := p.putState(r.Context(), "ceremony:"+id, kindCeremony, ps.Person, c, ceremonyLifetime); err != nil {
		fail(w, http.StatusServiceUnavailable, "Try again in a moment.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ceremony": id, "publicKey": assertion.Response})
}

// passwordTOTP takes the app's code that follows a password.
func (p *Provider) passwordTOTP(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Step string `json:"step"`
		Code string `json:"code"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if !p.allow(r) {
		fail(w, http.StatusTooManyRequests, "Too many attempts. Wait a minute and try again.")
		return
	}
	var ps passwordStep
	if _, err := p.getState(r.Context(), "password:"+in.Step, false, &ps); err != nil {
		fail(w, http.StatusGone, "This sign-in has expired. Start again.")
		return
	}
	x, err := p.cfg.Store.IDPerson(r.Context(), ps.Person)
	if err != nil || x.Disabled || x.TOTP == nil {
		fail(w, http.StatusForbidden, "This account cannot sign in this way.")
		return
	}
	if p.locked(r.Context(), x.ID) {
		fail(w, http.StatusForbidden, errLocked.Error())
		return
	}
	secretKey, err := p.openTOTP(x.ID, x.TOTP)
	if err != nil {
		p.cfg.Logf("identity provider: app secret of %s: %v", x.Email, err)
		fail(w, http.StatusForbidden, "This account's app cannot be used. Ask your administrator.")
		return
	}
	step := checkTOTP(secretKey, in.Code, x.TOTPStep, p.cfg.Now())
	if step == 0 {
		p.failed(r.Context(), x.ID)
		p.audit(r, "id_signin", x.Email+": wrong code from the app", "denied")
		fail(w, http.StatusForbidden, "Wrong code. Type the code your app shows now.")
		return
	}
	// The code is used: a later step only, so it never counts twice (also on the other node).
	if _, err := p.cfg.Store.UpdateIDPerson(r.Context(), x.ID, func(y store.IDPerson) (store.IDPerson, error) {
		if y.TOTPStep >= step {
			return y, errCodeUsed
		}
		y.TOTPStep, y.LastSignIn = step, p.cfg.Now()
		return y, nil
	}); err != nil {
		fail(w, http.StatusForbidden, "This code was used already. Wait for the next one.")
		return
	}
	if _, err := p.getState(r.Context(), "password:"+in.Step, true, &ps); err != nil {
		fail(w, http.StatusGone, "This sign-in has expired. Start again.")
		return
	}
	a, err := p.access(r.Context(), x)
	if err != nil || !a.can(MethodPasswordTOTP) {
		fail(w, http.StatusForbidden, "This way of signing in is not allowed for your account.")
		return
	}
	p.complete(w, r, ps.goal, x, MethodPasswordTOTP)
}

var errCodeUsed = errors.New("code used")
