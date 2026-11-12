package id

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"entowire.com/ento/internal/store"
)

// The account page (https://<Name>/account): what people sign in with, and their own changes to it
// (a password, passkeys, an authenticator app). It opens after a full sign-in, for accountLifetime,
// so every change is made within minutes of one. A change that would leave the person no way in
// their groups allow is refused.

const (
	accountLifetime = 15 * time.Minute
	accountCookie   = "__Host-ento-id"
)

type accountSession struct {
	Person string    `json:"person"`
	Method string    `json:"method"`
	Since  time.Time `json:"since"`
}

// openAccount opens the account page's session for a person who just signed in.
func (p *Provider) openAccount(w http.ResponseWriter, r *http.Request, x store.IDPerson, method string) {
	s := secret(32)
	if err := p.putState(r.Context(), "account:"+hash("account", s), kindAccount, x.ID,
		accountSession{Person: x.ID, Method: method, Since: p.cfg.Now()}, accountLifetime); err != nil {
		fail(w, http.StatusServiceUnavailable, "Try again in a moment.")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: accountCookie, Value: s, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: int(accountLifetime / time.Second)})
	p.audit(r, "id_account", x.Email+" signed in with "+method, "ok")
	writeJSON(w, http.StatusOK, map[string]string{"redirect": "/account"})
}

// account returns the signed-in person of the account page, or answers that there is none.
func (p *Provider) account(w http.ResponseWriter, r *http.Request) (store.IDPerson, access, bool) {
	c, err := r.Cookie(accountCookie)
	var sess accountSession
	if err == nil {
		_, err = p.getState(r.Context(), "account:"+hash("account", c.Value), false, &sess)
	}
	var x store.IDPerson
	if err == nil {
		x, err = p.cfg.Store.IDPerson(r.Context(), sess.Person)
	}
	if err != nil || x.Disabled {
		fail(w, http.StatusUnauthorized, "Sign in first.")
		return x, access{}, false
	}
	a, err := p.access(r.Context(), x)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "Try again in a moment.")
		return x, access{}, false
	}
	return x, a, true
}

func (p *Provider) accountPage(w http.ResponseWriter, r *http.Request) {
	p.page(w, http.StatusOK, pageData{Mode: "account"})
}

func (p *Provider) accountState(w http.ResponseWriter, r *http.Request) {
	x, a, ok := p.account(w, r)
	if !ok {
		return
	}
	keys := []map[string]string{}
	for _, k := range a.passkeys {
		keys = append(keys, map[string]string{"name": k.Name, "created": stamp(k.CreatedAt), "last_used": stamp(k.LastUsed)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"email": x.Email, "name": personName(x), "password": x.Password != "",
		"totp": x.TOTP != nil, "passkeys": keys, "allowed": a.allowed, "has": a.has, "title": p.cfg.Title})
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// keepsAWayIn refuses a change after which the person could not sign in as their groups allow.
func keepsAWayIn(w http.ResponseWriter, a access, after store.IDPerson, passkeys int) bool {
	if slices.ContainsFunc(Has(after, passkeys), func(m string) bool { return slices.Contains(a.allowed, m) }) {
		return true
	}
	fail(w, http.StatusConflict, "After this change you could not sign in any more. Add another way first.")
	return false
}

// accountChange applies fn to the signed-in person, if they keep a way in, and audits it.
func (p *Provider) accountChange(w http.ResponseWriter, r *http.Request, x store.IDPerson, a access, what string, fn func(*store.IDPerson) string) {
	y := x
	if msg := fn(&y); msg != "" {
		fail(w, http.StatusBadRequest, msg)
		return
	}
	if !keepsAWayIn(w, a, y, len(a.passkeys)) {
		return
	}
	if _, err := p.cfg.Store.UpdateIDPerson(r.Context(), x.ID, func(z store.IDPerson) (store.IDPerson, error) {
		z.Password, z.TOTP, z.TOTPStep = y.Password, y.TOTP, y.TOTPStep
		return z, nil
	}); err != nil {
		fail(w, http.StatusServiceUnavailable, "Try again in a moment.")
		return
	}
	p.audit(r, "id_account", x.Email+": "+what, "ok")
	w.WriteHeader(http.StatusNoContent)
}

// accountPassword sets or changes the password ("remove": takes it away).
func (p *Provider) accountPassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Password string `json:"password"`
		Remove   bool   `json:"remove"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	x, a, ok := p.account(w, r)
	if !ok {
		return
	}
	what := "password set"
	if in.Remove {
		what = "password removed"
	}
	p.accountChange(w, r, x, a, what, func(y *store.IDPerson) string {
		if in.Remove {
			y.Password = ""
			return ""
		}
		if msg := CheckNewPassword(in.Password); msg != "" {
			return msg
		}
		y.Password = hashPassword(in.Password)
		return ""
	})
}

// accountPasskeyBegin starts adding a passkey.
func (p *Provider) accountPasskeyBegin(w http.ResponseWriter, r *http.Request) {
	var in struct{}
	if !readJSON(w, r, &in) {
		return
	}
	x, a, ok := p.account(w, r)
	if !ok {
		return
	}
	creation, session, err := p.beginRegistration(x, a.passkeys)
	if err != nil {
		fail(w, http.StatusInternalServerError, "The passkey could not be started.")
		return
	}
	id := secret(24)
	if err := p.putState(r.Context(), "ceremony:"+id, kindCeremony, x.ID, ceremony{Purpose: "account", Person: x.ID, Session: *session}, ceremonyLifetime); err != nil {
		fail(w, http.StatusServiceUnavailable, "Try again in a moment.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ceremony": id, "publicKey": creation.Response})
}

func (p *Provider) accountPasskeyFinish(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Ceremony   string          `json:"ceremony"`
		Credential json.RawMessage `json:"credential"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	x, _, ok := p.account(w, r)
	if !ok {
		return
	}
	var c ceremony
	if _, err := p.getState(r.Context(), "ceremony:"+in.Ceremony, true, &c); err != nil || c.Purpose != "account" || c.Person != x.ID {
		fail(w, http.StatusGone, "This has expired. Start again.")
		return
	}
	name, err := p.addPasskey(r, x, c.Session, in.Credential)
	if err != nil {
		p.audit(r, "id_account", x.Email+": passkey not added: "+err.Error(), "denied")
		fail(w, http.StatusBadRequest, "The passkey was not accepted.")
		return
	}
	p.audit(r, "id_account", x.Email+": passkey "+name+" added", "ok")
	writeJSON(w, http.StatusOK, map[string]string{"name": name})
}

func (p *Provider) accountPasskeyDelete(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	x, a, ok := p.account(w, r)
	if !ok {
		return
	}
	i := slices.IndexFunc(a.passkeys, func(k store.IDPasskey) bool { return k.Name == in.Name })
	if i < 0 {
		fail(w, http.StatusNotFound, "No such passkey.")
		return
	}
	if !keepsAWayIn(w, a, x, len(a.passkeys)-1) {
		return
	}
	if err := p.cfg.Store.DeleteIDPasskey(r.Context(), x.ID, a.passkeys[i].CredentialID); err != nil {
		fail(w, http.StatusServiceUnavailable, "Try again in a moment.")
		return
	}
	p.audit(r, "id_account", x.Email+": passkey "+in.Name+" removed", "ok")
	w.WriteHeader(http.StatusNoContent)
}

// newApp is an app secret offered to a person, waiting for a first code from the app.
type newApp struct {
	Person string `json:"person"`
	Sealed []byte `json:"sealed"`
}

// offerApp makes a new app secret for x and keeps it, sealed, until a code confirms it.
func (p *Provider) offerApp(r *http.Request, x store.IDPerson) (string, totpOffer, error) {
	sec := randomBytes(20)
	id := secret(24)
	err := p.putState(r.Context(), "newapp:"+id, kindNewApp, x.ID, newApp{Person: x.ID, Sealed: p.sealTOTP(x.ID, sec)}, 10*time.Minute)
	return id, p.offerTOTP(x, sec), err
}

// confirmApp takes an offered app secret once a code from it is right: its sealed secret and step.
func (p *Provider) confirmApp(r *http.Request, x store.IDPerson, id, code string) ([]byte, int64, error) {
	var n newApp
	if _, err := p.getState(r.Context(), "newapp:"+id, false, &n); err != nil || n.Person != x.ID {
		return nil, 0, errors.New("This has expired. Start again.")
	}
	sec, err := p.openTOTP(x.ID, n.Sealed)
	if err != nil {
		return nil, 0, err
	}
	step := checkTOTP(sec, code, 0, p.cfg.Now())
	if step == 0 {
		return nil, 0, errors.New("Wrong code. Type the code the app shows now.")
	}
	p.cfg.Store.TakeIDState(r.Context(), "newapp:"+id, p.cfg.Now())
	return n.Sealed, step, nil
}

func (p *Provider) accountTOTPBegin(w http.ResponseWriter, r *http.Request) {
	var in struct{}
	if !readJSON(w, r, &in) {
		return
	}
	x, _, ok := p.account(w, r)
	if !ok {
		return
	}
	id, offer, err := p.offerApp(r, x)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "Try again in a moment.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"app": id, "offer": offer})
}

func (p *Provider) accountTOTPFinish(w http.ResponseWriter, r *http.Request) {
	var in struct {
		App  string `json:"app"`
		Code string `json:"code"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	x, a, ok := p.account(w, r)
	if !ok {
		return
	}
	sealed, step, err := p.confirmApp(r, x, in.App, in.Code)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	what := "authenticator app set up"
	if x.TOTP != nil {
		what = "authenticator app replaced"
	}
	p.accountChange(w, r, x, a, what, func(y *store.IDPerson) string {
		y.TOTP, y.TOTPStep = sealed, step
		return ""
	})
}

func (p *Provider) accountTOTPDelete(w http.ResponseWriter, r *http.Request) {
	var in struct{}
	if !readJSON(w, r, &in) {
		return
	}
	x, a, ok := p.account(w, r)
	if !ok {
		return
	}
	p.accountChange(w, r, x, a, "authenticator app removed", func(y *store.IDPerson) string {
		y.TOTP, y.TOTPStep = nil, 0
		return ""
	})
}

func (p *Provider) accountSignOut(w http.ResponseWriter, r *http.Request) {
	var in struct{}
	if !readJSON(w, r, &in) {
		return
	}
	if c, err := r.Cookie(accountCookie); err == nil {
		p.cfg.Store.TakeIDState(r.Context(), "account:"+hash("account", c.Value), p.cfg.Now())
	}
	http.SetCookie(w, &http.Cookie{Name: accountCookie, Value: "", Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}

// beginRegistration starts making a passkey for x (none of theirs again).
func (p *Provider) beginRegistration(x store.IDPerson, have []store.IDPasskey) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	var exclude []protocol.CredentialDescriptor
	for _, k := range have {
		exclude = append(exclude, protocol.CredentialDescriptor{Type: protocol.PublicKeyCredentialType, CredentialID: k.CredentialID})
	}
	return p.wa.BeginRegistration(&user{person: x, handle: []byte(x.ID)},
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired), webauthn.WithExclusions(exclude))
}

// addPasskey checks a new passkey's answer and keeps it under a free name, which it returns.
func (p *Provider) addPasskey(r *http.Request, x store.IDPerson, session webauthn.SessionData, raw json.RawMessage) (string, error) {
	parsed, err := protocol.ParseCredentialCreationResponseBytes(raw)
	if err != nil {
		return "", fmt.Errorf("unreadable answer: %w", err)
	}
	u := &user{person: x, handle: []byte(x.ID)}
	cred, err := p.wa.CreateCredential(u, session, parsed)
	if err != nil {
		return "", err
	}
	rec, err := json.Marshal(passkeyRecord{Credential: *cred, UserHandle: u.handle})
	if err != nil {
		return "", err
	}
	base := passkeyName(r.UserAgent())
	now := p.cfg.Now().UTC()
	for i := 1; i <= 50; i++ {
		name := base
		if i > 1 {
			name = fmt.Sprintf("%s %d", base, i)
		}
		err = p.cfg.Store.AddIDPasskey(r.Context(), store.IDPasskey{CredentialID: cred.ID, PersonID: x.ID, Name: name, Credential: rec, CreatedAt: now})
		if err == nil {
			return name, nil
		}
		if !errors.Is(err, store.ErrExists) {
			return "", err
		}
		if _, e := p.cfg.Store.IDPasskey(r.Context(), cred.ID); e == nil {
			return "", errors.New("this passkey is registered already")
		}
	}
	return "", err
}
