package id

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"entowire.com/ento/internal/store"
)

// What the control nodes do with the provider's people (in process; the dashboard's People and
// `ento control person` call these). Changes that cut access take effect at once: a disabled or
// deleted person's refresh and access tokens are gone, so the control nodes' next refresh is
// refused and their devices lose what the sign-in gave them.

// ErrSetUp: a setup link is only for an account that cannot sign in yet (else whoever got the link
// could add a way into an account in use); its passkeys or app must be removed first.
var ErrSetUp = errors.New("the account can sign in already: remove its passkeys or app first")

// NewPerson adds a person, without a passkey. The address is kept in lower case.
func (p *Provider) NewPerson(ctx context.Context, email, given, family string, groups []string) (store.IDPerson, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if at := strings.IndexByte(email, '@'); at < 1 || at == len(email)-1 || strings.ContainsAny(email, " \t\r\n<>\"") || len(email) > 254 {
		return store.IDPerson{}, fmt.Errorf("%q is not an e-mail address", email)
	}
	x := store.IDPerson{ID: hex.EncodeToString(randomBytes(16)), Email: email, GivenName: strings.TrimSpace(given),
		FamilyName: strings.TrimSpace(family), Groups: groups, CreatedAt: p.cfg.Now().UTC()}
	if x.Groups == nil {
		x.Groups = []string{}
	}
	return x, p.cfg.Store.CreateIDPerson(ctx, x)
}

// UpdatePerson changes a person with fn. Disabling them ends their tokens.
func (p *Provider) UpdatePerson(ctx context.Context, id string, fn func(store.IDPerson) (store.IDPerson, error)) (store.IDPerson, error) {
	x, err := p.cfg.Store.UpdateIDPerson(ctx, id, fn)
	if err == nil && x.Disabled {
		err = p.endTokens(ctx, id)
	}
	return x, err
}

// DeletePerson removes a person, their passkeys and everything they were signed in with.
func (p *Provider) DeletePerson(ctx context.Context, id string) error {
	return p.cfg.Store.DeleteIDPerson(ctx, id)
}

// DeletePasskey removes one of a person's passkeys.
func (p *Provider) DeletePasskey(ctx context.Context, person string, credentialID []byte) error {
	return p.cfg.Store.DeleteIDPasskey(ctx, person, credentialID)
}

// ResetPerson takes every way in from the person of an address (passkeys, password, app) and ends
// what they are signed in with, so that a setup link can be made for them.
func (p *Provider) ResetPerson(ctx context.Context, email string) error {
	x, err := p.cfg.Store.IDPersonByEmail(ctx, email)
	if err != nil {
		return fmt.Errorf("%s: %w", email, err)
	}
	keys, err := p.cfg.Store.IDPasskeys(ctx, x.ID)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if err := p.cfg.Store.DeleteIDPasskey(ctx, x.ID, k.CredentialID); err != nil {
			return err
		}
	}
	if _, err := p.cfg.Store.UpdateIDPerson(ctx, x.ID, func(y store.IDPerson) (store.IDPerson, error) {
		y.Password, y.TOTP, y.TOTPStep = "", nil, 0
		return y, nil
	}); err != nil {
		return err
	}
	return p.endTokens(ctx, x.ID)
}

func (p *Provider) endTokens(ctx context.Context, person string) error {
	for _, kind := range []string{kindRefresh, kindAccess, kindCode, kindConfirm} {
		if err := p.cfg.Store.DeleteIDStates(ctx, person, kind); err != nil {
			return err
		}
	}
	return nil
}

// setupLink is what a setup link stands for.
type setupLink struct {
	Person string `json:"person"`
	Next   string `json:"next,omitempty"` // where the browser goes once the passkey is made
}

// SetupLink returns a new one-time link with which a person who cannot sign in yet sets up a way
// their groups allow, valid for life (0: DefaultSetupLink); any earlier link of theirs stops working,
// and a password set with it but never completed goes. next, if not "", is where the browser goes
// afterwards (an https address). The secret is in the link's fragment, which browsers never send: it
// reaches the provider only in the page's own call.
func (p *Provider) SetupLink(ctx context.Context, person string, life time.Duration, next string) (string, time.Time, error) {
	if life <= 0 {
		life = DefaultSetupLink
	}
	if next != "" && !strings.HasPrefix(next, "https://") {
		return "", time.Time{}, errors.New("the next address must be https")
	}
	x, err := p.cfg.Store.IDPerson(ctx, person)
	if err != nil {
		return "", time.Time{}, err
	}
	keys, err := p.cfg.Store.IDPasskeys(ctx, x.ID)
	if err != nil {
		return "", time.Time{}, err
	}
	if setUp(x, len(keys)) {
		return "", time.Time{}, ErrSetUp
	}
	if x.Password != "" {
		if _, err := p.cfg.Store.UpdateIDPerson(ctx, x.ID, func(y store.IDPerson) (store.IDPerson, error) { y.Password = ""; return y, nil }); err != nil {
			return "", time.Time{}, err
		}
	}
	if err := p.cfg.Store.DeleteIDStates(ctx, x.ID, kindSetup); err != nil {
		return "", time.Time{}, err
	}
	s := secret(32)
	if err := p.putState(ctx, "setup:"+hash("setup", s), kindSetup, x.ID, setupLink{Person: x.ID, Next: next}, life); err != nil {
		return "", time.Time{}, err
	}
	return p.Issuer() + "/setup#" + s, p.cfg.Now().Add(life), nil
}

// setupFor reads a setup link's person, and what they set up: the way their groups allow first
// (a passkey before a password and passkey, before a password and app) and its next step.
func (p *Provider) setupFor(w http.ResponseWriter, r *http.Request, sec string) (key string, l setupLink, x store.IDPerson, a access, way, step string, ok bool) {
	key = "setup:" + hash("setup", sec)
	if _, err := p.getState(r.Context(), key, false, &l); err != nil {
		fail(w, http.StatusGone, "This link has expired or was already used. Ask your administrator for a new one.")
		return
	}
	var err error
	if x, err = p.cfg.Store.IDPerson(r.Context(), l.Person); err != nil || x.Disabled {
		fail(w, http.StatusGone, "This account cannot be set up. Ask your administrator.")
		return
	}
	if a, err = p.access(r.Context(), x); err != nil {
		fail(w, http.StatusServiceUnavailable, "Try again in a moment.")
		return
	}
	if setUp(x, len(a.passkeys)) {
		fail(w, http.StatusConflict, "This account is set up already. Sign in with it.")
		return
	}
	for _, m := range Methods {
		if slices.Contains(a.allowed, m) {
			way = m
			break
		}
	}
	switch {
	case way == "":
		fail(w, http.StatusConflict, "No way of signing in is allowed for this account. Ask your administrator.")
		return
	case way != MethodPasskey && x.Password == "":
		step = "password"
	case way == MethodPasswordTOTP:
		step = "totp"
	default:
		step = "passkey"
	}
	return key, l, x, a, way, step, true
}

// setupBegin says what a setup link's person sets up next, and starts it: the passkey's options,
// or a new app's secret (a password is asked for by the page itself).
func (p *Provider) setupBegin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Secret string `json:"secret"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if !p.allow(r) {
		fail(w, http.StatusTooManyRequests, "Too many attempts. Wait a minute and try again.")
		return
	}
	key, _, x, a, way, step, ok := p.setupFor(w, r, in.Secret)
	if !ok {
		return
	}
	out := map[string]any{"email": x.Email, "name": personName(x), "way": way, "step": step}
	switch step {
	case "passkey":
		creation, session, err := p.beginRegistration(x, a.passkeys)
		if err != nil {
			p.cfg.Logf("identity provider: passkey registration: %v", err)
			fail(w, http.StatusInternalServerError, "The setup could not start.")
			return
		}
		id := secret(24)
		if err := p.putState(r.Context(), "ceremony:"+id, kindCeremony, x.ID,
			ceremony{Purpose: "setup", Setup: key, Person: x.ID, Session: *session}, ceremonyLifetime); err != nil {
			fail(w, http.StatusServiceUnavailable, "The setup could not start. Try again in a moment.")
			return
		}
		out["ceremony"], out["publicKey"] = id, creation.Response
	case "totp":
		id, offer, err := p.offerApp(r, x)
		if err != nil {
			fail(w, http.StatusServiceUnavailable, "Try again in a moment.")
			return
		}
		out["app"], out["offer"] = id, offer
	}
	writeJSON(w, http.StatusOK, out)
}

// setupPassword sets the password of a setup link's person, where their way in starts with one.
func (p *Provider) setupPassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Secret   string `json:"secret"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	_, _, x, _, _, step, ok := p.setupFor(w, r, in.Secret)
	if !ok {
		return
	}
	if step != "password" {
		fail(w, http.StatusConflict, "The password is set already.")
		return
	}
	if msg := CheckNewPassword(in.Password); msg != "" {
		fail(w, http.StatusBadRequest, msg)
		return
	}
	h := hashPassword(in.Password)
	if _, err := p.cfg.Store.UpdateIDPerson(r.Context(), x.ID, func(y store.IDPerson) (store.IDPerson, error) { y.Password = h; return y, nil }); err != nil {
		fail(w, http.StatusServiceUnavailable, "Try again in a moment.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// setupDone uses the link and says where the browser goes. A link whose next step is the provider's
// own (an application's authorization request, or a device's code page: the sign-in its device
// started, 0.57) has that step done at once for the person, who just made their way in (method)
// with user verification: one touch, not two.
func (p *Provider) setupDone(w http.ResponseWriter, r *http.Request, key string, x store.IDPerson, what, method string) {
	var l setupLink
	if _, err := p.getState(r.Context(), key, true, &l); err != nil || l.Person != x.ID {
		fail(w, http.StatusGone, "This link has expired or was already used. Ask your administrator for a new one.")
		return
	}
	p.audit(r, "id_setup", x.Email+" "+what, "ok")
	out := map[string]string{"done": "setup", "email": x.Email, "next": l.Next}
	if p.hereOn() && (l.Next == p.cfg.HereOrigin+HerePath || strings.HasPrefix(l.Next, p.cfg.HereOrigin+HerePath+"?")) {
		// A device's own sign-in (an invited device): the person is signed in on it at once, when the
		// account was set up on that device (the link was opened on its own origin).
		out["next"] = ""
		u, _ := url.Parse(l.Next)
		if done, err := p.signInHere(r, x, method, u.Query().Get("then")); err == nil {
			out["done"], out["person"], out["device"], out["next"] = done["done"], done["person"], done["device"], done["next"]
		} else {
			// Set up all the same; signing in on the device is left to the device's own page.
			out["next"] = p.HereURL(u.Query().Get("then"))
		}
	} else if u, err := url.Parse(l.Next); err == nil && l.Next != "" && "https://"+u.Host == p.Issuer() {
		out["next"] = ""
		switch u.Path {
		case "/authorize":
			req, _, known, code, _ := p.checkAuthRequest(u.Query())
			if known && code == "" {
				if to, err := p.codeFor(r, req, x, method); err == nil {
					out["next"] = to
				}
			}
		case "/device":
			uc := normalizeUserCode(u.Query().Get("user_code"))
			if err := p.answerDevice(r, uc, x, p.cfg.Now(), method, true); err == nil {
				p.audit(r, "id_device", x.Email+" code from the setup link of the device that asked, with "+method, "ok")
				out["done"], out["person"] = "device", personName(x)
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// setupFinish keeps the new passkey; the link is then used.
func (p *Provider) setupFinish(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Ceremony   string          `json:"ceremony"`
		Credential json.RawMessage `json:"credential"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	var c ceremony
	if _, err := p.getState(r.Context(), "ceremony:"+in.Ceremony, true, &c); err != nil || c.Purpose != "setup" {
		fail(w, http.StatusGone, "This setup has expired. Open the link again.")
		return
	}
	x, err := p.cfg.Store.IDPerson(r.Context(), c.Person)
	if err != nil || x.Disabled {
		fail(w, http.StatusGone, "This account cannot be set up. Ask your administrator.")
		return
	}
	// Only once the passkey is good is the link used: a failed attempt leaves it for another.
	var l setupLink
	if _, err := p.getState(r.Context(), c.Setup, false, &l); err != nil || l.Person != x.ID {
		fail(w, http.StatusGone, "This link has expired or was already used. Ask your administrator for a new one.")
		return
	}
	name, err := p.addPasskey(r, x, c.Session, in.Credential)
	if err != nil {
		p.audit(r, "id_setup", x.Email+": "+err.Error(), "denied")
		fail(w, http.StatusBadRequest, "The passkey was not accepted.")
		return
	}
	method := MethodPasskey
	if x.Password != "" {
		method = MethodPasswordPasskey
	}
	p.setupDone(w, r, c.Setup, x, "passkey="+name, method)
}

// setupTOTP confirms the new app with a code from it; the link is then used.
func (p *Provider) setupTOTP(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Secret string `json:"secret"`
		App    string `json:"app"`
		Code   string `json:"code"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	key, _, x, _, _, step, ok := p.setupFor(w, r, in.Secret)
	if !ok {
		return
	}
	if step != "totp" {
		fail(w, http.StatusConflict, "Set your password first.")
		return
	}
	sealed, st, err := p.confirmApp(r, x, in.App, in.Code)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := p.cfg.Store.UpdateIDPerson(r.Context(), x.ID, func(y store.IDPerson) (store.IDPerson, error) {
		y.TOTP, y.TOTPStep = sealed, st
		return y, nil
	}); err != nil {
		fail(w, http.StatusServiceUnavailable, "Try again in a moment.")
		return
	}
	p.setupDone(w, r, key, x, "password and authenticator app", MethodPasswordTOTP)
}
