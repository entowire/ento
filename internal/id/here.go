package id

import (
	"net/http"
	"net/url"
	"strings"

	"entowire.com/ento/internal/store"
)

// Signing in on the device the browser runs on (0.57). Besides its own name, the provider can be
// served on a second origin (Config.HereOrigin) that only the device itself reaches: whoever serves
// it makes sure of that (the control nodes serve it on a port of their own, which every device's
// agent keeps everything it forwards from). A sign-in there (/here) signs the person in on that
// device: the provider makes the tokens of its built-in client (Config.HereClient), as a device
// code's sign-in would, and hands them to Config.Here, which knows the device. Nothing is typed and
// no code travels: the browser being on the device is what a device code stood for.

// Here signs people in on the device a request comes from (Config.Here).
type Here interface {
	// HereDevice names the device r comes from, if a person may sign in on it from there; otherwise
	// why not, for the person.
	HereDevice(r *http.Request) (device, why string)
	// HereSignedIn signs person in on that device with the tokens of the built-in client: a signed
	// ID token and a refresh token. then is what the sign-in was for (Goal.Then; "": the device
	// alone); next is where the browser goes once done ("": it stays, and says so).
	HereSignedIn(r *http.Request, person store.IDPerson, idToken, refreshToken, then string) (next string, err error)
}

// HerePath is the device's own sign-in page.
const HerePath = "/here"

// hereOn reports whether the provider signs people in on devices.
func (p *Provider) hereOn() bool {
	return p.cfg.Here != nil && p.cfg.HereOrigin != "" && p.cfg.HereClient != ""
}

// HereURL is the address of the device's own sign-in ("" when there is none); then says what it is
// for, as Here.HereSignedIn receives it.
func (p *Provider) HereURL(then string) string {
	if !p.hereOn() {
		return ""
	}
	u := p.cfg.HereOrigin + HerePath
	if then != "" {
		u += "?" + url.Values{"then": {then}}.Encode()
	}
	return u
}

// OnHere moves a link of the provider (such as a setup link) to the device's own origin.
func (p *Provider) OnHere(link string) string {
	if !p.hereOn() {
		return link
	}
	if rest, ok := strings.CutPrefix(link, p.Issuer()+"/"); ok {
		return p.cfg.HereOrigin + "/" + rest
	}
	return link
}

// herePage is the device's own sign-in.
func (p *Provider) herePage(w http.ResponseWriter, r *http.Request) {
	if !p.hereOn() {
		p.page(w, http.StatusNotFound, pageData{Mode: "error", Message: "Devices do not sign in here."})
		return
	}
	device, why := p.cfg.Here.HereDevice(r)
	if why != "" {
		p.page(w, http.StatusForbidden, pageData{Mode: "error", Message: why})
		return
	}
	p.page(w, http.StatusOK, pageData{Mode: "here", Device: device})
}

// signInHere signs person in on the device r comes from, after they signed in with method.
func (p *Provider) signInHere(r *http.Request, person store.IDPerson, method, then string) (map[string]string, error) {
	device, why := p.cfg.Here.HereDevice(r)
	if why != "" {
		return nil, &userError{http.StatusForbidden, why}
	}
	c, ok := p.client(p.cfg.HereClient)
	if !ok {
		return nil, &userError{http.StatusInternalServerError, "Devices cannot sign in now."}
	}
	toks, terr := p.tokens(r.Context(), c, refreshGrant{Client: c.ID, Scope: "openid profile email", Person: person.ID,
		AuthTime: p.cfg.Now(), Method: method}, "", "")
	if terr != nil {
		return nil, &userError{http.StatusServiceUnavailable, "Try again in a moment."}
	}
	idToken, _ := toks["id_token"].(string)
	refresh, _ := toks["refresh_token"].(string)
	next, err := p.cfg.Here.HereSignedIn(r, person, idToken, refresh, then)
	if err != nil {
		p.audit(r, "id_here", person.Email+" on "+device+": "+err.Error(), "denied")
		return nil, &userError{http.StatusForbidden, err.Error()}
	}
	p.audit(r, "id_here", person.Email+" signed in on "+device+", with "+method, "ok")
	return map[string]string{"done": "device", "person": personName(person), "device": device, "next": next}, nil
}

// finishHere ends a sign-in on the device's own page.
func (p *Provider) finishHere(w http.ResponseWriter, r *http.Request, g goal, person store.IDPerson, method string) {
	out, err := p.signInHere(r, person, method, g.Then)
	if err != nil {
		e := err.(*userError)
		fail(w, e.status, e.msg)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// userError is a refusal with a message for the person.
type userError struct {
	status int
	msg    string
}

func (e *userError) Error() string { return e.msg }
