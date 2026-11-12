package id

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"entowire.com/ento/internal/id/idtest"
	"entowire.com/ento/internal/store"
)

const testHere = "https://" + testName + ":4443"

// fakeHere is a device sign-in whose device is the request's X-Device header (the listener a real
// one knows).
type fakeHere struct {
	signedIn []string // person, ID token, refresh token, then
	refuse   error
}

func (h *fakeHere) HereDevice(r *http.Request) (string, string) {
	if d := r.Header.Get("X-Device"); d != "" {
		return d, ""
	}
	return "", "Open this page on the device itself."
}

func (h *fakeHere) HereSignedIn(r *http.Request, x store.IDPerson, idToken, refresh, then string) (string, error) {
	if h.refuse != nil {
		return "", h.refuse
	}
	h.signedIn = []string{x.Email, idToken, refresh, then}
	if then == "ui" {
		return "https://net.example.net/ui/here?t=1", nil
	}
	return "", nil
}

func TestHere(t *testing.T) {
	h := &fakeHere{}
	f := newFixtureWith(t, func(c *Config) { c.Here, c.HereOrigin, c.HereClient = h, testHere, "ento" })
	_, a := f.person("ana@example.com", "admins")
	if got := f.p.HereURL("ui"); got != testHere+"/here?then=ui" {
		t.Fatalf("HereURL %q", got)
	}
	// Not from a device: no page, no sign-in.
	if w := f.do(httptest.NewRequest("GET", testHere+"/here", nil)); w.Code != 403 || !strings.Contains(w.Body.String(), "on the device itself") {
		t.Fatalf("page off the device: %d %s", w.Code, w.Body)
	}
	f.call("/passkey/begin", map[string]any{"goal": "here"}, 410)

	// From the device: the passkey of the provider's name works on its second origin.
	f.h = withDevice(f.p.Handler(), "laptop-1")
	if w := f.do(httptest.NewRequest("GET", testHere+"/here", nil)); w.Code != 200 || !strings.Contains(w.Body.String(), `data-device="laptop-1"`) {
		t.Fatalf("page on the device: %d %s", w.Code, w.Body)
	}
	a.Origin = testHere
	out := f.signIn(a, map[string]any{"goal": "here"}, 200)
	if out["done"] != "device" || out["device"] != "laptop-1" || out["next"] != "" || len(h.signedIn) != 4 || h.signedIn[0] != "ana@example.com" {
		t.Fatalf("here: %v %v", out, h.signedIn)
	}
	c := f.verifyJWT(h.signedIn[1])
	if c["aud"] != "ento" || c["email"] != "ana@example.com" || h.signedIn[2] == "" {
		t.Fatalf("tokens %v", c)
	}
	// The refresh token is the built-in client's, as a device code's would be.
	if code, tok := f.form("/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {h.signedIn[2]},
		"client_id": {"ento"}, "client_secret": {testSecret}}); code != 200 || tok["id_token"] == nil {
		t.Fatalf("refresh: %d %v", code, tok)
	}
	// For the dashboard: the browser goes on to it.
	if out := f.signIn(a, map[string]any{"goal": "here", "then": "ui"}, 200); out["next"] != "https://net.example.net/ui/here?t=1" {
		t.Fatalf("then=ui: %v", out)
	}
	// Refused by the device's side (an invitation for another account): the person is told why.
	h.refuse = errors.New("This device was invited for another account.")
	if out := f.signIn(a, map[string]any{"goal": "here"}, 403); !strings.Contains(out["error"].(string), "invited") {
		t.Fatalf("refused: %v", out)
	}
}

// TestHereSetup: an invited device's setup link, opened on the device's own origin, signs the
// person in on it as it sets the account up.
func TestHereSetup(t *testing.T) {
	h := &fakeHere{}
	f := newFixtureWith(t, func(c *Config) { c.Here, c.HereOrigin, c.HereClient = h, testHere, "ento" })
	ctx := context.Background()
	x, _ := f.p.NewPerson(ctx, "bo@example.com", "", "", nil)
	link, _, err := f.p.SetupLink(ctx, x.ID, 0, f.p.HereURL(""))
	if err != nil {
		t.Fatal(err)
	}
	if link = f.p.OnHere(link); !strings.HasPrefix(link, testHere+"/setup#") {
		t.Fatalf("link %q", link)
	}
	f.h = withDevice(f.p.Handler(), "laptop-2")
	a := idtest.New(t, testName)
	a.Origin = testHere
	start := f.call("/setup/begin", map[string]any{"secret": strings.SplitN(link, "#", 2)[1]}, 200)
	out := f.call("/setup/finish", map[string]any{"ceremony": start["ceremony"], "credential": a.Create(start["publicKey"].(map[string]any))}, 200)
	if out["done"] != "device" || out["device"] != "laptop-2" || len(h.signedIn) == 0 || h.signedIn[0] != "bo@example.com" {
		t.Fatalf("setup: %v %v", out, h.signedIn)
	}
}

func withDevice(h http.Handler, device string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("X-Device", device)
		h.ServeHTTP(w, r)
	})
}
