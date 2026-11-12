package id

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/websocket"

	"entowire.com/ento/internal/ipam"
	"entowire.com/ento/internal/store"
)

// TestBrowser drives the provider's real pages in headless Chromium, with a virtual authenticator
// (the DevTools protocol's WebAuthn domain): setup, sign-in to an application, the account page, a
// device code from a link, and a password with an app. It runs only where ENTO_TEST_BROWSER names a
// Chromium (or chrome-headless-shell) binary.
func TestBrowser(t *testing.T) {
	bin := os.Getenv("ENTO_TEST_BROWSER")
	if bin == "" {
		t.Skip("ENTO_TEST_BROWSER not set")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	origin := fmt.Sprintf("http://localhost:%d", ln.Addr().(*net.TCPAddr).Port)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	st := store.NewMemory(ipam.Space{Prefix: netip.MustParsePrefix("100.64.0.0/16")})
	p, err := New(Config{Name: "localhost", Title: "Example", Key: key, Store: st, Origin: origin,
		Clients: []Client{{ID: "app", Secret: testSecret, RedirectURIs: []string{origin + "/cb"}, DeviceGrant: true}}})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/", p.Handler())
	mux.HandleFunc("/cb", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "callback") })
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Close()

	b := startBrowser(t, bin)
	ctx := context.Background()

	// Setup with a link: a passkey.
	ana, _ := p.NewPerson(ctx, "ana@example.com", "Ana", "", []string{"staff"})
	link, _, _ := p.SetupLink(ctx, ana.ID, 0, "")
	b.open(origin + "/setup#" + strings.SplitN(link, "#", 2)[1])
	b.waitVisible("setup-go")
	b.click("setup-go")
	b.waitText("done-title", "Your account is ready")
	if keys, _ := st.IDPasskeys(ctx, ana.ID); len(keys) != 1 {
		t.Fatalf("passkeys after setup: %d", len(keys))
	}

	// An application's sign-in: the passkey, then back to the application with a code.
	_, challenge := pkce()
	q := url.Values{"client_id": {"app"}, "redirect_uri": {origin + "/cb"}, "response_type": {"code"}, "scope": {"openid"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {"s1"}}
	b.open(origin + "/authorize?" + q.Encode())
	b.waitVisible("passkey-go")
	b.click("passkey-go")
	b.wait(`location.pathname === "/cb" && new URLSearchParams(location.search).get("code") !== null`)

	// The account page: sign in, set a password.
	b.open(origin + "/account")
	b.waitVisible("passkey-go")
	b.click("passkey-go")
	b.waitText("acct-email", "ana@example.com")
	b.eval(`document.getElementById("acct-password").value = "a long enough password"`)
	b.eval(`document.getElementById("acct-password-form").requestSubmit()`)
	b.waitText("notice", "Password saved.")
	if x, _ := st.IDPerson(ctx, ana.ID); x.Password == "" {
		t.Fatal("no password after the account page")
	}

	// A device code from a link: signed in, then accepted.
	form := url.Values{"client_id": {"app"}, "client_secret": {testSecret}}
	resp, err := http.PostForm(origin+"/device_authorization", form)
	if err != nil {
		t.Fatal(err)
	}
	var da map[string]any
	json.NewDecoder(resp.Body).Decode(&da)
	resp.Body.Close()
	b.open(strings.Replace(da["verification_uri_complete"].(string), p.Issuer(), origin, 1))
	b.waitVisible("passkey-go")
	b.click("passkey-go")
	b.waitVisible("device-accept")
	b.click("device-accept")
	b.waitText("done-title", "Signed in")
	form.Set("grant_type", deviceGrantType)
	form.Set("device_code", da["device_code"].(string))
	if resp, err := http.PostForm(origin+"/token", form); err != nil || resp.StatusCode != 200 {
		t.Fatalf("device token after accepting: %v %v", resp, err)
	}

	// A password and an app (a group that allows only that): setup, then an application's sign-in.
	st.PutIDGroup(ctx, store.IDGroup{Name: "ops", Kind: "people", Signin: []string{MethodPasswordTOTP}})
	op, _ := p.NewPerson(ctx, "op@example.com", "", "", []string{"ops"})
	link, _, _ = p.SetupLink(ctx, op.ID, 0, "")
	b.open(origin + "/setup#" + strings.SplitN(link, "#", 2)[1])
	b.waitVisible("setup-password")
	b.eval(`document.getElementById("setup-password").value = "operator's long password"`)
	b.eval(`document.getElementById("setup-password-form").requestSubmit()`)
	b.waitVisible("setup-totp-code")
	sec, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(b.text("setup-totp-key"))
	if err != nil {
		t.Fatal(err)
	}
	b.eval(fmt.Sprintf(`document.getElementById("setup-totp-code").value = %q`, totpCode(sec, time.Now().Unix()/30)))
	b.eval(`document.getElementById("setup-totp-form").requestSubmit()`)
	b.waitText("done-title", "Your account is ready")

	q.Set("state", "s2")
	b.open(origin + "/authorize?" + q.Encode())
	b.waitVisible("password-show")
	b.click("password-show")
	b.eval(`document.getElementById("email").value = "op@example.com"`)
	b.eval(`document.getElementById("password").value = "operator's long password"`)
	b.eval(`document.getElementById("password-form").requestSubmit()`)
	b.waitVisible("code")
	// The setup used this step's code: the next one.
	b.eval(fmt.Sprintf(`document.getElementById("code").value = %q`, totpCode(sec, time.Now().Unix()/30+1)))
	b.eval(`document.getElementById("second-code").requestSubmit()`)
	b.wait(`location.pathname === "/cb" && new URLSearchParams(location.search).get("state") === "s2"`)
}

// browser is a headless Chromium driven over the DevTools protocol: one page, with a virtual
// passkey authenticator that verifies the user.
type browser struct {
	t       *testing.T
	ws      *websocket.Conn
	session string
	mu      sync.Mutex
	next    int
	waiting map[int]chan map[string]any
}

func startBrowser(t *testing.T, bin string) *browser {
	t.Helper()
	cmd := exec.Command(bin, "--headless", "--no-sandbox", "--remote-debugging-port=0", "--remote-allow-origins=*", "--user-data-dir="+t.TempDir(), "about:blank")
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	var wsURL string
	sc := bufio.NewScanner(stderr)
	for sc.Scan() {
		if u, ok := strings.CutPrefix(sc.Text(), "DevTools listening on "); ok {
			wsURL = u
			break
		}
	}
	go func() {
		for sc.Scan() {
		}
	}()
	if wsURL == "" {
		t.Fatal("the browser did not start")
	}
	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Fatal(err)
	}
	ws.MaxPayloadBytes = 64 << 20
	b := &browser{t: t, ws: ws, waiting: map[int]chan map[string]any{}}
	go b.read()
	tgt := b.send("", "Target.createTarget", map[string]any{"url": "about:blank"})
	att := b.send("", "Target.attachToTarget", map[string]any{"targetId": tgt["targetId"], "flatten": true})
	b.session = att["sessionId"].(string)
	b.send(b.session, "Page.enable", nil)
	b.send(b.session, "WebAuthn.enable", nil)
	b.send(b.session, "WebAuthn.addVirtualAuthenticator", map[string]any{"options": map[string]any{
		"protocol": "ctap2", "transport": "internal", "hasResidentKey": true, "hasUserVerification": true,
		"isUserVerified": true, "automaticPresenceSimulation": true}})
	return b
}

func (b *browser) read() {
	for {
		var msg map[string]any
		if err := websocket.JSON.Receive(b.ws, &msg); err != nil {
			return
		}
		id, ok := msg["id"].(float64)
		if !ok {
			continue
		}
		b.mu.Lock()
		ch := b.waiting[int(id)]
		delete(b.waiting, int(id))
		b.mu.Unlock()
		if ch != nil {
			ch <- msg
		}
	}
}

func (b *browser) send(session, method string, params map[string]any) map[string]any {
	b.t.Helper()
	b.mu.Lock()
	b.next++
	id := b.next
	ch := make(chan map[string]any, 1)
	b.waiting[id] = ch
	b.mu.Unlock()
	msg := map[string]any{"id": id, "method": method, "params": params}
	if params == nil {
		msg["params"] = map[string]any{}
	}
	if session != "" {
		msg["sessionId"] = session
	}
	if err := websocket.JSON.Send(b.ws, msg); err != nil {
		b.t.Fatal(err)
	}
	select {
	case r := <-ch:
		if e, ok := r["error"]; ok {
			b.t.Fatalf("%s: %v", method, e)
		}
		res, _ := r["result"].(map[string]any)
		return res
	case <-time.After(20 * time.Second):
		b.t.Fatalf("%s: no answer", method)
		return nil
	}
}

// eval runs an expression in the page and returns its value.
func (b *browser) eval(expr string) any {
	b.t.Helper()
	r := b.send(b.session, "Runtime.evaluate", map[string]any{"expression": expr, "awaitPromise": true, "returnByValue": true})
	if ex, ok := r["exceptionDetails"]; ok {
		b.t.Fatalf("%s: %v", expr, ex)
	}
	res, _ := r["result"].(map[string]any)
	return res["value"]
}

func (b *browser) open(u string) {
	b.t.Helper()
	if r := b.send(b.session, "Page.navigate", map[string]any{"url": u}); r["errorText"] != nil {
		b.t.Fatalf("open %s: %v", u, r["errorText"])
	}
	b.wait(`document.readyState === "complete"`)
}

// wait waits until cond is true in the page, and fails with the page's error line if it never is.
func (b *browser) wait(cond string) {
	b.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		r := b.send(b.session, "Runtime.evaluate", map[string]any{"expression": "!!(" + cond + ")", "returnByValue": true})
		if res, _ := r["result"].(map[string]any); res["value"] == true {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	b.t.Fatalf("never true: %s (page error: %v, at %v)", cond,
		b.eval(`(document.getElementById("error")||{}).textContent`), b.eval(`location.href`))
}

func (b *browser) waitVisible(id string) {
	b.t.Helper()
	b.wait(fmt.Sprintf(`(() => { const e = document.getElementById(%q); return e && e.offsetParent !== null })()`, id))
}

func (b *browser) waitText(id, text string) {
	b.t.Helper()
	b.wait(fmt.Sprintf(`(() => { const e = document.getElementById(%q); return e && e.offsetParent !== null && e.textContent.includes(%q) })()`, id, text))
}

func (b *browser) click(id string) {
	b.t.Helper()
	b.eval(fmt.Sprintf(`document.getElementById(%q).click()`, id))
}

func (b *browser) text(id string) string {
	b.t.Helper()
	s, _ := b.eval(fmt.Sprintf(`document.getElementById(%q).textContent`, id)).(string)
	return s
}
