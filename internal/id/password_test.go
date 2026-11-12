package id

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"entowire.com/ento/internal/id/idtest"
	"entowire.com/ento/internal/store"
)

func TestPasswordHashes(t *testing.T) {
	h := hashPassword("correct horse battery")
	if ok, err := verifyPassword(h, "correct horse battery"); !ok || err != nil {
		t.Fatalf("own hash: %v %v", ok, err)
	}
	if ok, _ := verifyPassword(h, "correct horse batterY"); ok {
		t.Fatal("a wrong password passed")
	}
	// Rauthy's hashes (its tests' own, m=16384,t=3,p=2) are taken as they are.
	rauthy := "$argon2id$v=19$m=16384,t=3,p=2$l8F0ar1wSQsce+OdPgYbhg$I2XrvC/XRW+22eI2ptBg5GQp3SHjgSQXsfstuTZne1I"
	if _, err := verifyPassword(rauthy, "x"); err != nil {
		t.Fatalf("Rauthy's form: %v", err)
	}
	for _, bad := range []string{"", "$argon2i$v=19$m=1,t=1,p=1$AA$AA", "$argon2id$v=19$m=99999999,t=3,p=2$AAAA$AAAAAAAAAAAAAAAAAAAAAA"} {
		if _, err := verifyPassword(bad, "x"); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	if CheckNewPassword("short") == "" || CheckNewPassword("twelve chars") != "" {
		t.Fatal("password length rules")
	}
}

func TestTOTPCodes(t *testing.T) {
	// RFC 6238's SHA-1 test vectors (8 digits there; the last 6 here).
	sec := []byte("12345678901234567890")
	for at, want := range map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 2000000000: "279037"} {
		if got := totpCode(sec, at/30); got != want {
			t.Fatalf("at %d: %s, want %s", at, got, want)
		}
	}
	now := time.Unix(1234567890, 0)
	if checkTOTP(sec, "005 924", 0, now) == 0 {
		t.Fatal("a valid code with a space was refused")
	}
	if checkTOTP(sec, "005924", 1234567890/30, now) != 0 {
		t.Fatal("a code was taken twice")
	}
}

func TestPolicies(t *testing.T) {
	gs := []store.IDGroup{{Name: "admins", Kind: "people", Signin: []string{MethodPasskey}},
		{Name: "staff", Kind: "people"}, {Name: "d:laptops", Kind: "devices", Signin: []string{MethodPasswordTOTP}}}
	def := []string{MethodPasskey, MethodPasswordTOTP}
	if got := Allowed([]string{"admins", "staff", "d:laptops"}, gs, def); len(got) != 1 || got[0] != MethodPasskey {
		t.Fatalf("admins and staff: %v", got)
	}
	if got := Allowed(nil, gs, def); len(got) != 2 {
		t.Fatalf("no group: %v", got)
	}
}

// totpNow is the code an app shows for a sealed secret.
func (f *fixture) totpNow(x store.IDPerson) string {
	f.t.Helper()
	y, _ := f.st.IDPerson(context.Background(), x.ID)
	sec, err := f.p.openTOTP(y.ID, y.TOTP)
	if err != nil {
		f.t.Fatal(err)
	}
	return totpCode(sec, f.now.Unix()/totpPeriod)
}

// A group that allows only a password and an app: the setup link sets both, sign-in takes both,
// a passkey alone is refused, wrong passwords lock the account's password, not its passkeys.
func TestPasswordAndApp(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.st.PutIDGroup(ctx, store.IDGroup{Name: "ops", Kind: "people", Signin: []string{MethodPasswordTOTP}})
	x, _ := f.p.NewPerson(ctx, "op@example.com", "", "", []string{"ops"})
	link, _, _ := f.p.SetupLink(ctx, x.ID, 0, "")
	s := strings.SplitN(link, "#", 2)[1]
	st := f.call("/setup/begin", map[string]any{"secret": s}, 200)
	if st["step"] != "password" || st["way"] != MethodPasswordTOTP {
		t.Fatalf("setup starts with %v", st)
	}
	f.call("/setup/password", map[string]any{"secret": s, "password": "short"}, 400)
	f.call("/setup/password", map[string]any{"secret": s, "password": "a long enough password"}, 204)
	st = f.call("/setup/begin", map[string]any{"secret": s}, 200)
	if st["step"] != "totp" || !strings.HasPrefix(st["offer"].(map[string]any)["uri"].(string), "otpauth://totp/") ||
		!strings.HasPrefix(st["offer"].(map[string]any)["qr"].(string), "data:image/png;base64,") {
		t.Fatalf("app step: %v", st)
	}
	// The app's secret as the person would scan it.
	var n newApp
	f.p.getState(ctx, "newapp:"+st["app"].(string), false, &n)
	sec, _ := f.p.openTOTP(x.ID, n.Sealed)
	f.call("/setup/totp", map[string]any{"secret": s, "app": st["app"], "code": "000000"}, 400)
	f.call("/setup/totp", map[string]any{"secret": s, "app": st["app"], "code": totpCode(sec, f.now.Unix()/30)}, 200)
	f.call("/setup/begin", map[string]any{"secret": s}, 410)

	// Sign in to an application: the password, then the code.
	_, challenge := pkce()
	req := f.authorize(challenge)
	f.call("/password", map[string]any{"goal": "authorize", "request": req, "email": "op@example.com", "password": "wrong password!"}, 403)
	out := f.call("/password", map[string]any{"goal": "authorize", "request": req, "email": "OP@example.com", "password": "a long enough password"}, 200)
	if next := out["next"].([]any); len(next) != 1 || next[0] != "totp" {
		t.Fatalf("second steps %v", out["next"])
	}
	step := out["step"]
	f.call("/password/totp", map[string]any{"step": step, "code": "123456"}, 403)
	f.now = f.now.Add(31 * time.Second)
	out = f.call("/password/totp", map[string]any{"step": step, "code": f.totpNow(x)}, 200)
	u, _ := url.Parse(out["redirect"].(string))
	if u.Query().Get("code") == "" {
		t.Fatalf("no code: %v", out)
	}
	// The same app code twice: refused.
	req = f.authorize(challenge)
	out = f.call("/password", map[string]any{"goal": "authorize", "request": req, "email": "op@example.com", "password": "a long enough password"}, 200)
	f.call("/password/totp", map[string]any{"step": out["step"], "code": f.totpNow(x)}, 403)

	// Ten wrong passwords lock the password for 15 minutes; the right one is refused meanwhile.
	for range failLimit {
		f.call("/password", map[string]any{"goal": "authorize", "request": req, "email": "op@example.com", "password": "wrong password!"}, 403)
	}
	out = f.call("/password", map[string]any{"goal": "authorize", "request": req, "email": "op@example.com", "password": "a long enough password"}, 403)
	if !strings.Contains(out["error"].(string), "15 minutes") {
		t.Fatalf("locked: %v", out)
	}
	f.now = f.now.Add(failWindow + time.Second)
	f.call("/password", map[string]any{"goal": "authorize", "request": f.authorize(challenge), "email": "op@example.com", "password": "a long enough password"}, 200)
}

// The account page: sign in, add a passkey, set a password, then the group's policy decides what
// may go.
func TestAccountPage(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	x, a := f.person("ana@example.com", "staff")
	// Sign in to the account page with the passkey: a session cookie.
	start := f.call("/passkey/begin", map[string]any{"goal": "account"}, 200)
	b := jsonBody(map[string]any{"ceremony": start["ceremony"], "credential": a.Get(start["publicKey"].(map[string]any))})
	req := httptest.NewRequest("POST", "https://"+testName+"/passkey/finish", b)
	req.Header.Set("Content-Type", "application/json")
	w := f.do(req)
	if w.Code != 200 || len(w.Result().Cookies()) != 1 || w.Result().Cookies()[0].Name != accountCookie || !w.Result().Cookies()[0].HttpOnly {
		t.Fatalf("account sign-in: %d %v", w.Code, w.Result().Cookies())
	}
	cookie := w.Result().Cookies()[0]
	acct := func(path string, in any, want int) map[string]any {
		t.Helper()
		var req *http.Request
		if in == nil {
			req = httptest.NewRequest("GET", "https://"+testName+path, nil)
		} else {
			req = httptest.NewRequest("POST", "https://"+testName+path, jsonBody(in))
			req.Header.Set("Content-Type", "application/json")
		}
		req.AddCookie(cookie)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0)")
		w := f.do(req)
		if w.Code != want {
			t.Fatalf("%s: %d %s, want %d", path, w.Code, w.Body, want)
		}
		return decode(w)
	}
	if f.do(httptest.NewRequest("GET", "https://"+testName+"/account/state", nil)).Code != 401 {
		t.Fatal("the account's state without a session")
	}
	st := acct("/account/state", nil, 200)
	if st["email"] != "ana@example.com" || st["password"] != false || len(st["passkeys"].([]any)) != 1 {
		t.Fatalf("state %v", st)
	}
	// Her only passkey cannot go: she would have no way in.
	acct("/account/passkey/delete", map[string]any{"name": "Android"}, 409)
	// A second passkey, then the first may go.
	b2 := idtest.New(t, testName)
	reg := acct("/account/passkey/begin", map[string]any{}, 200)
	acct("/account/passkey/finish", map[string]any{"ceremony": reg["ceremony"], "credential": b2.Create(reg["publicKey"].(map[string]any))}, 200)
	if keys, _ := f.st.IDPasskeys(ctx, x.ID); len(keys) != 2 || keys[1].Name != "Windows" {
		t.Fatalf("passkeys %+v", keys)
	}
	acct("/account/passkey/delete", map[string]any{"name": "Android"}, 204)
	// A password and an app.
	acct("/account/password", map[string]any{"password": "short"}, 400)
	acct("/account/password", map[string]any{"password": "another long password"}, 204)
	app := acct("/account/totp/begin", map[string]any{}, 200)
	var n newApp
	f.p.getState(ctx, "newapp:"+app["app"].(string), false, &n)
	sec, _ := f.p.openTOTP(x.ID, n.Sealed)
	acct("/account/totp/finish", map[string]any{"app": app["app"], "code": totpCode(sec, f.now.Unix()/30)}, 204)
	// The group now allows only a password and an app: the passkey may go, the app may not.
	f.st.PutIDGroup(ctx, store.IDGroup{Name: "staff", Kind: "people", Signin: []string{MethodPasswordTOTP}})
	acct("/account/totp/delete", map[string]any{}, 409)
	acct("/account/password", map[string]any{"remove": true}, 409)
	acct("/account/passkey/delete", map[string]any{"name": "Windows"}, 204)
	// A passkey alone is no longer enough to sign in anywhere.
	_, challenge := pkce()
	f.signIn(b2, map[string]any{"goal": "authorize", "request": f.authorize(challenge)}, 403)
	acct("/account/signout", map[string]any{}, 204)
	acct("/account/state", nil, 401)
}

func jsonBody(v any) *strings.Reader {
	b, _ := json.Marshal(v)
	return strings.NewReader(string(b))
}

func decode(w *httptest.ResponseRecorder) map[string]any {
	var out map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	return out
}

func TestPasswordThenPasskey(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	x, a := f.person("ana@example.com", "finance")
	_, other := f.person("bo@example.com")
	f.p.UpdatePerson(ctx, x.ID, func(y store.IDPerson) (store.IDPerson, error) {
		y.Password = hashPassword("ana's long password")
		return y, nil
	})
	f.st.PutIDGroup(ctx, store.IDGroup{Name: "finance", Kind: "people", Signin: []string{MethodPasswordPasskey}})
	_, challenge := pkce()
	// The passkey alone: refused, with what to do instead.
	out := f.signIn(a, map[string]any{"goal": "authorize", "request": f.authorize(challenge)}, 403)
	if !strings.Contains(out["error"].(string), "password first") {
		t.Fatalf("passkey alone: %v", out)
	}
	pw := func() any {
		out := f.call("/password", map[string]any{"goal": "authorize", "request": f.authorize(challenge), "email": "ana@example.com", "password": "ana's long password"}, 200)
		if next := out["next"].([]any); len(next) != 1 || next[0] != "passkey" {
			t.Fatalf("second steps %v", out["next"])
		}
		return out["step"]
	}
	// Someone else's passkey after her password: refused.
	f.signInAt(other, "/password/passkey", map[string]any{"step": pw()}, 403)
	out = f.signInAt(a, "/password/passkey", map[string]any{"step": pw()}, 200)
	if !strings.HasPrefix(out["redirect"].(string), testApp+"?") {
		t.Fatalf("redirect %v", out)
	}
}

// signInAt runs a passkey sign-in started at path.
func (f *fixture) signInAt(a *idtest.Authenticator, path string, begin map[string]any, want int) map[string]any {
	f.t.Helper()
	start := f.call(path, begin, 200)
	return f.call("/passkey/finish", map[string]any{"ceremony": start["ceremony"], "credential": a.Get(start["publicKey"].(map[string]any))}, want)
}
