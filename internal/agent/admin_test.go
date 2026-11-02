package agent

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/reqsig"
)

// The admin client signs every call with the device's key, so the control node it addresses can
// tell the agent (or root) from any other program on the device.
func TestAdminClientSigns(t *testing.T) {
	device, _ := wgtypes.GeneratePrivateKey()
	control, _ := wgtypes.GeneratePrivateKey()
	var verified error
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		k, err := reqsig.ControlKey(control, device.PublicKey())
		if err == nil {
			_, err = reqsig.Verify(r, k, body, time.Now())
		}
		verified = err
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"url":"https://net.example.test/#code=x"}`)
	}))
	defer srv.Close()
	ctl := api.Control{Name: "c1", PublicKey: control.PublicKey().String(), Address: strings.TrimPrefix(srv.URL, "http://")}

	c := &AdminClient{Controls: []api.Control{ctl}, Key: device}
	var l api.AdminUI
	if err := c.Do(context.Background(), "POST", api.PathTokens, api.CreateTokenRequest{Groups: []string{"a"}}, &l); err != nil {
		t.Fatal(err)
	}
	if verified != nil {
		t.Fatalf("signed request refused: %v", verified)
	}
	// Without the key, nothing is signed.
	unsigned := &AdminClient{Controls: []api.Control{ctl}}
	if err := unsigned.Do(context.Background(), "GET", api.PathPeers, nil, nil); err != nil {
		t.Fatal(err)
	}
	if verified != reqsig.ErrUnsigned {
		t.Fatalf("request without a key: %v", verified)
	}
}

// A link's refusal over the device's posture carries the failing checks, which the agent keeps
// for ento agent status until it gets a credential again.
func TestPostureRefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, `{"error":"this device fails the posture checks link acme requires: enc (disk not encrypted)",`+
			`"posture_failing":[{"check":"enc","reason":"disk not encrypted"}]}`)
	}))
	defer srv.Close()
	c := &AdminClient{Controls: []api.Control{{Name: "c1", Address: strings.TrimPrefix(srv.URL, "http://")}}}
	err := c.Do(context.Background(), "POST", api.PathLinks+"/acme/credential", api.LinkCredentialRequest{}, nil)
	failing := PostureRefusal(err)
	if HTTPStatus(err) != http.StatusForbidden || len(failing) != 1 || failing[0] != (api.PostureFailure{Check: "enc", Reason: "disk not encrypted"}) ||
		!strings.Contains(err.Error(), "enc (disk not encrypted)") {
		t.Fatalf("refusal: %v %+v", err, failing)
	}
	if PostureRefusal(io.EOF) != nil {
		t.Fatal("posture failures from an error that is no answer")
	}

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(LinksDir(dir), "acme"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFailing(linkHomeFailingFile(dir, "acme"), failing)
	if got := LinkHomePostureFailing(dir, "acme"); len(got) != 1 || got[0].Reason != "disk not encrypted" {
		t.Fatalf("kept: %+v", got)
	}
	writeFailing(linkHomeFailingFile(dir, "acme"), nil)
	if got := LinkHomePostureFailing(dir, "acme"); got != nil {
		t.Fatalf("not cleared: %+v", got)
	}
}

// homeCredential keeps the home network's answer for ento agent status (the failing checks of a
// refusal over posture, cleared by a credential, untouched when no control node answered) and asks
// for a posture report at once when the refusal was only for want of a recent one.
func TestHomeCredential(t *testing.T) {
	answer := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if answer == "" {
			io.WriteString(w, `{"credential":"c"}`)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, answer)
	}))
	defer srv.Close()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(LinksDir(dir), "acme"), 0o700); err != nil {
		t.Fatal(err)
	}
	file := linkHomeFailingFile(dir, "acme")
	home := &runner{st: State{Controls: []api.Control{{Name: "c1", Address: strings.TrimPrefix(srv.URL, "http://")}}},
		postureWake: make(chan struct{}, 1), started: time.Now().Add(-time.Hour)}
	ctx := context.Background()
	woken := func() bool {
		select {
		case <-home.postureWake:
			return true
		default:
			return false
		}
	}

	// Refused for want of a report: kept, reported at once, worth asking again soon.
	answer = `{"error":"x","posture_failing":[{"check":"enc","reason":"no report in 30m"}]}`
	_, stale, err := homeCredential(ctx, home, "acme", file, api.LinkCredentialRequest{})
	if HTTPStatus(err) != http.StatusForbidden || !stale || !woken() || len(LinkHomePostureFailing(dir, "acme")) != 1 {
		t.Fatalf("stale refusal: %v stale=%v %+v", err, stale, LinkHomePostureFailing(dir, "acme"))
	}
	// Refused over a fact (and a missing report): kept, nothing to report.
	answer = `{"error":"x","posture_failing":[{"check":"enc","reason":"disk not encrypted"},{"check":"fw","reason":"no report"}]}`
	_, stale, err = homeCredential(ctx, home, "acme", file, api.LinkCredentialRequest{})
	if HTTPStatus(err) != http.StatusForbidden || stale || woken() || len(LinkHomePostureFailing(dir, "acme")) != 2 {
		t.Fatalf("refusal over a fact: %v stale=%v %+v", err, stale, LinkHomePostureFailing(dir, "acme"))
	}
	// No control node answers: what was kept stays.
	down := &runner{st: State{Controls: []api.Control{{Name: "c1", Address: "127.0.0.1:1"}}}, postureWake: make(chan struct{}, 1)}
	if _, _, err = homeCredential(ctx, down, "acme", file, api.LinkCredentialRequest{}); err == nil || HTTPStatus(err) != 0 ||
		len(LinkHomePostureFailing(dir, "acme")) != 2 {
		t.Fatalf("no answer: %v %+v", err, LinkHomePostureFailing(dir, "acme"))
	}
	// Refused over something else: nothing about posture is kept.
	answer = `{"error":"not a member of the link's groups"}`
	if _, stale, err = homeCredential(ctx, home, "acme", file, api.LinkCredentialRequest{}); HTTPStatus(err) != http.StatusForbidden || stale ||
		LinkHomePostureFailing(dir, "acme") != nil {
		t.Fatalf("other refusal: %v %+v", err, LinkHomePostureFailing(dir, "acme"))
	}
	// A credential clears it.
	answer = `{"error":"x","posture_failing":[{"check":"enc","reason":"disk not encrypted"}]}`
	homeCredential(ctx, home, "acme", file, api.LinkCredentialRequest{})
	answer = ""
	res, stale, err := homeCredential(ctx, home, "acme", file, api.LinkCredentialRequest{})
	if err != nil || stale || res.Credential != "c" || LinkHomePostureFailing(dir, "acme") != nil {
		t.Fatalf("credential: %v %+v %+v", err, res, LinkHomePostureFailing(dir, "acme"))
	}
}

// awaitReport holds a link's first credential request until the home network took a posture
// report, for a moment after the agent started only.
func TestAwaitReport(t *testing.T) {
	ctx := context.Background()
	a := &runner{started: time.Now()}
	start := time.Now()
	a.awaitReport(ctx, 300*time.Millisecond)
	if d := time.Since(start); d < 250*time.Millisecond || d > 2*time.Second {
		t.Fatalf("waited %s without a report", d)
	}
	start = time.Now()
	a.awaitReport(ctx, 300*time.Millisecond) // that moment is over
	a.started, a.postureAt = time.Now(), time.Now()
	a.awaitReport(ctx, time.Hour) // a report was taken
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Fatalf("waited %s", d)
	}
}
