package control

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"entowire.com/ento/internal/api"
	entoid "entowire.com/ento/internal/id"
	"entowire.com/ento/internal/ipam"
	"entowire.com/ento/internal/store"
)

// TestProviders: full administration names an outside provider once its discovery answers, its
// secret kept sealed; removing it is refused while it is someone's only way in (constitution 4.5).
func TestProviders(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"issuer": srv.URL, "authorization_endpoint": srv.URL + "/auth",
			"token_endpoint": srv.URL + "/token", "jwks_uri": srv.URL + "/jwks"})
	}))
	defer srv.Close()
	space, _ := ipam.New(netip.MustParsePrefix("100.64.0.0/16"))
	st := store.NewMemory(space)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	idp, err := entoid.New(entoid.Config{Name: "id.example.test", Key: k, Store: st, UpstreamHTTP: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	var audit []string
	logf := func(format string, args ...any) { audit = append(audit, fmt.Sprintf(format, args...)) }
	s := &Server{cfg: Config{Logf: logf, Store: st, ID: &IDConfig{Name: "id.example.test", Key: k}}, id: idp, people: &idPeople{p: idp, st: st}}
	admin := store.Peer{Hostname: "admin-laptop", User: "u1", Person: store.PersonLayer{Active: true}}
	call := func(method, name string, body any) (int, string) {
		b, _ := json.Marshal(body)
		r := httptest.NewRequest(method, "/x", bytes.NewReader(b))
		r.SetPathValue("name", name)
		w := httptest.NewRecorder()
		switch method {
		case "PUT":
			s.handleSetProvider(w, r, admin)
		case "DELETE":
			s.handleDeleteProvider(w, r, admin)
		default:
			s.handleListProviders(w, r, admin)
		}
		return w.Code, w.Body.String()
	}
	if code, body := call("PUT", "google", api.SetIDProviderRequest{Title: "Google", Issuer: "http://insecure.example", ClientID: "c", ClientSecret: "s"}); code != 400 {
		t.Fatalf("an http issuer: %d %s", code, body)
	}
	if code, body := call("PUT", "google", api.SetIDProviderRequest{Title: "Google", Issuer: srv.URL + "/other", ClientID: "c", ClientSecret: "s"}); code != http.StatusBadGateway || !strings.Contains(body, "names itself") {
		t.Fatalf("an issuer its discovery does not name: %d %s", code, body)
	}
	if code, body := call("PUT", "google", api.SetIDProviderRequest{Title: "Google", Issuer: srv.URL, ClientID: "c"}); code != 400 {
		t.Fatalf("no secret: %d %s", code, body)
	}
	if code, body := call("PUT", "google", api.SetIDProviderRequest{Title: "Google", Issuer: srv.URL, ClientID: "c", ClientSecret: "s3cret", Domains: []string{"Example.TEST"}}); code != 204 {
		t.Fatalf("add: %d %s", code, body)
	}
	ups, _ := entoid.Upstreams(context.Background(), st)
	if len(ups) != 1 || ups[0].Secret == "" || strings.Contains(ups[0].Secret, "s3cret") || ups[0].Domains[0] != "example.test" {
		t.Fatalf("kept: %+v", ups)
	}
	// A change without a secret keeps the sealed one.
	if code, body := call("PUT", "google", api.SetIDProviderRequest{Title: "Google Workspace", Issuer: srv.URL, ClientID: "c2", Domains: []string{"example.test"}}); code != 204 {
		t.Fatalf("change: %d %s", code, body)
	}
	if after, _ := entoid.Upstreams(context.Background(), st); after[0].Secret != ups[0].Secret || after[0].ClientID != "c2" {
		t.Fatalf("changed: %+v", after)
	}
	code, body := call("GET", "", nil)
	var list api.IDProviders
	json.Unmarshal([]byte(body), &list)
	if code != 200 || len(list.Providers) != 1 || list.RedirectURIs[0] != "https://id.example.test/upstream/callback" || !list.Allowed {
		t.Fatalf("list: %d %s", code, body)
	}

	// Ana can sign in only through it (no passkey, her address in its domain): it stays.
	seed(t, st, "u1", "ana@example.test", []string{"admins"}, true, nil, false, false)
	if code, body := call("DELETE", "google", nil); code != http.StatusConflict || !strings.Contains(body, "ana@example.test") {
		t.Fatalf("remove Ana's only way in: %d %s", code, body)
	}
	// With a passkey of her own, it can go.
	st.AddIDPasskey(context.Background(), store.IDPasskey{CredentialID: []byte("k"), PersonID: "u1", Name: "Key", Credential: []byte("{}"), CreatedAt: time.Now()})
	if code, body := call("DELETE", "google", nil); code != 204 {
		t.Fatalf("remove: %d %s", code, body)
	}
	if ups, _ := entoid.Upstreams(context.Background(), st); len(ups) != 0 {
		t.Fatalf("removed: %+v", ups)
	}
	joined := strings.Join(audit, "\n")
	for _, want := range []string{"action=id_provider", `added" result=ok`, `changed" result=ok`, `the only way in of ana@example.test" result=denied`, `removed" result=ok`} {
		if !strings.Contains(joined, want) {
			t.Errorf("audit lacks %q:\n%s", want, joined)
		}
	}
}
