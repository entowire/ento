package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/agent"
	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/ipam"
	"entowire.com/ento/internal/store"
)

func TestSetAdmin(t *testing.T) {
	ctx := context.Background()
	space, _ := ipam.New(netip.MustParsePrefix("100.64.0.0/16"))
	st := store.NewMemory(space)
	temp, _ := wgtypes.GeneratePrivateKey()
	perm, _ := wgtypes.GeneratePrivateKey()
	tok, err := st.CreateToken(ctx, store.Token{PublicKey: temp.PublicKey(), Name: "ops-laptop", Approve: true,
		ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Redeem(ctx, tok.TempAddress, perm.PublicKey(), "laptop", "linux", time.Now(), nil); err != nil {
		t.Fatal(err)
	}
	if p, err := setAdmin(ctx, st, "ops-laptop", true); err != nil || !p.Machine.Admin || p.Admin {
		t.Fatalf("admin: %+v %v", p, err)
	}
	if p, err := setAdmin(ctx, st, "ops-laptop", false); err != nil || p.Machine.Admin {
		t.Fatalf("admin off: %+v %v", p, err)
	}
	if _, err := setAdmin(ctx, st, "nobody", true); err == nil {
		t.Fatal("a device that does not exist was made an administrator")
	}
}

// link create --posture tells a control plane that can require checks of links (0.14) from an
// older one, which would create the link without them, before creating anything.
func TestKnowsLinkChecks(t *testing.T) {
	for _, v := range []struct {
		name  string
		patch bool
	}{{"0.13", false}, {"0.14", true}} {
		mux := http.NewServeMux()
		created := false
		mux.HandleFunc("POST "+api.PathAdminLinks, func(w http.ResponseWriter, r *http.Request) { created = true })
		mux.HandleFunc("DELETE "+api.PathAdminLinks+"/{name}", func(w http.ResponseWriter, r *http.Request) {})
		if v.patch {
			mux.HandleFunc("PATCH "+api.PathAdminLinks+"/{name}", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"error":"posture: the checks the link requires (an empty list: none)"}`))
			})
		}
		srv := httptest.NewServer(mux)
		c := &agent.AdminClient{Controls: []api.Control{{Name: "c1", Address: strings.TrimPrefix(srv.URL, "http://")}}}
		err := knowsLinkChecks(context.Background(), c)
		srv.Close()
		if older := err != nil && strings.Contains(err.Error(), "older than ento 0.14"); older != !v.patch || (err == nil) != v.patch || created {
			t.Errorf("%s: %v (created %v)", v.name, err, created)
		}
	}
}
