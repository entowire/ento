package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
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

// ento admin ui CODE without --network finds the page in whichever of the device's networks shows
// it: the default network first, then the others; with --network only that one is asked.
func TestApproveAdminUIEveryNetwork(t *testing.T) {
	base := t.TempDir()
	asked := map[string]int{}
	control := func(name string, shows bool) api.Control {
		mux := http.NewServeMux()
		mux.HandleFunc("POST "+api.PathAdminUI, func(w http.ResponseWriter, r *http.Request) {
			asked[name]++
			if !shows {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"error":"no admin page on this device shows this code"}`))
				return
			}
			w.Write([]byte(`{"opened_at":"2026-11-26T13:03:28Z","browser":"Firefox"}`))
		})
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)
		return api.Control{Name: name, Address: strings.TrimPrefix(srv.URL, "http://")}
	}
	if err := agent.SaveState(base, agent.State{RecordDomain: "md.example.com", Controls: []api.Control{control("md", false)}}); err != nil {
		t.Fatal(err)
	}
	for d, shows := range map[string]bool{"mm.example.com": false, "njoy.example.com": true} {
		dir := agent.NetworkDir(base, d)
		if err := agent.SaveState(dir, agent.State{RecordDomain: d, Controls: []api.Control{control(strings.Split(d, ".")[0], shows)}}); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "network.json"), []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	first, _ := agent.LoadState(base)
	c := &agent.AdminClient{Controls: first.Controls}
	var ok api.ApprovedAdminUI
	where, err := approveAdminUI(context.Background(), c, base, "", false, "UM36-SEPF", &ok)
	if err != nil || where != "njoy.example.com" || ok.Browser != "Firefox" || asked["md"] != 1 || asked["njoy"] != 1 {
		t.Fatalf("every network: %q %v %+v %v", where, err, ok, asked)
	}
	// Asked for md alone, md's refusal stands.
	if _, err := approveAdminUI(context.Background(), c, base, "", true, "UM36-SEPF", &ok); agent.HTTPStatus(err) != http.StatusNotFound || asked["njoy"] != 1 {
		t.Fatalf("--network: %v %v", err, asked)
	}
	// Nowhere: the error names every network asked.
	njoyDir := agent.NetworkDir(base, "njoy.example.com")
	os.Remove(filepath.Join(njoyDir, "network.json"))
	_, err = approveAdminUI(context.Background(), c, base, "", false, "UM36-SEPF", &ok)
	if err == nil || !strings.Contains(err.Error(), "md.example.com, mm.example.com") {
		t.Fatalf("nowhere: %v", err)
	}
}
