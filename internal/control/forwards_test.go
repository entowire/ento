package control

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/ipam"
	"entowire.com/ento/internal/store"
)

func TestParseLinkForwards(t *testing.T) {
	network := netip.MustParsePrefix("100.64.0.0/16")
	fs, err := ParseLinkForwards("id.example.com:443=100.64.0.1:443+100.64.0.2:443, git.example.com:22=100.64.1.9:2222", network)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 || fs[0].Name != "id.example.com" || fs[0].Port != 443 || len(fs[0].Targets) != 2 || fs[1].Targets[0] != "100.64.1.9:2222" {
		t.Fatalf("got %+v", fs)
	}
	for _, bad := range []string{
		"id.example.com=100.64.0.1:443",             // no port
		"id.example.com:0=100.64.0.1:443",           // port out of range
		"localhost:443=100.64.0.1:443",              // single label
		"id.example.com:443=10.0.0.1:443",           // target outside the network
		"id.example.com:443=100.64.0.1",             // target without port
		"a.b:443=100.64.0.1:1,a.b:443=100.64.0.2:1", // duplicate
	} {
		if _, err := ParseLinkForwards(bad, network); err == nil {
			t.Errorf("%q: accepted", bad)
		}
	}
}

// Named forwards: a TLS hello for a forwarded name reaches its targets, any other name the identity
// provider; devices are told to resolve the name to the control nodes.
func TestNamedForwards(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var hits sync.Map // backend label -> count
	backend := func(label string) string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				v, _ := hits.LoadOrStore(label, new(atomic.Int32))
				v.(*atomic.Int32).Add(1)
				c.Close()
			}
		}()
		return ln.Addr().String()
	}
	idp, agentSvc := backend("idp"), backend("agent")
	space, _ := ipam.New(netip.MustParsePrefix("100.64.0.0/16"))
	st := store.NewMemory(space)
	key, _ := wgtypes.GeneratePrivateKey()
	port := freeUDPPort(t)
	srv, err := Start(ctx, Config{Name: "c1", PrivateKey: key, ListenPort: port, Endpoint: fmt.Sprintf("127.0.0.1:%d", port),
		Space: space, Store: st, Logf: t.Logf,
		OIDC:     &OIDCConfig{Issuer: "https://id.example.invalid/x", ClientID: "c", ClientSecret: "s", ConnectTo: []string{idp}},
		Forwards: map[string][]string{"agent.example.invalid": {"127.0.0.1:1", agentSvc}}})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	tok, _, _ := IssueToken(ctx, st, TokenOptions{Approve: true})
	srv.checkVersion(ctx)
	dev, _ := enroll(t, tok, "desktop")
	hello := func(name string) {
		c, err := dev.net.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(srv.Address(), IdentityProviderPort))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		tc := tls.Client(c, &tls.Config{ServerName: name, InsecureSkipVerify: true})
		_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
		_ = tc.Handshake() // the backends are no TLS servers: only where the hello went counts
	}
	count := func(label string) int32 {
		for i := 0; i < 50; i++ {
			if v, ok := hits.Load(label); ok && v.(*atomic.Int32).Load() > 0 {
				return v.(*atomic.Int32).Load()
			}
			time.Sleep(50 * time.Millisecond)
		}
		return 0
	}
	hello("AGENT.example.invalid")
	if count("agent") != 1 || count("idp") != 0 {
		t.Fatalf("the forwarded name: agent %d, idp %d", count("agent"), count("idp"))
	}
	hello("id.example.invalid")
	if count("idp") != 1 {
		t.Fatalf("another name: idp %d", count("idp"))
	}
	var nm api.NetMap
	if code := dev.do(t, "GET", api.PathNetMap, nil, &nm); code != 200 || nm.DNS == nil {
		t.Fatalf("map: HTTP %d %+v", code, nm.DNS)
	}
	found := false
	for _, h := range nm.DNS.Fixed {
		found = found || h.Name == "agent.example.invalid"
	}
	if !found {
		t.Fatalf("devices are not told the forwarded name: %+v", nm.DNS.Fixed)
	}
}

func TestParseForwards(t *testing.T) {
	got, err := ParseForwards("Agent.Example.com=10.0.0.1:8462+10.0.0.2:8462, b.example.com=h:1")
	if err != nil || len(got) != 2 || len(got["agent.example.com"]) != 2 || got["b.example.com"][0] != "h:1" {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []string{"agent=10.0.0.1:1", "a.example.com", "a.example.com=10.0.0.1", "a.example.com=x:1,a.example.com=y:2"} {
		if _, err := ParseForwards(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
