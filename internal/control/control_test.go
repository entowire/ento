package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/ipam"
	"entowire.com/ento/internal/reqsig"
	"entowire.com/ento/internal/store"
	"entowire.com/ento/internal/token"
)

func freeUDPPort(t *testing.T) int {
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// testClient is a userspace WireGuard peer talking to the control API, standing in for an agent.
type testClient struct {
	dev  *device.Device
	http *http.Client
	ctl  netip.Addr
	net  *netstack.Net
	// sign: requests carry the signature of key (the device's) for the control node's ctlKey.
	key, ctlKey wgtypes.Key
	unsigned    bool // send requests without a signature
}

func newTestClient(t *testing.T, key wgtypes.Key, psk wgtypes.Key, addr netip.Addr, ctl token.Control) *testClient {
	t.Helper()
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{addr}, nil, 1380)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	cfg := fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=%s/32\npersistent_keepalive_interval=1\n",
		hexKey(key), hexKey(ctl.PublicKey), ctl.Endpoint, ctl.Address)
	if psk != (wgtypes.Key{}) {
		cfg += "preshared_key=" + hexKey(psk) + "\n"
	}
	if err := dev.IpcSet(cfg); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dev.Close)
	return &testClient{dev: dev, ctl: ctl.Address, net: tnet, key: key, ctlKey: ctl.PublicKey, http: &http.Client{
		Timeout:   40 * time.Second,
		Transport: &http.Transport{DialContext: tnet.DialContext},
	}}
}

func (c *testClient) do(t *testing.T, method, path string, in, out any) int {
	t.Helper()
	var body bytes.Buffer
	if in != nil {
		_ = json.NewEncoder(&body).Encode(in)
	}
	b := body.Bytes()
	req, _ := http.NewRequest(method, fmt.Sprintf("http://%s%s", c.ctl, path), bytes.NewReader(b))
	if len(b) > 0 {
		req.Header.Set("Content-Type", "application/json") // as agents send it
	}
	if !c.unsigned {
		k, err := reqsig.DeviceKey(c.key, c.ctlKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := reqsig.Sign(req, k, b, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	if _, isErr := out.(*api.Error); out != nil && (resp.StatusCode < 300) != isErr {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatal(err)
		}
	}
	return resp.StatusCode
}

// enroll redeems a token and returns a client using the permanent key and address.
func enroll(t *testing.T, tokStr, hostname string) (*testClient, api.RedeemResponse) {
	t.Helper()
	tok, err := token.Parse(tokStr)
	if err != nil {
		t.Fatal(err)
	}
	creds, _ := token.Derive(tok.Secret)
	temp := newTestClient(t, creds.PrivateKey, creds.PresharedKey, tok.TempAddress, tok.Controls[0])
	perm, _ := wgtypes.GeneratePrivateKey()
	var res api.RedeemResponse
	if code := temp.do(t, "POST", api.PathRedeem, api.RedeemRequest{PublicKey: perm.PublicKey().String(), Hostname: hostname, OS: "test"}, &res); code != 200 {
		t.Fatalf("redeem: HTTP %d", code)
	}
	// The token is one-time: a second redeem is refused.
	other, _ := wgtypes.GeneratePrivateKey()
	if code := temp.do(t, "POST", api.PathRedeem, api.RedeemRequest{PublicKey: other.PublicKey().String(), Hostname: "x", OS: "test"}, nil); code != http.StatusGone {
		t.Fatalf("second redeem: expected 410, got %d", code)
	}
	temp.dev.Close()
	return newTestClient(t, perm, wgtypes.Key{}, netip.MustParseAddr(res.Address), tok.Controls[0]), res
}

func TestEnrollmentApprovalAndNetMap(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	space, _ := ipam.New(netip.MustParsePrefix("100.64.0.0/16"))
	st := store.NewMemory(space)
	key, _ := wgtypes.GeneratePrivateKey()
	port := freeUDPPort(t)
	srv, err := Start(ctx, Config{Name: "c1", PrivateKey: key, ListenPort: port,
		Endpoint: fmt.Sprintf("127.0.0.1:%d", port), Space: space, Store: st, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	// Bootstrap: the first admin comes from a token created directly on the store.
	adminTok, _, err := IssueToken(ctx, st, TokenOptions{Approve: true, Admin: true, Groups: []string{"admins"}})
	if err != nil {
		t.Fatal(err)
	}
	srv.checkVersion(ctx)
	admin, adminRes := enroll(t, adminTok, "admin-host")
	signInRoles(t, st)
	if !adminRes.Approved || len(adminRes.Controls) != 1 {
		t.Fatalf("unexpected admin enrollment: %+v", adminRes)
	}

	// The admin issues a token without groups: the device lands in isolated, as if not approved.
	var created api.CreateTokenResponse
	if code := admin.do(t, "POST", api.PathTokens, api.CreateTokenRequest{TTLSeconds: 600}, &created); code != 201 {
		t.Fatalf("create token: HTTP %d", code)
	}
	laptop, laptopRes := enroll(t, created.Token, "laptop")
	if laptopRes.Approved {
		t.Fatal("laptop must not be approved yet")
	}

	// Record the endpoints WireGuard observed (normally done every reconcile interval).
	srv.observe(ctx)

	// Pending peers see only the control nodes and cannot use the admin API.
	var nm api.NetMap
	if code := laptop.do(t, "GET", api.PathNetMap, nil, &nm); code != 200 {
		t.Fatalf("netmap: HTTP %d", code)
	}
	if nm.Self.Approved || len(nm.Peers) != 0 || len(nm.Controls) != 1 {
		t.Fatalf("pending peer got too much: %+v", nm)
	}
	if code := laptop.do(t, "GET", api.PathPeers, nil, nil); code != http.StatusForbidden {
		t.Fatalf("non-admin reached the admin API: HTTP %d", code)
	}

	// Long-poll from the laptop while the admin approves it and adds a policy.
	done := make(chan api.NetMap, 1)
	go func() {
		var next api.NetMap
		for {
			var got api.NetMap
			laptop.do(t, "GET", fmt.Sprintf("%s?since=%d", api.PathNetMap, nm.Version), nil, &got)
			if len(got.Peers) > 0 {
				next = got
				break
			}
			nm.Version = got.Version
		}
		done <- next
	}()

	var peers []api.PeerInfo
	admin.do(t, "GET", api.PathPeers, nil, &peers)
	var laptopID int64
	for _, p := range peers {
		if p.Hostname == "z-laptop" {
			laptopID = p.ID
		}
	}
	if code := admin.do(t, "PATCH", fmt.Sprintf("%s/%d", api.PathPeers, laptopID), api.UpdatePeerRequest{Groups: &[]string{"laptops"}}, nil); code != 200 {
		t.Fatalf("approve: HTTP %d", code)
	}
	if code := admin.do(t, "POST", api.PathPolicies, api.Policy{Source: "laptops", Destination: "admins"}, nil); code != 201 {
		t.Fatalf("policy: HTTP %d", code)
	}

	select {
	case got := <-done:
		if !got.Self.Approved || len(got.Peers) != 1 || got.Peers[0].Hostname != "z-admin-host" {
			t.Fatalf("unexpected netmap after approval: %+v", got)
		}
		if len(got.Peers[0].Endpoints) == 0 {
			t.Fatalf("the admin's observed endpoint is missing: %+v", got.Peers[0])
		}
	case <-time.After(60 * time.Second):
		t.Fatal("netmap long-poll did not deliver the change")
	}
}

// signInRoles signs a person in on every device in admin or operator that has nobody signed in: a
// person in admins on a device in admin, in operators on a device in operator. A role takes both
func signInRoles(t *testing.T, st store.Store) {
	t.Helper()
	ctx := context.Background()
	peers, err := st.Peers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	on, now := true, time.Now()
	for _, p := range peers {
		if !(p.Machine.Admin || p.Machine.Operator) || p.Person.Active {
			continue
		}
		admin, operator, groups := p.Machine.Admin, !p.Machine.Admin, []string{"admins"}
		if operator {
			groups = []string{"operators"}
		}
		sub := p.User
		if sub == "" {
			sub = "sub-" + p.Hostname
		}
		if _, err := st.UpdatePeer(ctx, p.ID, store.PeerUpdate{User: &sub, LoginAt: &now, PersonActive: &on, PersonApproved: &on,
			PersonAdmin: &admin, PersonOperator: &operator, PersonGroups: &groups}); err != nil {
			t.Fatal(err)
		}
	}
}
