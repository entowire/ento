package agent

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestUAPIRoundTrip(t *testing.T) {
	priv, _ := wgtypes.GeneratePrivateKey()
	peer, _ := wgtypes.GeneratePrivateKey()
	gone, _ := wgtypes.GeneratePrivateKey()
	port, ka := 51830, 25*time.Second
	psk := wgtypes.Key{1, 2, 3}
	cfg := wgtypes.Config{PrivateKey: &priv, ListenPort: &port, Peers: []wgtypes.PeerConfig{
		{PublicKey: gone.PublicKey(), Remove: true},
		{PublicKey: peer.PublicKey(), PresharedKey: &psk, Endpoint: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 51830},
			PersistentKeepaliveInterval: &ka, ReplaceAllowedIPs: true,
			AllowedIPs: []net.IPNet{{IP: net.IPv4(100, 64, 1, 7).To4(), Mask: net.CIDRMask(32, 32)}}},
	}}
	text := uapiConfig(cfg)
	// What a "get" answers for that configuration (without the removed peer).
	get := "private_key=" + text[len("private_key="):len("private_key=")+64] + "\nlisten_port=51830\n" +
		"public_key=" + hexKey(peer.PublicKey()) + "\npreshared_key=" + hexKey(psk) +
		"\nendpoint=203.0.113.9:51830\nlast_handshake_time_sec=1700000000\nlast_handshake_time_nsec=5\n" +
		"tx_bytes=10\nrx_bytes=20\npersistent_keepalive_interval=25\nallowed_ip=100.64.1.7/32\nerrno=0\n"
	dev, err := parseUAPI(get)
	if err != nil {
		t.Fatal(err)
	}
	if dev.PrivateKey != priv || dev.ListenPort != 51830 || len(dev.Peers) != 1 {
		t.Fatalf("device %+v", dev)
	}
	p := dev.Peers[0]
	if p.PublicKey != peer.PublicKey() || p.PresharedKey != psk || p.Endpoint.String() != "203.0.113.9:51830" ||
		p.ReceiveBytes != 20 || p.TransmitBytes != 10 || p.LastHandshakeTime.Unix() != 1700000000 ||
		p.PersistentKeepaliveInterval != ka || p.AllowedIPs[0].String() != "100.64.1.7/32" {
		t.Fatalf("peer %+v", p)
	}
	// The same desired state again plans no change.
	desired := []PeerConfig{{PublicKey: peer.PublicKey(), PresharedKey: psk, AllowedIPs: []netip.Prefix{netip.PrefixFrom(mustAddr("100.64.1.7"), 32)}, Endpoint: "203.0.113.9:51830", Keepalive: ka}}
	if c, err := planConfig(dev, priv, 51830, desired); err != nil || c != nil {
		t.Fatalf("expected no change, got %+v %v", c, err)
	}
	// A peer that became quiet (a phone, 0.34) loses its keepalive.
	desired[0].Keepalive = 0
	c, err := planConfig(dev, priv, 51830, desired)
	if err != nil || c == nil || len(c.Peers) != 1 || *c.Peers[0].PersistentKeepaliveInterval != 0 {
		t.Fatalf("expected the keepalive turned off, got %+v %v", c, err)
	}
}

func hexKey(k wgtypes.Key) string {
	return uapiConfig(wgtypes.Config{PrivateKey: &k})[len("private_key=") : len("private_key=")+64]
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }
