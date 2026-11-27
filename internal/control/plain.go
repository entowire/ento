package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/names"
	"entowire.com/ento/internal/store"
)

// Plain WireGuard peers (Constitution 6): devices that only speak WireGuard (a router's client, the
// official apps) join through a gateway, a Linux device with the agent and the kernel's WireGuard.
// The gateway is their only peer: it forwards their traffic, and filters for them what others may
// open on them; the devices they reach filter what they open, as for any peer. They have device
// groups like any device, never a role's, no posture, no direct connections, and a configuration
// that changes only when an administrator makes a new one (their preshared key with it, 9.3).

// handleAddPlain adds a plain WireGuard peer and answers with its configuration.
func (s *Server) handleAddPlain(w http.ResponseWriter, r *http.Request, self store.Peer) {
	var req api.PlainRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	if err := names.Check(req.Name); err != nil {
		writeErr(w, http.StatusBadRequest, "name: "+err.Error())
		return
	}
	if err := checkGroups(req.Groups, false); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	groups := deviceGroups(req.Groups)
	if _, admin, operator := s.groupRights(groups); admin || operator || hasGroup(groups, DeviceAdminGroup) || hasGroup(groups, DeviceOperatorGroup) {
		writeErr(w, http.StatusBadRequest, "a plain WireGuard peer is never in admin or operator (Constitution 6.1)")
		return
	}
	peers, err := s.cfg.Store.Peers(r.Context())
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	plain, err := s.cfg.Store.PlainPeers(r.Context())
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	var gw *store.Peer
	for i := range peers {
		if peers[i].Hostname == req.Via {
			gw = &peers[i]
		}
	}
	var why string
	switch {
	case gw == nil:
		why = "no device named " + req.Via
	case plain[gw.ID] != (store.PlainPeer{}):
		why = req.Via + " is a plain WireGuard peer itself"
	case gw.OS != "linux":
		why = req.Via + " is no Linux device: a gateway of plain WireGuard peers forwards with the kernel's WireGuard"
	case !gw.Approved || gw.Suspended:
		why = req.Via + " is not approved, or suspended"
	case neverGateway(*gw, s.cfg.NoGateways) != "":
		why = fmt.Sprintf("%s is in %s, whose devices are never gateways in this network", req.Via, neverGateway(*gw, s.cfg.NoGateways))
	}
	if why != "" {
		writeErr(w, http.StatusBadRequest, why)
		return
	}
	endpoint := req.Endpoint
	if endpoint == "" {
		endpoint = gw.Endpoint
	}
	if host, port, err := net.SplitHostPort(endpoint); err != nil || host == "" || port == "" {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("the gateway's endpoint (host:port, its WireGuard port reachable by the device): %q", endpoint))
		return
	}
	var priv *wgtypes.Key
	var pub wgtypes.Key
	if req.PublicKey != "" {
		if pub, err = wgtypes.ParseKey(req.PublicKey); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid public key")
			return
		}
	} else {
		k, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			s.respondStoreErr(w, err)
			return
		}
		priv, pub = &k, k.PublicKey()
	}
	psk := newKey()
	p, err := s.cfg.Store.CreatePlainPeer(r.Context(), pub, req.Name, groups,
		store.PlainPeer{Gateway: gw.ID, PresharedKey: psk, Endpoint: req.Endpoint}, time.Now())
	switch {
	case err == store.ErrKeyInUse:
		writeErr(w, http.StatusConflict, "that public key is in use")
		return
	case err != nil:
		s.respondStoreErr(w, err)
		return
	}
	s.audit(r, &self, "plain_peer_added", fmt.Sprintf("%s via %s groups=%s key=%s", peerLabel(p), gw.Hostname,
		strings.Join(groups, ","), keyLabel(pub.String())), "ok")
	s.checkVersion(r.Context())
	writeJSON(w, http.StatusOK, api.PlainResponse{ID: p.ID, Address: p.Address.String(),
		Config: plainConfig(priv, p, *gw, psk, endpoint, s.cfg.Space.Prefix.String())})
}

// plainConfig is a plain peer's WireGuard configuration, in wg-quick's format: one peer, its
// gateway, for the network's whole range.
func plainConfig(priv *wgtypes.Key, p, gw store.Peer, psk wgtypes.Key, endpoint, network string) string {
	key := "<this device's private key: it made the key pair>"
	if priv != nil {
		key = priv.String()
	}
	return fmt.Sprintf(`# %s in this network, through %s (ento)
[Interface]
PrivateKey = %s
Address = %s/32

[Peer]
PublicKey = %s
PresharedKey = %s
AllowedIPs = %s
Endpoint = %s
PersistentKeepalive = 25
`, p.Hostname, gw.Hostname, key, p.Address, gw.PublicKey, psk, network, endpoint)
}

// isPlain reports whether device id is a plain WireGuard peer.
func (s *Server) isPlain(ctx context.Context, id int64) bool {
	plain, err := s.cfg.Store.PlainPeers(ctx)
	_, ok := plain[id]
	return err == nil && ok
}

// carriesPlain reports whether device id is the gateway of a plain WireGuard peer.
func (s *Server) carriesPlain(ctx context.Context, id int64) bool {
	plain, err := s.cfg.Store.PlainPeers(ctx)
	if err != nil {
		return false
	}
	for _, pp := range plain {
		if pp.Gateway == id {
			return true
		}
	}
	return false
}
