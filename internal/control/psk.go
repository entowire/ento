package control

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/psk"
	"entowire.com/ento/internal/store"
)

// Preshared keys between a device and its control nodes (Constitution 9.1; design: Preshared
// keys). The agent starts an exchange (handlePSK), keeps the key it derived as its next one, sets
// it on its tunnels with the control nodes and confirms it (handlePSKConfirm), which makes it the
// one every control node sets. Until then the control nodes keep the current key, so a device that
// never confirms loses nothing. A change moves the store's key version, not the network map's:
// only the control nodes' own tunnels change.

var errUnknownTag = errors.New("no key with that tag")

// handlePSK answers an agent's encapsulation key with the ciphertext and keeps what it derived
// as the device's next key; a later exchange replaces a next key not confirmed yet.
func (s *Server) handlePSK(w http.ResponseWriter, r *http.Request, self store.Peer) {
	var req api.PSKRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	ct, agreed, err := psk.Answer(req.EncapsulationKey, self.PublicKey)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.cfg.Store.UpdatePresharedKey(r.Context(), self.ID, func(k store.PresharedKey, _ bool) (store.PresharedKey, error) {
		k.Next, k.NextTag = agreed.Key, agreed.Tag
		return k, nil
	}); err != nil {
		s.respondStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, api.PSKResponse{Ciphertext: ct})
}

// handlePSKConfirm makes the device's next key the current one, sets it on this node's tunnel
// before answering (the others follow the key version), and audits the change.
func (s *Server) handlePSKConfirm(w http.ResponseWriter, r *http.Request, self store.Peer) {
	var req api.PSKConfirm
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil || req.Tag == "" {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	changed := false
	_, err := s.cfg.Store.UpdatePresharedKey(r.Context(), self.ID, func(k store.PresharedKey, _ bool) (store.PresharedKey, error) {
		changed = false
		if k.NextTag == "" || !psk.SameTag(k.NextTag, req.Tag) {
			return k, errUnknownTag
		}
		if k.Next == (wgtypes.Key{}) { // confirmed already: the answer was lost
			return k, nil
		}
		k.Current, k.Next, k.ChangedAt = k.Next, wgtypes.Key{}, time.Now()
		changed = true
		return k, nil
	})
	switch {
	case errors.Is(err, errUnknownTag):
		// Another exchange replaced it, or the keys were reset: the agent keeps the key it has.
		writeErr(w, http.StatusConflict, err.Error())
		return
	case err != nil:
		s.respondStoreErr(w, err)
		return
	}
	if changed {
		s.audit(r, &self, "psk_changed", peerLabel(self), "ok")
		if err := s.reconcile(r.Context()); err != nil {
			s.cfg.Logf("reconcile after a preshared key change: %v", err)
		}
	}
	writeJSON(w, http.StatusOK, struct{}{})
}

// Pair keys (Constitution 9.1 between two devices): made where maps are built (addPairKeys), changed
// in one batch a day for the whole network (rotatePairKeys), so that the maps change once for all
// of them, and at once for a device whose WireGuard key changed.

// pairKeyEvery is how often pair keys change: daily, or ENTO_PSK_EVERY (tests).
func pairKeyEvery() time.Duration {
	if d, err := time.ParseDuration(os.Getenv("ENTO_PSK_EVERY")); err == nil && d > 0 {
		return d
	}
	return 24 * time.Hour
}

// newKey is a random preshared key.
func newKey() wgtypes.Key {
	var k wgtypes.Key
	if _, err := rand.Read(k[:]); err != nil {
		panic(err) // crypto/rand does not fail
	}
	return k
}

// rotatePairKeys runs every minute on every control node; the store lets one batch through a day.
func (s *Server) rotatePairKeys(ctx context.Context) {
	n, err := s.cfg.Store.RotatePairKeys(ctx, time.Now(), pairKeyEvery(), pairKeyLead, newKey)
	switch {
	case err != nil:
		if ctx.Err() == nil {
			s.cfg.Logf("pair keys: %v", err)
		}
	case n > 0:
		s.cfg.Logf("pair keys: %d change in %s", n, pairKeyLead)
		s.checkVersion(ctx)
	}
}
