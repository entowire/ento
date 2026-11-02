package control

// Hardware-bound identities (0.31, step 2 of copied identities; package hwsig says what is signed).
// A device whose agent finds a TPM binds a P-256 key the TPM keeps (POST /v1/hwkey): the first key a
// device binds is its key until an administrator releases it (ento admin unbind). From then on:
//
//   - Every check-in carries that key's signature. One without it (a copy of the device's state on
//     a machine without its TPM, or the device's own TPM failing) is refused and audited; the device
//     is asked to change its WireGuard key at its next signed check-in, which makes the copy's key
//     worthless; still unsigned after hwGrace (no signed check-in in between: the original is gone)
//     the device is suspended.
//   - A token that does not match, with a valid signature, is the original catching a copy that
//     checked in first: no suspension, the original changes its key at once.
//   - The device changes its WireGuard key daily (POST /v1/rotate), each new key certified by the
//     hardware key, so a copy taken from it stops working within a day at the latest.
//   - Another hardware key for a bound device (a copy with a TPM of its own) is refused and audited
//     (hwkey_conflict), and the original changes its key.
//
// The binding is trust on first use: whoever binds first holds the device. Proof that the key is a
// TPM's (its endorsement certificate) is step 3.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/hwsig"
	"entowire.com/ento/internal/store"
)

// hwGrace is how long a bound device may check in without its hardware key's signature before it is
// suspended: long enough for a TPM that failed once (check-ins come every 5 minutes) and for the
// original to change its key away from a copy.
const hwGrace = 15 * time.Minute

// errNotBound leaves a device without a hardware key as it is.
var errNotBound = errors.New("no hardware key bound")

// hwKey returns a device's bound hardware key (found false: none).
func (s *Server) hwKey(ctx context.Context, id int64) (store.HWKey, bool, error) {
	k, err := s.cfg.Store.HWKey(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return k, false, nil
	}
	return k, err == nil, err
}

// keyLabel names a key in audit lines: the first 8 characters of its base64.
func keyLabel(k string) string {
	if len(k) > 8 {
		return k[:8]
	}
	return k
}

// hwKeyLabel names a hardware key: the first 16 hex digits of its SHA-256.
func hwKeyLabel(pub string) string {
	der, _ := base64.StdEncoding.DecodeString(pub)
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:8])
}

func (s *Server) handleHWKey(w http.ResponseWriter, r *http.Request, self store.Peer) {
	var req api.HWKeyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048)).Decode(&req); err != nil || req.Kind != hwsig.KindTPM {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	now := time.Now()
	if err := hwsig.Verify(req.PublicKey, req.Signature, hwsig.BindMessage(self.PublicKey.String(), req.PublicKey, req.Time), req.Time, now); err != nil {
		writeErr(w, http.StatusBadRequest, "the binding is not signed by that key: "+err.Error())
		return
	}
	var created, conflict bool
	var bound store.HWKey
	_, err := s.cfg.Store.UpdateHWKey(r.Context(), self.ID, func(k store.HWKey, found bool) (store.HWKey, error) {
		created, conflict, bound = !found, false, k
		switch {
		case !found:
			k.Kind, k.PublicKey, k.BoundAt, k.SeenAt = req.Kind, req.PublicKey, now, now
		case k.PublicKey != req.PublicKey:
			conflict, k.Rotate = true, true
		}
		return k, nil
	})
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	switch {
	case created:
		s.audit(r, &self, "hwkey_bound", fmt.Sprintf("%s kind=%s key=%s", peerLabel(self), req.Kind, hwKeyLabel(req.PublicKey)), "ok")
		writeJSON(w, http.StatusCreated, struct{}{})
	case conflict:
		s.audit(r, &self, "hwkey_conflict", fmt.Sprintf("%s bound=%s since=%s other=%s endpoint=%s (another machine with this identity and a TPM of its own: refused; the original changes its key at once)",
			peerLabel(self), hwKeyLabel(bound.PublicKey), bound.BoundAt.UTC().Format(time.RFC3339), hwKeyLabel(req.PublicKey), self.Endpoint), "denied")
		writeErr(w, http.StatusConflict, "this device is bound to another hardware key: an administrator releases it (ento admin unbind) if its TPM was cleared or replaced")
	default:
		writeJSON(w, http.StatusOK, struct{}{})
	}
}

func (s *Server) handleRotate(w http.ResponseWriter, r *http.Request, self store.Peer) {
	var req api.RotateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	next, err := wgtypes.ParseKey(req.PublicKey)
	if err != nil || next == (wgtypes.Key{}) || next == self.PublicKey {
		writeErr(w, http.StatusBadRequest, "invalid key")
		return
	}
	k, found, err := s.hwKey(r.Context(), self.ID)
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	if !found {
		writeErr(w, http.StatusConflict, "this device has no hardware key bound")
		return
	}
	if err := hwsig.Verify(k.PublicKey, req.Signature, hwsig.RotateMessage(self.PublicKey.String(), req.PublicKey, req.Time), req.Time, time.Now()); err != nil {
		s.audit(r, &self, "key_rotated", fmt.Sprintf("%s to %s: %v", peerLabel(self), keyLabel(req.PublicKey), err), "denied")
		writeErr(w, http.StatusForbidden, "the new key is not certified by the device's hardware key: "+err.Error())
		return
	}
	if other, err := s.cfg.Store.PeerByPublicKey(r.Context(), next); err == nil && other.ID != self.ID {
		writeErr(w, http.StatusConflict, "that key is in use")
		return
	}
	// Answer first, then change the key: the change wakes every control node's WireGuard, which
	// drops the old key's session, and with it the way back for this answer. Should the change fail
	// after the answer, the device finds out (no control node answers its new key) and goes back to
	// the old one (internal/agent/hwkey.go).
	writeJSON(w, http.StatusOK, struct{}{})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	old, label := self.PublicKey, peerLabel(self)
	go func() {
		time.Sleep(500 * time.Millisecond)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := s.cfg.Store.RotatePeerKey(ctx, self.ID, old, next); err != nil {
			s.audit(nil, &self, "key_rotated", fmt.Sprintf("%s to %s: %v (the device goes back to its key)", label, keyLabel(req.PublicKey), err), "failed")
			return
		}
		// The machine's fingerprint is salted with the device's key: the next check-in brings a new
		// one, expected again from then on (a copy cannot change the key: it has no hardware key).
		if _, err := s.cfg.Store.UpdateCheckIn(ctx, self.ID, func(c store.CheckIn, found bool) (store.CheckIn, error) {
			c.Fingerprint = ""
			return c, nil
		}); err != nil {
			s.cfg.Logf("check-ins of peer %d: %v", self.ID, err)
		}
		s.audit(nil, &self, "key_rotated", fmt.Sprintf("%s from %s to %s", label, keyLabel(old.String()), keyLabel(req.PublicKey)), "ok")
		s.checkVersion(ctx)
	}()
}

// hwCheckIn is what a check-in's hardware signature says.
type hwCheckIn struct {
	bound   bool
	signed  bool
	why     string // why the signature does not count
	rotate  bool   // the device is to change its key
	suspend bool   // unsigned for longer than hwGrace
}

// checkInHW checks a check-in's hardware signature against the device's binding and records it.
func (s *Server) checkInHW(ctx context.Context, self store.Peer, req api.CheckInRequest, now time.Time) (hwCheckIn, error) {
	var out hwCheckIn
	_, err := s.cfg.Store.UpdateHWKey(ctx, self.ID, func(k store.HWKey, found bool) (store.HWKey, error) {
		out = hwCheckIn{}
		if !found {
			return k, errNotBound
		}
		out.bound = true
		err := errors.New("no hardware signature")
		if req.HWSignature != "" {
			err = hwsig.Verify(k.PublicKey, req.HWSignature, hwsig.CheckInMessage(self.PublicKey.String(), req.Token, req.HWTime), req.HWTime, now)
		}
		if err == nil {
			out.signed, out.rotate = true, k.Rotate
			k.SeenAt, k.UnsignedSince = now, time.Time{}
			return k, nil
		}
		out.why = err.Error()
		if k.UnsignedSince.IsZero() {
			k.UnsignedSince = now
		}
		k.Rotate, out.rotate = true, true
		out.suspend = now.Sub(k.UnsignedSince) >= hwGrace
		return k, nil
	})
	if errors.Is(err, errNotBound) {
		return hwCheckIn{}, nil
	}
	return out, err
}

// markRotate asks a bound device to change its key at its next signed check-in.
func (s *Server) markRotate(ctx context.Context, id int64) {
	if _, err := s.cfg.Store.UpdateHWKey(ctx, id, func(k store.HWKey, found bool) (store.HWKey, error) {
		if !found {
			return k, errNotBound
		}
		k.Rotate = true
		return k, nil
	}); err != nil && !errors.Is(err, errNotBound) {
		s.cfg.Logf("hardware key of peer %d: %v", id, err)
	}
}

// hwKeyInfo adds what the peer list shows of each device's hardware key.
func hwKeyInfo(out []api.PeerInfo, keys []store.HWKey) {
	byID := map[int64]store.HWKey{}
	for _, k := range keys {
		byID[k.PeerID] = k
	}
	for i := range out {
		k, ok := byID[out[i].ID]
		if !ok {
			continue
		}
		out[i].HardwareKey = k.Kind
		if !k.SeenAt.IsZero() {
			out[i].HardwareKeyAt = k.SeenAt.UTC().Format(time.RFC3339)
		}
		if !k.RotatedAt.IsZero() {
			out[i].KeyRotatedAt = k.RotatedAt.UTC().Format(time.RFC3339)
		}
	}
}
