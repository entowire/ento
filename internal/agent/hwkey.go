package agent

// The device's hardware-held key (0.31; packages hwsig and tpmkey, the control package's hwkey.go
// for the rules). Where the system has a TPM, the home network's agent keeps a P-256 key in it
// (<state dir>/hwkey.json is its blob, useless on any other TPM), binds it to the device, signs
// every check-in with it, and changes its WireGuard key once a day, each new key certified by it: a
// copy of the state on another machine cannot sign, so its check-ins are refused and its key stops
// working at the original's next change. Linux only for now (macOS's Secure Enclave and Windows'
// TPM later; Android's Keystore key is the posture attestation's).

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/hwsig"
)

// HardwareKey values (Config.HardwareKey).
const (
	HardwareKeyAuto = "auto" // the TPM's, when there is one
	HardwareKeyOff  = "off"
)

// keyRotateEvery is how often a device with a bound hardware key changes its WireGuard key;
// ENTO_KEY_ROTATE_EVERY overrides it (tests).
func keyRotateEvery() time.Duration {
	if d, err := time.ParseDuration(os.Getenv("ENTO_KEY_ROTATE_EVERY")); err == nil && d > 0 {
		return d
	}
	return 24 * time.Hour
}

// pendingSwapAfter is how long the agent tries one key before the other while a key change's
// outcome is unknown (rotateKey).
const pendingSwapAfter = 30 * time.Second

// startHardwareKey opens the device's hardware key, if any; the home network's runner only.
func (a *runner) startHardwareKey() {
	if a.cfg.HardwareKey == HardwareKeyOff {
		return
	}
	k, err := openHardwareKey(a.cfg)
	switch {
	case err != nil:
		a.hwNote = "unusable: " + err.Error()
		a.cfg.Logf("hardware key: %v; check-ins go unsigned (a device bound to a hardware key is then refused, and suspended after 15 minutes)", err)
	case k == nil:
		a.hwNote = "none (no TPM)"
	default:
		a.hw = k
		a.hwNote = k.Kind() + ", not bound yet"
	}
}

// bindHardwareKey binds the hardware key, if not done in this run: once bound, every check-in is
// signed. The control plane answers the same for a key already bound.
func (a *runner) bindHardwareKey(ctx context.Context) {
	if a.hw == nil || a.hwBound || time.Since(a.hwTried) < time.Hour && !a.hwTried.IsZero() {
		return
	}
	a.hwTried = time.Now()
	pub, err := hwsig.EncodePublic(a.hw.Public())
	if err != nil {
		return
	}
	now := time.Now().Unix()
	sig, err := hwsig.Sign(a.hw, hwsig.BindMessage(a.key().PublicKey().String(), pub, now))
	if err != nil {
		a.cfg.Logf("hardware key: sign the binding: %v", err)
		return
	}
	c := &AdminClient{Controls: a.controls(), Key: a.key(), HTTP: a.env.http}
	err = c.Do(ctx, http.MethodPost, api.PathHWKey, api.HWKeyRequest{Kind: a.hw.Kind(), PublicKey: pub, Time: now, Signature: sig}, nil)
	switch status := HTTPStatus(err); {
	case err == nil:
		a.mu.Lock()
		a.hwBound, a.hwNote = true, a.hw.Kind()+", bound"
		if a.st.KeyCreatedAt.IsZero() { // its key's day starts now
			a.st.KeyCreatedAt = time.Now()
			if err := a.save(); err != nil {
				a.cfg.Logf("save state: %v", err)
			}
		}
		a.mu.Unlock()
		a.cfg.Logf("hardware key (%s) bound: check-ins are signed, and the WireGuard key changes every %s", a.hw.Kind(), keyRotateEvery())
		a.announce()
	case status == http.StatusNotFound || status == http.StatusMethodNotAllowed:
		a.setHWNote(a.hw.Kind() + ", not bound (the control plane is older than ento 0.31)")
	case status == http.StatusConflict:
		a.setHWNote(a.hw.Kind() + ", refused: the device is bound to another hardware key")
		a.cfg.Logf("hardware key: %v (an administrator releases the old binding with ento admin unbind, e.g. after the TPM was cleared)", err)
	default:
		a.hwTried = time.Time{} // the control plane did not answer: again at the next check-in
	}
}

func (a *runner) setHWNote(note string) {
	a.mu.Lock()
	a.hwNote = note
	a.mu.Unlock()
	a.announce()
}

// signCheckIn adds the hardware key's signature to a check-in, once the key is bound.
func (a *runner) signCheckIn(req *api.CheckInRequest) {
	if a.hw == nil || !a.hwBound {
		return
	}
	now := time.Now().Unix()
	sig, err := hwsig.Sign(a.hw, hwsig.CheckInMessage(a.key().PublicKey().String(), req.Token, now))
	if err != nil {
		a.cfg.Logf("hardware key: sign the check-in: %v", err)
		return
	}
	req.HWSignature, req.HWTime = sig, now
}

// keyDue reports whether the device's WireGuard key is due to change.
func (a *runner) keyDue() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.hwBound && !a.st.KeyCreatedAt.IsZero() && time.Since(a.st.KeyCreatedAt) >= keyRotateEvery()
}

// rotateKey changes the device's WireGuard key, certified by its hardware key. The new key is saved
// before it is asked for (NextPrivateKey); if the answer is lost, the agent tries both keys in turn
// (resolvePendingKey) until one reaches a control node, so neither a crash nor a lost answer leaves
// the device with a key nobody knows.
func (a *runner) rotateKey(ctx context.Context, why string) {
	if a.hw == nil || !a.hwBound {
		return
	}
	next, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return
	}
	a.mu.Lock()
	if a.st.NextPrivateKey != nil { // an earlier change's outcome is still open
		a.mu.Unlock()
		return
	}
	old := wgtypes.Key(a.st.PrivateKey)
	nk := Key(next)
	a.st.NextPrivateKey = &nk
	a.rotating = true
	err = a.save()
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.rotating = false
		a.mu.Unlock()
	}()
	if err != nil {
		a.cfg.Logf("key change: save state: %v", err)
		a.dropPendingKey()
		return
	}
	now := time.Now().Unix()
	sig, err := hwsig.Sign(a.hw, hwsig.RotateMessage(old.PublicKey().String(), next.PublicKey().String(), now))
	if err != nil {
		a.cfg.Logf("key change: the hardware key: %v", err)
		a.dropPendingKey()
		return
	}
	c := &AdminClient{Controls: a.controls(), Key: old, HTTP: a.env.http}
	err = c.Do(ctx, http.MethodPost, api.PathRotate, api.RotateRequest{PublicKey: next.PublicKey().String(), Time: now, Signature: sig}, nil)
	if err == nil {
		a.useKey(next)
		a.cfg.Logf("WireGuard key changed (%s), certified by the hardware key", why)
		return
	}
	if HTTPStatus(err) != 0 { // refused: the old key stays
		a.cfg.Logf("key change refused: %v", err)
		a.dropPendingKey()
		return
	}
	// No answer: the control plane may have the new key or not; the map loop finds out.
	a.cfg.Logf("key change: no answer (%v): trying both keys until a control node answers", err)
}

// useKey makes next the device's key (the control plane said yes) and applies it, keeping the old
// one as the pending key until a control node answers the new one: the control plane changes the
// key just after its answer, and should that fail, the old key is what it still has.
func (a *runner) useKey(next wgtypes.Key) {
	a.mu.Lock()
	old := a.st.PrivateKey
	a.st.PrivateKey, a.st.NextPrivateKey, a.st.KeyCreatedAt = Key(next), &old, time.Now()
	a.swappedKey, a.pendingSwapAt = false, time.Now()
	err := a.save()
	nm := a.last
	a.mu.Unlock()
	if err != nil {
		a.cfg.Logf("save state: %v", err)
	}
	if err := a.apply(nm); err != nil {
		a.cfg.Logf("apply network map: %v", err)
	}
	a.announce()
}

func (a *runner) dropPendingKey() {
	a.mu.Lock()
	a.st.NextPrivateKey = nil
	err := a.save()
	a.mu.Unlock()
	if err != nil {
		a.cfg.Logf("save state: %v", err)
	}
}

// resolvePendingKey runs with the map loop while a key change's outcome is open: a control node
// answered (ok) with the key in use, so the other is dropped; none answered for pendingSwapAfter,
// so the other is tried.
func (a *runner) resolvePendingKey(ok bool) {
	a.mu.Lock()
	if a.st.NextPrivateKey == nil || a.rotating {
		a.mu.Unlock()
		return
	}
	if ok {
		a.st.NextPrivateKey = nil
		if a.swappedKey { // the other key is the one the control plane has: its age is unknown, so
			// the next check-in changes it again
			a.st.KeyCreatedAt = time.Now().Add(-keyRotateEvery())
		}
		a.swappedKey = false
		err := a.save()
		a.mu.Unlock()
		if err != nil {
			a.cfg.Logf("save state: %v", err)
		}
		a.cfg.Logf("key change settled: the control plane has key %s", strings.TrimRight(a.key().PublicKey().String()[:8], "="))
		a.announce()
		return
	}
	if a.unansweredSince.IsZero() || time.Since(a.pendingSwapAt) < pendingSwapAfter || time.Since(a.unansweredSince) < pendingSwapAfter {
		a.mu.Unlock()
		return
	}
	a.st.PrivateKey, *a.st.NextPrivateKey = *a.st.NextPrivateKey, a.st.PrivateKey
	a.swappedKey = !a.swappedKey
	a.pendingSwapAt = time.Now()
	err := a.save()
	nm := a.last
	a.mu.Unlock()
	if err != nil {
		a.cfg.Logf("save state: %v", err)
	}
	a.cfg.Logf("key change: no control node answers; trying the other key")
	if err := a.apply(nm); err != nil {
		a.cfg.Logf("apply network map: %v", err)
	}
}
