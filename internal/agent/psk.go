package agent

import (
	"context"
	"net/http"
	"os"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/psk"
)

// The preshared key with the control nodes (Constitution 9.1; design: Preshared keys). The device
// joins with one (the redeem call's exchange) or, joined before, agrees on one over its tunnel;
// either way it changes daily and when the device's WireGuard key does (9.2). A change: an ML-KEM
// exchange (PathPSK) gives the next key, saved before anything else; the agent sets it on its
// tunnels with the control nodes and confirms it (PathPSKConfirm), which makes the control nodes
// set it too. The running sessions carry traffic meanwhile (WireGuard keeps a session when its
// preshared key changes; only the next handshake needs the same key on both ends).
//
// Whenever the outcome is unknown (an answer lost, a crash, the database restored from a backup
// with keys the device forgot), the agent finds the key the control nodes have by trying: while no
// control node answers for pskTryAfter, it uses another candidate (the other key, then none) for
// pskTryFor, then the key it believes in again; the candidate that gets an answer is the one the
// control nodes have. An ordinary outage costs at most pskTryFor more.

const (
	pskTryAfter = time.Minute
	pskTryFor   = 20 * time.Second
)

// pskEvery is how often the key changes: daily, or ENTO_PSK_EVERY (tests).
func pskEvery() time.Duration {
	if d, err := time.ParseDuration(os.Getenv("ENTO_PSK_EVERY")); err == nil && d > 0 {
		return d
	}
	return 24 * time.Hour
}

func keyOf(k *Key) wgtypes.Key {
	if k == nil {
		return wgtypes.Key{}
	}
	return wgtypes.Key(*k)
}

func optionalKey(k wgtypes.Key) *Key {
	if k == (wgtypes.Key{}) {
		return nil
	}
	kk := Key(k)
	return &kk
}

// pskBase is the key the agent believes the control nodes have, or will have once it confirms:
// the next key while a change is open. The caller holds a.mu.
func (a *runner) pskBase() wgtypes.Key {
	if a.st.NextPresharedKey != nil {
		return keyOf(a.st.NextPresharedKey)
	}
	return keyOf(a.st.PresharedKey)
}

// pskCandidates are the keys the control nodes may have, the believed one first. The caller holds
// a.mu.
func (a *runner) pskCandidates() []wgtypes.Key {
	out := []wgtypes.Key{a.pskBase()}
	for _, k := range []wgtypes.Key{keyOf(a.st.PresharedKey), keyOf(a.st.NextPresharedKey), {}} {
		dup := false
		for _, o := range out {
			dup = dup || o == k
		}
		if !dup {
			out = append(out, k)
		}
	}
	return out
}

// pskInUse is the key set on the tunnels with control nodes that set preshared keys: pskTry counts
// turns while no control node answers, odd ones trying another candidate, even ones the believed
// key again. The caller holds a.mu.
func (a *runner) pskInUse() wgtypes.Key {
	c := a.pskCandidates()
	if a.pskTry%2 == 1 && len(c) > 1 {
		return c[1+(a.pskTry/2)%(len(c)-1)]
	}
	return c[0]
}

// notePSKApplied records when the key in use last changed on the tunnels (apply): only a handshake
// after that proves which key the control nodes have. The caller holds a.mu.
func (a *runner) notePSKApplied(k wgtypes.Key) {
	if k != a.pskApplied {
		a.pskApplied, a.pskSetAt = k, time.Now()
	}
}

// controlsSetPSK reports whether any control node sets preshared keys. The caller holds a.mu.
func (a *runner) controlsSetPSK() bool {
	for _, c := range a.st.Controls {
		if c.PresharedKeys {
			return true
		}
	}
	return false
}

// resolvePSK runs with the map loop (ok: ctl answered). A handshake with a control node that sets
// preshared keys made after the key in use was set proves that the control nodes have that key
// (an answer alone does not: a session outlives a change of key by up to three minutes), and
// settles the state on it. While none answers, the agent tries the other candidates in turn.
func (a *runner) resolvePSK(ok bool, ctl api.Control) {
	if a.saveFn != nil { // a linked network's membership has no preshared key
		return
	}
	if ok {
		a.settlePSK(ctl)
		return
	}
	a.mu.Lock()
	if a.unansweredSince.IsZero() || time.Since(a.unansweredSince) < pskTryAfter || a.pskBusy || !a.controlsSetPSK() ||
		len(a.pskCandidates()) < 2 {
		a.mu.Unlock()
		return
	}
	switch {
	case a.pskTry%2 == 0 && time.Since(a.pskTryAt) >= pskTryAfter: // the believed key's turn is over
	case a.pskTry%2 == 1 && time.Since(a.pskTryAt) >= pskTryFor: // the candidate's turn is over
	default:
		a.mu.Unlock()
		return
	}
	a.pskTry++
	a.pskTryAt = time.Now()
	try := a.pskTry
	nm := a.last
	a.mu.Unlock()
	if try%2 == 1 {
		a.cfg.Logf("no control node answers: trying another preshared key for %s", pskTryFor)
	}
	if err := a.apply(nm); err != nil {
		a.cfg.Logf("apply network map: %v", err)
	}
}

func (a *runner) settlePSK(ctl api.Control) {
	if !ctl.PresharedKeys {
		return
	}
	ctlKey, err := wgtypes.ParseKey(ctl.PublicKey)
	if err != nil {
		return
	}
	status, err := a.ifc.Status()
	if err != nil {
		return
	}
	a.mu.Lock()
	hs := status[ctlKey].LastHandshake
	if a.pskBusy || hs.IsZero() || !hs.After(a.pskSetAt) {
		a.mu.Unlock()
		return
	}
	inUse, base := a.pskInUse(), a.pskBase()
	a.pskTry, a.pskTryAt = 0, time.Now()
	var note string
	switch {
	case inUse == base && a.st.NextPresharedKey == nil:
		a.mu.Unlock()
		return // nothing open
	case a.st.NextPresharedKey != nil && inUse == keyOf(a.st.NextPresharedKey):
		// The confirmation took effect, its answer was lost.
		a.st.PresharedKey, a.st.NextPresharedKey, a.st.NextPSKTag = a.st.NextPresharedKey, nil, ""
		a.st.PSKAt, a.st.PSKFor = time.Now(), wgtypes.Key(a.st.PrivateKey).PublicKey().String()
		note = "the control nodes have the new preshared key"
	case a.st.PresharedKey != nil && inUse == keyOf(a.st.PresharedKey):
		// The change did not reach them: another one later.
		a.st.NextPresharedKey, a.st.NextPSKTag = nil, ""
		note = "the control nodes kept the preshared key; a new one is agreed later"
	default: // none: the control nodes forgot the keys (ento control psk-reset)
		a.st.PresharedKey, a.st.NextPresharedKey, a.st.NextPSKTag, a.st.PSKAt = nil, nil, "", time.Time{}
		note = "the control nodes have no preshared key for this device (reset); a new one is agreed at the next check-in"
	}
	err = a.save()
	a.mu.Unlock()
	if err != nil {
		a.cfg.Logf("save state: %v", err)
	}
	a.cfg.Logf("%s", note)
}

// pskDue reports whether the key should change now. The caller holds a.mu.
func (a *runner) pskDue() bool {
	if !a.controlsSetPSK() || a.pskBusy || a.pskTry > 0 || a.st.NextPresharedKey != nil || a.st.NextPrivateKey != nil {
		return false
	}
	return a.st.PresharedKey == nil || time.Since(a.st.PSKAt) >= pskEvery() || a.st.PSKFor != wgtypes.Key(a.st.PrivateKey).PublicKey().String()
}

// changePSK agrees on a new key with the control nodes and confirms it, if one is due, or confirms
// again a change whose answer was lost (the control nodes answer a repeated confirmation alike).
func (a *runner) changePSK(ctx context.Context) {
	if a.saveFn != nil {
		return
	}
	a.mu.Lock()
	if a.st.NextPresharedKey != nil && !a.pskBusy && a.pskTry == 0 {
		a.pskBusy = true
		a.mu.Unlock()
		a.confirmPSK(ctx, "confirmed again")
		a.mu.Lock()
		a.pskBusy = false
		a.mu.Unlock()
		return
	}
	if !a.pskDue() {
		a.mu.Unlock()
		return
	}
	a.pskBusy = true
	why := "daily"
	switch {
	case a.st.PresharedKey == nil:
		why = "none yet"
	case a.st.PSKFor != wgtypes.Key(a.st.PrivateKey).PublicKey().String():
		why = "the WireGuard key changed"
	}
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.pskBusy = false
		a.mu.Unlock()
	}()
	req, err := psk.NewRequest()
	if err != nil {
		a.cfg.Logf("preshared key: %v", err)
		return
	}
	key := a.key()
	c := &AdminClient{Controls: a.controls(), Key: key, HTTP: a.env.http}
	var res api.PSKResponse
	if err := c.Do(ctx, http.MethodPost, api.PathPSK, api.PSKRequest{EncapsulationKey: req.EncapsulationKey()}, &res); err != nil {
		if s := HTTPStatus(err); s != http.StatusNotFound && s != http.StatusMethodNotAllowed && ctx.Err() == nil {
			a.cfg.Logf("preshared key: %v", err)
		}
		return
	}
	agreed, err := req.Finish(res.Ciphertext, key.PublicKey())
	if err != nil {
		a.cfg.Logf("preshared key: %v", err)
		return
	}
	// Saved before it is used: a crash from here on leaves the agent knowing both keys.
	a.mu.Lock()
	a.st.NextPresharedKey, a.st.NextPSKTag = optionalKey(agreed.Key), agreed.Tag
	err = a.save()
	nm := a.last
	a.mu.Unlock()
	if err != nil {
		a.cfg.Logf("preshared key: save state: %v", err)
		a.dropNextPSK()
		return
	}
	if err := a.apply(nm); err != nil {
		a.cfg.Logf("apply network map: %v", err)
	}
	a.confirmPSK(ctx, why)
}

// confirmPSK confirms the next key, once it is set on the agent's tunnels.
func (a *runner) confirmPSK(ctx context.Context, why string) {
	a.mu.Lock()
	tag := a.st.NextPSKTag
	a.mu.Unlock()
	if tag == "" {
		return
	}
	c := &AdminClient{Controls: a.controls(), Key: a.key(), HTTP: a.env.http}
	err := c.Do(ctx, http.MethodPost, api.PathPSKConfirm, api.PSKConfirm{Tag: tag}, nil)
	switch status := HTTPStatus(err); {
	case err == nil:
		a.mu.Lock()
		a.st.PresharedKey, a.st.NextPresharedKey, a.st.NextPSKTag = a.st.NextPresharedKey, nil, ""
		a.st.PSKAt, a.st.PSKFor = time.Now(), wgtypes.Key(a.st.PrivateKey).PublicKey().String()
		err := a.save()
		a.mu.Unlock()
		if err != nil {
			a.cfg.Logf("save state: %v", err)
		}
		a.cfg.Logf("preshared key with the control nodes changed (%s)", why)
	case status != 0: // refused: the control nodes keep the key they have
		a.cfg.Logf("preshared key change refused: %v", err)
		a.dropNextPSK()
	default:
		// No answer: whether it took effect shows when a control node next answers (resolvePSK).
		a.cfg.Logf("preshared key change: no answer (%v): settled when a control node answers", err)
	}
}

// dropNextPSK forgets a next key that the control nodes do not have, and sets the current one
// again.
func (a *runner) dropNextPSK() {
	a.mu.Lock()
	a.st.NextPresharedKey, a.st.NextPSKTag = nil, ""
	err := a.save()
	nm := a.last
	a.mu.Unlock()
	if err != nil {
		a.cfg.Logf("save state: %v", err)
	}
	if err := a.apply(nm); err != nil {
		a.cfg.Logf("apply network map: %v", err)
	}
}

// pskNote is what `ento status` shows of the preshared key. The caller holds a.mu.
func (a *runner) pskNote() string {
	switch {
	case !a.controlsSetPSK():
		return "none (the control nodes set none)"
	case a.pskTry%2 == 1:
		return "trying another (no control node answers)"
	case a.st.NextPresharedKey != nil:
		return "changing"
	case a.st.PresharedKey == nil:
		return "none yet"
	}
	return "from " + a.st.PSKAt.UTC().Format(time.RFC3339) + ", changed every " + pskEvery().String()
}

// pairKey is the preshared key of the tunnel with peer p now (Constitution 9.1): the map's next one
// once its time has come by the control nodes' clock, else the one in use; and it has a.pairTimer
// re-apply the map when the next is due, so that both ends switch within seconds of each other.
// The caller holds a.mu.
func (a *runner) pairKey(p api.Peer) wgtypes.Key {
	parse := func(s string) wgtypes.Key {
		if s == "" {
			return wgtypes.Key{}
		}
		k, err := wgtypes.ParseKey(s)
		if err != nil {
			return wgtypes.Key{}
		}
		return k
	}
	if p.PresharedKeyNext == "" {
		return parse(p.PresharedKey)
	}
	at := time.Unix(p.PresharedKeyAt, 0).Add(-a.clockOffset) // in the device's own clock
	if wait := time.Until(at); wait > 0 {
		a.pairDue(wait)
		return parse(p.PresharedKey)
	}
	return parse(p.PresharedKeyNext)
}

// pairDue has the map re-applied in wait, unless an earlier re-apply is set already. The caller
// holds a.mu.
func (a *runner) pairDue(wait time.Duration) {
	due := time.Now().Add(wait + 100*time.Millisecond)
	if a.pairTimer != nil && a.pairDueAt.After(time.Now()) && !a.pairDueAt.After(due) {
		return
	}
	if a.pairTimer != nil {
		a.pairTimer.Stop()
	}
	a.pairDueAt = due
	a.pairTimer = time.AfterFunc(time.Until(due), func() {
		a.mu.Lock()
		nm := a.last
		a.mu.Unlock()
		if err := a.apply(nm); err != nil {
			a.cfg.Logf("apply network map: %v", err)
		}
	})
}
