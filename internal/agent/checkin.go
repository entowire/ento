package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
)

// Check-ins (see the control package): every few minutes the agent presents the token the last
// check-in handed out, with a fingerprint of the machine, and keeps the new token, written to disk
// before it is used. A copy of the state on another machine presents a token one of the two has
// already spent, or another fingerprint, and the control plane notices.

const (
	checkInFile  = "checkin.token"
	checkInEvery = 5 * time.Minute
)

var appMachineID struct {
	sync.Mutex
	id string
}

// SetAppMachineID gives the agent the machine identifier only an app can read (Android's
// ANDROID_ID), for the check-ins' fingerprint.
func SetAppMachineID(id string) {
	appMachineID.Lock()
	appMachineID.id = strings.TrimSpace(id)
	appMachineID.Unlock()
}

// fingerprint is a hash of the machine's identifier salted with the device's key, so that one
// machine shows unrelated fingerprints in different networks; "" when there is no identifier.
func fingerprint(ctx context.Context, pub wgtypes.Key) string {
	appMachineID.Lock()
	id := appMachineID.id
	appMachineID.Unlock()
	if id == "" {
		id = machineID(ctx)
	}
	if id == "" {
		return ""
	}
	h := sha256.Sum256([]byte("ento-fingerprint-v1\n" + pub.String() + "\n" + id))
	return hex.EncodeToString(h[:])
}

func readCheckInToken(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, checkInFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// saveCheckInToken writes the next token durably before anything uses it: a token the control plane
// issued but the agent lost costs nothing (it presents the previous one), a token used but not kept
// would look like a copy.
func saveCheckInToken(dir, tok string) error {
	tmp := filepath.Join(dir, checkInFile+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(tok + "\n"); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, checkInFile))
}

// checkInInterval is checkInEvery, or ENTO_CHECKIN_EVERY (tests).
func checkInInterval() time.Duration {
	if d, err := time.ParseDuration(os.Getenv("ENTO_CHECKIN_EVERY")); err == nil && d > 0 {
		return d
	}
	return checkInEvery
}

// checkIns runs the check-ins of the home network, one at a time (two at once could present the
// same token), until ctx ends.
func (a *runner) checkIns(ctx context.Context) {
	wait, quiet, refused := 3*time.Second, false, false
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = checkInInterval()
		dir := a.cfg.StateDir
		a.sendPendingLogout(ctx)
		idle := personIdle()
		a.bindHardwareKey(ctx)
		req := api.CheckInRequest{Token: readCheckInToken(dir), Fingerprint: fingerprint(ctx, a.key().PublicKey()),
			PersonIdle: &idle, BootID: bootID()}
		a.mu.Lock()
		req.FilterFailed = a.filterErr
		req.HereGuard = a.hereGuard
		a.mu.Unlock()
		req.UpdateFailed = a.updateFailure()
		if len(req.UpdateFailed) > 200 {
			req.UpdateFailed = req.UpdateFailed[:200]
		}
		if len(req.FilterFailed) > 200 {
			req.FilterFailed = req.FilterFailed[:200]
		}
		a.signCheckIn(&req)
		c := &AdminClient{Controls: a.controls(), Key: a.key(), HTTP: a.env.http}
		var res api.CheckInResponse
		err := c.Do(ctx, http.MethodPost, api.PathCheckIn, req, &res)
		var he httpError
		switch {
		case err == nil:
			if err := saveCheckInToken(dir, res.Token); err != nil {
				a.cfg.Logf("check-in: keep the next token: %v", err)
			}
			refused = false
			switch {
			case res.RotateKey:
				a.rotateKey(ctx, "asked by the control plane")
			case a.keyDue():
				a.rotateKey(ctx, "daily")
			}
		case errors.As(err, &he) && (he.code == http.StatusNotFound || he.code == http.StatusMethodNotAllowed):
			if !quiet {
				a.cfg.Logf("check-in: the control plane takes none (older than ento 0.23)")
				quiet = true
			}
		case errors.As(err, &he) && he.code == http.StatusConflict:
			if !refused {
				a.cfg.Logf("check-in refused: %v", err)
				refused = true
			}
		default:
			if ctx.Err() == nil {
				a.cfg.Logf("check-in: %v", err)
			}
			wait = time.Minute
		}
	}
}
