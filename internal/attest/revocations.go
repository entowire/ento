package attest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"entowire.com/ento/internal/api"
)

// DefaultRevocationsURL is where Google publishes the attestation certificates it revoked.
const DefaultRevocationsURL = "https://android.googleapis.com/attestation/status"

// RevocationsMaxAge is how old the latest list fetched may be: older, and no attestation counts (a
// key that leaked from some phone lets any phone, rooted or not, claim a verified boot).
const RevocationsMaxAge = 3 * 24 * time.Hour

const (
	revocationsEvery   = 6 * time.Hour
	revocationsRetry   = 15 * time.Minute
	maxRevocationsBody = 32 << 20
)

// Revocations is Google's list of revoked attestation certificates (keys that leaked from phones,
// or flawed ones), fetched again every few hours by Run.
type Revocations struct {
	url  string
	logf func(string, ...any)
	http *http.Client

	mu      sync.Mutex
	serials map[string]bool
	at      time.Time     // when the list in serials was fetched
	tried   chan struct{} // closed once the first fetch ended, either way
	once    sync.Once
	failing bool
}

// NewRevocations returns the list at url, empty until Run fetched it.
func NewRevocations(url string, logf func(string, ...any)) *Revocations {
	return &Revocations{url: url, logf: logf, http: &http.Client{Timeout: 60 * time.Second}, tried: make(chan struct{})}
}

// Run fetches the list now and then every 6 hours (every 15 minutes while that fails), until ctx
// ends.
func (r *Revocations) Run(ctx context.Context) {
	for {
		wait := revocationsEvery
		if err := r.fetch(ctx); err != nil {
			wait = revocationsRetry
			if ctx.Err() == nil {
				r.mu.Lock()
				never, age := r.at.IsZero(), time.Since(r.at)
				r.failing = true
				r.mu.Unlock()
				if never {
					r.logf("attestation revocation list: %v; attestations do not count until it is fetched", err)
				} else {
					r.logf("attestation revocation list: %v; using the one fetched %s ago (attestations stop counting at %s)",
						err, api.HumanDuration(age), api.HumanDuration(RevocationsMaxAge))
				}
			}
		}
		r.once.Do(func() { close(r.tried) })
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// Wait waits until the first fetch ended (or max passed, or ctx ended), so that reports right after
// a start are not judged without the list.
func (r *Revocations) Wait(ctx context.Context, max time.Duration) {
	select {
	case <-r.tried:
	case <-ctx.Done():
	case <-time.After(max):
	}
}

// Revoked says whether a certificate serial number (lowercase hexadecimal) is on the list. It fails
// when no list younger than RevocationsMaxAge was fetched.
func (r *Revocations) Revoked(serial string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.at.IsZero() {
		return false, errors.New("the revocation list was not fetched yet")
	}
	if time.Since(r.at) > RevocationsMaxAge {
		return false, fmt.Errorf("the revocation list was not fetched in %s", api.HumanDuration(RevocationsMaxAge))
	}
	return r.serials[serial], nil
}

func (r *Revocations) fetch(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url, nil)
	if err != nil {
		return err
	}
	res, err := r.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", r.url, res.Status)
	}
	serials, err := parseRevocations(io.LimitReader(res.Body, maxRevocationsBody))
	if err != nil {
		return fmt.Errorf("%s: %v", r.url, err)
	}
	r.mu.Lock()
	recovered := r.failing
	r.serials, r.at, r.failing = serials, time.Now(), false
	r.mu.Unlock()
	if recovered {
		r.logf("attestation revocation list fetched again (%d revoked certificates)", len(serials))
	}
	return nil
}

// parseRevocations reads the list: {"entries": {"<serial in hex>": {"status": "REVOKED", ...}}}.
// Every entry counts as revoked, whatever its status (REVOKED, SUSPENDED).
func parseRevocations(body io.Reader) (map[string]bool, error) {
	var doc struct {
		Entries map[string]json.RawMessage `json:"entries"`
	}
	if err := json.NewDecoder(body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("unreadable: %v", err)
	}
	if doc.Entries == nil {
		return nil, errors.New("no entries")
	}
	out := make(map[string]bool, len(doc.Entries))
	for serial := range doc.Entries {
		s := strings.TrimLeft(strings.ToLower(serial), "0")
		if s == "" {
			s = "0"
		}
		out[s] = true
	}
	return out, nil
}
