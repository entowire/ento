package attest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const sampleStatus = `{"entries": {
  "2c8cdddfd5e03bfc": {"status": "REVOKED", "reason": "KEY_COMPROMISE"},
  "00C35747A084470C": {"status": "SUSPENDED", "reason": "SOFTWARE_FLAW"},
  "beef": {"status": "REVOKED", "reason": "KEY_COMPROMISE", "comment": "a field the list may gain"}
}}`

func TestRevocations(t *testing.T) {
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "no", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte(sampleStatus))
	}))
	defer srv.Close()
	var logged []string
	r := NewRevocations(srv.URL, func(f string, a ...any) { logged = append(logged, f) })
	if _, err := r.Revoked("beef"); err == nil || !strings.Contains(err.Error(), "not fetched yet") {
		t.Fatalf("before the first fetch: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)
	r.Wait(ctx, 5*time.Second)
	for serial, want := range map[string]bool{"2c8cdddfd5e03bfc": true, "c35747a084470c": true, "beef": true, "beee": false} {
		if got, err := r.Revoked(serial); err != nil || got != want {
			t.Errorf("%s: %v %v", serial, got, err)
		}
	}
	// A failed fetch keeps the list until it is RevocationsMaxAge old.
	fail.Store(true)
	if err := r.fetch(ctx); err == nil {
		t.Fatal("fetch did not fail")
	}
	if got, err := r.Revoked("beef"); err != nil || !got {
		t.Errorf("after a failed fetch: %v %v", got, err)
	}
	r.mu.Lock()
	r.at = time.Now().Add(-RevocationsMaxAge - time.Minute)
	r.mu.Unlock()
	if _, err := r.Revoked("beee"); err == nil || !strings.Contains(err.Error(), "not fetched in 3d") {
		t.Errorf("stale list: %v", err)
	}
}

func TestParseRevocations(t *testing.T) {
	for _, bad := range []string{"", "[]", `{"entries": null}`, `{}`, `{"entries": {"a": 1}`} {
		if _, err := parseRevocations(strings.NewReader(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	m, err := parseRevocations(strings.NewReader(`{"entries": {}}`))
	if err != nil || len(m) != 0 {
		t.Error(m, err)
	}
}
