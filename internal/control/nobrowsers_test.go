package control

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestNoBrowsers checks the plain API's guard: agents pass, a browser opening a page by name is sent
// to https, and every other browser request is refused.
func TestNoBrowsers(t *testing.T) {
	h := noBrowsers(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	cases := []struct {
		name, method, host string
		headers            map[string]string
		code               int
		location           string
	}{
		{"agent", "GET", "100.64.0.1", nil, http.StatusTeapot, ""},
		{"page by name", "GET", "net.example.com", map[string]string{"Sec-Fetch-Mode": "navigate"}, http.StatusPermanentRedirect, "https://net.example.com/v1/x?y=1"},
		{"page by name and port", "GET", "net.example.com:80", map[string]string{"Sec-Fetch-Mode": "navigate"}, http.StatusPermanentRedirect, "https://net.example.com/v1/x?y=1"},
		{"page by address", "GET", "100.64.0.1", map[string]string{"Sec-Fetch-Mode": "navigate"}, http.StatusForbidden, ""},
		{"page by IPv6 address", "GET", "[fd00::1]:80", map[string]string{"Sec-Fetch-Mode": "navigate"}, http.StatusForbidden, ""},
		{"cross-site fetch", "GET", "net.example.com", map[string]string{"Sec-Fetch-Mode": "cors", "Origin": "https://evil.example"}, http.StatusForbidden, ""},
		{"form post", "POST", "net.example.com", map[string]string{"Sec-Fetch-Mode": "navigate", "Origin": "https://evil.example"}, http.StatusForbidden, ""},
		{"agent on IPv6", "GET", "[fd00::1]:80", nil, http.StatusTeapot, ""},
		{"agent with port", "GET", "100.64.0.1:80", nil, http.StatusTeapot, ""},
		{"rebound name, no fetch metadata", "GET", "evil.example", nil, http.StatusForbidden, ""},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, "http://placeholder/v1/x?y=1", nil)
		r.Host = c.host
		for k, v := range c.headers {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.code || w.Header().Get("Location") != c.location {
			t.Errorf("%s: %d %q, want %d %q", c.name, w.Code, w.Header().Get("Location"), c.code, c.location)
		}
	}
}

// TestNoBrowsersBody: a body must be JSON (an older browser's page can post text without asking).
func TestNoBrowsersBody(t *testing.T) {
	h := noBrowsers(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	for ct, want := range map[string]int{
		"application/json":                  http.StatusTeapot,
		"application/json; charset=utf-8":   http.StatusTeapot,
		"text/plain":                        http.StatusUnsupportedMediaType,
		"application/x-www-form-urlencoded": http.StatusUnsupportedMediaType,
		"":                                  http.StatusUnsupportedMediaType,
	} {
		r := httptest.NewRequest("POST", "http://100.64.0.1/v1/peers", strings.NewReader(`{"a":1}`))
		if ct != "" {
			r.Header.Set("Content-Type", ct)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Errorf("%q: %d, want %d", ct, w.Code, want)
		}
	}
	r := httptest.NewRequest("POST", "http://100.64.0.1/v1/login", nil) // no body: no type needed
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusTeapot {
		t.Errorf("empty POST: %d", w.Code)
	}
}
