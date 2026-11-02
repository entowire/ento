package token

import (
	"strings"
	"testing"
)

func TestJoinCode(t *testing.T) {
	j, err := NewJoinCode("Demo.Example.NET.", "8A4D-0034-38bf-6588", "abacus-zoom gumdrop dropbox snowdrop")
	if err != nil {
		t.Fatal(err)
	}
	text := j.String()
	if text != "ENTO1:DEMO.EXAMPLE.NET:8A4D-0034-38BF-6588:ABACUS ZOOM GUMDROP DROPBOX SNOWDROP" {
		t.Fatalf("code %q", text)
	}
	// Only characters of the QR code's alphanumeric mode.
	for _, r := range text {
		if !strings.ContainsRune("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:", r) {
			t.Fatalf("%q is outside the alphanumeric mode", r)
		}
	}
	for _, in := range []string{text, strings.ToLower(text), "  " + text + "\n"} {
		got, err := ParseJoinCode(in)
		if err != nil || got.Domain != "demo.example.net" || got.Fingerprint != "8a4d-0034-38bf-6588" ||
			strings.Join(got.Words, " ") != "abacus zoom gumdrop dropbox snowdrop" {
			t.Errorf("%q: %+v %v", in, got, err)
		}
	}
	for _, in := range []string{
		"",
		"ento1:AAAA", // a token, not a join code
		"ENTO2:EXAMPLE.COM:8A4D-0034-38BF-6588:ABACUS ZOOM GUMDROP DROPBOX SNOWDROP", // another version
		"ENTO1:EXAMPLE.COM:ABACUS ZOOM GUMDROP DROPBOX SNOWDROP",                     // no fingerprint
		"ENTO1:EXAMPLE:8A4D-0034-38BF-6588:ABACUS ZOOM GUMDROP DROPBOX SNOWDROP",     // no domain
		"ENTO1:EX_AMPLE.COM:8A4D-0034-38BF-6588:ABACUS ZOOM GUMDROP DROPBOX SNOWDROP",
		"ENTO1:EXAMPLE.COM:8A4D-0034-38BF:ABACUS ZOOM GUMDROP DROPBOX SNOWDROP",
		"ENTO1:EXAMPLE.COM:8A4D-0034-38BF-6588:ABACUS ZOOM GUMDROP DROPBOX",
		"ENTO1:EXAMPLE.COM:8A4D-0034-38BF-6588:ABACUS ZOOM GUMDROP DROPBOX SNOWDRIP",
		"ENTO1:EXAMPLE.COM:8A4D-0034-38BF-6588:" + strings.Repeat("ABACUS ", 100),
	} {
		if j, err := ParseJoinCode(in); err == nil {
			t.Errorf("%q accepted: %+v", in, j)
		}
	}
}
