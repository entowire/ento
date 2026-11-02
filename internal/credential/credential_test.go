package credential

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSignVerify(t *testing.T) {
	pub, priv, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	c := Claims{Key: "k", User: "alice", Device: "laptop", Groups: []string{"operators"},
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix()}
	s, err := Sign(priv, c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(pub, s, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.User != "alice" || got.Groups[0] != "operators" {
		t.Fatalf("claims = %+v", got)
	}

	if _, err := Verify(pub, s, now.Add(2*time.Hour)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expired credential accepted: %v", err)
	}
	other, _, _ := NewKey()
	if _, err := Verify(other, s, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("credential verified with another authority key: %v", err)
	}
	// Tamper with the claims: the signature must no longer match.
	body := strings.TrimPrefix(s, credentialPrefix)
	if _, err := Verify(pub, credentialPrefix+"e30"+body[strings.Index(body, "."):], now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tampered credential accepted: %v", err)
	}
}

func TestPublicKeyText(t *testing.T) {
	pub, _, _ := NewKey()
	got, err := ParsePublicKey(EncodePublicKey(pub))
	if err != nil || !got.Equal(pub) {
		t.Fatalf("round trip: %v", err)
	}
	if _, err := ParsePublicKey("entoa1:AAAA"); err == nil {
		t.Fatal("short key accepted")
	}
}

// A credential issued in the future (beyond clock drift) or expiring before it was issued is
// refused: a future issue time would stretch the authority's limit, which counts from issuance.
func TestIssueTime(t *testing.T) {
	pub, priv, _ := NewKey()
	now := time.Now()
	at := func(d time.Duration) int64 { return now.Add(d).Unix() }
	for name, c := range map[string]Claims{
		"issued an hour ahead":  {Key: "k", IssuedAt: at(time.Hour), ExpiresAt: at(2 * time.Hour)},
		"expires before issued": {Key: "k", IssuedAt: at(90 * time.Second), ExpiresAt: at(time.Minute)},
		"expires when issued":   {Key: "k", IssuedAt: at(time.Minute), ExpiresAt: at(time.Minute)},
	} {
		s, _ := Sign(priv, c)
		if _, err := Verify(pub, s, now); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
	s, _ := Sign(priv, Claims{Key: "k", IssuedAt: at(time.Minute), ExpiresAt: at(time.Hour)})
	if _, err := Verify(pub, s, now); err != nil {
		t.Errorf("a minute of clock drift refused: %v", err)
	}
}
