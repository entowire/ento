// Package credential implements the access credentials of linked networks.
//
// A home network links to another, independent network (the linked network) through an authority:
// an Ed25519 key pair whose private half stays with the home network's control plane and whose
// public half is registered in the linked network. The home control plane signs short-lived
// credentials for its devices; the linked network's control plane verifies them and admits the
// device with the groups the credential carries, limited to those it allows the authority, until
// the credential expires.
//
// Every linked network registers a different authority key, so a credential issued for one linked
// network cannot be used in another.
package credential

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	credentialPrefix = "entoc1."
	publicKeyPrefix  = "entoa1:"
	// signingContext separates these signatures from any other use of the key.
	signingContext = "ento/v1/credential\x00"
)

// Claims is what a credential asserts about a device.
type Claims struct {
	Key       string   `json:"key"`    // the device's WireGuard public key in the linked network
	User      string   `json:"user"`   // who uses the device, as known to the home network
	Device    string   `json:"device"` // the device's hostname
	Groups    []string `json:"groups"` // groups requested in the linked network
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
	// ID identifies this credential in both networks' audit lines.
	ID string `json:"jti,omitempty"`
	// DeviceID identifies the device in its home network, so the linked network keeps one
	// membership per device: a new one (a new key) replaces the previous.
	DeviceID string `json:"did,omitempty"`
}

// NewID returns a random credential identifier.
func NewID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// MaxClockSkew is how far a home network's clock may run ahead of the linked network's.
const MaxClockSkew = 2 * time.Minute

// Issued returns the issue time.
func (c Claims) Issued() time.Time { return time.Unix(c.IssuedAt, 0) }

// Expires returns the expiry as a time.
func (c Claims) Expires() time.Time { return time.Unix(c.ExpiresAt, 0) }

// NewKey generates an authority key pair.
func NewKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// Sign returns the textual credential for claims.
func Sign(priv ed25519.PrivateKey, c Claims) (string, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, append([]byte(signingContext), payload...))
	return credentialPrefix + base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(sig), nil
}

// ErrInvalid is returned for credentials that are malformed, not signed by the expected key or
// expired.
var ErrInvalid = errors.New("invalid credential")

// Verify checks a credential against an authority's public key and returns its claims if it is
// valid at now.
func Verify(pub ed25519.PublicKey, s string, now time.Time) (Claims, error) {
	var c Claims
	if len(pub) != ed25519.PublicKeySize {
		return c, fmt.Errorf("%w: bad authority key", ErrInvalid)
	}
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), credentialPrefix)
	if !ok {
		return c, fmt.Errorf("%w: not a credential", ErrInvalid)
	}
	p, sg, ok := strings.Cut(rest, ".")
	if !ok {
		return c, fmt.Errorf("%w: malformed", ErrInvalid)
	}
	payload, err1 := base64.RawURLEncoding.DecodeString(p)
	sig, err2 := base64.RawURLEncoding.DecodeString(sg)
	if err1 != nil || err2 != nil {
		return c, fmt.Errorf("%w: malformed", ErrInvalid)
	}
	if !ed25519.Verify(pub, append([]byte(signingContext), payload...), sig) {
		return c, fmt.Errorf("%w: bad signature", ErrInvalid)
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return c, fmt.Errorf("%w: malformed claims", ErrInvalid)
	}
	if !now.Before(c.Expires()) {
		return c, fmt.Errorf("%w: expired", ErrInvalid)
	}
	// Issued in the future (beyond clock drift), or expiring before it was issued: not a credential
	// any home network makes, and a future issue time would stretch the authority's limit.
	if c.IssuedAt > now.Add(MaxClockSkew).Unix() || c.ExpiresAt <= c.IssuedAt {
		return c, fmt.Errorf("%w: issue time out of range", ErrInvalid)
	}
	if c.Key == "" {
		return c, fmt.Errorf("%w: no device key", ErrInvalid)
	}
	return c, nil
}

// EncodePublicKey returns the textual form of an authority public key.
func EncodePublicKey(pub ed25519.PublicKey) string {
	return publicKeyPrefix + base64.RawURLEncoding.EncodeToString(pub)
}

// ParsePublicKey decodes the textual form of an authority public key.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), publicKeyPrefix)
	if !ok {
		return nil, errors.New("not an authority public key")
	}
	b, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("malformed authority public key")
	}
	return ed25519.PublicKey(b), nil
}
