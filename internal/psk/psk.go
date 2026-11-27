// Package psk agrees on the WireGuard preshared key between a device and its control nodes
// (Constitution 9.1): the agent makes an ML-KEM-768 decapsulation key and sends the encapsulation
// key inside the tunnel, a control node encapsulates and answers with the ciphertext, and both
// derive the preshared key and a confirmation tag from the shared secret with HKDF-SHA256. Neither
// the key nor the secret is ever sent, so recording the exchange gives nothing, even to someone
// who breaks the curve of the tunnel's WireGuard keys later.
package psk

import (
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Versioned labels: a later scheme takes new ones, so a key never means two things.
const (
	labelSalt    = "ento-psk-v1"
	labelKey     = "wireguard-preshared-key"
	labelConfirm = "confirmation"
)

// ErrInvalid is a malformed encapsulation key or ciphertext.
var ErrInvalid = errors.New("invalid key exchange")

// Agreed is what both ends derive from the shared secret: the preshared key, and the tag the agent
// confirms it with (so that the confirmation names the key without being it).
type Agreed struct {
	Key wgtypes.Key
	Tag string // base64url, 32 bytes
}

// derive binds the key to the device's WireGuard public key at the time of the exchange.
func derive(secret []byte, device wgtypes.Key) (Agreed, error) {
	var a Agreed
	k, err := hkdf.Key(sha256.New, secret, []byte(labelSalt), labelKey+"\x00"+device.String(), 32)
	if err != nil {
		return a, err
	}
	copy(a.Key[:], k)
	t, err := hkdf.Key(sha256.New, secret, []byte(labelSalt), labelConfirm+"\x00"+device.String(), 32)
	if err != nil {
		return a, err
	}
	a.Tag = base64.RawURLEncoding.EncodeToString(t)
	return a, nil
}

// Request is the agent's half of an exchange: it keeps the decapsulation key in memory only.
type Request struct {
	dk *mlkem.DecapsulationKey768
}

// NewRequest makes a fresh decapsulation key.
func NewRequest() (*Request, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	return &Request{dk: dk}, nil
}

// EncapsulationKey is what the agent sends (base64url).
func (r *Request) EncapsulationKey() string {
	return base64.RawURLEncoding.EncodeToString(r.dk.EncapsulationKey().Bytes())
}

// Finish derives the agreed key from the control node's ciphertext.
func (r *Request) Finish(ciphertext string, device wgtypes.Key) (Agreed, error) {
	ct, err := base64.RawURLEncoding.DecodeString(ciphertext)
	if err != nil || len(ct) != mlkem.CiphertextSize768 {
		return Agreed{}, ErrInvalid
	}
	secret, err := r.dk.Decapsulate(ct)
	if err != nil {
		return Agreed{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return derive(secret, device)
}

// Answer is the control node's half: it encapsulates to the agent's key and returns the ciphertext
// to send back with what it derived.
func Answer(encapsulationKey string, device wgtypes.Key) (ciphertext string, a Agreed, err error) {
	b, err := base64.RawURLEncoding.DecodeString(encapsulationKey)
	if err != nil || len(b) != mlkem.EncapsulationKeySize768 {
		return "", Agreed{}, ErrInvalid
	}
	ek, err := mlkem.NewEncapsulationKey768(b)
	if err != nil {
		return "", Agreed{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	secret, ct := ek.Encapsulate()
	if a, err = derive(secret, device); err != nil {
		return "", Agreed{}, err
	}
	return base64.RawURLEncoding.EncodeToString(ct), a, nil
}

// SameTag compares two tags in constant time.
func SameTag(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
