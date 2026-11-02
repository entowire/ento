// Package hwsig is what a device's hardware-held key signs, and how a control node checks it.
//
// A device's identity is its WireGuard key, which lives in the agent's state: a copy of that state
// is the device. A hardware-held key (a P-256 key kept by the TPM, which never hands out its private
// half) cannot be copied. It cannot be the WireGuard key itself (WireGuard's Curve25519 is not among
// what TPMs do), so it vouches for it instead: it signs each check-in, and each new WireGuard key
// the device changes to. The messages bind what is signed to the device's current WireGuard key and a
// time, under a label per purpose, so that no signature serves another purpose or another key.
//
// Signatures are ECDSA P-256 over SHA-256, ASN.1 DER, base64; public keys PKIX DER, base64.
package hwsig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// Kinds of hardware-held keys.
const (
	KindTPM = "tpm"
)

// MaxSkew is how far a signed time may be from the control node's clock.
const MaxSkew = 5 * time.Minute

// Signer is a hardware-held key.
type Signer interface {
	// Kind names the hardware (KindTPM).
	Kind() string
	// Public returns the key's public half.
	Public() *ecdsa.PublicKey
	// SignDigest signs a SHA-256 digest, ASN.1 DER.
	SignDigest(digest []byte) ([]byte, error)
}

// BindMessage is what a device signs to bind its hardware key: the key and the WireGuard key it
// vouches for.
func BindMessage(wgPublic, hwPublic string, t int64) []byte {
	return message("ento-hwkey-v1", wgPublic, hwPublic, strconv.FormatInt(t, 10))
}

// CheckInMessage is what a device signs at each check-in: the token it presents with its WireGuard
// key, so the signature is fresh and serves that check-in only.
func CheckInMessage(wgPublic, token string, t int64) []byte {
	return message("ento-checkin-v1", wgPublic, token, strconv.FormatInt(t, 10))
}

// RotateMessage is what a device signs to change its WireGuard key: from the current one to the next.
func RotateMessage(oldPublic, newPublic string, t int64) []byte {
	return message("ento-rotate-v1", oldPublic, newPublic, strconv.FormatInt(t, 10))
}

func message(label string, fields ...string) []byte {
	b := []byte(label)
	for _, f := range fields {
		b = append(b, '\n')
		b = append(b, f...)
	}
	return b
}

// Sign signs a message with s, base64.
func Sign(s Signer, msg []byte) (string, error) {
	d := sha256.Sum256(msg)
	sig, err := s.SignDigest(d[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// EncodePublic returns a public key as a control node stores it (PKIX DER, base64).
func EncodePublic(k *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// ParsePublic reads a public key in that form; only P-256 keys are accepted.
func ParsePublic(s string) (*ecdsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(der) > 512 {
		return nil, errors.New("not a public key")
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("not a public key: %v", err)
	}
	ec, ok := k.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("not a P-256 key")
	}
	return ec, nil
}

// Verify checks a base64 signature of msg by the public key pub (as EncodePublic gives it), made at
// t (Unix seconds), against now.
func Verify(pub, sig string, msg []byte, t int64, now time.Time) error {
	if d := now.Sub(time.Unix(t, 0)); d > MaxSkew || d < -MaxSkew {
		return fmt.Errorf("signed at %s, too far from now", time.Unix(t, 0).UTC().Format(time.RFC3339))
	}
	k, err := ParsePublic(pub)
	if err != nil {
		return err
	}
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil || len(raw) > 128 {
		return errors.New("not a signature")
	}
	d := sha256.Sum256(msg)
	if !ecdsa.VerifyASN1(k, d[:], raw) {
		return errors.New("the signature does not match the device's hardware key")
	}
	return nil
}
