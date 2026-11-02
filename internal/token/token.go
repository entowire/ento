// Package token encodes enrollment tokens and derives the temporary WireGuard credentials they
// stand for.
//
// A token carries a random secret, the temporary overlay address reserved for it and the control
// nodes to contact. The secret deterministically derives a temporary WireGuard key pair and a
// preshared key (HKDF-SHA256 with versioned labels), so the control plane can pre-register the
// temporary peer and the agent can reach the control plane with nothing but the token.
package token

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	prefix  = "ento1:"
	version = 1

	labelSalt = "ento/v1/enroll"
	labelKey  = "wireguard-private-key"
	labelPSK  = "wireguard-preshared-key"
)

// Control describes how to reach one control node.
type Control struct {
	PublicKey wgtypes.Key
	Endpoint  string     // host:port of the node's WireGuard UDP socket
	Address   netip.Addr // the node's overlay address, where its API listens
}

// Token is the decoded form of an enrollment token.
type Token struct {
	Secret      [32]byte
	TempAddress netip.Addr // overlay address reserved for the temporary key
	Controls    []Control
}

// Credentials are the temporary WireGuard credentials derived from a token secret.
type Credentials struct {
	PrivateKey   wgtypes.Key
	PublicKey    wgtypes.Key
	PresharedKey wgtypes.Key
}

// NewSecret returns a fresh random token secret.
func NewSecret() ([32]byte, error) {
	var s [32]byte
	_, err := io.ReadFull(rand.Reader, s[:])
	return s, err
}

// Derive returns the temporary credentials a token secret stands for.
func Derive(secret [32]byte) (Credentials, error) {
	var c Credentials
	r := hkdf.New(sha256.New, secret[:], []byte(labelSalt), []byte(labelKey))
	if _, err := io.ReadFull(r, c.PrivateKey[:]); err != nil {
		return c, err
	}
	// Curve25519 clamping, as done by wgtypes.GeneratePrivateKey.
	c.PrivateKey[0] &= 248
	c.PrivateKey[31] = (c.PrivateKey[31] & 127) | 64
	pub, err := curve25519.X25519(c.PrivateKey[:], curve25519.Basepoint)
	if err != nil {
		return c, err
	}
	copy(c.PublicKey[:], pub)

	r = hkdf.New(sha256.New, secret[:], []byte(labelSalt), []byte(labelPSK))
	if _, err := io.ReadFull(r, c.PresharedKey[:]); err != nil {
		return c, err
	}
	return c, nil
}

// Encode returns the textual form of the token.
func (t Token) Encode() (string, error) {
	if !t.TempAddress.Is4() {
		return "", errors.New("temporary address must be IPv4")
	}
	if len(t.Controls) == 0 || len(t.Controls) > 255 {
		return "", errors.New("a token needs between 1 and 255 control nodes")
	}
	var b bytes.Buffer
	b.WriteByte(version)
	b.Write(t.Secret[:])
	a := t.TempAddress.As4()
	b.Write(a[:])
	b.WriteByte(byte(len(t.Controls)))
	for _, c := range t.Controls {
		if !c.Address.Is4() {
			return "", errors.New("control address must be IPv4")
		}
		if len(c.Endpoint) == 0 || len(c.Endpoint) > 255 {
			return "", errors.New("invalid control endpoint")
		}
		b.Write(c.PublicKey[:])
		ca := c.Address.As4()
		b.Write(ca[:])
		b.WriteByte(byte(len(c.Endpoint)))
		b.WriteString(c.Endpoint)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b.Bytes()), nil
}

// Parse decodes the textual form of a token. Surrounding whitespace is ignored.
func Parse(s string) (Token, error) {
	var t Token
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, prefix) {
		return t, errors.New("not an ento token")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, prefix))
	if err != nil {
		return t, fmt.Errorf("malformed token: %w", err)
	}
	r := bytes.NewReader(raw)
	var hdr struct {
		Version byte
		Secret  [32]byte
		Temp    [4]byte
		N       byte
	}
	if err := binary.Read(r, binary.BigEndian, &hdr); err != nil {
		return t, errors.New("truncated token")
	}
	if hdr.Version != version {
		return t, fmt.Errorf("unsupported token version %d", hdr.Version)
	}
	t.Secret = hdr.Secret
	t.TempAddress = netip.AddrFrom4(hdr.Temp)
	for i := 0; i < int(hdr.N); i++ {
		var c struct {
			Key  [32]byte
			Addr [4]byte
			Len  byte
		}
		if err := binary.Read(r, binary.BigEndian, &c); err != nil {
			return t, errors.New("truncated token")
		}
		ep := make([]byte, c.Len)
		if _, err := io.ReadFull(r, ep); err != nil {
			return t, errors.New("truncated token")
		}
		t.Controls = append(t.Controls, Control{
			PublicKey: wgtypes.Key(c.Key),
			Address:   netip.AddrFrom4(c.Addr),
			Endpoint:  string(ep),
		})
	}
	if r.Len() != 0 {
		return t, errors.New("trailing data in token")
	}
	if len(t.Controls) == 0 {
		return t, errors.New("token lists no control node")
	}
	return t, nil
}
