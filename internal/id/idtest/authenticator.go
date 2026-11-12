// Package idtest has a software passkey authenticator for tests of the identity provider.
package idtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// Authenticator is a software passkey authenticator for tests: one ES256 credential, made with
// Create and used with Get, as a browser's navigator.credentials would answer.
type Authenticator struct {
	t       testing.TB
	Origin  string // the page's origin it reports
	rpID    string
	key     *ecdsa.PrivateKey
	credID  []byte
	Handle  []byte // the user handle, set by Create
	Counter uint32
	NoUV    bool // answers without user verification
}

// New returns an authenticator for the relying party rpID, used from https://<rpID>.
func New(t testing.TB, rpID string) *Authenticator {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	rand.Read(id)
	return &Authenticator{t: t, Origin: "https://" + rpID, rpID: rpID, key: k, credID: id}
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (a *Authenticator) clientData(typ, challenge string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": a.Origin, "crossOrigin": false})
	return b
}

func (a *Authenticator) flags(attested bool) byte {
	f := byte(0x01) // user present
	if !a.NoUV {
		f |= 0x04 // user verified
	}
	if attested {
		f |= 0x40
	}
	return f
}

func (a *Authenticator) authData(attested bool) []byte {
	rp := sha256.Sum256([]byte(a.rpID))
	out := append([]byte{}, rp[:]...)
	out = append(out, a.flags(attested))
	out = binary.BigEndian.AppendUint32(out, a.Counter)
	if attested {
		out = append(out, make([]byte, 16)...) // AAGUID
		out = binary.BigEndian.AppendUint16(out, uint16(len(a.credID)))
		out = append(out, a.credID...)
		x, y := make([]byte, 32), make([]byte, 32)
		a.key.PublicKey.X.FillBytes(x)
		a.key.PublicKey.Y.FillBytes(y)
		cose, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
		if err != nil {
			a.t.Fatal(err)
		}
		out = append(out, cose...)
	}
	return out
}

// Create answers a registration: options as the provider sent them (publicKey).
func (a *Authenticator) Create(options map[string]any) map[string]any {
	a.t.Helper()
	user := options["user"].(map[string]any)
	h, err := base64.RawURLEncoding.DecodeString(user["id"].(string))
	if err != nil {
		a.t.Fatal(err)
	}
	a.Handle = h
	cd := a.clientData("webauthn.create", options["challenge"].(string))
	att, err := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": a.authData(true)})
	if err != nil {
		a.t.Fatal(err)
	}
	return map[string]any{"id": b64u(a.credID), "rawId": b64u(a.credID), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64u(cd), "attestationObject": b64u(att)}, "clientExtensionResults": map[string]any{}}
}

// Get answers a sign-in with the credential.
func (a *Authenticator) Get(options map[string]any) map[string]any {
	a.t.Helper()
	a.Counter++
	cd := a.clientData("webauthn.get", options["challenge"].(string))
	ad := a.authData(false)
	sum := sha256.Sum256(cd)
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, sha256Of(append(append([]byte{}, ad...), sum[:]...)))
	if err != nil {
		a.t.Fatal(err)
	}
	return map[string]any{"id": b64u(a.credID), "rawId": b64u(a.credID), "type": "public-key",
		"response":               map[string]any{"clientDataJSON": b64u(cd), "authenticatorData": b64u(ad), "signature": b64u(sig), "userHandle": b64u(a.Handle)},
		"clientExtensionResults": map[string]any{}}
}

func sha256Of(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

// CredentialID is the credential's ID.
func (a *Authenticator) CredentialID() []byte { return a.credID }

// PublicKey returns the credential's public key, its X and Y coordinates.
func (a *Authenticator) PublicKey() (x, y []byte) {
	x, y = make([]byte, 32), make([]byte, 32)
	a.key.PublicKey.X.FillBytes(x)
	a.key.PublicKey.Y.FillBytes(y)
	return x, y
}
