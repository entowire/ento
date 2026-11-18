// Package oidcrp is what a relying party of an OpenID Connect provider needs to trust its ID
// tokens: the provider's published signing keys (its JWKS, fetched over verified TLS and cached),
// signatures checked with an allow-list of algorithms (never none or HMAC, which a public key cannot
// check), and the claims every ID token must carry checked (issuer, audience, authorized party,
// expiry, issue time, nonce). The control nodes use it for the network's identity provider, and
// ento id for the outside providers people sign in through.
package oidcrp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

// Skew is how far a provider's clock and ours may differ.
const Skew = 2 * time.Minute

// Refetch: an unknown key ID fetches the keys again, at most this often.
var Refetch = 30 * time.Second

// Algs are the signature algorithms accepted.
var Algs = []string{"EdDSA", "ES256", "ES384", "RS256", "RS384", "RS512"}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type parsedKey struct {
	kid string
	alg string // as published; "" when the key names none
	pub crypto.PublicKey
}

// Keys are a provider's signing keys, fetched from the address URI returns (its jwks_uri) with
// Client and cached; a token signed with a key ID not among them fetches them again (Refetch).
type Keys struct {
	Client *http.Client
	URI    func(ctx context.Context) (string, error)

	mu      sync.Mutex
	keys    []parsedKey
	fetched time.Time
}

func b64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

func parseJWK(k jwk) (crypto.PublicKey, error) {
	switch k.Kty {
	case "OKP":
		x, err := b64(k.X)
		if err != nil || k.Crv != "Ed25519" || len(x) != ed25519.PublicKeySize {
			return nil, errors.New("bad Ed25519 key")
		}
		return ed25519.PublicKey(x), nil
	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		default:
			return nil, fmt.Errorf("curve %q", k.Crv)
		}
		x, err1 := b64(k.X)
		y, err2 := b64(k.Y)
		if err1 != nil || err2 != nil {
			return nil, errors.New("bad EC key")
		}
		pub := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !curve.IsOnCurve(pub.X, pub.Y) {
			return nil, errors.New("EC key not on its curve")
		}
		return pub, nil
	case "RSA":
		n, err1 := b64(k.N)
		e, err2 := b64(k.E)
		if err1 != nil || err2 != nil || len(n) < 256 || len(e) == 0 || len(e) > 4 {
			return nil, errors.New("bad RSA key (at least 2048 bits)")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
	}
	return nil, fmt.Errorf("key type %q", k.Kty)
}

func (k *Keys) get(ctx context.Context, refresh bool) ([]parsedKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.keys) > 0 && (!refresh || time.Since(k.fetched) < Refetch) {
		return k.keys, nil
	}
	uri, err := k.URI(ctx)
	if err != nil {
		return nil, err
	}
	if uri == "" {
		return nil, errors.New("the provider publishes no keys (jwks_uri)")
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	resp, err := k.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("provider keys: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("provider keys: HTTP %d", resp.StatusCode)
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		return nil, fmt.Errorf("provider keys: %w", err)
	}
	var keys []parsedKey
	for _, j := range set.Keys {
		if j.Use != "" && j.Use != "sig" {
			continue
		}
		pub, err := parseJWK(j)
		if err != nil {
			continue // a key of a kind ento does not use
		}
		keys = append(keys, parsedKey{kid: j.Kid, alg: j.Alg, pub: pub})
	}
	if len(keys) == 0 {
		return nil, errors.New("provider keys: none usable")
	}
	k.keys, k.fetched = keys, time.Now()
	return keys, nil
}

func verifySig(alg string, pub crypto.PublicKey, signed, sig []byte) bool {
	digest := func(h hash.Hash) []byte { h.Write(signed); return h.Sum(nil) }
	switch alg {
	case "EdDSA":
		k, ok := pub.(ed25519.PublicKey)
		return ok && ed25519.Verify(k, signed, sig)
	case "ES256", "ES384":
		k, ok := pub.(*ecdsa.PublicKey)
		size, d := 32, []byte(nil)
		if alg == "ES256" {
			ok = ok && k.Curve == elliptic.P256()
			d = digest(sha256.New())
		} else {
			size = 48
			ok = ok && k.Curve == elliptic.P384()
			d = digest(sha512.New384())
		}
		if !ok || len(sig) != 2*size {
			return false
		}
		return ecdsa.Verify(k, d, new(big.Int).SetBytes(sig[:size]), new(big.Int).SetBytes(sig[size:]))
	case "RS256", "RS384", "RS512":
		k, ok := pub.(*rsa.PublicKey)
		if !ok {
			return false
		}
		h, ch := sha256.New(), crypto.SHA256
		switch alg {
		case "RS384":
			h, ch = sha512.New384(), crypto.SHA384
		case "RS512":
			h, ch = sha512.New(), crypto.SHA512
		}
		return rsa.VerifyPKCS1v15(k, ch, digest(h), sig) == nil
	}
	return false
}

// Verify checks a token's signature against the provider's keys and returns its payload (JSON),
// unchecked otherwise: Check checks the claims.
func (k *Keys) Verify(ctx context.Context, tok string) ([]byte, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed ID token")
	}
	hb, err := b64(parts[0])
	if err != nil {
		return nil, errors.New("malformed ID token header")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return nil, errors.New("malformed ID token header")
	}
	if !slices.Contains(Algs, hdr.Alg) {
		return nil, fmt.Errorf("ID token algorithm %q not accepted", hdr.Alg)
	}
	sig, err := b64(parts[2])
	if err != nil {
		return nil, errors.New("malformed ID token signature")
	}
	signed := []byte(parts[0] + "." + parts[1])
	check := func(keys []parsedKey) (found, ok bool) {
		for _, key := range keys {
			if (hdr.Kid != "" && key.kid != hdr.Kid) || (key.alg != "" && key.alg != hdr.Alg) {
				continue
			}
			found = true
			if verifySig(hdr.Alg, key.pub, signed, sig) {
				return true, true
			}
		}
		return found, false
	}
	keys, err := k.get(ctx, false)
	if err != nil {
		return nil, err
	}
	found, ok := check(keys)
	if !found { // a key the provider rotated in since: fetch again
		if keys, err = k.get(ctx, true); err != nil {
			return nil, err
		}
		_, ok = check(keys)
	}
	if !ok {
		return nil, errors.New("ID token signature does not verify")
	}
	payload, err := b64(parts[1])
	if err != nil {
		return nil, errors.New("malformed ID token payload")
	}
	return payload, nil
}

// Check checks the claims every ID token carries: from issuer, for one of clients (its audience,
// and its authorized party if it names one), with a subject, not expired, not issued in the
// future, and for the sign-in that sent nonce ("": none sent).
func Check(payload []byte, issuer string, clients []string, nonce string, now time.Time) error {
	var c struct {
		Issuer  string          `json:"iss"`
		Subject string          `json:"sub"`
		Aud     json.RawMessage `json:"aud"`
		Exp     *float64        `json:"exp"`
		Iat     *float64        `json:"iat"`
		Azp     string          `json:"azp"`
		Nonce   string          `json:"nonce"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return errors.New("malformed ID token payload")
	}
	var auds []string
	var one string
	if json.Unmarshal(c.Aud, &one) == nil {
		auds = []string{one}
	} else {
		_ = json.Unmarshal(c.Aud, &auds)
	}
	ours := false
	for _, id := range clients {
		if id != "" && slices.Contains(auds, id) && (c.Azp == "" || c.Azp == id) {
			ours = true
		}
	}
	switch {
	case c.Issuer != issuer:
		return errors.New("ID token from another issuer")
	case !ours:
		return errors.New("ID token for another client")
	case c.Subject == "":
		return errors.New("ID token without a subject")
	case c.Exp == nil || now.After(time.Unix(int64(*c.Exp), 0).Add(Skew)):
		return errors.New("ID token expired")
	case c.Iat != nil && time.Unix(int64(*c.Iat), 0).After(now.Add(Skew)):
		return errors.New("ID token issued in the future")
	case nonce != "" && c.Nonce != nonce:
		return errors.New("ID token for another sign-in (nonce)")
	}
	return nil
}
