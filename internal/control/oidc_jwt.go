package control

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

// ID tokens are verified against the provider's published keys (its JWKS, fetched over verified
// TLS), with an allow-list of algorithms, whatever the channel they came on (0.50; before, TLS to
// the token endpoint was the only check, and a local process that took the provider's port could
// answer as it). A token that fails gives no rights.

// idTokenSkew is how far the provider's clock and this node's may differ.
const idTokenSkew = 2 * time.Minute

// jwksRefetch: an unknown key ID fetches the keys again, at most this often.
var jwksRefetch = 30 * time.Second

// idTokenAlgs are the signature algorithms accepted (never none or HMAC, which a public key
// cannot check).
var idTokenAlgs = []string{"EdDSA", "ES256", "ES384", "RS256", "RS384", "RS512"}

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

type jwksCache struct {
	mu      sync.Mutex
	keys    []parsedKey
	fetched time.Time
}

type parsedKey struct {
	kid string
	alg string // as published; "" when the key names none
	pub crypto.PublicKey
}

func b64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "=")) }

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

// jwks returns the provider's keys, fetching them again when refresh is set and the last fetch is
// older than jwksRefetch.
func (o *oidcProvider) jwks(ctx context.Context, refresh bool) ([]parsedKey, error) {
	o.keys.mu.Lock()
	defer o.keys.mu.Unlock()
	if len(o.keys.keys) > 0 && (!refresh || time.Since(o.keys.fetched) < jwksRefetch) {
		return o.keys.keys, nil
	}
	d, err := o.discover(ctx)
	if err != nil {
		return nil, err
	}
	if d.JWKSURI == "" {
		return nil, errors.New("the provider publishes no keys (jwks_uri)")
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, d.JWKSURI, nil)
	resp, err := o.client.Do(req)
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
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := parseJWK(k)
		if err != nil {
			continue // a key of a kind ento does not use
		}
		keys = append(keys, parsedKey{kid: k.Kid, alg: k.Alg, pub: pub})
	}
	if len(keys) == 0 {
		return nil, errors.New("provider keys: none usable")
	}
	o.keys.keys, o.keys.fetched = keys, time.Now()
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

// verifyIDToken checks an ID token's signature against the provider's keys, and its issuer,
// audience, authorized party, expiry and issue time, and nonce when one was sent ("": none).
func (o *oidcProvider) verifyIDToken(ctx context.Context, tok, nonce string) (idClaims, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return idClaims{}, errors.New("malformed ID token")
	}
	hb, err := b64(parts[0])
	if err != nil {
		return idClaims{}, errors.New("malformed ID token header")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return idClaims{}, errors.New("malformed ID token header")
	}
	if !slices.Contains(idTokenAlgs, hdr.Alg) {
		return idClaims{}, fmt.Errorf("ID token algorithm %q not accepted", hdr.Alg)
	}
	sig, err := b64(parts[2])
	if err != nil {
		return idClaims{}, errors.New("malformed ID token signature")
	}
	signed := []byte(parts[0] + "." + parts[1])
	check := func(keys []parsedKey) (found, ok bool) {
		for _, k := range keys {
			if (hdr.Kid != "" && k.kid != hdr.Kid) || (k.alg != "" && k.alg != hdr.Alg) {
				continue
			}
			found = true
			if verifySig(hdr.Alg, k.pub, signed, sig) {
				return true, true
			}
		}
		return found, false
	}
	keys, err := o.jwks(ctx, false)
	if err != nil {
		return idClaims{}, err
	}
	found, ok := check(keys)
	if !found { // a key the provider rotated in since: fetch again
		if keys, err = o.jwks(ctx, true); err != nil {
			return idClaims{}, err
		}
		_, ok = check(keys)
	}
	if !ok {
		return idClaims{}, errors.New("ID token signature does not verify")
	}
	c, err := parseIDToken(tok)
	if err != nil {
		return idClaims{}, err
	}
	var times struct {
		Exp   *float64 `json:"exp"`
		Iat   *float64 `json:"iat"`
		Azp   string   `json:"azp"`
		Nonce string   `json:"nonce"`
	}
	payload, _ := b64(parts[1])
	_ = json.Unmarshal(payload, &times)
	now := time.Now()
	switch {
	case c.Issuer != o.cfg.Issuer:
		return idClaims{}, errors.New("ID token from another issuer")
	case !c.hasAudience(o.cfg.ClientID) || (times.Azp != "" && times.Azp != o.cfg.ClientID):
		return idClaims{}, errors.New("ID token for another client")
	case c.Subject == "":
		return idClaims{}, errors.New("ID token without a subject")
	case times.Exp == nil || now.After(time.Unix(int64(*times.Exp), 0).Add(idTokenSkew)):
		return idClaims{}, errors.New("ID token expired")
	case times.Iat != nil && time.Unix(int64(*times.Iat), 0).After(now.Add(idTokenSkew)):
		return idClaims{}, errors.New("ID token issued in the future")
	case nonce != "" && times.Nonce != nonce:
		return idClaims{}, errors.New("ID token for another sign-in (nonce)")
	}
	return c, nil
}
