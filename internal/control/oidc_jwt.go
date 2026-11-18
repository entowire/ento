package control

import (
	"context"
	"time"

	"entowire.com/ento/internal/oidcrp"
)

// ID tokens are verified against the provider's published keys (its JWKS, fetched over verified
// TLS), with an allow-list of algorithms, whatever the channel they came on (0.50; before, TLS to
// the token endpoint was the only check, and a local process that took the provider's port could
// answer as it). A token that fails gives no rights. The checks are internal/oidcrp's, which ento
// id uses too for the outside providers people sign in through.

// idTokenSkew is how far the provider's clock and this node's may differ.
const idTokenSkew = oidcrp.Skew

// keysOf returns the provider's signing keys, cached (their address from its discovery).
func (o *oidcProvider) keysOf() *oidcrp.Keys {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.keys == nil {
		o.keys = &oidcrp.Keys{Client: o.client, URI: func(ctx context.Context) (string, error) {
			d, err := o.discover(ctx)
			if err != nil {
				return "", err
			}
			return d.JWKSURI, nil
		}}
	}
	return o.keys
}

// verifyIDToken checks an ID token's signature against the provider's keys, and its issuer,
// audience, authorized party, expiry and issue time, and nonce when one was sent ("": none).
func (o *oidcProvider) verifyIDToken(ctx context.Context, tok, nonce string) (idClaims, error) {
	payload, err := o.keysOf().Verify(ctx, tok)
	if err != nil {
		return idClaims{}, err
	}
	if err := oidcrp.Check(payload, o.cfg.Issuer, []string{o.cfg.ClientID}, nonce, time.Now()); err != nil {
		return idClaims{}, err
	}
	return parseIDToken(tok)
}
