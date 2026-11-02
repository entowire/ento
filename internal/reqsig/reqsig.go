// Package reqsig binds requests to a control node to the calling device's WireGuard key.
//
// A control node knows who calls by the overlay address: WireGuard proves which device sent the
// packets, but not which program on that device. Every process, container or app there holds the
// same address. Requests that act with the device's rights (administration, sign-in, credentials
// for linked networks) therefore also carry a signature that only a holder of the device's private
// key can make, which on every system means the agent, root or an administrator.
//
// The key is the X25519 agreement between the device's key and the control node's (both already
// exist: no registration), through HKDF-SHA256 with both public keys. Each request is signed with
// HMAC-SHA256 over its method, target, time, a random nonce and the hash of its body. A control
// node accepts a time within MaxSkew of its own and each nonce once.
package reqsig

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Headers of a signed request.
const (
	HeaderTime      = "X-Ento-Time"
	HeaderNonce     = "X-Ento-Nonce"
	HeaderSignature = "X-Ento-Signature"
)

// MaxSkew is how far a request's time may be from the control node's clock.
const MaxSkew = 5 * time.Minute

const (
	keyLabel = "ento/v1/request-key"
	macLabel = "ento/v1/request\n"
)

// ErrUnsigned is returned for a request without a signature.
var ErrUnsigned = errors.New("the request is not signed")

// DeviceKey returns the signing key of device (its private key) with a control node (its public
// key), as the device computes it.
func DeviceKey(device, control [32]byte) ([]byte, error) {
	return derive(device, control, publicOf(device), control)
}

// ControlKey returns the same key as the control node computes it, from its private key and the
// device's public key.
func ControlKey(control, device [32]byte) ([]byte, error) {
	return derive(control, device, device, publicOf(control))
}

func publicOf(priv [32]byte) [32]byte {
	var out [32]byte
	k, err := ecdh.X25519().NewPrivateKey(priv[:])
	if err != nil {
		return out
	}
	copy(out[:], k.PublicKey().Bytes())
	return out
}

func derive(priv, peer, devicePub, controlPub [32]byte) ([]byte, error) {
	k, err := ecdh.X25519().NewPrivateKey(priv[:])
	if err != nil {
		return nil, err
	}
	p, err := ecdh.X25519().NewPublicKey(peer[:])
	if err != nil {
		return nil, err
	}
	shared, err := k.ECDH(p) // fails for low-order points
	if err != nil {
		return nil, err
	}
	info := append(append([]byte(keyLabel), devicePub[:]...), controlPub[:]...)
	return hkdf.Key(sha256.New, shared, nil, string(info), 32)
}

func mac(key []byte, method, target, ts, nonce string, body []byte) []byte {
	sum := sha256.Sum256(body)
	m := hmac.New(sha256.New, key)
	fmt.Fprintf(m, "%s%s\n%s\n%s\n%s\n%s", macLabel, method, target, ts, nonce, hex.EncodeToString(sum[:]))
	return m.Sum(nil)
}

// Sign adds the signature headers to req, whose body must be body (nil for none).
func Sign(req *http.Request, key, body []byte, now time.Time) error {
	var n [16]byte
	if _, err := rand.Read(n[:]); err != nil {
		return err
	}
	ts := strconv.FormatInt(now.Unix(), 10)
	nonce := base64.RawURLEncoding.EncodeToString(n[:])
	req.Header.Set(HeaderTime, ts)
	req.Header.Set(HeaderNonce, nonce)
	req.Header.Set(HeaderSignature, base64.RawURLEncoding.EncodeToString(mac(key, req.Method, req.URL.RequestURI(), ts, nonce, body)))
	return nil
}

// Verify checks the signature of r, received with body, against key. It returns ErrUnsigned for a
// request without one. Nonces must be checked by the caller (Nonces.Check) once this succeeds.
func Verify(r *http.Request, key, body []byte, now time.Time) (nonce string, err error) {
	ts, nonce, sig := r.Header.Get(HeaderTime), r.Header.Get(HeaderNonce), r.Header.Get(HeaderSignature)
	if ts == "" && nonce == "" && sig == "" {
		return "", ErrUnsigned
	}
	t, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || len(nonce) < 16 || len(nonce) > 64 {
		return "", errors.New("malformed signature headers")
	}
	if d := now.Sub(time.Unix(t, 0)); d > MaxSkew || d < -MaxSkew {
		return "", fmt.Errorf("the request's time is %s off: check this device's clock", d.Round(time.Second))
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, mac(key, r.Method, r.RequestURI, ts, nonce, body)) {
		return "", errors.New("bad signature")
	}
	return nonce, nil
}

// Nonces remembers the nonces of accepted requests for twice MaxSkew, so none is accepted twice
// (by this control node: each has its own keys, and a restart forgets, which leaves a replay window
// of MaxSkew for someone who could read a request inside the device's tunnel).
type Nonces struct {
	mu     sync.Mutex
	seen   map[string]map[string]time.Time // device -> nonce -> accepted
	pruned time.Time
}

// MaxNonces bounds the nonces remembered per device (a request every 150 ms, sustained): beyond
// it, that device's signed requests are refused until older ones age out, and only that device's.
const MaxNonces = 4096

var (
	// ErrReplayed is returned for a nonce already accepted.
	ErrReplayed = errors.New("replayed request")
	// ErrBusy is returned to a device with MaxNonces recent requests.
	ErrBusy = errors.New("too many signed requests from this device: try again later")
)

// Check records a device's nonce, or says why it cannot be accepted.
func (n *Nonces) Check(device, nonce string, now time.Time) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.seen == nil {
		n.seen = map[string]map[string]time.Time{}
	}
	if now.Sub(n.pruned) > time.Minute { // forget devices that went quiet
		n.pruned = now
		for d, m := range n.seen {
			prune(m, now)
			if len(m) == 0 {
				delete(n.seen, d)
			}
		}
	}
	m := n.seen[device]
	if m == nil {
		m = map[string]time.Time{}
		n.seen[device] = m
	}
	if t, ok := m[nonce]; ok && now.Sub(t) <= 2*MaxSkew {
		return ErrReplayed
	}
	if len(m) >= MaxNonces {
		prune(m, now)
		if len(m) >= MaxNonces {
			return ErrBusy
		}
	}
	m[nonce] = now
	return nil
}

func prune(m map[string]time.Time, now time.Time) {
	for k, t := range m {
		if now.Sub(t) > 2*MaxSkew {
			delete(m, k)
		}
	}
}
