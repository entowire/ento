//go:build linux && !android

// Package tpmkey keeps a device's hardware-held key in its TPM 2.0 (package hwsig says what it
// signs). The key is a P-256 signing key created under the TPM's storage root key (the owner
// hierarchy's primary ECC key, made again from its standard template at each use, so nothing is
// left in the TPM's memory): fixedTPM and fixedParent, so the TPM never exports it, and its blob
// (the public part and the private part as the TPM encrypted it to itself) is useless on any other
// TPM. No PCR policy: firmware and boot updates must not lose the key. Clearing the TPM does.
package tpmkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/google/go-tpm/tpm2/transport/linuxudstpm"
)

// DefaultDevice is the kernel's TPM resource manager, which shares the TPM between programs.
const DefaultDevice = "/dev/tpmrm0"

// File is where a device's key blob is kept, in the agent's state directory.
const File = "hwkey.json"

// Key is a P-256 key held by the TPM.
type Key struct {
	device string
	pub    *ecdsa.PublicKey
	public tpm2.TPM2BPublic
	priv   tpm2.TPM2BPrivate
	mu     sync.Mutex // one command sequence at a time
}

type blob struct {
	Kind    string `json:"kind"`
	Public  string `json:"public"`  // TPM2B_PUBLIC
	Private string `json:"private"` // TPM2B_PRIVATE, encrypted by the TPM to itself
}

// Available reports whether device is a TPM the agent can use (a character device, or a socket a
// software TPM listens on, for tests).
func Available(device string) bool {
	fi, err := os.Stat(device)
	return err == nil && (fi.Mode()&os.ModeCharDevice != 0 || fi.Mode()&os.ModeSocket != 0)
}

func open(device string) (transport.TPMCloser, error) {
	fi, err := os.Stat(device)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSocket != 0 {
		return linuxudstpm.Open(device)
	}
	return linuxtpm.Open(device)
}

// Load reads the key from dir, creating it in the TPM first if dir has none. A blob the TPM refuses
// (another TPM, or this one cleared) is an error, never replaced: the device's binding is to the
// old key, and a new one would look like a copy until an administrator releases it.
func Load(device, dir string) (*Key, error) {
	path := filepath.Join(dir, File)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return create(device, path)
	}
	if err != nil {
		return nil, err
	}
	var bl blob
	if err := json.Unmarshal(b, &bl); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	k := &Key{device: device}
	if err := k.decode(bl); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	// Prove the TPM still has it: sign once.
	if _, err := k.SignDigest(make([]byte, 32)); err != nil {
		return nil, fmt.Errorf("the TPM does not take the key in %s (another TPM, or this one cleared?): %v", path, err)
	}
	return k, nil
}

func (k *Key) decode(bl blob) error {
	pubRaw, err := base64.StdEncoding.DecodeString(bl.Public)
	if err != nil {
		return err
	}
	privRaw, err := base64.StdEncoding.DecodeString(bl.Private)
	if err != nil {
		return err
	}
	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](pubRaw)
	if err != nil {
		return err
	}
	priv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](privRaw)
	if err != nil {
		return err
	}
	k.public, k.priv = *pub, *priv
	return k.setPublic()
}

func (k *Key) setPublic() error {
	pub, err := k.public.Contents()
	if err != nil {
		return err
	}
	if pub.Type != tpm2.TPMAlgECC {
		return errors.New("not an ECC key")
	}
	ecc, err := pub.Unique.ECC()
	if err != nil {
		return err
	}
	k.pub = &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(ecc.X.Buffer), Y: new(big.Int).SetBytes(ecc.Y.Buffer)}
	if !k.pub.Curve.IsOnCurve(k.pub.X, k.pub.Y) {
		return errors.New("not a P-256 key")
	}
	return nil
}

// signingTemplate is a P-256 ECDSA (SHA-256) signing key that never leaves the TPM.
var signingTemplate = tpm2.TPMTPublic{
	Type:    tpm2.TPMAlgECC,
	NameAlg: tpm2.TPMAlgSHA256,
	ObjectAttributes: tpm2.TPMAObject{FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true,
		UserWithAuth: true, SignEncrypt: true},
	Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
		Scheme: tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256})},
		CurveID: tpm2.TPMECCNistP256,
	}),
	Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{}),
}

func create(device, path string) (*Key, error) {
	t, err := open(device)
	if err != nil {
		return nil, err
	}
	defer t.Close()
	srk, err := primary(t)
	if err != nil {
		return nil, err
	}
	defer flush(t, srk.ObjectHandle)
	created, err := tpm2.Create{ParentHandle: tpm2.NamedHandle{Handle: srk.ObjectHandle, Name: srk.Name},
		InPublic: tpm2.New2B(signingTemplate)}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("create the key: %w", err)
	}
	k := &Key{device: device, public: created.OutPublic, priv: created.OutPrivate}
	if err := k.setPublic(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(blob{Kind: "tpm2-p256", Public: base64.StdEncoding.EncodeToString(tpm2.Marshal(k.public)),
		Private: base64.StdEncoding.EncodeToString(tpm2.Marshal(k.priv))})
	if err != nil {
		return nil, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, err
	}
	return k, nil
}

// primary makes the owner hierarchy's storage root key (the same key every time, from the standard
// template) in the TPM's memory.
func primary(t transport.TPM) (*tpm2.CreatePrimaryResponse, error) {
	srk, err := tpm2.CreatePrimary{PrimaryHandle: tpm2.TPMRHOwner, InPublic: tpm2.New2B(tpm2.ECCSRKTemplate)}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("the TPM's storage root key: %w", err)
	}
	return srk, nil
}

func flush(t transport.TPM, h tpm2.TPMHandle) {
	_, _ = tpm2.FlushContext{FlushHandle: h}.Execute(t)
}

// Kind names the hardware (hwsig.KindTPM).
func (k *Key) Kind() string { return "tpm" }

// Public returns the key's public half.
func (k *Key) Public() *ecdsa.PublicKey { return k.pub }

// SignDigest signs a SHA-256 digest in the TPM, ASN.1 DER.
func (k *Key) SignDigest(digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, errors.New("a SHA-256 digest is 32 bytes")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	t, err := open(k.device)
	if err != nil {
		return nil, err
	}
	defer t.Close()
	srk, err := primary(t)
	if err != nil {
		return nil, err
	}
	defer flush(t, srk.ObjectHandle)
	loaded, err := tpm2.Load{ParentHandle: tpm2.NamedHandle{Handle: srk.ObjectHandle, Name: srk.Name},
		InPrivate: k.priv, InPublic: k.public}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("load the key: %w", err)
	}
	defer flush(t, loaded.ObjectHandle)
	res, err := tpm2.Sign{KeyHandle: tpm2.NamedHandle{Handle: loaded.ObjectHandle, Name: loaded.Name},
		Digest: tpm2.TPM2BDigest{Buffer: digest},
		InScheme: tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256})},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck}}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	sig, err := res.Signature.Signature.ECDSA()
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(sig.SignatureR.Buffer), new(big.Int).SetBytes(sig.SignatureS.Buffer)})
}
