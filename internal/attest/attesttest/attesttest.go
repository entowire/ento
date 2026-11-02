// Package attesttest makes Android key attestations for tests: a made-up root and intermediate
// stand for a phone's secure hardware (trust them with attest.Options.Roots).
package attesttest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/attest"
)

// Numbers of Android's KeyDescription.
const (
	LevelSoftware   = 0
	LevelTEE        = 1
	LevelStrongBox  = 2
	OriginGenerated = 0
	OriginImported  = 2

	TagOrigin           = 702
	TagRootOfTrust      = 704
	TagOSVersion        = 705
	TagOSPatchLevel     = 706
	TagApplicationID    = 709
	TagVendorPatchLevel = 718
	TagBootPatchLevel   = 719
)

// OIDKeyDescription is the attestation extension.
var OIDKeyDescription = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

// Hardware is a made-up phone's attestation hierarchy.
type Hardware struct {
	Root, Inter       *x509.Certificate
	rootKey, interKey *ecdsa.PrivateKey
}

// New makes a root (P-384) and an intermediate (P-256), valid for an hour either way.
func New(t testing.TB) *Hardware {
	t.Helper()
	h := &Hardware{}
	h.rootKey, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	h.interKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	h.Root = Certificate(t, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"}, IsCA: true,
		BasicConstraintsValid: true, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}, nil, &h.rootKey.PublicKey, h.rootKey)
	h.Inter = Certificate(t, &x509.Certificate{SerialNumber: big.NewInt(0xbeef), Subject: pkix.Name{CommonName: "TEE"}, IsCA: true,
		BasicConstraintsValid: true, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}, h.Root, &h.interKey.PublicKey, h.rootKey)
	return h
}

// Roots are the hardware's root, for attest.Options.Roots.
func (h *Hardware) Roots() [][]byte { return [][]byte{h.Root.RawSubjectPublicKeyInfo} }

// Certificate makes a certificate from tmpl, signed by signer as parent (nil: self-signed).
func Certificate(t testing.TB, tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

// Spec is what the made-up hardware writes into a key's certificate.
type Spec struct {
	Level     int
	Challenge []byte
	Origin    int
	State     int // 0 verified, 1 self-signed, 2 unverified, 3 failed
	Locked    bool
	OSVersion int // MMmmpp
	Patch     int // YYYYMM (vendor and boot images: YYYYMM05)
	App       string
	Signer    [32]byte
	// Edit, if set, changes the authorization lists before they are written.
	Edit func(hw, sw *[]asn1.RawValue)
}

// Good is what a phone in order attests: TEE, a verified boot with the bootloader locked, Android 16,
// patched 2026-09, made for device by com.example.app.
func Good(device [32]byte) Spec {
	return Spec{Level: LevelTEE, Challenge: attest.Challenge(device), State: 0, Locked: true, OSVersion: 160000, Patch: 202609,
		App: "com.example.app", Signer: Signer()}
}

// Signer is the signing certificate digest of Good's app.
func Signer() [32]byte { return sha256.Sum256([]byte("signer")) }

// Explicit is an authorization list entry.
func Explicit(tag int, v any) asn1.RawValue {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: b}
}

func sequence(items []asn1.RawValue) asn1.RawValue {
	var b []byte
	for _, it := range items {
		enc, err := asn1.Marshal(it)
		if err != nil {
			panic(err)
		}
		b = append(b, enc...)
	}
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: b}
}

type rootOfTrust struct {
	VerifiedBootKey   []byte
	DeviceLocked      bool
	VerifiedBootState asn1.Enumerated
	VerifiedBootHash  []byte
}

type applicationIDs struct {
	Packages []packageInfo `asn1:"set"`
	Signers  [][]byte      `asn1:"set"`
}

type packageInfo struct {
	Name    []byte
	Version int64
}

type keyDescription struct {
	Version          int
	SecurityLevel    asn1.Enumerated
	KeyMintVersion   int
	KeyMintLevel     asn1.Enumerated
	Challenge        []byte
	UniqueID         []byte
	SoftwareEnforced asn1.RawValue
	HardwareEnforced asn1.RawValue
}

// Extension is the key description extension's value for s.
func (s Spec) Extension() []byte {
	rot := rootOfTrust{VerifiedBootKey: make([]byte, 32), DeviceLocked: s.Locked, VerifiedBootState: asn1.Enumerated(s.State),
		VerifiedBootHash: make([]byte, 32)}
	appID, _ := asn1.Marshal(applicationIDs{Packages: []packageInfo{{Name: []byte(s.App), Version: 30}}, Signers: [][]byte{s.Signer[:]}})
	hw := []asn1.RawValue{Explicit(1, []int{2}), Explicit(TagOrigin, s.Origin), Explicit(TagRootOfTrust, rot),
		Explicit(TagOSVersion, s.OSVersion), Explicit(TagOSPatchLevel, s.Patch), Explicit(TagVendorPatchLevel, s.Patch*100+5),
		Explicit(TagBootPatchLevel, s.Patch*100+5)}
	sw := []asn1.RawValue{Explicit(701, 1759650000000), Explicit(TagApplicationID, appID)}
	if s.Edit != nil {
		s.Edit(&hw, &sw)
	}
	b, err := asn1.Marshal(keyDescription{Version: 300, SecurityLevel: asn1.Enumerated(s.Level), KeyMintVersion: 300,
		KeyMintLevel: asn1.Enumerated(s.Level), Challenge: s.Challenge, UniqueID: []byte{}, SoftwareEnforced: sequence(sw),
		HardwareEnforced: sequence(hw)})
	if err != nil {
		panic(err)
	}
	return b
}

// Attest makes a key as the hardware would for s, its chain, and its signature for device at
// signedAt; it returns the attestation and the key.
func (h *Hardware) Attest(t testing.TB, device [32]byte, s Spec, signedAt time.Time) (*api.Attestation, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := Certificate(t, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Android Keystore Key"},
		NotBefore: time.Unix(0, 0), NotAfter: time.Date(2048, 1, 1, 0, 0, 0, 0, time.UTC),
		ExtraExtensions: []pkix.Extension{{Id: OIDKeyDescription, Value: s.Extension()}}}, h.Inter, &key.PublicKey, h.interKey)
	a := &api.Attestation{Format: attest.FormatAndroid, Chain: [][]byte{leaf.Raw, h.Inter.Raw, h.Root.Raw}}
	Sign(a, key, device, signedAt)
	return a, key
}

// Sign (re)signs an attestation's time with key, for device.
func Sign(a *api.Attestation, key *ecdsa.PrivateKey, device [32]byte, at time.Time) {
	a.SignedAt = at.UTC().Format(time.RFC3339)
	d := sha256.Sum256(attest.Message(device, a.SignedAt))
	a.Signature, _ = ecdsa.SignASN1(rand.Reader, key, d[:])
}
