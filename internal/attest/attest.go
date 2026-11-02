// Package attest verifies what a device's secure hardware says about it: Android key attestation.
//
// The app asks the phone's Keystore for a key made inside its secure hardware (the trusted
// execution environment, or StrongBox), with a challenge derived from the device's WireGuard key.
// The hardware certifies the key with a certificate chain that ends at Google's attestation root,
// and writes into the key's certificate what it knows: whether the phone started the system its
// maker signed, with the bootloader locked (Android Verified Boot), the system's version and patch
// levels, and which app asked. With each posture report the app signs the time with that key, which
// never leaves the hardware: a copy of the device's state on another phone carries no attestation.
//
// What it does not prove: that nothing runs on the phone now that should not (the boot state is the
// one the phone started with), or anything at all about a phone whose hardware keys leaked, which
// is why every certificate is checked against Google's list of revoked ones (Revocations).
package attest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"time"

	"entowire.com/ento/internal/api"
)

const (
	// FormatAndroid is the format of an Android key attestation (api.Attestation).
	FormatAndroid = "android-key"

	challengeLabel = "ento-attest-v1"
	messageLabel   = "ento-attest-signed-v1"

	// MaxSkew is how far the time a device signed at may be from the verifier's.
	MaxSkew  = 10 * time.Minute
	maxChain = 10
)

// The key description extension of Android key attestation certificates.
var oidKeyDescription = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

// Challenge is the attestation challenge of a device: its key's attestation must carry it.
func Challenge(device [32]byte) []byte {
	h := sha256.New()
	h.Write([]byte(challengeLabel))
	h.Write([]byte{0})
	h.Write(device[:])
	return h.Sum(nil)
}

// Message is what the attested key signs to show, at signedAt (RFC 3339), that it is still on the
// device.
func Message(device [32]byte, signedAt string) []byte {
	m := append([]byte(messageLabel), 0)
	m = append(m, device[:]...)
	return append(m, signedAt...)
}

// googleRoots are the public keys (SubjectPublicKeyInfo) of Google's hardware attestation roots,
// as https://android.googleapis.com/attestation/root listed them on 2026-10-05: an RSA key, which
// certificates of 2016, 2019 and 2022 carry (phones hold any of them, some expired: the key is the
// anchor, not the certificate), and the ECDSA P-384 key of "Key Attestation CA1" (2025).
//
//go:embed roots/*.pem
var rootFiles embed.FS

var googleRoots = loadRoots()

func loadRoots() [][]byte {
	var out [][]byte
	files, _ := fs.Glob(rootFiles, "roots/*.pem")
	for _, f := range files {
		b, _ := rootFiles.ReadFile(f)
		block, _ := pem.Decode(b)
		if block == nil {
			panic("attest: " + f + " is not PEM")
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			panic("attest: " + f + ": " + err.Error())
		}
		out = append(out, c.RawSubjectPublicKeyInfo)
	}
	return out
}

// App is an app whose attestations count: its package name and the SHA-256 of its signing
// certificate (as `apksigner verify --print-certs` shows it).
type App struct {
	Package string
	Signer  [32]byte
}

// ParseApps reads apps as PACKAGE:SHA256 (hex, colons between bytes allowed), comma-separated.
func ParseApps(s string) ([]App, error) {
	var out []App
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		pkg, digest, ok := strings.Cut(item, ":")
		b, err := hex.DecodeString(strings.ReplaceAll(digest, ":", ""))
		if !ok || pkg == "" || err != nil || len(b) != 32 {
			return nil, fmt.Errorf("%q: expected PACKAGE:SHA256 (the signing certificate's SHA-256, in hex)", item)
		}
		a := App{Package: pkg}
		copy(a.Signer[:], b)
		out = append(out, a)
	}
	return out, nil
}

// Options are what a verification checks besides the chain and the device's key.
type Options struct {
	Now time.Time
	// Revoked says whether a certificate's serial number (lowercase hexadecimal) is revoked; an
	// error means it cannot tell, and the attestation does not count. Nil: not checked.
	Revoked func(serial string) (bool, error)
	// Apps, when set, are the only apps whose attestations count.
	Apps []App
	// Roots are the public keys (SubjectPublicKeyInfo) of the roots trusted instead of Google's
	// (tests; nil: Google's).
	Roots [][]byte
}

// Verify checks an attestation of the device with WireGuard key device and returns what it
// attests. When it does not count, Error says why and nothing else is set.
func Verify(a *api.Attestation, device [32]byte, o Options) api.Attested {
	out, err := verify(a, device, o)
	if err != nil {
		return api.Attested{Error: err.Error()}
	}
	return out
}

func verify(a *api.Attestation, device [32]byte, o Options) (api.Attested, error) {
	var out api.Attested
	if a.Format != FormatAndroid {
		return out, errors.New("unknown attestation format")
	}
	certs, err := verifyChain(a.Chain, o)
	if err != nil {
		return out, err
	}
	kd, err := keyDescriptionOf(certs)
	if err != nil {
		return out, err
	}
	switch kd.SecurityLevel {
	case levelTEE:
		out.SecurityLevel = "tee"
	case levelStrongBox:
		out.SecurityLevel = "strongbox"
	default:
		return out, errors.New("software attestation (the key is not in secure hardware)")
	}
	if !bytes.Equal(kd.Challenge, Challenge(device)) {
		return out, errors.New("made for another device key")
	}
	hw, err := authorizations(kd.HardwareEnforced)
	if err != nil {
		return out, err
	}
	sw, err := authorizations(kd.SoftwareEnforced)
	if err != nil {
		return out, err
	}
	// A key imported into the hardware was known outside it: whoever imported it signs anywhere.
	if origin, ok := integer(hw[tagOrigin]); !ok || origin != originGenerated {
		return out, errors.New("the key was not made in the secure hardware")
	}
	var rot rootOfTrust
	if b, ok := hw[tagRootOfTrust]; !ok {
		return out, errors.New("no root of trust")
	} else if rest, err := asn1.Unmarshal(b, &rot); err != nil || len(rest) > 0 {
		return out, errors.New("root of trust unreadable")
	}
	states := []string{"verified", "self-signed", "unverified", "failed"}
	if rot.VerifiedBootState < 0 || int(rot.VerifiedBootState) >= len(states) {
		return out, errors.New("unknown verified boot state")
	}
	if err := checkSignature(certs[0], a, device, o.Now); err != nil {
		return out, err
	}
	app, signers := applicationID(sw[tagApplicationID])
	if len(o.Apps) > 0 && !slices.ContainsFunc(o.Apps, func(x App) bool {
		return slices.Contains(app, x.Package) && slices.Contains(signers, x.Signer)
	}) {
		return out, errors.New("made by an app this network does not accept")
	}
	out.BootState = states[rot.VerifiedBootState]
	out.Locked = rot.DeviceLocked
	out.BootKey = hex.EncodeToString(rot.VerifiedBootKey)
	if v, ok := integer(hw[tagOSVersion]); ok {
		out.OSVersion = osVersion(v)
	}
	for _, f := range []struct {
		tag int
		dst *string
	}{{tagOSPatchLevel, &out.PatchLevel}, {tagVendorPatchLevel, &out.VendorPatchLevel}, {tagBootPatchLevel, &out.BootPatchLevel}} {
		if v, ok := integer(hw[f.tag]); ok {
			*f.dst = patchLevel(v)
		}
	}
	if len(app) > 0 {
		out.App = printable(app[0])
	}
	if len(signers) > 0 {
		out.AppSigner = hex.EncodeToString(signers[0][:])
	}
	return out, nil
}

// verifyChain parses the chain (leaf first) and checks that each certificate is signed by the next,
// that the last carries one of the roots' keys, that none but the root is outside its validity, and
// that none is revoked.
func verifyChain(chain [][]byte, o Options) ([]*x509.Certificate, error) {
	n := len(chain)
	if n < 2 || n > maxChain {
		return nil, fmt.Errorf("a chain of 2 to %d certificates expected", maxChain)
	}
	certs := make([]*x509.Certificate, n)
	for i, der := range chain {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("certificate %d unreadable", i)
		}
		certs[i] = c
	}
	for i := 0; i < n-1; i++ {
		if err := certs[i+1].CheckSignature(certs[i].SignatureAlgorithm, certs[i].RawTBSCertificate, certs[i].Signature); err != nil {
			return nil, fmt.Errorf("certificate %d is not signed by the next", i)
		}
	}
	roots := o.Roots
	if roots == nil {
		roots = googleRoots
	}
	if !slices.ContainsFunc(roots, func(k []byte) bool { return bytes.Equal(k, certs[n-1].RawSubjectPublicKeyInfo) }) {
		return nil, errors.New("not certified by Google's attestation root")
	}
	for i, c := range certs[:n-1] {
		if o.Now.Before(c.NotBefore.Add(-MaxSkew)) || o.Now.After(c.NotAfter) {
			return nil, fmt.Errorf("certificate %d is outside its validity", i)
		}
	}
	if o.Revoked != nil {
		for i, c := range certs {
			revoked, err := o.Revoked(c.SerialNumber.Text(16))
			if err != nil {
				return nil, err
			}
			if revoked {
				return nil, fmt.Errorf("certificate %d is revoked (a leaked or flawed key)", i)
			}
		}
	}
	return certs, nil
}

// keyDescriptionOf reads the attestation of the leaf certificate. Only the leaf may carry one: the
// attested key belongs to the app, which can sign a certificate of its own making with it, and such
// a certificate placed in front of the chain would otherwise attest whatever it says.
func keyDescriptionOf(certs []*x509.Certificate) (keyDescription, error) {
	var kd keyDescription
	var ext []byte
	for i, c := range certs {
		for _, e := range c.Extensions {
			if !e.Id.Equal(oidKeyDescription) {
				continue
			}
			if i != 0 || ext != nil {
				return kd, errors.New("an attestation outside the leaf certificate")
			}
			ext = e.Value
		}
	}
	if ext == nil {
		return kd, errors.New("no attestation in the certificate")
	}
	if rest, err := asn1.Unmarshal(ext, &kd); err != nil || len(rest) > 0 {
		return kd, errors.New("attestation unreadable")
	}
	return kd, nil
}

// checkSignature checks the signature the attested key made of the report's time.
func checkSignature(leaf *x509.Certificate, a *api.Attestation, device [32]byte, now time.Time) error {
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return errors.New("the attested key is not a P-256 key")
	}
	at, err := time.Parse(time.RFC3339, a.SignedAt)
	if err != nil {
		return errors.New("signature time unreadable")
	}
	if d := now.Sub(at); d > MaxSkew || d < -MaxSkew {
		return fmt.Errorf("signed more than %s away from the control node's time (the device's clock?)", api.HumanDuration(MaxSkew))
	}
	h := sha256.Sum256(Message(device, a.SignedAt))
	if !ecdsa.VerifyASN1(pub, h[:], a.Signature) {
		return errors.New("signature invalid")
	}
	return nil
}

// --- the key description (Android's KeyDescription, attestation versions 1 to 400) ---------------

const (
	levelTEE        = 1
	levelStrongBox  = 2
	originGenerated = 0

	tagOrigin           = 702
	tagRootOfTrust      = 704
	tagOSVersion        = 705
	tagOSPatchLevel     = 706
	tagApplicationID    = 709
	tagVendorPatchLevel = 718
	tagBootPatchLevel   = 719
)

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

type rootOfTrust struct {
	VerifiedBootKey   []byte
	DeviceLocked      bool
	VerifiedBootState asn1.Enumerated
	VerifiedBootHash  []byte `asn1:"optional"`
}

type applicationIDs struct {
	Packages []packageInfo `asn1:"set"`
	Signers  [][]byte      `asn1:"set"`
}

type packageInfo struct {
	Name    []byte
	Version int64
}

// authorizations reads an authorization list: each entry is tagged explicitly with its number;
// the result maps numbers to the tagged values' encodings. Entries are kept whatever their number
// (later versions add some), each at most once.
func authorizations(list asn1.RawValue) (map[int][]byte, error) {
	if list.Class != asn1.ClassUniversal || list.Tag != asn1.TagSequence || !list.IsCompound {
		return nil, errors.New("authorization list unreadable")
	}
	out := map[int][]byte{}
	for rest := list.Bytes; len(rest) > 0; {
		var v asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &v); err != nil || v.Class != asn1.ClassContextSpecific || !v.IsCompound {
			return nil, errors.New("authorization list unreadable")
		}
		if _, dup := out[v.Tag]; dup {
			return nil, fmt.Errorf("authorization %d twice", v.Tag)
		}
		out[v.Tag] = v.Bytes
	}
	return out, nil
}

// integer reads an INTEGER entry; false when it is missing or another type.
func integer(b []byte) (int64, bool) {
	if b == nil {
		return 0, false
	}
	var v int64
	rest, err := asn1.Unmarshal(b, &v)
	return v, err == nil && len(rest) == 0
}

// applicationID reads the app that asked for the key: package names and signing certificates'
// SHA-256 (nothing when the entry is missing or unreadable).
func applicationID(b []byte) ([]string, [][32]byte) {
	var octets []byte
	if rest, err := asn1.Unmarshal(b, &octets); err != nil || len(rest) > 0 {
		return nil, nil
	}
	var ids applicationIDs
	if rest, err := asn1.Unmarshal(octets, &ids); err != nil || len(rest) > 0 {
		return nil, nil
	}
	var names []string
	for _, p := range ids.Packages {
		names = append(names, string(p.Name))
	}
	var signers [][32]byte
	for _, s := range ids.Signers {
		if len(s) == 32 {
			signers = append(signers, [32]byte(s))
		}
	}
	return names, signers
}

// osVersion writes Android's MMmmpp ("140000" is 14.0.0); "" for 0 (not reported).
func osVersion(v int64) string {
	if v <= 0 || v > 999999 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d", v/10000, v/100%100, v%100)
}

// patchLevel writes YYYYMM as "2026-09" and YYYYMMDD as "2026-09-05"; "" for anything else.
func patchLevel(v int64) string {
	switch {
	case v >= 200001 && v <= 999912 && v%100 >= 1 && v%100 <= 12:
		return fmt.Sprintf("%04d-%02d", v/100, v%100)
	case v >= 20000101 && v <= 99991231 && v/100%100 >= 1 && v/100%100 <= 12 && v%100 >= 1 && v%100 <= 31:
		return fmt.Sprintf("%04d-%02d-%02d", v/10000, v/100%100, v%100)
	}
	return ""
}

// printable keeps the printable ASCII of a package name, at most 128 characters.
func printable(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x21 || r > 0x7e {
			return -1
		}
		return r
	}, s)
	if len(s) > 128 {
		s = s[:128]
	}
	return s
}
