package attest

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"entowire.com/ento/internal/api"
)

func TestRoots(t *testing.T) {
	// The roots as https://android.googleapis.com/attestation/root served them on 2026-10-05
	// (SHA-256 of each certificate).
	want := map[string]string{
		"roots/google-rsa.pem": "cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc",
		"roots/google-ec.pem":  "6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0",
	}
	for f, sum := range want {
		b, err := rootFiles.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		c := parsePEM(t, b)
		if got := sha256.Sum256(c.Raw); hex.EncodeToString(got[:]) != sum {
			t.Errorf("%s: %x", f, got)
		}
	}
	if len(googleRoots) != len(want) {
		t.Fatalf("%d roots", len(googleRoots))
	}
}

// readChain reads a chain of testdata (DER files cert0.der, cert1.der, ...).
func readChain(t *testing.T, dir string) [][]byte {
	files, _ := filepath.Glob(filepath.Join("testdata", dir, "cert*.der"))
	var out [][]byte
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, b)
	}
	if len(out) < 2 {
		t.Fatalf("%s: %d certificates", dir, len(out))
	}
	return out
}

// Chains of real phones (Pixel 3, 2019, from google/android-key-attestation's tests, Apache 2.0):
// a TEE chain ending at Google's RSA root (in its 2016 certificate, expired since May 2026: the key
// counts), and a StrongBox chain of a pre-production device, ending at another root. Both were made
// with the challenge "abc", so they never count for a device: the verification must get as far as
// the challenge, and their contents must read as the hardware wrote them.
func TestRealChains(t *testing.T) {
	var device [32]byte
	tee := readChain(t, "ec-tee")
	at2019 := Options{Now: time.Date(2019, 7, 15, 0, 0, 0, 0, time.UTC)}
	for _, now := range []time.Time{at2019.Now, time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)} {
		got := Verify(&api.Attestation{Format: FormatAndroid, Chain: tee}, device, Options{Now: now})
		if got.Error != "made for another device key" {
			t.Errorf("TEE chain at %s: %+v", now.Format(time.DateOnly), got)
		}
	}
	certs, err := verifyChain(tee, at2019)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := keyDescriptionOf(certs)
	if err != nil {
		t.Fatal(err)
	}
	if kd.Version != 3 || kd.SecurityLevel != levelTEE || string(kd.Challenge) != "abc" {
		t.Fatalf("key description %+v", kd)
	}
	hw, err := authorizations(kd.HardwareEnforced)
	if err != nil {
		t.Fatal(err)
	}
	var rot rootOfTrust
	if _, err := asn1.Unmarshal(hw[tagRootOfTrust], &rot); err != nil {
		t.Fatal(err)
	}
	if rot.DeviceLocked || rot.VerifiedBootState != 2 || len(rot.VerifiedBootHash) != 32 {
		t.Errorf("root of trust %+v", rot)
	}
	if v, _ := integer(hw[tagOSPatchLevel]); patchLevel(v) != "2019-07" {
		t.Errorf("patch level %d", v)
	}
	if v, ok := integer(hw[tagOrigin]); !ok || v != originGenerated {
		t.Errorf("origin %d %v", v, ok)
	}
	sw, err := authorizations(kd.SoftwareEnforced)
	if err != nil {
		t.Fatal(err)
	}
	names, signers := applicationID(sw[tagApplicationID])
	if len(names) != 13 || names[0] != "android" || len(signers) != 1 {
		t.Errorf("application %q %x", names, signers)
	}

	sb := readChain(t, "ec-strongbox")
	if got := Verify(&api.Attestation{Format: FormatAndroid, Chain: sb}, device, at2019); got.Error != "not certified by Google's attestation root" {
		t.Errorf("StrongBox chain: %+v", got)
	}
	root, _ := x509.ParseCertificate(sb[len(sb)-1])
	withRoot := at2019
	withRoot.Roots = [][]byte{root.RawSubjectPublicKeyInfo}
	if got := Verify(&api.Attestation{Format: FormatAndroid, Chain: sb}, device, withRoot); got.Error != "made for another device key" {
		t.Errorf("StrongBox chain with its root: %+v", got)
	}
	// Its certificates expired in 2028.
	withRoot.Now = time.Date(2028, 6, 1, 0, 0, 0, 0, time.UTC)
	if got := Verify(&api.Attestation{Format: FormatAndroid, Chain: sb}, device, withRoot); !strings.Contains(got.Error, "outside its validity") {
		t.Errorf("StrongBox chain in 2028: %+v", got)
	}
}

func TestLevels(t *testing.T) {
	for v, want := range map[int64]string{202609: "2026-09", 20260905: "2026-09-05", 0: "", 202613: "", 20261301: "", 1234: ""} {
		if got := patchLevel(v); got != want {
			t.Errorf("patch level %d: %q", v, got)
		}
	}
	for v, want := range map[int64]string{140000: "14.0.0", 160102: "16.1.2", 0: "", 80100: "8.1.0"} {
		if got := osVersion(v); got != want {
			t.Errorf("os version %d: %q", v, got)
		}
	}
}

func parsePEM(t *testing.T, b []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatal("not PEM")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
