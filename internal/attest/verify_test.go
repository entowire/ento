package attest_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/attest"
	at "entowire.com/ento/internal/attest/attesttest"
)

func options(h *at.Hardware) attest.Options { return attest.Options{Now: time.Now(), Roots: h.Roots()} }

func TestVerify(t *testing.T) {
	h := at.New(t)
	device := [32]byte{1, 2, 3}
	a, _ := h.Attest(t, device, at.Good(device), time.Now())
	got := attest.Verify(a, device, options(h))
	signer := at.Signer()
	want := api.Attested{SecurityLevel: "tee", BootState: "verified", Locked: true, BootKey: strings.Repeat("00", 32),
		OSVersion: "16.0.0", PatchLevel: "2026-09", VendorPatchLevel: "2026-09-05", BootPatchLevel: "2026-09-05",
		App: "com.example.app", AppSigner: hex.EncodeToString(signer[:])}
	if got != want {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}

	// What the hardware attests is reported as it is, also when it is no verified boot.
	for _, c := range []struct {
		state  int
		locked bool
		want   string
	}{{1, true, "self-signed"}, {2, false, "unverified"}, {3, false, "failed"}} {
		s := at.Good(device)
		s.State, s.Locked = c.state, c.locked
		a, _ := h.Attest(t, device, s, time.Now())
		if got := attest.Verify(a, device, options(h)); got.Error != "" || got.BootState != c.want || got.Locked != c.locked {
			t.Errorf("state %d: %+v", c.state, got)
		}
	}
	s := at.Good(device)
	s.Level = at.LevelStrongBox
	if a, _ := h.Attest(t, device, s, time.Now()); attest.Verify(a, device, options(h)).SecurityLevel != "strongbox" {
		t.Error("StrongBox not reported")
	}

	// Accepted apps.
	o := options(h)
	o.Apps = []attest.App{{Package: "com.example.app", Signer: signer}}
	if got := attest.Verify(a, device, o); got.Error != "" {
		t.Errorf("accepted app: %+v", got)
	}
	o.Apps = []attest.App{{Package: "com.example.app", Signer: sha256.Sum256([]byte("someone else"))}}
	if got := attest.Verify(a, device, o); got.Error != "made by an app this network does not accept" {
		t.Errorf("another signer: %+v", got)
	}
	o.Apps = []attest.App{{Package: "com.example.other", Signer: signer}}
	if got := attest.Verify(a, device, o); got.Error != "made by an app this network does not accept" {
		t.Errorf("another package: %+v", got)
	}

	// Revocation.
	o = options(h)
	o.Revoked = func(serial string) (bool, error) { return serial == "beef", nil }
	if got := attest.Verify(a, device, o); !strings.Contains(got.Error, "certificate 1 is revoked") {
		t.Errorf("revoked intermediate: %+v", got)
	}
	o.Revoked = func(string) (bool, error) { return false, errors.New("the revocation list was not fetched yet") }
	if got := attest.Verify(a, device, o); got.Error != "the revocation list was not fetched yet" {
		t.Errorf("no revocation list: %+v", got)
	}

	// Without roots of its own, only Google's count.
	if got := attest.Verify(a, device, attest.Options{Now: time.Now()}); got.Error != "not certified by Google's attestation root" {
		t.Errorf("made-up root trusted: %+v", got)
	}
}

func TestVerifyRefuses(t *testing.T) {
	h := at.New(t)
	device, other := [32]byte{1, 2, 3}, [32]byte{4, 5, 6}
	spec := func(f func(*at.Spec)) at.Spec {
		s := at.Good(device)
		f(&s)
		return s
	}
	for _, c := range []struct {
		name string
		spec at.Spec
		at   time.Time
		edit func(a *api.Attestation, key *ecdsa.PrivateKey)
		want string
	}{
		{name: "software", spec: spec(func(s *at.Spec) { s.Level = at.LevelSoftware }), want: "software attestation"},
		{name: "other device", spec: spec(func(s *at.Spec) { s.Challenge = attest.Challenge(other) }), want: "made for another device key"},
		{name: "imported key", spec: spec(func(s *at.Spec) { s.Origin = at.OriginImported }), want: "not made in the secure hardware"},
		{name: "no root of trust", spec: spec(func(s *at.Spec) {
			s.Edit = func(hw, _ *[]asn1.RawValue) { *hw = (*hw)[:2] }
		}), want: "no root of trust"},
		{name: "twice", spec: spec(func(s *at.Spec) {
			s.Edit = func(hw, _ *[]asn1.RawValue) { *hw = append(*hw, at.Explicit(at.TagOrigin, 0)) }
		}), want: "authorization 702 twice"},
		{name: "unknown entries are fine, a bad state is not", spec: spec(func(s *at.Spec) {
			s.State = 7
			s.Edit = func(hw, _ *[]asn1.RawValue) { *hw = append(*hw, at.Explicit(999, 1)) }
		}), want: "unknown verified boot state"},
		{name: "old signature", spec: at.Good(device), at: time.Now().Add(-attest.MaxSkew - time.Minute), want: "signed more than"},
		{name: "signature ahead", spec: at.Good(device), at: time.Now().Add(attest.MaxSkew + time.Minute), want: "signed more than"},
		{name: "signed for another device", spec: at.Good(device), edit: func(a *api.Attestation, key *ecdsa.PrivateKey) {
			at.Sign(a, key, other, time.Now())
		}, want: "signature invalid"},
		{name: "another time than signed", spec: at.Good(device), edit: func(a *api.Attestation, _ *ecdsa.PrivateKey) {
			a.SignedAt = time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano)
		}, want: "signature invalid"},
		{name: "signed by another key", spec: at.Good(device), edit: func(a *api.Attestation, _ *ecdsa.PrivateKey) {
			k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			at.Sign(a, k, device, time.Now())
		}, want: "signature invalid"},
		{name: "no root", spec: at.Good(device), edit: func(a *api.Attestation, _ *ecdsa.PrivateKey) {
			a.Chain = a.Chain[:2]
		}, want: "not certified by Google's attestation root"},
		{name: "a leaf alone", spec: at.Good(device), edit: func(a *api.Attestation, _ *ecdsa.PrivateKey) {
			a.Chain = a.Chain[:1]
		}, want: "a chain of 2 to"},
		{name: "broken chain", spec: at.Good(device), edit: func(a *api.Attestation, _ *ecdsa.PrivateKey) {
			a.Chain[1] = h.Root.Raw
		}, want: "certificate 0 is not signed by the next"},
		{name: "garbage", spec: at.Good(device), edit: func(a *api.Attestation, _ *ecdsa.PrivateKey) {
			a.Chain[0] = []byte("not a certificate")
		}, want: "certificate 0 unreadable"},
		{name: "format", spec: at.Good(device), edit: func(a *api.Attestation, _ *ecdsa.PrivateKey) {
			a.Format = "tpm"
		}, want: "unknown attestation format"},
	} {
		when := c.at
		if when.IsZero() {
			when = time.Now()
		}
		a, key := h.Attest(t, device, c.spec, when)
		if c.edit != nil {
			c.edit(a, key)
		}
		got := attest.Verify(a, device, options(h))
		if !strings.Contains(got.Error, c.want) || got.BootState != "" {
			t.Errorf("%s: %+v, want %q", c.name, got, c.want)
		}
	}
}

// The attested key belongs to the app: it can sign a certificate of its own making, with an
// attestation that says whatever it likes, and put it in front of a genuine chain. Only the leaf
// may carry an attestation, so the genuine one, now second, refuses the chain.
func TestForgedLeaf(t *testing.T) {
	h := at.New(t)
	device := [32]byte{1, 2, 3}
	s := at.Good(device)
	s.State, s.Locked = 2, false // the hardware says: unlocked
	a, appKey := h.Attest(t, device, s, time.Now())
	genuine, _ := x509.ParseCertificate(a.Chain[0])
	forgedKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	forged := at.Certificate(t, &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Unix(0, 0), NotAfter: time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: at.OIDKeyDescription, Value: at.Good(device).Extension()}}}, genuine, &forgedKey.PublicKey, appKey)
	a.Chain = append([][]byte{forged.Raw}, a.Chain...)
	at.Sign(a, forgedKey, device, time.Now())
	if got := attest.Verify(a, device, options(h)); got.Error != "an attestation outside the leaf certificate" {
		t.Fatalf("forged leaf: %+v", got)
	}
}

func TestParseApps(t *testing.T) {
	sum := strings.Repeat("ab", 32)
	apps, err := attest.ParseApps("com.example.app:" + sum + ", org.other:" + strings.ToUpper(strings.Repeat("ab:", 31)) + "AB")
	if err != nil || len(apps) != 2 || apps[0].Package != "com.example.app" || apps[1].Signer != apps[0].Signer || apps[0].Signer[0] != 0xab {
		t.Fatal(apps, err)
	}
	for _, bad := range []string{"com.example.app", "com.example.app:abcd", ":" + sum, "com.example.app:" + sum + "zz"} {
		if _, err := attest.ParseApps(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if apps, err := attest.ParseApps(""); err != nil || apps != nil {
		t.Error(apps, err)
	}
}
