package hwsig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"
)

type softKey struct{ k *ecdsa.PrivateKey }

func (s softKey) Kind() string                        { return "test" }
func (s softKey) Public() *ecdsa.PublicKey            { return &s.k.PublicKey }
func (s softKey) SignDigest(d []byte) ([]byte, error) { return ecdsa.SignASN1(rand.Reader, s.k, d) }

func TestSignVerify(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s := softKey{k}
	pub, err := EncodePublic(s.Public())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	msg := CheckInMessage("wgkey", "token", now.Unix())
	sig, err := Sign(s, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(pub, sig, msg, now.Unix(), now); err != nil {
		t.Fatalf("valid: %v", err)
	}
	// Another purpose, key, token or time: refused.
	for name, m := range map[string][]byte{
		"rotate": RotateMessage("wgkey", "token", now.Unix()),
		"key":    CheckInMessage("other", "token", now.Unix()),
		"token":  CheckInMessage("wgkey", "other", now.Unix()),
		"time":   CheckInMessage("wgkey", "token", now.Unix()+1),
	} {
		if Verify(pub, sig, m, now.Unix(), now) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if Verify(pub, sig, msg, now.Unix(), now.Add(MaxSkew+time.Second)) == nil {
		t.Error("an old signature was accepted")
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherPub, _ := EncodePublic(&other.PublicKey)
	if Verify(otherPub, sig, msg, now.Unix(), now) == nil {
		t.Error("another key's signature was accepted")
	}
}

func TestParsePublicP256Only(t *testing.T) {
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	if _, err := ParsePublic(base64.StdEncoding.EncodeToString(der)); err == nil {
		t.Error("a P-384 key was accepted")
	}
	r, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ = x509.MarshalPKIXPublicKey(&r.PublicKey)
	if _, err := ParsePublic(base64.StdEncoding.EncodeToString(der)); err == nil {
		t.Error("an RSA key was accepted")
	}
	if _, err := ParsePublic("not base64!"); err == nil {
		t.Error("garbage was accepted")
	}
}
