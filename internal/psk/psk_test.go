package psk

import (
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestExchange(t *testing.T) {
	priv, _ := wgtypes.GeneratePrivateKey()
	device := priv.PublicKey()
	req, err := NewRequest()
	if err != nil {
		t.Fatal(err)
	}
	ct, ctl, err := Answer(req.EncapsulationKey(), device)
	if err != nil {
		t.Fatal(err)
	}
	got, err := req.Finish(ct, device)
	if err != nil {
		t.Fatal(err)
	}
	if got.Key != ctl.Key || !SameTag(got.Tag, ctl.Tag) || got.Key == (wgtypes.Key{}) {
		t.Fatalf("the ends disagree: %v %v", got, ctl)
	}
	if string(got.Key[:]) == got.Tag {
		t.Fatal("the tag is the key")
	}
	// Bound to the device's key: another key derives another preshared key.
	other, _ := wgtypes.GeneratePrivateKey()
	if o, err := req.Finish(ct, other.PublicKey()); err != nil || o.Key == got.Key {
		t.Fatalf("not bound to the device's key: %v", err)
	}
	// Each exchange is fresh.
	ct2, ctl2, _ := Answer(req.EncapsulationKey(), device)
	if ct2 == ct || ctl2.Key == ctl.Key {
		t.Fatal("two exchanges agreed on the same key")
	}
	if _, _, err := Answer("not-a-key", device); err == nil {
		t.Fatal("a malformed encapsulation key was taken")
	}
	if _, err := req.Finish("AAAA", device); err == nil {
		t.Fatal("a malformed ciphertext was taken")
	}
}
