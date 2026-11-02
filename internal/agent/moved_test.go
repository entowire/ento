package agent

import (
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/token"
)

func TestMovedEndpoints(t *testing.T) {
	k1, _ := wgtypes.GeneratePrivateKey()
	k2, _ := wgtypes.GeneratePrivateKey()
	k3, _ := wgtypes.GeneratePrivateKey()
	controls := []api.Control{
		{Name: "a", PublicKey: k1.PublicKey().String(), Endpoint: "192.0.2.1:51821", Address: "100.64.0.1"},
		{Name: "b", PublicKey: k2.PublicKey().String(), Endpoint: "192.0.2.2:51821", Address: "100.64.0.2"},
	}
	rec, err := token.ParseRecord("ento1 net=100.64.0.0/16" +
		" c=" + k1.PublicKey().String() + ",198.51.100.1:51821,100.64.0.9" + // moved; its address stays
		" c=" + k2.PublicKey().String() + ",192.0.2.2:51821,100.64.0.2" + // where it was
		" c=" + k3.PublicKey().String() + ",198.51.100.3:51821,100.64.0.3") // a key the device does not know
	if err != nil {
		t.Fatal(err)
	}
	got, changes := movedEndpoints(controls, rec)
	if len(changes) != 1 || len(got) != 2 {
		t.Fatalf("changes %v, controls %v", changes, got)
	}
	if got[0].Endpoint != "198.51.100.1:51821" || got[0].Address != "100.64.0.1" || got[0].PublicKey != controls[0].PublicKey {
		t.Fatalf("moved control: %+v", got[0])
	}
	if got[1] != controls[1] {
		t.Fatalf("unchanged control: %+v", got[1])
	}
	if controls[0].Endpoint != "192.0.2.1:51821" {
		t.Fatal("the input was modified")
	}
	if _, changes := movedEndpoints(got, rec); len(changes) != 0 {
		t.Fatalf("second pass: %v", changes)
	}
}
