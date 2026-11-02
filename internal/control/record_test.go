package control

import (
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/token"
)

func TestRecordNames(t *testing.T) {
	k1, _ := wgtypes.GeneratePrivateKey()
	k2, _ := wgtypes.GeneratePrivateKey()
	rec, err := token.ParseRecord("ento1 net=100.64.0.0/16 c=" + k1.PublicKey().String() + ",192.0.2.1:51821,100.64.0.1")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		key      wgtypes.Key
		endpoint string
		want     string
	}{
		{k1.PublicKey(), "192.0.2.1:51821", "names this node at 192.0.2.1:51821"},
		{k1.PublicKey(), "198.51.100.1:51821", "names this node at 192.0.2.1:51821, not 198.51.100.1:51821"},
		{k2.PublicKey(), "192.0.2.1:51821", "does not name this node"},
	} {
		if got := recordNames("_ento.example.com", rec, tc.key, tc.endpoint); !strings.Contains(got, tc.want) {
			t.Errorf("%s: %q, want %q", tc.endpoint, got, tc.want)
		}
	}
}
