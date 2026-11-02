package agent

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestCheckEnrollment(t *testing.T) {
	fresh := t.TempDir()
	enrolled := t.TempDir()
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveState(enrolled, State{PrivateKey: Key(priv), Address: netip.MustParseAddr("100.64.1.7")}); err != nil {
		t.Fatal(err)
	}
	corrupt := t.TempDir()
	if err := os.WriteFile(filepath.Join(corrupt, stateFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name, dir, token string
		force, replace   bool
		err              string
	}{
		{"first enrollment", fresh, "ento1:t", false, false, ""},
		{"first enrollment, force", fresh, "ento1:t", true, false, ""},
		{"service update", enrolled, "", false, false, ""},
		{"force without token", enrolled, "", true, false, "give the token"},
		{"token on an enrolled device", enrolled, "ento1:t", false, false, "already enrolled (address 100.64.1.7, public key " + priv.PublicKey().String()},
		{"replace", enrolled, "ento1:t", true, true, ""},
		{"token on a corrupt state", corrupt, "ento1:t", false, false, "corrupt state"},
		{"replace a corrupt state", corrupt, "ento1:t", true, true, ""},
	} {
		replace, err := checkEnrollment(c.dir, c.token, c.force)
		switch {
		case c.err == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
			t.Errorf("%s: error %v, want one containing %q", c.name, err, c.err)
		case replace != c.replace:
			t.Errorf("%s: replace %v, want %v", c.name, replace, c.replace)
		}
	}
	if _, err := checkEnrollment(enrolled, "", true); !errors.Is(err, ErrForceWithoutToken) {
		t.Errorf("force without token: %v", err)
	}
}
