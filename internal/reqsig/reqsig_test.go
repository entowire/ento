package reqsig

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func keys(t *testing.T) (dev, ctl wgtypes.Key) {
	t.Helper()
	dev, _ = wgtypes.GeneratePrivateKey()
	ctl, _ = wgtypes.GeneratePrivateKey()
	return dev, ctl
}

// received turns a client request into what a server sees.
func received(t *testing.T, req *http.Request, body []byte) *http.Request {
	t.Helper()
	r := httptest.NewRequest(req.Method, req.URL.RequestURI(), bytes.NewReader(body))
	r.Header = req.Header.Clone()
	return r
}

func TestSignVerify(t *testing.T) {
	dev, ctl := keys(t)
	dk, err := DeviceKey(dev, ctl.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	ck, err := ControlKey(ctl, dev.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dk, ck) {
		t.Fatal("device and control node derive different keys")
	}
	now := time.Now()
	body := []byte(`{"admin":true}`)
	req, _ := http.NewRequest("POST", "http://100.64.0.1/v1/admin/tokens?x=1", bytes.NewReader(body))
	if err := Sign(req, dk, body, now); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(received(t, req, body), ck, body, now.Add(time.Minute)); err != nil {
		t.Fatalf("valid request refused: %v", err)
	}

	// Another body, method, target or time, another device's key, no signature: refused.
	if _, err := Verify(received(t, req, body), ck, []byte(`{"admin":false}`), now); err == nil {
		t.Error("changed body accepted")
	}
	other := req.Clone(req.Context())
	other.Method = "DELETE"
	if _, err := Verify(received(t, other, body), ck, body, now); err == nil {
		t.Error("changed method accepted")
	}
	moved, _ := http.NewRequest("POST", "http://100.64.0.1/v1/admin/peers", nil)
	moved.Header = req.Header.Clone()
	if _, err := Verify(received(t, moved, body), ck, body, now); err == nil {
		t.Error("changed target accepted")
	}
	if _, err := Verify(received(t, req, body), ck, body, now.Add(MaxSkew+time.Minute)); err == nil {
		t.Error("stale request accepted")
	}
	stranger, _ := wgtypes.GeneratePrivateKey()
	sk, _ := ControlKey(ctl, stranger.PublicKey())
	if _, err := Verify(received(t, req, body), sk, body, now); err == nil {
		t.Error("request accepted for another device's key")
	}
	plain, _ := http.NewRequest("GET", "http://100.64.0.1/v1/admin/peers", nil)
	if _, err := Verify(received(t, plain, nil), ck, nil, now); err != ErrUnsigned {
		t.Errorf("unsigned request: got %v, want ErrUnsigned", err)
	}
}

func TestNonces(t *testing.T) {
	var n Nonces
	now := time.Now()
	if n.Check("d1", "a", now) != nil || n.Check("d1", "a", now.Add(time.Second)) != ErrReplayed {
		t.Fatal("a nonce was accepted twice")
	}
	if err := n.Check("d2", "a", now); err != nil {
		t.Fatalf("another device's equal nonce: %v", err)
	}
	if err := n.Check("d1", "a", now.Add(3*MaxSkew)); err != nil {
		t.Fatalf("a nonce older than the window was refused: %v", err)
	}
	// Bounded per device: beyond MaxNonces recent ones, that device waits; others do not.
	for i := 0; i < MaxNonces; i++ {
		n.Check("d3", fmt.Sprint(i), now)
	}
	if err := n.Check("d3", "x", now.Add(time.Minute)); err != ErrBusy {
		t.Fatalf("beyond the bound: %v", err)
	}
	if err := n.Check("d4", "x", now.Add(time.Minute)); err != nil {
		t.Fatalf("another device while one is at its bound: %v", err)
	}
	if err := n.Check("d3", "y", now.Add(3*MaxSkew)); err != nil {
		t.Fatalf("after the old ones aged out: %v", err)
	}
}
