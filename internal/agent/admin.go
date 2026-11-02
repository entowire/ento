package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/reqsig"
)

// AdminClient calls the control plane through the local WireGuard interface. Control nodes know
// this device by its overlay address; calls that act with its rights (administration, sign-in,
// linked networks) are also signed with its key, which only root (an administrator) can read.
type AdminClient struct {
	Controls []api.Control
	Key      wgtypes.Key  // the device's private key; zero sends unsigned requests
	HTTP     *http.Client // nil: the agent's own namespace
}

// Do sends a request to the first control node that answers.
func (c *AdminClient) Do(ctx context.Context, method, path string, in, out any) error {
	if len(c.Controls) == 0 {
		return fmt.Errorf("no control node known")
	}
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
	}
	var lastErr error
	for _, ctl := range c.Controls {
		req, err := signedRequest(ctx, method, fmt.Sprintf("http://%s%s", ctl.Address, path), body, c.Key, ctl)
		if err != nil {
			return err
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		c2 := c.HTTP
		if c2 == nil {
			c2 = httpClient
		}
		lastErr = doJSON(c2, req, out)
		if lastErr == nil {
			return nil
		}
		// An HTTP error is an answer (e.g. forbidden); only connection failures try the next node.
		if _, isHTTP := lastErr.(httpError); isHTTP {
			return lastErr
		}
	}
	return lastErr
}

// signedRequest builds a request to a control node, signed with key (unless it is zero).
func signedRequest(ctx context.Context, method, url string, body []byte, key wgtypes.Key, ctl api.Control) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if key == (wgtypes.Key{}) {
		return req, nil
	}
	pub, err := wgtypes.ParseKey(ctl.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("control node %s: %w", ctl.Name, err)
	}
	k, err := reqsig.DeviceKey(key, pub)
	if err != nil {
		return nil, err
	}
	return req, reqsig.Sign(req, k, body, time.Now())
}
