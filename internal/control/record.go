package control

// The network record (0.29). With a record domain (Config.RecordDomain, --record-domain), the
// network map names the domain whose record (TXT _ento.<domain>, what `ento admin record`
// prints) devices look up when they reach no control node, to find where the control nodes moved
// (internal/agent/moved.go). Each node checks at its start and every hour that the record names
// it with the endpoint it serves: a record left as it was after the control nodes moved (rebuilt
// elsewhere) leaves the devices that lost them nowhere to look.

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/token"
)

func (s *Server) recordLoop(ctx context.Context) {
	last := ""
	for {
		lctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		msg := recordVerdict(lctx, net.DefaultResolver, s.cfg.RecordDomain, s.self.PublicKey, s.cfg.Endpoint)
		cancel()
		if msg != last && ctx.Err() == nil {
			s.cfg.Logf("%s", msg)
			last = msg
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Hour):
		}
	}
}

// recordVerdict says whether the domain's network record names this node (key) at endpoint.
func recordVerdict(ctx context.Context, r *net.Resolver, domain string, key wgtypes.Key, endpoint string) string {
	name := token.RecordName + "." + domain
	txts, err := r.LookupTXT(ctx, name)
	if err != nil {
		return fmt.Sprintf("network record: %v (devices that reach no control node look for them there)", err)
	}
	text, err := token.FindRecord(txts)
	if err == nil {
		var rec token.Record
		if rec, err = token.ParseRecord(text); err == nil {
			return recordNames(name, rec, key, endpoint)
		}
	}
	return fmt.Sprintf("network record %s: %v (devices that reach no control node look for them there)", name, err)
}

func recordNames(name string, rec token.Record, key wgtypes.Key, endpoint string) string {
	for _, c := range rec.Controls {
		if c.PublicKey != key {
			continue
		}
		if c.Endpoint == endpoint {
			return fmt.Sprintf("network record %s names this node at %s", name, endpoint)
		}
		return fmt.Sprintf("network record %s names this node at %s, not %s: devices that lose their control nodes will not find it (publish what ento admin record prints)", name, c.Endpoint, endpoint)
	}
	return fmt.Sprintf("network record %s does not name this node (key %s): devices that lose their control nodes will not find it (publish what ento admin record prints)", name, key)
}
