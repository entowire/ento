package control

import (
	"fmt"
	"net/http"
	"strings"

	"entowire.com/ento/internal/store"
)

// audit logs a security-relevant action in one line a SIEM can parse:
//
//	audit: action=peer_deleted by="laptop (alice@example.com)" from=100.64.1.2 target="peer 7 web-1" result=ok
//
// "by" is the device (and its SSO user) that made the request, "from" its overlay address. Values
// never contain secrets.
func (s *Server) audit(r *http.Request, by *store.Peer, action, target, result string) {
	who, from := "-", "-"
	if by != nil {
		who = by.Hostname
		if by.UserName != "" {
			who += " (" + by.UserName + ")"
		}
		from = by.Address.String()
	} else if r != nil {
		if a, ok := caller(r); ok {
			from = a.String()
		}
	}
	s.cfg.Logf("audit: action=%s by=%q from=%s target=%q result=%s", action, clean(who), from, clean(target), result)
}

func clean(s string) string { return strings.NewReplacer("\"", "'", "\n", " ").Replace(s) }

func peerLabel(p store.Peer) string { return fmt.Sprintf("peer %d %s %s", p.ID, p.Hostname, p.Address) }
