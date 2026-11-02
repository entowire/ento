package agent

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"entowire.com/ento/internal/token"
)

// Enrollment by words (see package token): the domain's network record and the words an
// administrator reads out stand for an enrollment token.

// LookupRecord finds a domain's network record (the TXT record _ento.<domain>) with resolver r
// (nil: the system's).
func LookupRecord(ctx context.Context, domain string, r *net.Resolver) (string, error) {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if d == "" || strings.ContainsFunc(d, func(c rune) bool { return !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.') }) {
		return "", fmt.Errorf("%q is not a domain name", domain)
	}
	if r == nil {
		r = net.DefaultResolver
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	name := token.RecordName + "." + d
	txts, err := r.LookupTXT(ctx, name)
	if err != nil {
		return "", fmt.Errorf("looking up the network record %s: %v", name, err)
	}
	rec, err := token.FindRecord(txts)
	if err != nil {
		return "", fmt.Errorf("%s: %v", name, err)
	}
	return rec, nil
}

// ResolverVia is a resolver that asks these DNS servers (addresses, port 53), for systems whose
// resolver Go cannot find by itself (Android has no /etc/resolv.conf). Each attempt goes to the
// next server: a UDP "connection" to a server that does not answer cannot fail, only its query.
func ResolverVia(servers []string) *net.Resolver {
	var next atomic.Uint32
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		if len(servers) == 0 {
			return nil, fmt.Errorf("no DNS server")
		}
		s := servers[int(next.Add(1)-1)%len(servers)]
		d := net.Dialer{Timeout: 5 * time.Second}
		return d.DialContext(ctx, network, net.JoinHostPort(strings.TrimSpace(s), "53"))
	}}
}

// WordsToken returns the token that words stand for in the network of a record (Argon2id: a
// second or two).
func WordsToken(record, words string) (string, error) {
	rec, err := token.ParseRecord(record)
	if err != nil {
		return "", err
	}
	w, err := token.ParseWords(words)
	if err != nil {
		return "", err
	}
	tok, err := rec.Token(w)
	if err != nil {
		return "", err
	}
	return tok.Encode()
}
