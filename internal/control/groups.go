package control

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"unicode"

	"entowire.com/ento/internal/token"
)

// checkGroups rejects group names an administrator should not be able to set: empty, longer than
// 64 characters, with commas (the command line's separator), control characters or surrounding
// spaces. "*" (every device) is allowed only where policies are made.
func checkGroups(groups []string, policy bool) error {
	for _, g := range groups {
		switch {
		case g == "" || len(g) > 64 || strings.TrimSpace(g) != g:
			return fmt.Errorf("group %q: 1 to 64 characters, no spaces around", g)
		case g == "*" && !policy:
			return fmt.Errorf(`"*" means every device and is only for policies`)
		case strings.ContainsFunc(g, func(r rune) bool { return r == ',' || unicode.IsControl(r) }):
			return fmt.Errorf("group %q: no commas or control characters", g)
		}
	}
	return nil
}

// linkedNetwork identifies the network a link leads to, from the control nodes in the token that
// network issued: links whose tokens name the same control nodes lead into the same network. It
// returns the control nodes' endpoints and a short fingerprint of their keys ("" without a token).
func linkedNetwork(tok string) (endpoints []string, id string) {
	t, err := token.Parse(tok)
	if err != nil {
		return nil, ""
	}
	var keys []string
	for _, c := range t.Controls {
		endpoints = append(endpoints, c.Endpoint)
		keys = append(keys, c.PublicKey.String())
	}
	slices.Sort(keys)
	sum := sha256.Sum256([]byte(strings.Join(keys, ",")))
	return endpoints, hex.EncodeToString(sum[:6])
}
