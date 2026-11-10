package main

import (
	"slices"
	"testing"
)

// --network and --link count anywhere on an admin command line (0.56.6: after the subcommand they
// were ignored, and the command administered the first network).
func TestTakeFlag(t *testing.T) {
	for _, c := range []struct {
		args  []string
		value string
		rest  []string
	}{
		{[]string{"--network", "md.example.net", "peers"}, "md.example.net", []string{"peers"}},
		{[]string{"peers", "--network", "md.example.net"}, "md.example.net", []string{"peers"}},
		{[]string{"policies", "--network=md.example.net"}, "md.example.net", []string{"policies"}},
		{[]string{"peers", "-network", "md.example.net", "--json"}, "md.example.net", []string{"peers", "--json"}},
		{[]string{"peers", "--json"}, "", []string{"peers", "--json"}},
		{[]string{"note", "--", "--network", "x"}, "", []string{"note", "--", "--network", "x"}},
	} {
		v, rest, err := takeFlag(c.args, "network")
		if err != nil || v != c.value || !slices.Equal(rest, c.rest) {
			t.Errorf("%q: %q %q %v", c.args, v, rest, err)
		}
	}
	for _, bad := range [][]string{{"peers", "--network"}, {"--network", "a", "peers", "--network", "b"}, {"peers", "--network="}} {
		if _, _, err := takeFlag(bad, "network"); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}
