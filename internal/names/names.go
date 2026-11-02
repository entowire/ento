// Package names gives devices their names in a network.
//
// An administrator names a device (with its enrollment token, or later); otherwise it is named
// after the host name it reports, under a prefix no administrator's name has, so a device cannot
// take a name that looks like one an administrator gave. Devices admitted by an authority (linked
// networks) carry the authority's name in front instead. Names are unique within a network, at
// most MaxLen characters of a-z, 0-9 and single dashes: safe in logs, terminals and hosts files.
package names

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	// MaxLen is the longest name, prefix and counter included.
	MaxLen = 32
	// SelfPrefix starts the name of a device named after its own host name. Administrators'
	// names never do; "z-" also sorts such devices after the others.
	SelfPrefix = "z-"
	// fallback stands in for a host name without any usable character.
	fallback = "device"
	// maxReported is how much of a reported host name is kept, for display.
	maxReported = 64
)

// Label reduces text to name characters: its first dot-separated label, in lowercase, with a-z
// and 0-9 kept and every other run of characters turned into one dash, none at either end.
// "Mariuss-MacBook-Pro.local" gives "mariuss-macbook-pro", "Pixel 7" gives "pixel-7".
func Label(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), ".")
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			if dash && b.Len() > 0 {
				b.WriteByte('-')
			}
			dash = false
			b.WriteRune(r)
		} else {
			dash = true
		}
	}
	return b.String()
}

// Base is what a name is made of when it comes from a reported host name: its label without the
// self-named prefix (a device admitted by an authority reports the name it has at home, which may
// carry it), "device" if nothing is left.
func Base(reported string) string {
	l := Label(reported)
	for strings.HasPrefix(l, SelfPrefix) {
		l = l[len(SelfPrefix):]
	}
	if l == "" {
		return fallback
	}
	return l
}

// Candidate is the n-th name to try for a device named prefix+base: the name itself for n = 0,
// then with "-1", "-2", ... The base is shortened so that the whole stays within MaxLen.
func Candidate(prefix, base string, n int) string {
	suffix := ""
	if n > 0 {
		suffix = "-" + strconv.Itoa(n)
	}
	if room := MaxLen - len(prefix) - len(suffix); len(base) > room {
		base = strings.TrimRight(base[:max(room, 0)], "-")
	}
	return prefix + base + suffix
}

// Free returns the first candidate name for prefix+base that taken does not report as used.
func Free(prefix, base string, taken func(string) (bool, error)) (string, error) {
	for n := 0; ; n++ {
		name := Candidate(prefix, base, n)
		used, err := taken(name)
		if err != nil || !used {
			return name, err
		}
	}
}

// Check tells why name cannot be given by an administrator, or returns nil.
func Check(name string) error {
	switch {
	case name == "":
		return errors.New("a name is required")
	case len(name) > MaxLen:
		return fmt.Errorf("%q is longer than %d characters", name, MaxLen)
	case strings.HasPrefix(name, SelfPrefix):
		return fmt.Errorf("names starting with %q are for devices named after their host name", SelfPrefix)
	case Label(name) != name:
		return fmt.Errorf("%q: use lowercase letters, digits and single dashes between them", name)
	}
	return nil
}

// FromReported is the name an administrator confirms for a device: the host name it reported,
// without the self-named prefix.
func FromReported(reported string) string { return Candidate("", Base(reported), 0) }

// Reported keeps a reported host name for display: printable ASCII only (anything else becomes
// '?'), at most 64 characters.
func Reported(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= maxReported {
			break
		}
		if r >= 0x20 && r < 0x7f {
			b.WriteRune(r)
		} else {
			b.WriteByte('?')
		}
	}
	return strings.TrimSpace(b.String())
}
