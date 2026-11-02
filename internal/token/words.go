package token

// Enrollment by words: an administrator reads a device's owner a domain and five words, nothing
// else. The domain's DNS TXT record (_ento.<domain>) says how to reach the network: its overlay
// range and its control nodes (key, public endpoint, overlay address). The words stretched with
// Argon2id, salted with the network's identity (its range and its control nodes' keys), are the
// token secret; the temporary key, preshared key and enrollment address derive from that secret.
// The control node that made the words stored only what a token stores (the derived public key,
// preshared key and address), never the words, so the device rebuilds the very token a control
// node would have printed.

import (
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// The EFF large wordlist (Electronic Frontier Foundation, CC BY 3.0 US), unchanged:
// https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt, SHA-256
// addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e (checked by the tests).
//
//go:embed eff_large_wordlist.txt
var effLargeWordlist string

const (
	// WordCount is how many words stand for a token: 5 of 7772 is 64.6 bits.
	WordCount = 5

	// RecordName is the label of the network record under a domain.
	RecordName = "_ento"

	recordVersion = "ento1"
	wordsLabel    = "ento-words-v1" // Argon2id parameters and salt layout below; a change is a new label

	argonTime    = 8
	argonMemory  = 256 * 1024 // KiB
	argonThreads = 4

	labelAddress = "enrollment-address"
)

var words, wordSet = loadWords()

// loadWords reads the wordlist, leaving out the four words with a hyphen (drop-down, felt-tip,
// t-shirt, yo-yo), so that typed words can be separated by anything that is not a letter.
func loadWords() ([]string, map[string]bool) {
	var list []string
	set := map[string]bool{}
	for _, line := range strings.Split(effLargeWordlist, "\n") {
		_, w, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if !ok || strings.ContainsRune(w, '-') {
			continue
		}
		list = append(list, w)
		set[w] = true
	}
	return list, set
}

// NewWords returns WordCount words chosen uniformly at random.
func NewWords() ([]string, error) {
	out := make([]string, WordCount)
	n := big.NewInt(int64(len(words)))
	for i := range out {
		k, err := rand.Int(rand.Reader, n)
		if err != nil {
			return nil, err
		}
		out[i] = words[k.Int64()]
	}
	return out, nil
}

// ParseWords reads words as a person types them: any case, separated by anything that is not a
// letter. Each must be in the list, and there must be WordCount of them.
func ParseWords(s string) ([]string, error) {
	f := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return !unicode.IsLetter(r) })
	if len(f) != WordCount {
		return nil, fmt.Errorf("expected %d words, got %d", WordCount, len(f))
	}
	for i, w := range f {
		if !wordSet[w] {
			return nil, fmt.Errorf("word %d (%q) is not one of the words ento uses: check its spelling", i+1, w)
		}
	}
	return f, nil
}

// Record is a network record: what a device needs to reach a network's control plane. Its text
// form is the TXT record at _ento.<domain>:
//
//	ento1 net=100.64.0.0/16 c=<public key>,<endpoint>,<overlay address> c=...
type Record struct {
	Network  netip.Prefix
	Controls []Control
}

// String returns the record's text, as published.
func (r Record) String() string {
	var b strings.Builder
	b.WriteString(recordVersion + " net=" + r.Network.String())
	for _, c := range r.Controls {
		fmt.Fprintf(&b, " c=%s,%s,%s", c.PublicKey, c.Endpoint, c.Address)
	}
	return b.String()
}

// ParseRecord reads a record's text.
func ParseRecord(s string) (Record, error) {
	var r Record
	f := strings.Fields(s)
	if len(f) == 0 || f[0] != recordVersion {
		return r, errors.New("not an ento network record (it starts with " + recordVersion + ")")
	}
	for _, field := range f[1:] {
		k, v, _ := strings.Cut(field, "=")
		switch k {
		case "net":
			p, err := netip.ParsePrefix(v)
			if err != nil || !p.Addr().Is4() || p.Bits() != 16 || p.Masked() != p {
				return r, fmt.Errorf("network record: net=%q is not an IPv4 /16", v)
			}
			r.Network = p
		case "c":
			parts := strings.Split(v, ",")
			if len(parts) != 3 {
				return r, fmt.Errorf("network record: c=%q is not key,endpoint,address", v)
			}
			key, err := wgtypes.ParseKey(parts[0])
			if err != nil {
				return r, fmt.Errorf("network record: control node key: %v", err)
			}
			if _, port, err := net.SplitHostPort(parts[1]); err != nil || port == "" {
				return r, fmt.Errorf("network record: control node endpoint %q is not host:port", parts[1])
			} else if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
				return r, fmt.Errorf("network record: control node endpoint %q has no valid port", parts[1])
			}
			addr, err := netip.ParseAddr(parts[2])
			if err != nil || !addr.Is4() {
				return r, fmt.Errorf("network record: control node address %q is not IPv4", parts[2])
			}
			r.Controls = append(r.Controls, Control{PublicKey: key, Endpoint: parts[1], Address: addr})
		default:
			// Fields a later version adds are left to it.
		}
	}
	if !r.Network.IsValid() {
		return r, errors.New("network record: no net=")
	}
	if len(r.Controls) == 0 || len(r.Controls) > 32 {
		return r, errors.New("network record: between 1 and 32 control nodes (c=)")
	}
	for _, c := range r.Controls {
		if !r.Network.Contains(c.Address) {
			return r, fmt.Errorf("network record: control node address %s is outside %s", c.Address, r.Network)
		}
	}
	return r, nil
}

// identity is what the words are salted with: the record's version label, the network's range
// and its control nodes' keys (sorted). Endpoints and overlay addresses are left out: a record
// that names others only fails to reach the network.
func (r Record) identity() []byte {
	keys := make([]string, 0, len(r.Controls))
	for _, c := range r.Controls {
		keys = append(keys, base64.StdEncoding.EncodeToString(c.PublicKey[:]))
	}
	slices.Sort(keys)
	h := sha256.New()
	h.Write([]byte(wordsLabel + "\n" + r.Network.String() + "\n" + strings.Join(keys, "\n")))
	return h.Sum(nil)
}

// Fingerprint names the network's identity, for a person to compare with what the administrator
// or a runbook says (16 hex digits in four groups).
func (r Record) Fingerprint() string {
	h := hex.EncodeToString(r.identity()[:8])
	return h[0:4] + "-" + h[4:8] + "-" + h[8:12] + "-" + h[12:16]
}

// WordsSecret stretches words into a token secret for the network the record describes (Argon2id,
// 256 MiB, 8 passes: about a second on a laptop).
func WordsSecret(w []string, r Record) [32]byte {
	var s [32]byte
	copy(s[:], argon2.IDKey([]byte(strings.Join(w, " ")), r.identity(), argonTime, argonMemory, argonThreads, 32))
	return s
}

// EnrollmentAddress derives the enrollment address a secret stands for, in network's enrollment
// range (x.y.255.1 to x.y.255.254).
func EnrollmentAddress(secret [32]byte, network netip.Prefix) (netip.Addr, error) {
	var b [2]byte
	if _, err := io.ReadFull(hkdf.New(sha256.New, secret[:], []byte(labelSalt), []byte(labelAddress)), b[:]); err != nil {
		return netip.Addr{}, err
	}
	a := network.Addr().As4()
	a[2], a[3] = 255, byte(binary.BigEndian.Uint16(b[:])%254+1)
	return netip.AddrFrom4(a), nil
}

// Token returns the token words stand for in the record's network.
func (r Record) Token(w []string) (Token, error) {
	secret := WordsSecret(w, r)
	addr, err := EnrollmentAddress(secret, r.Network)
	if err != nil {
		return Token{}, err
	}
	return Token{Secret: secret, TempAddress: addr, Controls: slices.Clone(r.Controls)}, nil
}

// FindRecord picks the network record among a domain's TXT records: exactly one must start with
// the record version.
func FindRecord(txts []string) (string, error) {
	var found []string
	for _, t := range txts {
		if strings.HasPrefix(t, recordVersion+" ") {
			found = append(found, t)
		}
	}
	switch len(found) {
	case 0:
		return "", errors.New("no ento network record")
	case 1:
		return found[0], nil
	}
	return "", fmt.Errorf("%d ento network records: a domain has one", len(found))
}
