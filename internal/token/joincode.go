package token

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// A join code is enrollment by words for a camera: what an enrollment QR code holds, so that a phone
// held up to an administrator's screen joins without typing. It carries the domain whose network
// record names the network, that record's fingerprint and the words:
//
//	ENTO1:EXAMPLE.COM:8A4D-0034-38BF-6588:ALPHA BRAVO CHARLIE DELTA ECHO
//
// in capitals, so that the QR code uses its alphanumeric mode and stays small. It is as secret as the
// words (single use, short-lived); the device still looks the record up in DNS, and refuses a record
// whose fingerprint is not the code's.

const joinPrefix = "ENTO1:"

// JoinCode is what an enrollment QR code says.
type JoinCode struct {
	Domain      string
	Fingerprint string
	Words       []string
}

var (
	joinDomain      = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	joinFingerprint = regexp.MustCompile(`^[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}$`)
)

// String returns the code's text, in capitals.
func (j JoinCode) String() string {
	return strings.ToUpper(joinPrefix + j.Domain + ":" + j.Fingerprint + ":" + strings.Join(j.Words, " "))
}

// NewJoinCode checks a domain, a fingerprint and words (as ParseWords reads them) and puts them
// together.
func NewJoinCode(domain, fingerprint, words string) (JoinCode, error) {
	return parseJoin(domain, fingerprint, words)
}

// ParseJoinCode reads a join code (any case).
func ParseJoinCode(s string) (JoinCode, error) {
	s = strings.TrimSpace(s)
	if len(s) > 512 || !strings.HasPrefix(strings.ToUpper(s), joinPrefix) {
		return JoinCode{}, errors.New("not an ento enrollment code")
	}
	parts := strings.SplitN(s[len(joinPrefix):], ":", 3)
	if len(parts) != 3 {
		return JoinCode{}, errors.New("enrollment code: expected domain, fingerprint and words")
	}
	return parseJoin(parts[0], parts[1], parts[2])
}

// JoinDomain checks the domain of a join code and returns it in lower case, without a final dot.
func JoinDomain(domain string) (string, error) {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if len(d) > 253 || !joinDomain.MatchString(d) {
		return "", fmt.Errorf("%q is not a domain", domain)
	}
	return d, nil
}

func parseJoin(domain, fingerprint, words string) (JoinCode, error) {
	d, err := JoinDomain(domain)
	if err != nil {
		return JoinCode{}, fmt.Errorf("enrollment code: %w", err)
	}
	fp := strings.ToLower(strings.TrimSpace(fingerprint))
	if !joinFingerprint.MatchString(fp) {
		return JoinCode{}, fmt.Errorf("enrollment code: %q is not a network fingerprint", fingerprint)
	}
	w, err := ParseWords(words)
	if err != nil {
		return JoinCode{}, fmt.Errorf("enrollment code: %w", err)
	}
	return JoinCode{Domain: d, Fingerprint: fp, Words: w}, nil
}
