// Package update checks ento releases before anything installs them: a release's manifest (its
// version, when it was released and the SHA-256 of every file) must carry valid signatures of both
// release keys pinned in this binary, the SSH key (Ed25519, ssh-keygen -Y, namespace
// ento-manifest) and the P-256 key (OpenSSL), and must be newer than the running version. Keys
// fetched with a release are never used: whoever controls what the website serves cannot hand out
// their own keys or an older, validly signed release (security review M13).
package update

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// The release keys, the same as ento/release-signing.pub and release-signing-p256.pem (a test
// keeps them equal).
var (
	//go:embed keys/release-signing.pub
	sshKey []byte
	//go:embed keys/release-signing-p256.pem
	p256Key []byte
)

// DefaultReleases is where ento releases are published (releases/<version>/manifest.json and the
// files it lists); what is fetched from there is trusted only by its signatures.
const DefaultReleases = "https://entowire.com/releases"

// Namespace is the SSH signature namespace of manifests: a signature made for a release file
// (ento-release) or a script (ento-file) is not a manifest's.
const Namespace = "ento-manifest"

// Manifest describes one release. Files are keyed by platform: linux-amd64, darwin-arm64,
// windows-amd64 (the zip), android (the APK).
type Manifest struct {
	Version  string          `json:"version"`
	Released time.Time       `json:"released"`
	Files    map[string]File `json:"files"`
}

// File is one file of a release, relative to the release's directory (releases/<version>/).
type File struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

var (
	versionRe = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)$`)
	nameRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
)

// Verify parses a manifest after checking both signatures over its exact bytes with the pinned keys.
func Verify(manifest, sshSig, p256Sig []byte) (*Manifest, error) {
	if err := verifySSH(manifest, sshSig); err != nil {
		return nil, fmt.Errorf("manifest: SSH signature: %w", err)
	}
	if err := verifyP256(manifest, p256Sig); err != nil {
		return nil, fmt.Errorf("manifest: P-256 signature: %w", err)
	}
	var m Manifest
	d := json.NewDecoder(bytes.NewReader(manifest))
	d.DisallowUnknownFields()
	if err := d.Decode(&m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if !versionRe.MatchString(m.Version) {
		return nil, fmt.Errorf("manifest: version %q", m.Version)
	}
	if m.Released.IsZero() || len(m.Files) == 0 {
		return nil, errors.New("manifest: no release time or no files")
	}
	for p, f := range m.Files {
		if !nameRe.MatchString(f.Name) || len(f.SHA256) != 64 || f.Size <= 0 {
			return nil, fmt.Errorf("manifest: file %s: %+v", p, f)
		}
		if _, err := hex.DecodeString(f.SHA256); err != nil {
			return nil, fmt.Errorf("manifest: file %s: sha256: %w", p, err)
		}
	}
	return &m, nil
}

// Newer tells whether version a is newer than b. Versions are X.Y.Z, or what scripts/build.sh calls
// a build after a tag (X.Y.Z-N-gHASH, -dirty), which is newer than X.Y.Z and older than the next
// release; anything else ("dev-...") is older than every version.
func Newer(a, b string) bool {
	return compare(rank(a), rank(b)) > 0
}

var describeRe = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)(-.+)?$`)

// rank is [x, y, z, after] with after 1 for a build after the tag; nil when unparsable.
func rank(v string) []int {
	m := describeRe.FindStringSubmatch(v)
	if m == nil {
		return nil
	}
	out := make([]int, 4)
	for i := 0; i < 3; i++ {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return nil
		}
		out[i] = n
	}
	if m[4] != "" {
		out[3] = 1
	}
	return out
}

func compare(a, b []int) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return -1
	case b == nil:
		return 1
	}
	for i := range a {
		if a[i] != b[i] {
			if a[i] > b[i] {
				return 1
			}
			return -1
		}
	}
	return 0
}

// Check reads a file's bytes from r (at most the manifest's size) and compares them with the manifest.
func (f File) Check(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, f.Size+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) != f.Size {
		return nil, fmt.Errorf("%s: %d bytes, the manifest says %d", f.Name, len(b), f.Size)
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != strings.ToLower(f.SHA256) {
		return nil, fmt.Errorf("%s: SHA-256 differs from the manifest", f.Name)
	}
	return b, nil
}

// --- signatures ---------------------------------------------------------------------------------

func verifyP256(msg, sig []byte) error {
	block, _ := pem.Decode(p256Key)
	if block == nil {
		return errors.New("no pinned key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	k, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("the pinned key is not ECDSA")
	}
	sum := sha256.Sum256(msg)
	if !ecdsa.VerifyASN1(k, sum[:], sig) {
		return errors.New("does not verify")
	}
	return nil
}

// verifySSH checks an armored SSH signature (PROTOCOL.sshsig) made with the pinned key.
func verifySSH(msg, armored []byte) error {
	pinned, _, _, _, err := ssh.ParseAuthorizedKey(sshKey)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(armored)
	if block == nil || block.Type != "SSH SIGNATURE" {
		return errors.New("not an SSH signature")
	}
	r := block.Bytes
	if !bytes.HasPrefix(r, []byte("SSHSIG")) {
		return errors.New("no SSHSIG magic")
	}
	r = r[6:]
	if len(r) < 4 || binary.BigEndian.Uint32(r) != 1 {
		return errors.New("unknown version")
	}
	r = r[4:]
	var fields [5][]byte
	for i := range fields {
		if fields[i], r, err = sshString(r); err != nil {
			return err
		}
	}
	pubBlob, ns, reserved, hashAlg, sigBlob := fields[0], fields[1], fields[2], fields[3], fields[4]
	if !bytes.Equal(pubBlob, pinned.Marshal()) {
		return errors.New("made with another key")
	}
	if string(ns) != Namespace {
		return fmt.Errorf("namespace %q, not %s", ns, Namespace)
	}
	var h []byte
	switch string(hashAlg) {
	case "sha512":
		s := sha512.Sum512(msg)
		h = s[:]
	case "sha256":
		s := sha256.Sum256(msg)
		h = s[:]
	default:
		return fmt.Errorf("hash %q", hashAlg)
	}
	var signed bytes.Buffer
	signed.WriteString("SSHSIG")
	for _, f := range [][]byte{ns, reserved, hashAlg, h} {
		writeString(&signed, f)
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(sigBlob, &sig); err != nil {
		return err
	}
	return pinned.Verify(signed.Bytes(), &sig)
}

func sshString(b []byte) ([]byte, []byte, error) {
	if len(b) < 4 {
		return nil, nil, errors.New("truncated")
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(len(b)-4) < uint64(n) {
		return nil, nil, errors.New("truncated")
	}
	return b[4 : 4+n], b[4+n:], nil
}

func writeString(w *bytes.Buffer, b []byte) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	w.Write(n[:])
	w.Write(b)
}

// Fingerprints of the pinned keys, for `ento update --check` and the runbook.
func Fingerprints() (string, string) {
	k, _, _, _, err := ssh.ParseAuthorizedKey(sshKey)
	fp := "?"
	if err == nil {
		fp = ssh.FingerprintSHA256(k)
	}
	block, _ := pem.Decode(p256Key)
	p := "?"
	if block != nil {
		s := sha256.Sum256(block.Bytes)
		p = "SHA256:" + base64.RawStdEncoding.EncodeToString(s[:])
	}
	return fp, p
}

// UseKeysForTest replaces the pinned keys with throwaway ones, for tests of packages that serve or
// install releases; it returns what puts the release keys back. Never called outside tests.
func UseKeysForTest(sshPub, p256PEM []byte) (restore func()) {
	oldSSH, oldP := sshKey, p256Key
	sshKey, p256Key = sshPub, p256PEM
	return func() { sshKey, p256Key = oldSSH, oldP }
}
