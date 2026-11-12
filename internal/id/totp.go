package id

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"rsc.io/qr"

	"entowire.com/ento/internal/store"
)

// Authenticator apps (RFC 6238): HMAC-SHA1, 6 digits, 30 seconds, as every app reads them. A code
// is taken one step early or late (clocks drift) and never twice. The secret is sealed with a key
// derived from the signing key, so the database alone gives no codes.
const (
	totpPeriod = 30
	totpDigits = 6
)

func totpCode(secret []byte, step int64) string {
	m := hmac.New(sha1.New, secret)
	binary.Write(m, binary.BigEndian, step)
	h := m.Sum(nil)
	off := h[len(h)-1] & 0x0f
	v := binary.BigEndian.Uint32(h[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1_000_000)
}

// checkTOTP returns the step the code is valid for, newer than last, or 0.
func checkTOTP(secret []byte, code string, last int64, now time.Time) int64 {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != totpDigits {
		return 0
	}
	cur := now.Unix() / totpPeriod
	for _, step := range []int64{cur, cur - 1, cur + 1} {
		if step > last && subtle.ConstantTimeCompare([]byte(totpCode(secret, step)), []byte(code)) == 1 {
			return step
		}
	}
	return 0
}

func (p *Provider) totpAEAD() cipher.AEAD {
	m := hmac.New(sha256.New, p.cfg.Key.D.FillBytes(make([]byte, 32)))
	m.Write([]byte("ento-id-totp-v1"))
	b, _ := aes.NewCipher(m.Sum(nil))
	g, _ := cipher.NewGCM(b)
	return g
}

// sealTOTP seals an app's secret for a person (bound to them: it opens for no one else).
func (p *Provider) sealTOTP(person string, secret []byte) []byte {
	a := p.totpAEAD()
	nonce := randomBytes(a.NonceSize())
	return a.Seal(nonce, nonce, secret, []byte(person))
}

func (p *Provider) openTOTP(person string, sealed []byte) ([]byte, error) {
	a := p.totpAEAD()
	if len(sealed) < a.NonceSize() {
		return nil, errors.New("sealed app secret too short")
	}
	return a.Open(nil, sealed[:a.NonceSize()], sealed[a.NonceSize():], []byte(person))
}

// totpOffer is a new app secret as the page shows it: the address apps read from the QR code, the
// QR code itself and the secret to type.
type totpOffer struct {
	URI    string `json:"uri"`
	QR     string `json:"qr"` // a data: URI of a PNG
	Secret string `json:"secret"`
}

func (p *Provider) offerTOTP(x store.IDPerson, secret []byte) totpOffer {
	b32 := strings.TrimRight(base32.StdEncoding.EncodeToString(secret), "=")
	label := url.PathEscape(p.cfg.Title + ":" + x.Email)
	uri := fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
		label, b32, url.QueryEscape(p.cfg.Title), totpDigits, totpPeriod)
	o := totpOffer{URI: uri, Secret: b32}
	if c, err := qr.Encode(uri, qr.M); err == nil {
		o.QR = "data:image/png;base64," + base64.StdEncoding.EncodeToString(c.PNG())
	}
	return o
}
