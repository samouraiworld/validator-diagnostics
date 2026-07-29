package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"time"

	"github.com/gnolang/gno/tm2/pkg/crypto"
)

// ErrInvalidSession is returned by SessionSigner.Verify for any
// malformed, tampered-with, or expired token. Deliberately
// undifferentiated (vs. separate "expired"/"bad signature" errors) so
// callers can't be tempted to treat an expired-but-correctly-signed
// token as partially trustworthy.
var ErrInvalidSession = errors.New("invalid or expired session token")

// SessionSigner issues and verifies short-lived, stateless tokens that
// bind a session to an operator address that has already completed the
// challenge-tx auth flow (see Verifier.VerifyChallenge). Deliberately
// not JWT: a custom fixed-layout HMAC token has a much smaller attack
// surface for this single, narrow use case (no algorithm negotiation,
// no header/claims parsing ambiguity).
//
// Being stateless (no server-side session store) is a trade-off: a
// token can't be revoked before it expires. Keep TTL short.
type SessionSigner struct {
	secret []byte
	ttl    time.Duration
}

// NewSessionSigner creates a signer. secret must be kept confidential
// server-side (e.g. loaded from an env var / secret manager) — anyone
// holding it can mint valid sessions for any operator address.
func NewSessionSigner(secret []byte, ttl time.Duration) *SessionSigner {
	return &SessionSigner{secret: secret, ttl: ttl}
}

const (
	expiryLen = 8 // unix seconds, big-endian
	macLen    = sha256.Size
)

// Issue mints a token binding operatorAddr, valid for the signer's TTL
// from now.
func (s *SessionSigner) Issue(operatorAddr crypto.Address) string {
	payload := make([]byte, crypto.AddressSize+expiryLen)
	copy(payload, operatorAddr.Bytes())
	binary.BigEndian.PutUint64(payload[crypto.AddressSize:], uint64(time.Now().Add(s.ttl).Unix()))

	mac := hmac.New(sha256.New, s.secret)
	mac.Write(payload)

	token := append(payload, mac.Sum(nil)...)
	return base64.RawURLEncoding.EncodeToString(token)
}

// Verify checks a token's signature and expiry, returning the bound
// operator address on success.
func (s *SessionSigner) Verify(token string) (crypto.Address, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return crypto.Address{}, ErrInvalidSession
	}
	if len(raw) != crypto.AddressSize+expiryLen+macLen {
		return crypto.Address{}, ErrInvalidSession
	}

	payload, gotMAC := raw[:crypto.AddressSize+expiryLen], raw[crypto.AddressSize+expiryLen:]

	mac := hmac.New(sha256.New, s.secret)
	mac.Write(payload)
	wantMAC := mac.Sum(nil)

	if !hmac.Equal(gotMAC, wantMAC) {
		return crypto.Address{}, ErrInvalidSession
	}

	expiry := int64(binary.BigEndian.Uint64(payload[crypto.AddressSize:]))
	if time.Now().Unix() > expiry {
		return crypto.Address{}, ErrInvalidSession
	}

	var addr crypto.Address
	copy(addr[:], payload[:crypto.AddressSize])

	return addr, nil
}
