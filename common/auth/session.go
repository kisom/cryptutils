package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/kisom/cryptutils/common/public"
	"github.com/kisom/cryptutils/common/util"
)

// This file contains a session authenticator.

// A Session is meant to be used by an authenticatee for computing the
// checksums.
type Session struct {
	shared []byte
}

// KeySession sets up a new session from the user's private key and the
// server's ephemeral public key.
func KeySession(priv, pub []byte) (*Session, bool) {
	privKey, err := public.UnmarshalPrivate(priv)
	if err != nil {
		return nil, false
	}
	defer privKey.Zero()

	pubKey, err := public.UnmarshalPublic(pub)
	if err != nil {
		return nil, false
	}

	shared := public.KeyExchange(privKey, pubKey)
	return &Session{shared: shared}, true
}

// OTP computes the next OTP for the session.
func (s *Session) OTP(next []byte) string {
	h := hmac.New(sha256.New, s.shared)
	h.Write(next)
	return hex.EncodeToString(append(next, h.Sum(nil)...))
}

// Zero wipes the key. The session is no longer valid, and should be
// discarded.
func (s *Session) Zero() {
	util.Zero(s.shared)
}

// TypeSession is a new session.
const TypeSession = "session"

// Sessions have 32 byte random values.
const sessionLength = 32

// NewSession sets up a new session. The Last field should be sent
// to the client. The returned public key should be sent to the
// user for generating a shared MAC key. The authenticator should ensure
// some mechanism for expiring sessions exists.
func NewSession(pub []byte) (*Authenticator, []byte, error) {
	next := util.RandBytes(sessionLength)
	if next == nil {
		return nil, nil, errors.New("auth: PRNG failure")
	}

	ephemeral, err := public.GenerateKey()
	if err != nil || !ephemeral.Valid() {
		return nil, nil, errors.New("auth: failed to set up session key")
	}

	// Validated that the key was correct previously.
	ephemeralPublic, _ := public.MarshalPublic(ephemeral.PublicKey)

	peer, err := public.UnmarshalPublic(pub)
	if err != nil {
		return nil, nil, err
	}

	shared := public.KeyExchange(ephemeral, peer)

	return &Authenticator{
		Type:   TypeSession,
		Last:   hex.EncodeToString(next),
		Secret: shared,
	}, ephemeralPublic, nil
}

// ValidateSession ensures that the OTP provided contains the next
// value and the appropriate HMAC for the session.
func ValidateSession(auth *Authenticator, otp string) (bool, error) {
	if (auth == nil) || (auth.Type != TypeSession) {
		return false, ErrInvalidAuthenticator
	}

	otpBytes, err := hex.DecodeString(otp)
	if err != nil {
		return false, err
	}

	if len(otpBytes) != 2*sessionLength {
		return false, ErrValidationFail
	}

	lastBytes, err := hex.DecodeString(auth.Last)
	if err != nil {
		return false, err
	}

	h := hmac.New(sha256.New, auth.Secret)
	h.Write(lastBytes)
	expected := h.Sum(nil)

	if !bytes.Equal(otpBytes[:sessionLength], lastBytes) {
		return false, ErrValidationFail
	}

	if !hmac.Equal(otpBytes[sessionLength:], expected) {
		return false, ErrValidationFail
	}

	next := util.RandBytes(sessionLength)
	if next == nil {
		return false, errors.New("auth: PRNG failure")
	}

	auth.Last = hex.EncodeToString(next)
	return true, nil
}
