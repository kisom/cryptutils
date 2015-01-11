package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/kisom/cryptutils/common/public"
	"github.com/kisom/cryptutils/common/util"
)

var (
	peerPrivate *public.PrivateKey
	peer        []byte
	sessionPub  []byte
	sessionAuth *Authenticator
	testSession *Session
)

func testCreateOTP(t *testing.T) string {
	if sessionAuth == nil {
		t.Fatal("auth: session not established")
	}

	last, err := hex.DecodeString(sessionAuth.Last)
	if err != nil {
		t.Fatalf("%v", err)
	}

	sessionPublic, err := public.UnmarshalPublic(sessionPub)
	if err != nil {
		t.Fatalf("%v", err)
	}

	shared := public.KeyExchange(peerPrivate, sessionPublic)

	h := hmac.New(sha256.New, shared)
	h.Write(last)
	last = append(last, h.Sum(nil)...)
	return hex.EncodeToString(last)
}

// TestSessionSetup validates creating a new session and successful
// validation of an OTP.
func TestSessionSetup(t *testing.T) {
	var err error

	peerPrivate, err = public.GenerateKey()
	if err != nil {
		t.Fatalf("%v", err)
	}

	peer, err = public.MarshalPublic(peerPrivate.PublicKey)
	if err != nil {
		t.Fatalf("%v", err)
	}

	sessionAuth, sessionPub, err = NewSession(peer)
	if err != nil {
		t.Fatalf("%v", err)
	}

	newOTP := testCreateOTP(t)

	shouldUpdate, err := ValidateSession(sessionAuth, newOTP)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !shouldUpdate {
		t.Fatal("auth: ValidateSession should signal that an update is required")
	}
}

// TestSessionValidationTypeErrors validates the sanity checks on the
// ValidateSession function.
func TestSessionValidationTypeErrors(t *testing.T) {
	if _, err := ValidateSession(nil, ""); err == nil {
		t.Fatal("auth: expect session validation failure with nil session")
	}

	if _, err := ValidateSession(yubiAuth, testInitialYKOTP); err == nil {
		t.Fatal("auth: expect session validation failure with wrong authenticator type")
	}

	if _, err := ValidateSession(sessionAuth, "ZZYZX"); err == nil {
		t.Fatal("auth: expect session validation failure with non-hex OTP")
	}

	if _, err := ValidateSession(sessionAuth, "deadbeef"); err == nil {
		t.Fatal("auth: expect session validation failure with short OTP")
	}
}

var priv []byte

// TestSessionKeying validates setting up a session.
func TestSessionKeying(t *testing.T) {
	var err error

	priv, err = public.MarshalPrivate(peerPrivate)
	if err != nil {
		t.Fatalf("%v", err)
	}

	sessionAuth, sessionPub, err = NewSession(peer)
	if err != nil {
		t.Fatalf("%v", err)
	}

	session, ok := KeySession(priv, sessionPub)
	if !ok {
		t.Fatal("auth: failed to key session")
	}

	next, err := hex.DecodeString(sessionAuth.Last)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if _, err := ValidateSession(sessionAuth, session.OTP(next)); err != nil {
		t.Fatalf("%v", err)
	}

	testSession = session
}

// TestSessionKeyingFailures validates the error handling in the session key exchange.
func TestSessionKeyingFailures(t *testing.T) {
	bad := make([]byte, 16)
	_, ok := KeySession(bad, sessionPub)
	if ok {
		t.Fatal("auth: expect session key exchange failure with bad private key")
	}

	_, ok = KeySession(priv, bad)
	if ok {
		t.Fatal("auth: expect session key exchange failure with bad public key")
	}
}

// TestSessionZero validates session zeroing.
func TestSessionZero(t *testing.T) {
	s, ok := KeySession(priv, sessionPub)
	if !ok {
		t.Fatalf("auth: failed to key session")
	}

	s.Zero()
	for i := 0; i < len(s.shared); i++ {
		if s.shared[i] != 0 {
			t.Fatalf("auth: failed to zeroise session")
		}
	}
}

// TestNewSessionFailures validates some of the failure modes for NewSession.
func TestNewSessionFailures(t *testing.T) {
	r := util.PRNG()
	b := &bytes.Buffer{}
	util.SetPRNG(b)

	if _, _, err := NewSession(peer); err == nil {
		util.SetPRNG(r)
		t.Fatal("auth: expected new session failure with PRNG failure")
	}

	tmp := make([]byte, sessionLength)
	b.Write(tmp)

	if _, _, err := NewSession(peer); err == nil {
		util.SetPRNG(r)
		t.Fatal("auth: expected new session failure with PRNG failure")
	}
	util.SetPRNG(r)

	tmp = make([]byte, 16)
	if _, _, err := NewSession(tmp); err == nil {
		t.Fatal("auth: expected new session failure with invalid public key")
	}

}

// TestSessionValidationFailures validates some of the failure modes
// for validating sessions.
func TestSessionValidationFailures(t *testing.T) {
	next, err := hex.DecodeString(sessionAuth.Last)
	if err != nil {
		t.Fatalf("%v", err)
	}

	otp := testSession.OTP(next)

	last := sessionAuth.Last
	sessionAuth.Last = "Z" + otp[1:]
	if _, err = ValidateSession(sessionAuth, otp); err == nil {
		t.Fatalf("auth: expect session validation failure with invalid last value")
	}
	sessionAuth.Last = last

	var tmpOTP string
	if otp[0] == 'a' {
		tmpOTP = "b" + otp[1:]
	} else {
		tmpOTP = "a" + otp[1:]
	}

	if _, err = ValidateSession(sessionAuth, tmpOTP); err == nil {
		t.Fatalf("auth: expect session validation failure with invalid last value")
	}

	offset := 3*sessionLength + 1
	if otp[sessionLength+1] == 'a' {
		tmpOTP = otp[:offset] + "b" + otp[offset+1:]
	} else {
		tmpOTP = otp[:offset] + "a" + otp[offset+1:]
	}

	if _, err = ValidateSession(sessionAuth, tmpOTP); err == nil {
		t.Fatal("auth: expect session validation failure with invalid HMAC")
	}

	b := &bytes.Buffer{}
	util.SetPRNG(b)
	_, err = ValidateSession(sessionAuth, otp)
	util.SetPRNG(rand.Reader)
	if err == nil {
		t.Fatal("auth: expect session validation failure with PRNG failure")
	}
}
