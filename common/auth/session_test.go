package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/kisom/cryptutils/common/public"
)

var (
	peerPrivate *public.PrivateKey
	peer        []byte
	sessionPub  []byte
	sessionAuth *Authenticator
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
