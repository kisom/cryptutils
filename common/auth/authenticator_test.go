package auth

import (
	"encoding/hex"
	"testing"
)

// Test validating a YubiKey OTP.
func TestValidationYubiKey(t *testing.T) {
	key, err := hex.DecodeString(testYubiKey)
	if err != nil {
		t.Fatalf("%v", err)
	}

	auth, err := NewYubiKey(key, testInitialYKOTP)
	if err != nil {
		t.Fatalf("%v", err)
	}

	_, err = Validate(nil, "ABCD")
	if err == nil {
		t.Fatal("auth: expect failure validating invalid authenticator")
	}

	auth.Last = ""
	_, err = Validate(auth, testInitialYKOTP)
	if err != nil {
		t.Fatalf("%v", err)
	}

	auth.Type = "Not a valid type"
	_, err = Validate(auth, "ABCD")
	if err == nil {
		t.Fatal("auth: expect failure with invalid Authenticator type")
	}
}

// Test validating a TOTP.
func TestValidationTOTP(t *testing.T) {
	auth, _, err := NewGoogleTOTP("")
	if err != nil {
		t.Fatalf("%v", err)
	}

	otp := auth.Last
	auth.Last = ""
	if _, err := Validate(auth, otp); err != nil {
		t.Fatalf("%v", err)
	}
}

// Test the zeroising code.
func TestAuthenticatorZero(t *testing.T) {
	auth, err := NewPasswordAuth("password", 10)
	if err != nil {
		t.Fatalf("%v", err)
	}

	auth.Zero()
	for i := 0; i < len(auth.Secret); i++ {
		if auth.Secret[i] != 0 {
			t.Fatal("auth: failed to wipe authenticator")
		}
	}
}
