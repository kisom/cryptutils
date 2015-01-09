package auth

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/conformal/yubikey"
)

/*
   The following parameters come from the following test YubiKey
   configuration:

--- START test.csv ---
LOGGING START,1/3/15 10:48 PM
Yubico OTP,1/3/15 10:48 PM,1,brknecvrdjcr,f365a983aa27,971ab1c6b0400448c685e650f895195a,,,0,0,0,0,0,0,0,0,0,0
--- END test.csv ---

*/
const testYubiKey = "971ab1c6b0400448c685e650f895195a"
const testInitialYKOTP = "brknecvrdjcrbvldbdffbvjuigjhjhugfcvudrndjufl"

var testYubiOTPs = []string{
	"brknecvrdjcrkgekkikibruncdieijlhcchhjhrftvlh",
	"brknecvrdjcrbcvhgkrclenutgtctllfnhulileuhljg",
	"brknecvrdjcridlnbrvlnkjnrnvnrtnrrnkunlkjhfdb",
	"brknecvrdjcrtugntfdigvuteevtfgubhbggbfbkvvcd",
	"brknecvrdjcrinunglgrrricebletiitvccvuhljiiud",
	"brknecvrdjcrvgehdtrcctgrejeechjhdcbbvujedfec",
	"brknecvrdjcrngkcilrgnivcvrtjugvurfbuikjldgnb",
	"brknecvrdjcrcrdlkuincktkklhftrcrhjfvhjhifhcj",
	"brknecvrdjcrrbbvtdfrgkrhjgvvlldehidfhidvitlb",
}

// This is the authenticator built from the example and a test
// user token.
var yubiAuth *Authenticator
var yubiToken *yubikey.Token

// TestBuildUserToken builds the test user token from an OTP.
func TestBuildUserToken(t *testing.T) {
	key, err := hex.DecodeString(testYubiKey)
	if err != nil {
		t.Fatalf("%v", err)
	}
	tmpKey := yubikey.NewKey(key)

	_, otp, err := yubikey.ParseOTPString(testInitialYKOTP)
	if err != nil {
		t.Fatalf("%v", err)
	}

	yubiToken, err = otp.Parse(tmpKey)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

// TestNewYubiKey validates creating a new YubiKey authenticator from
// a key and initial OTP.
func TestNewYubiKey(t *testing.T) {
	key, err := hex.DecodeString(testYubiKey)
	if err != nil {
		t.Fatalf("%v", err)
	}

	yubiAuth, err = NewYubiKey(key, testInitialYKOTP)
	if err != nil {
		t.Fatalf("%v", err)
	}

	_, err = NewYubiKey(key[1:], testInitialYKOTP)
	if err == nil {
		t.Fatal("auth: expect NewYubiKey to fail with bad key")
	}

	_, err = NewYubiKey(key, testInitialYKOTP[:1])
	if err == nil {
		t.Fatal("auth: expect NewYubiKey to fail with bad OTP")
	}
}

// TestParseYubiConfig validates the parsing and export of YubiKey
// configurations.
func TestParseYubiConfig(t *testing.T) {
	config, err := ParseYubiKeyConfig(yubiAuth.Secret)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !bytes.Equal(config.Bytes(), yubiAuth.Secret) {
		t.Fatalf("auth: expected '%x', have '%x'", config.Bytes(), yubiAuth.Secret)
	}

	for i := 0; i < len(yubiAuth.Secret)-1; i++ {
		if _, err = ParseYubiKeyConfig(yubiAuth.Secret[:i]); err == nil {
			t.Fatal("auth: expect failure parsing YubiKeyConfig with bad packed config")
		}
	}

	buf := make([]byte, len(yubiAuth.Secret))
	copy(buf, yubiAuth.Secret)
	buf[4] = yubikey.KeySize - 1
	if _, err = ParseYubiKeyConfig(buf); err == nil {
		t.Fatal("auth: expect failure parsing YubiKeyConfig with bad packed config")
	}
}

// TestInvalidAuthenticator tests the failure of the validator with
// an invalid authenticator.
func TestInvalidAuthenticator(t *testing.T) {
	if _, err := ValidateYubiKey(nil, testInitialYKOTP); err == nil {
		t.Fatal("auth: expect failure with invalid authenticator")
	}

	auth := &Authenticator{
		Type: "TOTP",
	}

	if _, err := ValidateYubiKey(auth, testInitialYKOTP); err == nil {
		t.Fatal("auth: expect failure with invalid authenticator")
	}
}

// TestInvalidAuth tests validation failure with the original OTP.
func TestInvalidAuth(t *testing.T) {
	if _, err := ValidateYubiKey(yubiAuth, testInitialYKOTP); err == nil {
		t.Fatal("auth: expect failure with re-used OTP")
	}
}

// TestInvalidYKConfig tests validation failure with bad YubiKey config.
func TestInvalidYKConfig(t *testing.T) {
	auth := &Authenticator{
		Type: yubiAuth.Type,
		Last: yubiAuth.Last,
	}

	if _, err := ValidateYubiKey(auth, "testOTP"); err == nil {
		t.Fatal("auth: expect failure with invalid YubiKeyConfig")
	}
}

// TestInvalidYKOTP tests validation failure with bad OTP string.
func TestInvalidYKOTP(t *testing.T) {
	if _, err := ValidateYubiKey(yubiAuth, "testOTP"); err == nil {
		t.Fatal("auth: expect failure with invalid OTP string")
	}
}

// TestWrongYKPublic tests validation failure with bad YubiKey public
// identifier.
func TestWrongYKPublic(t *testing.T) {
	auth := &Authenticator{
		Type: yubiAuth.Type,
		Last: "",
	}

	config, err := ParseYubiKeyConfig(yubiAuth.Secret)
	if err != nil {
		t.Fatalf("%v", err)
	}

	config.Public = []byte("AAAA")
	auth.Secret = config.Bytes()

	if _, err := ValidateYubiKey(auth, testInitialYKOTP); err == nil {
		t.Fatal("auth: expect failure with bad public identifier")
	}
}

// TestWrongYKKey tests validation failure with wrong key.
func TestWrongYKKey(t *testing.T) {
	auth := &Authenticator{
		Type: yubiAuth.Type,
		Last: "",
	}

	config, err := ParseYubiKeyConfig(yubiAuth.Secret)
	if err != nil {
		t.Fatalf("%v", err)
	}

	config.Key[0]++
	auth.Secret = config.Bytes()
	if _, err := ValidateYubiKey(auth, testInitialYKOTP); err == nil {
		t.Fatal("auth: expect failure with bad public identifier")
	}
}

// TestValidYKOTP tests validation with a valid yubikey token.
func TestValidYKOTP(t *testing.T) {
	key, err := hex.DecodeString(testYubiKey)
	if err != nil {
		t.Fatalf("%v", err)
	}

	yubiAuth, err = NewYubiKey(key, testInitialYKOTP)
	if err != nil {
		t.Fatalf("%v", err)
	}

	for i := range testYubiOTPs {
		_, err = ValidateYubiKey(yubiAuth, testYubiOTPs[i])
		if err != nil {
			t.Fatalf("%v", err)
		}
	}
}

func TestYKNoCounterStepback(t *testing.T) {
	_, err := ValidateYubiKey(yubiAuth, testInitialYKOTP)
	if err == nil {
		t.Fatalf("auth: expect failure when an OTP is reused")
	}

	for i := range testYubiOTPs {
		_, err = ValidateYubiKey(yubiAuth, testYubiOTPs[i])
		if err == nil {
			t.Fatalf("auth: expect failure when an OTP is reused")
		}
	}
}
