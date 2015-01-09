package auth

import (
	"bytes"
	"crypto"
	"encoding/base32"
	"log"
	"testing"
	"time"

	"github.com/kisom/cryptutils/common/util"
)

const testTOTPKey = "2TXLWDBCBQU6TLCFH4V2YPFVBIV7EFG5"

var totpAuth *Authenticator

const testInvalidDigest = crypto.SHA256

// TestNewTOTP validates generating a new, random token.
func TestNewTOTP(t *testing.T) {
	TOTPProvider = "auth test provider"

	var err error
	_, err = NewGoogleTOTP()
	if err != nil {
		t.Fatalf("%v", err)
	}
}

// TestImportTOTP validates importing a TOTP token.
func TestImportTOTP(t *testing.T) {
	var err error

	key, err := base32.StdEncoding.DecodeString(testTOTPKey)
	if err != nil {
		t.Fatalf("%v", err)
	}

	at := uint64(time.Now().Unix())

	totpAuth, err = ImportGoogleTOTP(key)
	if err != nil {
		t.Fatalf("%v", err)
	}

	config, err := ParseTOTPConfig(totpAuth.Secret)
	if err != nil {
		t.Fatalf("%v", err)
	}

	otpString, err := config.generateOTPAt(at)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if totpAuth.Last != otpString {
		t.Fatalf("auth: expected OTP of %s, have %s",
			totpAuth.Last, otpString)
	}
}

// TestExportTOTPQR ensures that a standard TOTP token can be exported
// to a QR code.
func TestExportTOTPQR(t *testing.T) {
	config, err := ParseTOTPConfig(totpAuth.Secret)
	if err != nil {
		t.Fatalf("%v", err)
	}

	_, err = config.ExportQR("auth test")
	if err != nil {
		t.Fatalf("%v", err)
	}
}

// TestTOTPValidation verifies that OTPs can be successfully validated
// with the TOTP authenticator.
func TestTOTPValidation(t *testing.T) {
	config, err := ParseTOTPConfig(totpAuth.Secret)
	if err != nil {
		t.Fatalf("%v", err)
	}

	config.Step = 1
	auth := &Authenticator{
		Type: TypeTOTP,
		Last: "",
	}
	auth.Secret, err = config.Bytes()
	if err != nil {
		t.Fatalf("%v", err)
	}

	first := time.Now().Unix()
	otp, err := config.generateOTP()
	if err != nil {
		t.Fatalf("%v", err)
	}

	shouldUpdate, err := ValidateTOTP(auth, otp)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !shouldUpdate {
		t.Fatal("auth: ValidateTOTP should signal that an update is required")
	}

	// Reset last TOTP to run skew check.
	auth.Last = ""

	for {
		now := time.Now().Unix()
		if now == first+1 {
			break
		}

		if now > first {
			log.Println("processing took too long, skipping skew test")
			log.Printf("first=%d, now=%d", first, now)
			t.Skip()
		}

		<-time.After(100 * time.Millisecond)
	}

	_, err = ValidateTOTP(auth, otp)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Reset last TOTP to run skew check.
	auth.Last = ""

	// Ensure that two steps out of sync authentication fails.
	for {
		now := time.Now().Unix()
		if now == first+2 {
			break
		}

		if now > (first + 2) {
			log.Println("processing took too long, skipping skew test")
			log.Printf("first=%d, now=%d", first, now)
			t.Skip()
		}

		<-time.After(100 * time.Millisecond)
	}

	_, err = ValidateTOTP(auth, otp)
	if err == nil {
		t.Fatal("auth: TOTP should fail when more than one step out of sync")
	}
}

// TestExportUserTOTP validates exporting the user TOTP data.
func TestExportUserTOTP(t *testing.T) {
	_, err := ExportUserTOTP(yubiAuth, "")
	if err == nil {
		t.Fatal("auth: should fail to export TOTP data from YubiKey authenticator")
	}

	user, err := ExportUserTOTP(totpAuth, "")
	if err != nil {
		t.Fatalf("%v", err)
	}

	if user.QR != nil {
		t.Fatal("auth: no QR code should be exported when no label is provided.")
	}

	user, err = ExportUserTOTP(totpAuth, "test auth")
	if err != nil {
		t.Fatalf("%v", err)
	}

	if user.QR == nil {
		t.Fatalf("auth: expected a QR code in the user details")
	}

	oldSecret := totpAuth.Secret[:]
	config, err := ParseTOTPConfig(totpAuth.Secret)
	if err != nil {
		t.Fatalf("%v", err)
	}
	config.Size = 8
	totpAuth.Secret, err = config.Bytes()
	if err != nil {
		t.Fatalf("%v", err)
	}

	_, err = ExportUserTOTP(totpAuth, "test auth")
	if err != nil {
		t.Fatalf("%v", err)
	}

	totpAuth.Secret = oldSecret

	auth := &Authenticator{
		Type:   TypeTOTP,
		Secret: []byte("A"),
	}

	_, err = ExportUserTOTP(auth, "test auth")
	if err == nil {
		t.Fatal("auth: should fail to export TOTP data with invalid secret")
	}
}

// TestTOTPInvalidHash validates failure with an invalid hash algorithm.
func TestTOTPInvalidHash(t *testing.T) {
	config, err := ParseTOTPConfig(totpAuth.Secret)
	if err != nil {
		t.Fatalf("%v", err)
	}
	config.Algo = testInvalidDigest

	_, err = config.generateOTP()
	if err == nil {
		t.Fatal("auth: generating OTP should fail with unsupported digest algorithm")
	}
}

// TestTOTPPRNGFailure validates failures when the PRNG fails.
func TestTOTPPRNGFailure(t *testing.T) {
	oldPRNG := util.PRNG()
	util.SetPRNG(&bytes.Buffer{})

	_, err := NewGoogleTOTP()
	if err == nil {
		t.Fatal("auth: expect TOTP generation failure in the face of a PRNG failure")
	}

	util.SetPRNG(oldPRNG)
}

// TestTOTPSanityChecks validates the Validate sanity checks.
func TestTOTPSanityChecks(t *testing.T) {
	if _, err := ValidateTOTP(nil, "123456"); err == nil {
		t.Fatal("auth: validation should fail with invalid authenticator")
	}

	if _, err := ValidateTOTP(yubiAuth, testInitialYKOTP); err == nil {
		t.Fatal("auth: validation should fail with invalid authenticator")
	}

	auth, err := NewGoogleTOTP()
	if err != nil {
		t.Fatalf("%v", err)
	}

	if _, err := ValidateTOTP(auth, auth.Last); err == nil {
		t.Fatal("auth: should fail to validate reused TOTP")
	}

	last := auth.Last
	auth.Secret = auth.Secret[1:]
	auth.Last = ""

	if _, err = ValidateTOTP(auth, last); err == nil {
		t.Fatal("auth: should fail to validate with invalid TOTP")
	}
}

// TestTOTPQRFailure validates that the QR encoding will fail if the
// label is too large.
func TestTOTPQRFailure(t *testing.T) {
	label := make([]byte, 8192)
	for i := 0; i < 8192; i++ {
		label[i] = 'A'
	}

	_, err := ExportUserTOTP(totpAuth, string(label))
	if err == nil {
		t.Fatalf("auth: expected failure to encode QR image with label=%d bytes", len(label))
	}
}

// TestTOTPParseFailures validates that the parser fails with invalid data.
func TestTOTPParseFailures(t *testing.T) {
	buf := make([]byte, len(totpAuth.Secret))
	copy(buf, totpAuth.Secret)

	for i := 0; i < len(buf)-1; i++ {
		_, err := ParseTOTPConfig(buf[:i])
		if err == nil {
			t.Fatal("auth: expect failure to parse TOTP config with invalid packed config")
		}
	}
}

// TestTOTPInvalidHashValidation validates failure of validation
// with an unsupported hash algo.
func TestTOTPInvalidHashValidation(t *testing.T) {
	auth, err := NewGoogleTOTP()
	if err != nil {
		t.Fatalf("%v", err)
	}
	last := auth.Last
	auth.Last = ""

	config, err := ParseTOTPConfig(auth.Secret)
	if err != nil {
		t.Fatalf("%v", err)
	}

	config.Algo = crypto.SHA256
	auth.Secret, err = config.Bytes()
	if err != nil {
		t.Fatalf("%v", err)
	}

	_, err = ValidateTOTP(auth, last)
	if err == nil {
		t.Fatal("auth: expect TOTP validation failure with invalid hash algo")
	}
}
