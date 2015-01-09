package auth

// This file contains support for TOTPs. Currently, only Google standard
// TOTP tokens (with a limited six digit, SHA-1, and 30-second step) are
// supported, because mobile clients are limited to this.

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"time"

	"code.google.com/p/rsc/qr"

	"github.com/kisom/cryptutils/common/tlv"
	"github.com/kisom/cryptutils/common/util"
)

// TypeTOTP is a TOTP token.
const TypeTOTP = "TOTP"

// TOTPProvider contains the value that should be used to fill in the
// Provider field of the TOTPConfig.
var TOTPProvider string

// TOTPConfig contains the details required to use a TOTP token.
type TOTPConfig struct {
	// Key is used as the HMAC key for generating OTPs. This should
	// be the same length as the hash algorithm's output size, but
	// not everyone does that.
	Key []byte

	// Start is the start time for the TOTP. Google defaults this to
	// the start of the epoch.
	Start uint64

	// Step is the time step between OTPs. Users will not be able
	// to authenticate inside this time period after the first
	// successful authentication to prevent replay attacks. Google
	// defaults to 30 seconds for this.
	Step uint64

	// Size is the number of digits to generate. Google defaults
	// to six.
	Size int

	// Algo contains the hash algorithm used in the HMAC. Google
	// defaults to SHA1.
	Algo crypto.Hash

	// Provider is an optional string that identifies the
	// authentication provider. This is used in generating QR codes.
	Provider string
}

// 6 because Google.
const totpDefaultDigits = 6

// ExportKey returns the base32-encoded key for the TOTP to hand off to
// the user.
func (config *TOTPConfig) ExportKey() string {
	return base32.StdEncoding.EncodeToString(config.Key)
}

// generateURL creates an OATH URL for the TOTP config.
func (config *TOTPConfig) generateURL(label string) string {
	secret := config.ExportKey()
	u := url.URL{}
	v := url.Values{}
	u.Scheme = "otpauth"
	u.Host = "totp"
	u.Path = label
	v.Add("secret", secret)
	if config.Size != totpDefaultDigits {
		v.Add("digits", fmt.Sprintf("%d", config.Size))
	}

	// If other hash algorithms become supported in Google
	// Authenticator, enable these.
	// switch {
	// case config.Algo == crypto.SHA256:
	// 	v.Add("algorithm", "SHA256")
	// case config.Algo == crypto.SHA512:
	// 	v.Add("algorithm", "SHA512")
	// }

	if config.Provider != "" {
		v.Add("provider", config.Provider)
	}

	u.RawQuery = v.Encode()
	return u.String()
}

// ExportQR returns a QR code as a PNG for the TOTP token.
func (config *TOTPConfig) ExportQR(label string) ([]byte, error) {
	u := config.generateURL(label)
	code, err := qr.Encode(u, qr.Q)
	if err != nil {
		return nil, err
	}
	return code.PNG(), nil
}

// Bytes exports the TOTP configuration as a byte slice.
func (config *TOTPConfig) Bytes() ([]byte, error) {
	enc := &tlv.Encoder{}
	enc.Encode(config.Key)
	enc.Encode(config.Start)
	enc.Encode(config.Step)
	enc.Encode(int32(config.Size))
	enc.Encode(int8(config.Algo))
	enc.Encode([]byte(config.Provider))
	return enc.Bytes(), nil
}

var errInvalidTOTPConfig = errors.New("auth: invalid TOTP configuration")

// ParseTOTPConfig parses a serialised TOTP configuration.
func ParseTOTPConfig(in []byte) (*TOTPConfig, error) {
	var size int32
	var algo int8
	var provider []byte

	var config = new(TOTPConfig)
	dec := tlv.NewDecoder(in)
	err := dec.Decode(&config.Key)
	if err != nil {
		return nil, errInvalidTOTPConfig
	}

	err = dec.Decode(&config.Start)
	if err != nil {
		return nil, errInvalidTOTPConfig
	}

	err = dec.Decode(&config.Step)
	if err != nil {
		return nil, errInvalidTOTPConfig
	}

	err = dec.Decode(&size)
	if err != nil {
		return nil, errInvalidTOTPConfig
	}
	config.Size = int(size)

	err = dec.Decode(&algo)
	if err != nil {
		return nil, errInvalidTOTPConfig
	}
	config.Algo = crypto.Hash(algo)

	err = dec.Decode(&provider)
	if err != nil {
		return nil, errInvalidTOTPConfig
	}
	config.Provider = string(provider)
	return config, nil
}

// UserTOTP contains the data a user needs to import the TOTP token in
// their TOTP app of choice.
type UserTOTP struct {
	Secret string // The TOTP secret, base32-encoded.
	QR     []byte // A QR code that may be used to import the token.
}

// ExportUserTOTP returns a UserTOTP value suitable for handing off
// to a user. If a label is provided, a QR code will be returned.
func ExportUserTOTP(auth *Authenticator, label string) (*UserTOTP, error) {
	if auth == nil || auth.Type != TypeTOTP {
		return nil, ErrInvalidAuthenticator
	}

	config, err := ParseTOTPConfig(auth.Secret)
	if err != nil {
		return nil, ErrInvalidAuthenticator
	}

	totp := &UserTOTP{
		Secret: config.ExportKey(),
	}

	if label != "" {
		totp.QR, err = config.ExportQR(label)
		if err != nil {
			return nil, err
		}
	}

	return totp, nil
}

var oathDigits = []int64{
	0:  1,
	1:  10,
	2:  100,
	3:  1000,
	4:  10000,
	5:  100000,
	6:  1000000,
	7:  10000000,
	8:  100000000,
	9:  1000000000,
	10: 10000000000,
}

func (config *TOTPConfig) generateOTP() (string, error) {
	counter := uint64(time.Now().Unix())
	return config.generateOTPAt(counter)
}

func (config *TOTPConfig) generateOTPAt(counter uint64) (string, error) {
	counter -= config.Start
	counter /= config.Step

	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], counter)

	var mod int64 = 1
	mod = oathDigits[config.Size]

	var hash func() hash.Hash
	switch config.Algo {
	case crypto.SHA1:
		hash = sha1.New
	default:
		return "", ErrUnsupportedHash
	}
	h := hmac.New(hash, config.Key)
	h.Write(ctr[:])
	dt := truncate(h.Sum(nil)) % mod
	fmtStr := fmt.Sprintf("%%0%dd", config.Size)
	return fmt.Sprintf(fmtStr, dt), nil
}

// truncate contains the DT function from the RFC; this is used to
// deterministically select a sequence of 4 bytes from the HMAC
// counter hash.
func truncate(in []byte) int64 {
	offset := int(in[len(in)-1] & 0xF)
	p := in[offset : offset+4]
	var binCode int32
	binCode = int32((p[0] & 0x7f)) << 24
	binCode += int32((p[1] & 0xff)) << 16
	binCode += int32((p[2] & 0xff)) << 8
	binCode += int32((p[3] & 0xff))
	return int64(binCode) & 0x7FFFFFFF
}

// NewGoogleTOTP generates a new Google-authenticator standard TOTP
// token.
func NewGoogleTOTP() (*Authenticator, error) {
	key := util.RandBytes(sha1.Size)
	if key == nil {
		return nil, errors.New("auth: PRNG failure")
	}

	return ImportGoogleTOTP(key)
}

// ImportGoogleTOTP creates a new Google-authenticator standard TOTP
// from an existing key.
func ImportGoogleTOTP(key []byte) (*Authenticator, error) {
	totp := &TOTPConfig{
		Key:      key,
		Start:    0,
		Step:     30,
		Size:     6,
		Algo:     crypto.SHA1,
		Provider: TOTPProvider,
	}

	// This won't fail, as the only failure mode is an invalid
	// hash. SHA1 is hardcoded for Google Authenticator tokens,
	// and is supported.
	initial, _ := totp.generateOTP()
	secret, _ := totp.Bytes()

	auth := &Authenticator{
		Type:   TypeTOTP,
		Last:   initial,
		Secret: secret,
	}

	return auth, nil

}

// ValidateTOTP takes an Authenticator that is presumed to be a
// TOTP authenticator and attempts to validate the given OTP
// using it. The TOTP authenticator will always need to be updated when
// successful to account for an updated last OTP.
func ValidateTOTP(auth *Authenticator, otp string) (bool, error) {
	if (auth == nil) || (auth.Type != TypeTOTP) {
		return false, ErrInvalidAuthenticator
	}

	if auth.Last == otp {
		return false, ErrInvalidOTP
	}

	config, err := ParseTOTPConfig(auth.Secret)
	if err != nil {
		return false, err
	}

	// Allow for some skew; this will step back one step if
	// verification fails to account for a possible delay in
	// processing the OTP.
	now := uint64(time.Now().Unix())
	times := []uint64{now, now - config.Step}

	var verified bool
	for i := range times {
		otpString, err := config.generateOTPAt(times[i])
		if err != nil {
			continue
		}

		if otpString == otp {
			auth.Last = otp
			verified = true
		}
	}

	if !verified {
		return false, ErrInvalidOTP
	}

	return true, nil
}
