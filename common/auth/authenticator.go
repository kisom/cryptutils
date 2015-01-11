package auth

import (
	"errors"

	"github.com/kisom/cryptutils/common/util"
)

var (
	// ErrUnsupportedHash is returned when the user tries to use a
	// hash algorithm that isn't supported by the authentication scheme.
	ErrUnsupportedHash = errors.New("auth: unsupported hash algorithm")
)

// An Authenticator stores a one-time password key for a user. The type is used to select the appropriate verification algorithm.
type Authenticator struct {
	Type   string `json:"type"`
	Label  string `json:"label"`
	Last   string `json:"last"`
	Secret []byte `json:"secret"`
}

// Zero wipes the Authenticator's secret.
func (a *Authenticator) Zero() {
	util.Zero(a.Secret)
}

var (
	// ErrInvalidAuthenticator indicates that the authenticator
	// passed to Validate is not a valid authenticator. Ensure
	// that it is a type supported by the server, and that it is
	// an actual value.
	ErrInvalidAuthenticator = errors.New("sync: invalid authenticator")

	// ErrInvalidOTP indicates that an OTP is invalid for the
	// Authenticator.
	ErrValidationFail = errors.New("sync: invalid OTP")
)

// Validators contains a mapping of authenticator types to validation
// functions.
var Validators = map[string]func(*Authenticator, string) (bool, error){
	TypeYubiKey:  ValidateYubiKey,
	TypeTOTP:     ValidateTOTP,
	TypeSession:  ValidateSession,
	TypePassword: ValidatePassword,
}

// Validate takes an Authenticator and an OTP, and checks whether
// the OTP is valid. It returns a boolean value indicating whether
// the Authenticator needs to be validated (i.e., if it contains
// a counter, and therefore the counter value needs to be stored).
func Validate(auth *Authenticator, password string) (needsUpdate bool, err error) {
	if auth == nil {
		return false, ErrInvalidAuthenticator
	}

	validator, ok := Validators[auth.Type]
	if !ok {
		return false, ErrInvalidAuthenticator
	}

	return validator(auth, password)
}
