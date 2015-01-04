package auth

import "errors"

var (
	// ErrUnsupportedHash is returned when the user tries to use a
	// hash algorithm that isn't supported by the authentication scheme.
	ErrUnsupportedHash = errors.New("auth: unsupported hash algorithm")
)

// An Authenticator stores a one-time password key for a user. The type is used to select the appropriate verification algorithm.
type Authenticator struct {
	Type   string `json:"type"`
	Last   string `json:"last"`
	Secret []byte `json:"secret"`
}

var (
	// ErrInvalidAuthenticator indicates that the authenticator
	// passed to Validate is not a valid authenticator. Ensure
	// that it is a type supported by the server, and that it is
	// an actual value.
	ErrInvalidAuthenticator = errors.New("sync: invalid authenticator")

	// ErrInvalidOTP indicates that an OTP is invalid for the
	// Authenticator.
	ErrInvalidOTP = errors.New("sync: invalid OTP")
)

// Validate takes an Authenticator and an OTP, and checks whether
// the OTP is valid. It returns a boolean value indicating whether
// the Authenticator needs to be validated (i.e., if it contains
// a counter, and therefore the counter value needs to be stored).
func Validate(auth *Authenticator, otp string) (needsUpdate bool, err error) {
	if auth == nil {
		return false, ErrInvalidAuthenticator
	}

	switch auth.Type {
	case TypeYubiKey:
		return ValidateYubiKey(auth, otp)
	case TypeTOTP:
		return ValidateTOTP(auth, otp)
	case TypeSession:
		return ValidateSession(auth, otp)
	default:
		return false, ErrInvalidAuthenticator
	}
}
