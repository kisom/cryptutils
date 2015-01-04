package sync

import (
	"encoding/base64"
	"errors"

	"github.com/kisom/cryptutils/common/auth"
	"github.com/kisom/cryptutils/common/public"
)

// A Registration is the message type used for requesting a new user be
// added to the system.
type Registration struct {
	Invite             string `json:"invite"`
	Login              string `json:"login"`
	Email              string `json:"email"`
	AuthenticationType string `json:"auth_type"`
	AuthenticationData map[string]string
	Link
}

// RegistrationIsValid returns true if the registration is valid. If the
// registration is invalid, the error will contain message regarding
// what is wrong with the registration. The requireEmail parameter will
// enforce the need for a non-empty email.
func RegistrationIsValid(reg *Registration, requireEmail bool) (bool, error) {
	if reg.Login == "" {
		return false, errors.New("login name is required")
	}

	if reg.Email == "" && requireEmail {
		return false, errors.New("email address is required")
	}

	if reg.Link.Label == "" {
		return false, errors.New("a valid label for this machine is required")
	}

	_, err := public.UnmarshalPublic(reg.Link.Public)
	if err != nil {
		return false, errors.New("a valid public key is required")
	}

	err = validateAuthenticator(reg)
	if err != nil {
		return false, err
	}

	return true, nil
}

func validateAuthenticator(reg *Registration) error {
	switch reg.AuthenticationType {
	case auth.TypeYubiKey:
		if v := reg.AuthenticationData["key"]; v == "" {
			return errors.New("yubikey authenticator requires an initial key")
		}

		if v := reg.AuthenticationData["otp"]; v == "" {
			return errors.New("yubikey authenticator requires an initial OTP")
		}
		return nil
	case auth.TypeTOTP:
		return nil
	default:
		return errors.New("unknown authentication type")
	}
}

// Register attempts to create a new user. If the user has requested
// a TOTP authenticator, the server must send the user their TOTP
// details after this function returns.
func Register(reg *Registration) *User {
	var authenticator *auth.Authenticator

	switch reg.AuthenticationType {
	case auth.TypeYubiKey:
		keyString := reg.AuthenticationData["key"]
		initialOTP := reg.AuthenticationData["otp"]

		if keyString == "" {
			return nil
		}

		if initialOTP == "" {
			return nil
		}

		key, err := base64.StdEncoding.DecodeString(keyString)
		if err != nil {
			return nil
		}

		authenticator, err = auth.NewYubiKey(key, initialOTP)
		if err != nil {
			return nil
		}
	case auth.TypeTOTP:
		var err error
		authenticator, err = auth.NewGoogleTOTP()
		if err != nil {
			return nil
		}
	default:
		return nil
	}

	user := &User{
		Login:         reg.Login,
		Email:         reg.Email,
		Authenticator: authenticator,
	}
	user.PublicKeys = make(map[string][]byte)
	user.PublicKeys[reg.Link.Label] = reg.Link.Public
	user.Blobs = make(map[string][]byte)
	return user
}

// RegistrationResult contains the user details sent back to the user.
type RegistrationResult struct {
	// AuthSecret contains the authentication secret to send back to
	// the user; for example, the TOTP key.
	AuthSecret string `json:"auth_secret"`

	// AuthData contains any additional authentication data, such as
	// a QR code or parameter information.
	AuthData []byte `json:"auth_data"`

	// After registration, the user will have a new session started
	// to get at least one machine linked and a store uploaded.
	SessionPublic []byte `json:"session_public"`

	// Next contains the next session nonce to HMAC.
	Next []byte `json:"next"`
}
