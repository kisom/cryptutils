package auth

import "code.google.com/p/go.crypto/bcrypt"

const defaultBcryptCost = 14

// TypePassword is a bcrypted password hash.
const TypePassword = "password"

// NewPasswordAuth creates a bcrypt hash authenticator for the password
// using the given cost, which must be between 8 and 31. If the cost
// is an invalid value, a default cost will be used.
func NewPasswordAuth(password string, cost int) (*Authenticator, error) {
	if cost == 0 || cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		cost = defaultBcryptCost
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return nil, err
	}

	return &Authenticator{
		Type:   TypePassword,
		Secret: hash,
	}, nil
}

// ValidatePassword takes an Authenticator that is presumed to be a
// bcrypted password hash and a password, and ensures that it matches.
func ValidatePassword(auth *Authenticator, password string) (bool, error) {
	if (auth == nil) || (auth.Type != TypePassword) {
		return false, ErrInvalidAuthenticator
	}

	err := bcrypt.CompareHashAndPassword(auth.Secret, []byte(password))
	if err != nil {
		err = ErrInvalidOTP
	}
	return false, err
}
