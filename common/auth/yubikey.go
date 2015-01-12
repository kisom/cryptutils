package auth

import (
	"bytes"
	"errors"

	"github.com/conformal/yubikey"
	"github.com/kisom/cryptutils/common/tlv"
	"github.com/kisom/cryptutils/common/util"
)

// This file contains support for YubiKey OTP authenticators.

func getTokenCounter(token *yubikey.Token) uint32 {
	var counter uint32
	counter = uint32(token.Use << 16)
	counter += uint32(token.Counter())

	return counter
}

// TypeYubiKey is a YubiOTP token.
const TypeYubiKey = "yubikey"

// YubiKeyConfig contains the token and key information for a YubiKey.
type YubiKeyConfig struct {
	Key     []byte
	Counter uint32
	Public  []byte
}

// Bytes returns a byte slice representation of the YubiKeyConfig.
func (config *YubiKeyConfig) Bytes() []byte {
	enc := &tlv.Encoder{}
	enc.Encode(config.Key)
	enc.Encode(config.Counter)
	enc.Encode(config.Public)
	return enc.Bytes()
}

var errInvalidYKConfig = errors.New("auth: invalid packed YubiKey config")

// ParseYubiKeyConfig attempts to parse a YubiKeyConfig from a
// byte slice.
func ParseYubiKeyConfig(in []byte) (*YubiKeyConfig, error) {
	config := &YubiKeyConfig{}
	dec := tlv.NewDecoder(in)
	err := dec.Decode(&config.Key)
	if err != nil {
		return nil, errInvalidYKConfig
	} else if len(config.Key) != yubikey.KeySize {
		return nil, errInvalidYKConfig
	}

	err = dec.Decode(&config.Counter)
	if err != nil {
		return nil, errInvalidYKConfig
	}

	err = dec.Decode(&config.Public)
	if err != nil {
		return nil, errInvalidYKConfig
	}

	return config, nil
}

// NewYubiKey takes the key and initial OTP and returns an
// authenticator.
func NewYubiKey(key []byte, initialOTP string) (*Authenticator, error) {
	pub, otp, err := yubikey.ParseOTPString(initialOTP)
	if err != nil {
		return nil, err
	}

	tmpKey := yubikey.NewKey(key)
	token, err := otp.Parse(tmpKey)
	if err != nil {
		return nil, err
	}
	util.Zero(tmpKey[:])

	config := &YubiKeyConfig{
		Counter: getTokenCounter(token),
		Key:     key,
		Public:  pub,
	}
	defer util.Zero(config.Key[:])

	auth := &Authenticator{
		Type:   TypeYubiKey,
		Last:   initialOTP,
		Secret: config.Bytes(),
	}

	return auth, nil
}

// ValidateYubiKey takes an Authenticator that is presumed to be a
// YubiKey authenticator and attempts to validate the given OTP
// using it. The YubiKey authenticator will always need to be updated
// when successful to account for changes in the counter, and to
// update the last OTP.
func ValidateYubiKey(auth *Authenticator, otp string) (bool, error) {
	if (auth == nil) || (auth.Type != TypeYubiKey) {
		return false, ErrInvalidAuthenticator
	}

	if auth.Last == otp {
		return false, ErrValidationFail
	}

	config, err := ParseYubiKeyConfig(auth.Secret)
	if err != nil {
		return false, ErrInvalidAuthenticator
	}

	tmpKey := yubikey.NewKey(config.Key)
	defer util.Zero(tmpKey[:])

	pub, ykOTP, err := yubikey.ParseOTPString(otp)
	if err != nil {
		return false, ErrValidationFail
	}

	if !bytes.Equal(pub, config.Public) {
		return false, ErrValidationFail
	}

	userToken, err := ykOTP.Parse(tmpKey)
	if err != nil {
		return false, ErrValidationFail
	}

	if getTokenCounter(userToken) < config.Counter {
		return false, ErrValidationFail
	}

	config.Counter = getTokenCounter(userToken)
	auth.Last = otp
	auth.Secret = config.Bytes()

	return true, nil
}
