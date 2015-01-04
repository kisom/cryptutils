package auth

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/conformal/yubikey"
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
	var buf = &bytes.Buffer{}
	buf.Write(config.Key)

	var counter [4]byte
	binary.BigEndian.PutUint32(counter[:], config.Counter)
	buf.Write(counter[:])
	buf.Write(config.Public)
	return buf.Bytes()
}

// ParseYubiKeyConfig attempts to parse a YubiKeyConfig from a
// byte slice.
func ParseYubiKeyConfig(in []byte) (*YubiKeyConfig, error) {
	if len(in) < (yubikey.KeySize + 2) {
		return nil, errors.New("sync: invalid packed YubiKey config")
	}

	config := &YubiKeyConfig{
		Key: in[:yubikey.KeySize],
	}

	config.Counter = (uint32(in[yubikey.KeySize])) << 24
	config.Counter += (uint32(in[yubikey.KeySize+1])) << 16
	config.Counter += (uint32(in[yubikey.KeySize+2])) << 8
	config.Counter += (uint32(in[yubikey.KeySize+3]))

	config.Public = make([]byte, len(in)-(yubikey.KeySize+4))
	copy(config.Public, in[yubikey.KeySize+4:])

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
		return false, ErrInvalidOTP
	}

	config, err := ParseYubiKeyConfig(auth.Secret)
	if err != nil {
		return false, ErrInvalidAuthenticator
	}

	tmpKey := yubikey.NewKey(config.Key)
	defer util.Zero(tmpKey[:])

	pub, ykOTP, err := yubikey.ParseOTPString(otp)
	if err != nil {
		return false, ErrInvalidOTP
	}

	if !bytes.Equal(pub, config.Public) {
		return false, ErrInvalidOTP
	}

	userToken, err := ykOTP.Parse(tmpKey)
	if err != nil {
		return false, ErrInvalidOTP
	}

	if getTokenCounter(userToken) < config.Counter {
		return false, ErrInvalidOTP
	}

	config.Counter = getTokenCounter(userToken)
	auth.Last = otp
	auth.Secret = config.Bytes()

	return true, nil
}
