// Package secret contains utilities for encrypting and decrypting
// data with secret keys; it is aimed primarily at password-based
// encryption. Encryption keys are typically derived from Scrypt
// (using 32768, 8, and 4 as the parameters) to obtain a key suitable
// for use with NaCl's secretbox (XSalsa20 and Poly1305).
package secret

import (
	"errors"
	"io/ioutil"

	"code.google.com/p/go.crypto/nacl/secretbox"
	"code.google.com/p/go.crypto/scrypt"
	"github.com/kisom/cryptutils/common/util"
)

// KeySize contains the size (in bytes) of a NaCl secretbox key.
const (
	KeySize   = 32
	SaltSize  = 32
	nonceSize = 24
)

// GenerateKey returns a randomly generated secretbox key. Typically,
// you should use DeriveKey to get a key from a passphrase
// instead. Returns nil on failure.
func GenerateKey() *[KeySize]byte {
	var key [KeySize]byte
	rb := util.RandBytes(KeySize)
	if rb == nil || len(rb) != KeySize {
		return nil
	}
	defer util.Zero(rb)

	copy(key[:], rb)
	return &key
}

var scryptParams = struct {
	N int
	r int
	p int
}{32768, 8, 4}

// DeriveKey applies Scrypt with very strong parameters to generate an
// encryption key from a passphrase and salt.
func DeriveKey(passphrase []byte, salt []byte) *[KeySize]byte {
	rawKey, err := scrypt.Key(passphrase, salt, scryptParams.N, scryptParams.r, scryptParams.p, KeySize)
	if err != nil {
		return nil
	}

	var key [KeySize]byte
	copy(key[:], rawKey)
	util.Zero(rawKey)
	return &key
}

// Encrypt generates a random nonce and encrypts the input using
// NaCl's secretbox package. The nonce is prepended to the ciphertext.
func Encrypt(key *[KeySize]byte, in []byte) ([]byte, bool) {
	var out = make([]byte, nonceSize)
	nonce := util.NewNonce()
	if nonce == nil {
		return nil, false
	}

	copy(out, nonce[:])
	out = secretbox.Seal(out, in, nonce, key)
	return out, true
}

// Decrypt extracts the nonce from the ciphertext, and attempts to
// decrypt with NaCl's secretbox.
func Decrypt(key *[KeySize]byte, in []byte) ([]byte, bool) {
	if len(in) < nonceSize {
		return nil, false
	}
	var nonce [nonceSize]byte
	copy(nonce[:], in)
	return secretbox.Open(nil, in[nonceSize:], &nonce, key)
}

// DecryptFile recovers a secured blob from a file, returning a byte
// slice for parsing by the caller.
func DecryptFile(filename string, passphrase []byte) (data []byte, err error) {
	data, err = ioutil.ReadFile(filename)
	if err != nil {
		return
	}

	salt := data[:SaltSize]
	data = data[SaltSize:]

	key := DeriveKey(passphrase, salt)
	data, ok := Decrypt(key, data)
	if !ok {
		err = errors.New("password: failed to decrypt password store")
	}
	return
}

// EncryptFile securely stores the encoded blob under the filename.
func EncryptFile(filename string, passphrase, encoded []byte) (err error) {
	salt := util.RandBytes(SaltSize)
	if salt == nil {
		err = errors.New("password: failed to generate new salt")
		return
	}
	defer util.Zero(encoded)

	key := DeriveKey(passphrase, salt)
	data, ok := Encrypt(key, encoded)
	if !ok {
		data = nil
		err = errors.New("password: failed to encrypt data")
		return
	}

	data = append(salt, data...)
	err = ioutil.WriteFile(filename, data, 0600)
	return
}
