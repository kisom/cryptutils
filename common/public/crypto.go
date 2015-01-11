// Package public contains utilities for public key encryption with
// Curve25519 and digital signatures with Ed25519.
package public

import (
	"bytes"
	"encoding/pem"
	"errors"
	"fmt"

	"code.google.com/p/go.crypto/nacl/box"
	"github.com/agl/ed25519"
	"github.com/kisom/cryptutils/common/secret"
	"github.com/kisom/cryptutils/common/tlv"
	"github.com/kisom/cryptutils/common/util"
)

const saltSize = 32

// These types are used in PEM-encoded keys.
const (
	PrivateType            = "CRYPTUTIL PRIVATE KEY"
	PublicType             = "CRYPTUTIL PUBLIC KEY"
	EncryptedType          = "CRYPTUTIL ENCRYPTED MESSAGE"
	SignatureType          = "CRYPTUTIL SIGNATURE"
	SignedAndEncryptedType = "CRYPTUTIL SIGNED AND ENCRYPTED MESSAGE"
)

// A PrivateKey contains both encryption and signing keys.
type PrivateKey struct {
	D *[32]byte // Decryption key (encryption private key).
	S *[64]byte // Signature key (signing private key).
	*PublicKey
}

// Valid runs checks to make sure the private key is valid.
func (priv *PrivateKey) Valid() bool {
	if priv == nil {
		return false
	} else if !priv.PublicKey.Valid() {
		return false
	} else if priv.D == nil {
		return false
	} else if priv.S == nil {
		return false
	}
	return true
}

// Zero clears out the private key. The public key components will
// remain intact.
func (priv *PrivateKey) Zero() {
	util.Zero(priv.D[:])
	util.Zero(priv.S[:])
	priv.D = nil
	priv.S = nil
}

// These errors are used to signal invalid public and private keys.
var (
	ErrCorruptPrivateKey = errors.New("public: private key is corrupt")
	ErrCorruptPublicKey  = errors.New("public: public key is corrupt")
)

// MarshalPrivate serialises a private key into a byte slice. If the
// key is invalid, a corrupt key error is returned.
func MarshalPrivate(priv *PrivateKey) ([]byte, error) {
	if !priv.Valid() {
		return nil, ErrCorruptPrivateKey
	}

	enc := tlv.NewFixedEncoder(160, 4)
	enc.Encode(priv.D[:])
	enc.Encode(priv.S[:])
	enc.Encode(priv.E[:])
	enc.Encode(priv.V[:])
	return enc.Bytes(), nil
}

// ExportPrivate PEM-encodes the locked private key. The private key is secured
// with the passphrase using LockKey.
func ExportPrivate(priv *PrivateKey, passphrase []byte) ([]byte, error) {
	locked, ok := LockKey(priv, passphrase)
	if !ok {
		return nil, ErrCorruptPrivateKey
	}

	block := pem.Block{
		Type: PrivateType,
		Headers: map[string]string{
			"Version": fmt.Sprintf("%s", util.VersionString()),
		},
		Bytes: locked,
	}
	return pem.EncodeToMemory(&block), nil
}

// ImportPrivate parses a PEM-encoded private key. UnlockKey is called
// on the contents of the PEM-encoded file.
func ImportPrivate(enc, passphrase []byte) (*PrivateKey, error) {
	block, _ := pem.Decode(enc)
	if block == nil {
		return nil, ErrCorruptPrivateKey
	}

	if block.Type != PrivateType {
		return nil, ErrCorruptPrivateKey
	}

	priv, ok := UnlockKey(block.Bytes, passphrase)
	if !ok {
		return nil, ErrCorruptPrivateKey
	}

	return priv, nil
}

const marshalLen = 160

// UnmarshalPrivate parses a byte slice into a private key.
func UnmarshalPrivate(in []byte) (*PrivateKey, error) {
	priv := PrivateKey{
		D: new([32]byte),
		S: new([64]byte),
		PublicKey: &PublicKey{
			E: new([32]byte),
			V: new([32]byte),
		},
	}

	var mkey struct {
		D []byte
		S []byte
		E []byte
		V []byte
	}

	dec := tlv.NewDecoder(in)
	err := dec.Decode(&mkey.D)
	if err != nil {
		return nil, err
	}
	err = dec.Decode(&mkey.S)
	if err != nil {
		return nil, err
	}
	err = dec.Decode(&mkey.E)
	if err != nil {
		return nil, err
	}
	err = dec.Decode(&mkey.V)
	if err != nil {
		return nil, err
	}

	copy(priv.D[:], mkey.D)
	copy(priv.S[:], mkey.S)
	copy(priv.E[:], mkey.E)
	copy(priv.V[:], mkey.V)

	util.Zero(mkey.D)
	util.Zero(mkey.S)
	util.Zero(mkey.E)
	util.Zero(mkey.V)
	return &priv, nil
}

// A PublicKey contains the public components of the key pair.
type PublicKey struct {
	E *[32]byte // Encryption key (encryption public key).
	V *[32]byte // Verification key (decryption public key).
}

// Valid ensures the public key is a valid public key.
func (pub *PublicKey) Valid() bool {
	if pub == nil {
		return false
	} else if pub.E == nil {
		return false
	} else if pub.V == nil {
		return false
	}
	return true
}

// MarshalPublic serialises a public key into a byte slice.
func MarshalPublic(pub *PublicKey) ([]byte, error) {
	if !pub.Valid() {
		return nil, ErrCorruptPublicKey
	}

	var buf = new(bytes.Buffer)
	buf.Write(pub.E[:])
	buf.Write(pub.V[:])
	return buf.Bytes(), nil
}

const pubKeyLen = 64

// UnmarshalPublic parses a byte slice into a public key.
func UnmarshalPublic(in []byte) (*PublicKey, error) {
	if len(in) != pubKeyLen {
		return nil, ErrCorruptPublicKey
	}

	var pub = PublicKey{
		E: new([32]byte),
		V: new([32]byte),
	}

	buf := bytes.NewBuffer(in)
	buf.Read(pub.E[:])
	buf.Read(pub.V[:])
	return &pub, nil
}

// GenerateKey creates a new set of encryption and signature keys
// using the operating system's random number generator.
func GenerateKey() (*PrivateKey, error) {
	var priv PrivateKey
	var err error
	prng := util.PRNG()

	priv.PublicKey = &PublicKey{}
	priv.E, priv.D, err = box.GenerateKey(prng)
	if err != nil {
		return nil, err
	}

	priv.V, priv.S, err = ed25519.GenerateKey(prng)
	if err != nil {
		return nil, err
	}

	return &priv, nil
}

// Encrypt generates an ephemeral curve25519 key pair and encrypts a
// new message to the peer's public key.
func Encrypt(pub *PublicKey, message []byte) (out []byte, ok bool) {
	enc := &tlv.Encoder{}
	enc.Encode(message)
	return encrypt(pub, enc.Bytes())
}

func encrypt(pub *PublicKey, message []byte) (out []byte, ok bool) {
	if !pub.Valid() {
		return nil, false
	}

	prng := util.PRNG()
	epub, epriv, err := box.GenerateKey(prng)
	if err != nil {
		return nil, false
	}

	out = epub[:]
	nonce := util.NewNonce()
	out = append(out, nonce[:]...)

	out = box.Seal(out, message, nonce, pub.E, epriv)
	ok = true
	return
}

const msgStart = 32 + util.NonceSize
const overhead = 32 + util.NonceSize + box.Overhead

// Decrypt opens the secured message using the private key.
func Decrypt(priv *PrivateKey, enc []byte) (message []byte, ok bool) {
	out, ok := decrypt(priv, enc)
	if !ok {
		return nil, false
	}
	defer util.Zero(out)

	var m []byte
	dec := tlv.NewDecoder(out)
	err := dec.Decode(&m)
	if err != nil {
		return nil, false
	}

	if dec.Length() != 0 {
		util.Zero(m)
		return nil, false
	}

	return m, true
}

func decrypt(priv *PrivateKey, enc []byte) (message []byte, ok bool) {
	if !priv.Valid() {
		return nil, false
	}

	if len(enc) < (32 + util.NonceSize + box.Overhead) {
		return nil, false
	}

	var pub [32]byte
	copy(pub[:], enc[:32])

	var nonce [util.NonceSize]byte
	copy(nonce[:], enc[32:])

	return box.Open(message, enc[msgStart:], &nonce, &pub, priv.D)
}

// Sign signs the message with the private key using Ed25519.
func Sign(priv *PrivateKey, message []byte) ([]byte, bool) {
	if !priv.Valid() {
		return nil, false
	}
	sig := ed25519.Sign(priv.S, message)
	return sig[:], true
}

// Verify verifies the signature on the message with the public key
// using Ed25519.
func Verify(pub *PublicKey, message []byte, sig []byte) bool {
	if !pub.Valid() {
		return false
	}

	if len(sig) != ed25519.SignatureSize {
		return false
	}

	var signature [ed25519.SignatureSize]byte
	copy(signature[:], sig)
	return ed25519.Verify(pub.V, message, &signature)
}

// EncryptAndSign signs the message with the private key, then
// encrypts it to the peer's public key.
func EncryptAndSign(priv *PrivateKey, pub *PublicKey, message []byte) ([]byte, bool) {
	sig, ok := Sign(priv, message)
	if !ok {
		return nil, false
	}

	var enc = &tlv.Encoder{}
	enc.Encode(message)
	enc.Encode(sig)

	ct, ok := encrypt(pub, enc.Bytes())
	if !ok {
		return nil, false
	}
	return ct, true
}

// DecryptAndVerify decrypts the message and verifies its signature.
func DecryptAndVerify(priv *PrivateKey, pub *PublicKey, enc []byte) ([]byte, bool) {
	if !priv.Valid() || !pub.Valid() {
		return nil, false
	}

	if len(enc) < overhead {
		return nil, false
	}

	out, ok := decrypt(priv, enc)
	if !ok {
		return nil, false
	}

	var m, s []byte
	dec := tlv.NewDecoder(out)
	err := dec.Decode(&m)
	if err != nil {
		return nil, false
	}

	err = dec.Decode(&s)
	if err != nil {
		util.Zero(m)
		return nil, false
	}

	if dec.Length() != 0 {
		util.Zero(m)
		return nil, false
	}

	if len(s) != ed25519.SignatureSize {
		util.Zero(m)
		return nil, false
	}

	if !Verify(pub, m, s) {
		util.Zero(m)
		return nil, false
	}

	return m, true
}

// LockKey secures the private key with the passphrase, using Scrypt
// and NaCl's secretbox.
func LockKey(priv *PrivateKey, passphrase []byte) ([]byte, bool) {
	out, err := MarshalPrivate(priv)
	if err != nil {
		return nil, false
	}
	defer util.Zero(out)

	salt := util.RandBytes(saltSize)
	if salt == nil {
		return nil, false
	}

	key := secret.DeriveKey(passphrase, salt)
	defer util.Zero(key[:])

	out, ok := secret.Encrypt(key, out)
	if !ok {
		return nil, false
	}

	out = append(salt, out...)
	return out, true
}

// UnlockKey recovers the secured private key with the passphrase.
func UnlockKey(locked, passphrase []byte) (*PrivateKey, bool) {
	if len(locked) <= saltSize {
		return nil, false
	}
	salt := locked[:saltSize]
	locked = locked[saltSize:]

	key := secret.DeriveKey(passphrase, salt)
	defer util.Zero(key[:])

	out, ok := secret.Decrypt(key, locked)
	if !ok {
		return nil, false
	}
	defer util.Zero(out)

	priv, err := UnmarshalPrivate(out)
	if err != nil {
		return nil, false
	}
	return priv, true
}

// KeyExchange performs an ECDH key exchange with the private and
// public key pairs.
func KeyExchange(priv *PrivateKey, peer *PublicKey) []byte {
	var shared [32]byte

	box.Precompute(&shared, peer.E, priv.D)
	return shared[:]
}
