package store

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/kisom/cryptutils/common/public"
	"github.com/kisom/cryptutils/common/util"
)

// KeyStoreVersion is the current version of the keystore format.
const KeyStoreVersion = 1

// A PublicKeyRecord contains information about a public key contained
// in the data store. A keystore should contain, at a minimum, the public
// key that the keystore belongs to.
type PublicKeyRecord struct {
	// Label contains a string identifier for this record. It is
	// for organisational use only, and there is nothing
	// cryptographically tying it to the key. The special label
	// "self" always points to the keystore owner's key.
	Label string

	// Version should point to the current keystore format version
	// that this record belongs to. This is used when updating the
	// keystore format.
	Version int

	// Timestamp contains the Unix timestamp of when the record
	// was last modified.
	Timestamp int64

	// Keys contains the serialised public key.
	Keys []byte

	// The KeySignature contains a signature on the key; signatures are
	// done using VerifiedKeys.
	KeySignature []byte

	// KeySigner contains the serialised public key of the key
	// that signed this record.
	KeySigner []byte

	// SignatureTime is the timestamp on the signature.
	SignatureTime int64

	// Metadata contains any additional information about the key
	// that should be stored with the key.
	Metadata map[string]string
}

// A KeyStore represents a collection of keys with an owner. A
// KeyStore with a private key should be locked before serialisation.
type KeyStore struct {
	// Version should reflect the version of the keystore format
	// in use.
	Version int

	// Timestamp is a Unix timestamp pointing to the last time the
	// keystore was updated.
	Timestamp int64

	// Keys is a hash map of the public key records, indexed by
	// label.
	Keys map[string]*PublicKeyRecord

	// PrivateKey contains the locked private key. The private key
	// is encrypted with a passphrase using Scrypt and the NaCl
	// secretbox format.
	PrivateKey []byte

	// PublicKey contains the owner's public key.
	PublicKey []byte

	// ExportKey contains a signed version of the public key as a
	// PEM-encoded VerifiedKey.
	ExportKey []byte

	privateKey *public.PrivateKey
	locked     bool
}

// NewPrivateKeyStore builds a keystore from a private key.
func NewPrivateKeyStore(priv *public.PrivateKey) (*KeyStore, bool) {
	if !priv.Valid() {
		return nil, false
	}

	pub, err := public.MarshalPublic(priv.PublicKey)
	if err != nil {
		return nil, false
	}

	vkey := &VerifiedKey{
		Public:    pub,
		Signer:    pub,
		Timestamp: time.Now().Unix(),
	}
	signatureData := vkey.SignatureData()
	sig, ok := public.Sign(priv, signatureData)
	if !ok {
		return nil, false
	}
	vkey.Signature = sig
	verified, err := vkey.Serialise()
	if err != nil {
		return nil, false
	}

	return &KeyStore{
		Version:    KeyStoreVersion,
		Timestamp:  time.Now().Unix(),
		Keys:       map[string]*PublicKeyRecord{},
		privateKey: priv,
		locked:     false,
		PublicKey:  pub,
		ExportKey:  verified,
	}, true

}

func (s *KeyStore) Dump() ([]byte, error) {
	copy := &KeyStore{
		Version:    s.Version,
		Timestamp:  s.Timestamp,
		Keys:       s.Keys,
		PrivateKey: s.PrivateKey,
		PublicKey:  s.PublicKey,
		ExportKey:  s.ExportKey,
	}
	return json.Marshal(copy)
}

// Locked indicates whether the keystore is locked. When unlocked, it
// may perform signature and decryption operations.
func (s *KeyStore) Locked() bool { return s.locked }

// Lock clears out the unlocked private key, if the keystore is
// locked. This should always return true, and if it doesn't, a
// serious error has occurred.
func (s *KeyStore) Lock() bool {
	if !s.Valid(false) {
		return false
	}

	if s.locked {
		return true
	}

	s.privateKey.Zero()
	s.privateKey = nil
	s.locked = true
	return s.Locked()
}

// LockWith locks the key store with the given passphrase. This can be
// used with a new keystore to set the passphrase.
func (s *KeyStore) LockWith(passphrase []byte) bool {
	if !s.Valid(false) {
		return false
	}

	if s.locked {
		return true
	}

	var ok bool
	s.PrivateKey, ok = public.LockKey(s.privateKey, passphrase)
	if !ok {
		return false
	}
	s.privateKey.Zero()
	s.privateKey = nil
	s.locked = true
	return s.Locked()
}

// Unlock decrypts the private key stored in the keystore.
func (s *KeyStore) Unlock(passphrase []byte) bool {
	if !s.Valid(true) {
		return false
	} else if !s.Locked() {
		return true
	}

	priv, ok := public.UnlockKey(s.PrivateKey, passphrase)
	if !ok {
		return false
	}
	pub, err := public.MarshalPublic(priv.PublicKey)
	if err != nil {
		priv.Zero()
		return false
	}

	s.privateKey = priv
	s.PublicKey = pub
	s.locked = false

	if s.ExportKey == nil {
		fmt.Println("Building export key.")
		vkey := &VerifiedKey{
			Public:    s.PublicKey,
			Signer:    s.PublicKey,
			Timestamp: time.Now().Unix(),
		}
		signatureData := vkey.SignatureData()
		sig, ok := public.Sign(s.privateKey, signatureData)
		if !ok {
			s.Lock()
			return false
		}
		vkey.Signature = sig
		verified, err := vkey.Serialise()
		if err != nil {
			s.Lock()
			return false
		}
		s.ExportKey = verified
	}

	return !s.Locked()
}

// Valid performs sanity checks on the keystore to make sure it is
// valid. If quick is false, the public key and private key (if
// unlocked) will be checked as well.
func (s *KeyStore) Valid(quick bool) bool {
	if s == nil {
		return false
	}

	if s.Version != KeyStoreVersion {
		return false
	}

	if s.Timestamp == 0 {
		return false
	}

	if s.Keys == nil {
		return false
	}

	if quick {
		return true
	}

	if !s.locked {
		if !s.privateKey.Valid() {
			return false
		}
		pub, err := public.MarshalPublic(s.privateKey.PublicKey)
		if err != nil {
			return false
		}
		if !bytes.Equal(pub, s.PublicKey) {
			return false
		}
	}

	if s.PublicKey == nil {
		return false
	} else if _, err := public.UnmarshalPublic(s.PublicKey); err != nil {
		return false
	}

	return true
}

// Has returns true if the label is present in the keystore.
func (s *KeyStore) Has(label string) bool {
	if !s.Valid(true) {
		return false
	} else if label == "self" {
		return true
	}

	_, ok := s.Keys[label]
	return ok
}

// AddKey adds the new peer key to the keystore, signing it with the
// owner's key. If the keystore is locked, this will fail.
func (s *KeyStore) AddKey(label string, peer []byte, metadata map[string]string) bool {
	if !s.Valid(true) {
		return false
	} else if s.Has(label) {
		return false
	} else if s.Locked() {
		return false
	} else if _, err := public.UnmarshalPublic(peer); err != nil {
		return false
	}

	signTime := time.Now().Unix()
	vkey := &VerifiedKey{
		Public:    peer,
		Signer:    s.PublicKey,
		Timestamp: signTime,
	}
	signatureData := vkey.SignatureData()

	sig, ok := public.Sign(s.privateKey, signatureData)
	if !ok {
		return false
	}
	if !public.Verify(s.privateKey.PublicKey, signatureData, sig) {
		return false
	}

	metadataCopy := map[string]string{}
	for k, v := range metadata {
		metadataCopy[k] = v
	}

	s.Keys[label] = &PublicKeyRecord{
		Label:         label,
		Timestamp:     time.Now().Unix(),
		Keys:          peer,
		KeySignature:  sig,
		KeySigner:     s.PublicKey,
		SignatureTime: signTime,
		Metadata:      metadataCopy,
	}
	return true
}

// A VerifiedKey is a structure that associates a signature with a
// public key. The signature is performed on the concatenation of the
// public key, the signer, and the timestamp.
type VerifiedKey struct {
	// Public is the serialised public key.
	Public []byte

	// Signer is the serialised public key that signed Public.
	Signer []byte

	// Timestamp contains a Unix timestamp that indicates when the
	// key was signed.
	Timestamp int64

	// Signature contains the Ed25519 signature on the key.
	Signature []byte
}

// ParseVerifiedKey parses a verified key from a byte slice.
func ParseVerifiedKey(in []byte) (*VerifiedKey, error) {
	p, _ := pem.Decode(in)
	if p == nil {
		return nil, errors.New("invalid verified key")
	}

	if p.Type != VerifiedKeyType {
		return nil, errors.New("invalid verified key")
	}

	var vkey VerifiedKey
	_, err := asn1.Unmarshal(p.Bytes, &vkey)
	if err != nil {
		return nil, err
	}
	return &vkey, nil
}

// Serialises PEM-encodes the verified key.
func (vkey *VerifiedKey) Serialise() ([]byte, error) {
	signedKey, err := asn1.Marshal(*vkey)
	if err != nil {
		return nil, err
	}

	block := pem.Block{
		Type:  VerifiedKeyType,
		Bytes: signedKey,
	}

	return pem.EncodeToMemory(&block), nil
}

// SignatureData returns the byte slice containing the public key,
// signer's public key, and the big-endian encoded 64-bit signed
// integer timestamp.
func (vkey *VerifiedKey) SignatureData() []byte {
	var signatureData []byte
	var timestamp = make([]byte, 8)
	signatureData = append(signatureData, vkey.Public...)
	signatureData = append(signatureData, vkey.Signer...)
	binary.BigEndian.PutUint64(timestamp, uint64(vkey.Timestamp))
	signatureData = append(signatureData, timestamp...)
	return signatureData
}

// IsSelfSigned returns true if the verified key is self-signed.
func (vkey *VerifiedKey) IsSelfSigned() bool {
	if !bytes.Equal(vkey.Public, vkey.Signer) {
		return false
	}

	signer, err := public.UnmarshalPublic(vkey.Signer)
	if err != nil {
		return false
	}

	sigData := vkey.SignatureData()
	return public.Verify(signer, sigData, vkey.Signature)
}

// VerifiedKeyType is the PEM type used when exporting a verified key.
const VerifiedKeyType = "CRYPTUTIL VERIFIED KEY"

// ExportVerified returns a verified key from the label. The verified
// key will be signed by the keystore owner; the key's signature chain is
// first checked before exporting.
func (s *KeyStore) ExportVerified(label string) ([]byte, bool) {
	if !s.Valid(true) || !s.Has(label) || s.Locked() {
		return nil, false
	}

	if !s.VerifyChain(label) {
		return nil, false
	}

	var vkey *VerifiedKey

	if label == "self" {
		if s.ExportKey != nil {
			return s.ExportKey, true
		}
		vkey = &VerifiedKey{
			Public:    s.PublicKey,
			Signer:    s.PublicKey,
			Timestamp: time.Now().Unix(),
		}
	} else {
		vkey = &VerifiedKey{
			Public:    s.Keys[label].Keys,
			Signer:    s.PublicKey,
			Timestamp: time.Now().Unix(),
		}
	}
	signatureData := vkey.SignatureData()

	sig, ok := public.Sign(s.privateKey, signatureData)
	if !ok {
		return nil, false
	}

	vkey.Signature = sig
	signedKey, err := vkey.Serialise()
	return signedKey, err == nil
}

// ImportVerifiedKey imports a PEM-encoded verified key.
func (s *KeyStore) ImportVerifiedKey(label string, signedKey []byte) bool {
	p, _ := pem.Decode(signedKey)
	if p == nil {
		return false
	}

	if p.Type != VerifiedKeyType {
		return false
	}

	return s.ImportVerified(label, p.Bytes)
}

// ImportVerified imports a verified key under the label. The original
// signature data is preserved in the keystore.
func (s *KeyStore) ImportVerified(label string, signedKey []byte) bool {
	var pub []byte

	if !s.Valid(true) || s.Has(label) {
		return false
	}

	var vkey VerifiedKey
	_, err := asn1.Unmarshal(signedKey, &vkey)
	if err != nil {
		return false
	}

	var signerLabel string
	if bytes.Equal(vkey.Signer, s.PublicKey) {
		signerLabel = "self"
		pub = s.PublicKey
	} else {
		var ok bool
		signerLabel, ok = s.FindPublic(vkey.Signer)
		if !ok {
			return false
		}
		pub = s.Keys[signerLabel].Keys
	}

	if signerLabel == "" || pub == nil {
		return false
	} else if _, ok := s.VerifyKeySignature(signerLabel); !ok {
		return false
	}

	pubkey, err := public.UnmarshalPublic(pub)
	if err != nil {
		return false
	}

	signatureData := vkey.SignatureData()
	if !public.Verify(pubkey, signatureData, vkey.Signature) {
		return false
	}

	rec := &PublicKeyRecord{
		Label:         label,
		Version:       KeyStoreVersion,
		Timestamp:     time.Now().Unix(),
		Keys:          vkey.Public,
		KeySignature:  vkey.Signature,
		KeySigner:     pub,
		SignatureTime: vkey.Timestamp,
	}
	s.Keys[label] = rec
	return true
}

// FindPublic looks up the public key in the key store, returning its label.
func (s *KeyStore) FindPublic(pub []byte) (string, bool) {
	var label string
	if bytes.Equal(pub, s.PublicKey) {
		return "self", true
	}

	for _, v := range s.Keys {
		if bytes.Equal(pub, v.Keys) {
			label = v.Label
			return label, true
		}
	}
	return "", false

}

// VerifyKeySignature authenticates the signature on the key indicated
// by label. If the label is self, Verify returns true as that label
// is assumed always valid.
func (s *KeyStore) VerifyKeySignature(label string) (string, bool) {
	if !s.Valid(true) {
		return "", false
	}

	if label == "self" {
		return "self", true
	}

	rec := s.Keys[label]
	var signerLabel string

	var vkey = &VerifiedKey{
		Public:    rec.Keys,
		Signature: rec.KeySignature,
		Timestamp: rec.SignatureTime,
	}
	if bytes.Equal(rec.KeySigner, s.PublicKey) {
		vkey.Signer = s.PublicKey
		signerLabel = "self"
	} else {
		var ok bool
		signerLabel, ok = s.FindPublic(rec.KeySigner)
		if !ok {
			return "", false
		}
		vkey.Signer = s.Keys[signerLabel].Keys
	}
	pub, err := public.UnmarshalPublic(vkey.Signer)
	if err != nil {
		return "", false
	}
	signatureData := vkey.SignatureData()

	if !public.Verify(pub, signatureData, vkey.Signature) {
		return "", false
	}
	return signerLabel, true
}

// VerifyChain verifies the signature chain on the key pointed to by
// label. First, the signature on the key pointed to by the label is
// verified. Then, the signature key is validated; this is continued
// until the keystore's public key ends up at the keystore's public
// key.
func (s *KeyStore) VerifyChain(label string) bool {
	if !s.Valid(true) || !s.Has(label) {
		return false
	} else if label == "self" {
		return true
	}

	var (
		signerLabel string
		ok          bool
	)
	for {
		signerLabel, ok = s.VerifyKeySignature(label)
		if !ok {
			return false
		} else if signerLabel == "self" {
			return true
		}

		label = signerLabel
	}
}

// KeyAudit verifies the signature chain on all keys in the
// keystore. This operation may be slow, and it is recommended that it
// be run at most once per hour. For large keystores, once per day
// might be more suitable.
func (s *KeyStore) KeyAudit() bool {
	if !s.Valid(true) {
		return false
	}

	for lbl := range s.Keys {
		if !s.VerifyChain(lbl) {
			util.Errorf("Key %s is not trusted.", lbl)
			return false
		}
	}
	return true
}

func (s *KeyStore) getPublic(label string) *public.PublicKey {
	if !s.Has(label) {
		return nil
	}

	if label == "self" {
		if s.Locked() {
			pub, err := public.UnmarshalPublic(s.PublicKey)
			if err != nil {
				return nil
			}
			return pub
		}
		return s.privateKey.PublicKey
	}
	pub, err := public.UnmarshalPublic(s.Keys[label].Keys)
	if err != nil {
		return nil
	}
	return pub
}

// EncryptTo encrypts the message to the named public key.
func (s *KeyStore) EncryptTo(label string, message []byte) ([]byte, bool) {
	if !s.Valid(true) || !s.Has(label) {
		return nil, false
	}

	var pubBytes []byte
	if label == "self" {
		pubBytes = s.PublicKey
	} else {
		pubBytes = s.Keys[label].Keys
	}

	pub, err := public.UnmarshalPublic(pubBytes)
	if err != nil {
		return nil, false
	}

	return public.Encrypt(pub, message)
}

// Decrypt decrypts the message using the keystore's private key.
func (s *KeyStore) Decrypt(message []byte) ([]byte, bool) {
	if !s.Valid(false) || s.Locked() {
		return nil, false
	}

	return public.Decrypt(s.privateKey, message)
}

// Sign signs the message using the keystore's private key.
func (s *KeyStore) Sign(message []byte) ([]byte, bool) {
	if !s.Valid(false) || s.Locked() {
		return nil, false
	}

	return public.Sign(s.privateKey, message)
}

// Verify validates that the message was signed by the named public
// key.
func (s *KeyStore) Verify(label string, message, sig []byte) bool {
	if !s.Valid(true) {
		return false
	} else if !s.Has(label) {
		return false
	}

	pub := s.getPublic(label)
	if pub == nil {
		return false
	}

	return public.Verify(pub, message, sig)
}

// EncryptAndSignTo signs the message and encrypts to the named key.
func (s *KeyStore) EncryptAndSignTo(label string, message []byte) ([]byte, bool) {
	if !s.Valid(false) || s.Locked() {
		return nil, false
	} else if !s.Has(label) {
		return nil, false
	}

	pub := s.getPublic(label)
	if pub == nil {
		return nil, false
	}

	return public.EncryptAndSign(s.privateKey, pub, message)
}

// DecryptAndVerify decrypts the message and verifies the message was
// signed by the named key.
func (s *KeyStore) DecryptAndVerify(label string, message []byte) ([]byte, bool) {
	if !s.Valid(false) || s.Locked() {
		return nil, false
	} else if !s.Has(label) {
		return nil, false
	}

	pub := s.getPublic(label)
	if pub == nil {
		return nil, false
	}

	return public.DecryptAndVerify(s.privateKey, pub, message)
}

// LoadKeyStore attempts to load a keystore from the given path. If
// the keystore doesn't exist, a new one is created with a
// freshly-generated keys if the orNew argument is true.
func LoadKeyStore(path string, orNew bool) (*KeyStore, bool) {
	data, err := ioutil.ReadFile(path)
	if err != nil && os.IsNotExist(err) && orNew {
		var priv *public.PrivateKey
		priv, err = public.GenerateKey()
		if err != nil {
			util.Errorf("Failed to generate key.")
			return nil, false
		}
		return NewPrivateKeyStore(priv)
	} else if err != nil {
		util.Errorf("%v", err)
		return nil, false
	}

	store := new(KeyStore)
	err = json.Unmarshal(data, store)
	if err != nil {
		util.Errorf("%v", err)
		return nil, false
	}
	if store.Keys == nil {
		store.Keys = map[string]*PublicKeyRecord{}
	}
	if store.PrivateKey != nil {
		store.locked = true
	}

	if !store.Valid(true) {
		util.Errorf("invalid keystore %v", store)
		return nil, false
	}
	return store, true
}

// DumpKeyStore locks the keystore and serialises it to a byte slice,
// i.e. in preparation for writing to file.
func DumpKeyStore(store *KeyStore) []byte {
	store.Lock()
	data, err := json.Marshal(store)
	if err != nil {
		return nil
	}
	return data
}
