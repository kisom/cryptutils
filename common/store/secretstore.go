package store

import (
	"encoding/json"
	"time"

	"github.com/kisom/cryptutils/common/secret"
	"github.com/kisom/cryptutils/common/util"
)

// SecretStoreVersion is the current version of the secret store
// format.
const SecretStoreVersion = 1

const saltSize = 32

// SecretType is the PEM type used when exporting the store.
const SecretType = "CRYPTUTIL SECRET STORE"

// A SecretRecord stores a secret in the secret store.
type SecretRecord struct {
	// The label is used to identify the secret in the store.
	Label string

	// The timestamp stores the Unix timestamp of when the record
	// was modified last.
	Timestamp int64

	// Secret contains the secret being stored.
	Secret []byte

	// Metadata contains any additional information that should be
	// stored alongside the secret.
	Metadata map[string][]byte
}

// Zero clears out the secret. The discussion for the util.Zero
// function contains a more in-depth discussion on the security of
// this.
func (r *SecretRecord) Zero() {
	if r == nil {
		return
	}

	util.Zero(r.Secret)
	for k := range r.Metadata {
		util.Zero(r.Metadata[k])
	}
}

// A SecretStore contains a collection of secrets protected by a
// passphrase. The passphrase is kept with the store until it is
// either marshalled (at which point the store is zeroised), or until
// the store is zeroised manually.
type SecretStore struct {
	// Version should reflect the version of the secret store
	// format in use.
	Version int

	// Timestamp is a Unix timestamp pointing to the last time the
	// secret store was updated.
	Timestamp int64

	// Store is a hash map of secret records, indexed by label.
	Store map[string]*SecretRecord

	passphrase []byte
}

// Zero wipes the sensitive data from the store. See the discussion of
// util.Zero for a more in-depth discussion on the subject.
func (s *SecretStore) Zero() {
	for k := range s.Store {
		s.Store[k].Zero()
	}
	util.Zero(s.passphrase)
}

// Valid performs a sanity check on the secret store, and returns
// false if any discrepencies are noticed.
func (s *SecretStore) Valid() bool {
	if SecretStoreVersion != s.Version {
		return false
	}

	if s.Timestamp == 0 {
		return false
	}

	if s.Store == nil {
		return false
	}

	if s.passphrase == nil {
		return false
	}

	return true
}

// NewSecretStore initialises a new secret store.
func NewSecretStore(passphrase []byte) *SecretStore {
	passcopy := make([]byte, len(passphrase))
	copy(passcopy, passphrase)
	return &SecretStore{
		Version:    SecretStoreVersion,
		Timestamp:  time.Now().Unix(),
		Store:      map[string]*SecretRecord{},
		passphrase: passcopy,
	}
}

// Has returns true if the secret store contains the named secret.
func (s *SecretStore) Has(name string) bool {
	_, ok := s.Store[name]
	return ok
}

// AddRecord adds a new secret to the store. If the secret already
// exists, it will fail. This is by design to prevent overwriting
// secrets unintentionally.
func (s *SecretStore) AddRecord(name string, secret []byte, md map[string][]byte) bool {
	if !s.Valid() {
		return false
	}

	if !s.Has(name) {
		metadata := map[string][]byte{}
		for k, v := range md {
			metadata[k] = v[:]
		}

		s.Store[name] = &SecretRecord{
			Label:     name,
			Secret:    secret,
			Metadata:  md,
			Timestamp: time.Now().Unix(),
		}
		return true
	}
	return false
}

// UpdateSecret updates the named secret in the key store.
func (s *SecretStore) UpdateSecret(name string, secret []byte) bool {
	if !s.Has(name) {
		return false
	}

	s.Store[name].Secret = secret
	s.Store[name].Timestamp = time.Now().Unix()
	return true
}

// Merge compares the timestamp of the record to the other record;
// the record that was modified most recently is selected.
func (r *SecretRecord) Merge(other *SecretRecord) (*SecretRecord, bool) {
	if r.Timestamp >= other.Timestamp {
		return r, false
	}

	return other, true
}

// Merge handles the merging of two password stores. For each record
// in the other password store, if the entry doesn't exist in the password
// store it is added. If it does exist, the two records are merged.
func (s *SecretStore) Merge(other *SecretStore) []string {
	var mergeList []string
	for k, v := range other.Store {
		var merged bool
		if r, ok := s.Store[k]; !ok {
			s.Store[k] = v
			merged = true
		} else {
			s.Store[k], merged = r.Merge(v)
		}

		if merged {
			mergeList = append(mergeList, s.Store[k].Label)
		}
	}
	s.Timestamp = time.Now().Unix()
	return mergeList
}

// MarshalSecretStore serialises and encrypts the data store to a byte
// slice suitable for writing to disk.
func MarshalSecretStore(s *SecretStore) ([]byte, bool) {
	if !s.Valid() {
		return nil, false
	}

	out, err := json.Marshal(s)
	if err != nil {
		return nil, false
	}
	defer util.Zero(out)

	salt := util.RandBytes(saltSize)
	if salt == nil {
		return nil, false
	}

	key := secret.DeriveKey(s.passphrase, salt)
	if key == nil {
		return nil, false
	}
	defer util.Zero(key[:])

	enc, ok := secret.Encrypt(key, out)
	if !ok {
		return nil, false
	}
	defer s.Zero()

	enc = append(salt, enc...)
	return enc, true
}

// UnmarshalSecretStore decrypts and parses the secret store contained
// in the input byte slice.
func UnmarshalSecretStore(in, passphrase []byte) (*SecretStore, bool) {
	if len(in) < saltSize {
		return nil, false
	}

	salt := in[:saltSize]
	enc := in[saltSize:]
	key := secret.DeriveKey(passphrase, salt)
	if key == nil {
		return nil, false
	}
	defer util.Zero(key[:])

	data, ok := secret.Decrypt(key, enc)
	if !ok {
		util.Errorf("decrypt fails")
		return nil, false
	}
	defer util.Zero(data)

	var store SecretStore
	err := json.Unmarshal(data, &store)
	if err != nil {
		util.Errorf("encrypt fails")
		return nil, false
	}

	store.passphrase = make([]byte, len(passphrase))
	copy(store.passphrase, passphrase)
	return &store, true
}

// ChangePassword changes the password for the SecretStore; this will
// take effect the next time the password store is marshalled.
func (s *SecretStore) ChangePassword(newPass []byte) {
	util.Zero(s.passphrase)
	s.passphrase = make([]byte, len(newPass))
	copy(s.passphrase, newPass)
}
