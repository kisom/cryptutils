package public

import (
	"bytes"
	"crypto/rand"
	"encoding/pem"
	"testing"

	"github.com/kisom/cryptutils/common/util"
)

var testKey *PrivateKey

func TestGenerateKey(t *testing.T) {
	var err error
	testKey, err = GenerateKey()
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestPrivateValid(t *testing.T) {
	var priv *PrivateKey
	if priv.Valid() {
		t.Fatal("public: invalid private key marked as valid")
	}

	priv = &PrivateKey{}
	if priv.Valid() {
		t.Fatal("public: invalid private key marked as valid")
	}

	priv.PublicKey = testKey.PublicKey
	if priv.Valid() {
		t.Fatal("public: invalid private key marked as valid")
	}

	priv.D = testKey.D
	if priv.Valid() {
		t.Fatal("public: invalid private key marked as valid")
	}

	if _, err := MarshalPrivate(priv); err == nil {
		t.Fatal("public: expect failure when marshaling invalid private key")
	}

	if _, err := ExportPrivate(priv, nil); err == nil {
		t.Fatal("public: expect failure when exporting private key")
	}

	priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("%v", err)
	}

	priv.Zero()
	if priv.D != nil || priv.S != nil {
		t.Fatal("public: failed to zeroise private key")
	}
}

func TestExportKeyFails(t *testing.T) {
	util.SetPRNG(&bytes.Buffer{})
	if _, err := ExportPrivate(testKey, []byte("hello, world")); err == nil {
		t.Fatalf("public: expect exporting private key to fail with PRNG failure")
	}

	util.SetPRNG(rand.Reader)
}

func TestImportKey(t *testing.T) {
	password := []byte("password")
	wrongpass := []byte("passwort")
	out, err := ExportPrivate(testKey, password)
	if err != nil {
		t.Fatalf("%v", err)
	}

	var data = []byte("not PEM encoded")
	if _, err = ImportPrivate(data, password); err == nil {
		t.Fatal("public: importing private key should fail when data isn't PEM encoded")
	}

	data = pem.EncodeToMemory(&pem.Block{Type: "WHATEVER", Bytes: data})
	if _, err = ImportPrivate(data, password); err == nil {
		t.Fatal("public: importing private key should fail with improper PEM type")
	}

	if _, err = ImportPrivate(out, wrongpass); err == nil {
		t.Fatal("public: importing private key should fail with wrong password")
	}

	if _, err = ImportPrivate(out, password); err != nil {
		t.Fatalf("%v", err)
	}

}

func TestPrivateSerialisation(t *testing.T) {
	out, err := MarshalPrivate(testKey)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if _, err = UnmarshalPrivate(out[1:]); err == nil {
		t.Fatal("public: expect unmarshaling to fail with invalid private key")
	}

	priv, err := UnmarshalPrivate(out)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if !bytes.Equal(priv.D[:], testKey.D[:]) {
		t.Fatalf("Unmarshalled key doesn't match original.")
	}

	if !bytes.Equal(priv.S[:], testKey.S[:]) {
		t.Fatal("Unmarshalled key doesn't match original.")
	}

	if !bytes.Equal(priv.E[:], testKey.E[:]) {
		t.Fatal("Unmarshalled key doesn't match original.")
	}

	if !bytes.Equal(priv.V[:], testKey.V[:]) {
		t.Fatal("Unmarshalled key doesn't match original.")
	}
}

func TestPublicValidity(t *testing.T) {
	pub := &PublicKey{}
	if pub.Valid() {
		t.Fatal("public: invalid public key marked as valid")
	}

	if _, err := MarshalPublic(pub); err == nil {
		t.Fatal("public: serialising invalid public key should fail")
	}

	pub.E = new([32]byte)
	if pub.Valid() {
		t.Fatal("public: invalid public key marked as valid")
	}

	pub.V = new([32]byte)
	if !pub.Valid() {
		t.Fatal("public: valid public key marked as invalid")
	}

	out, err := MarshalPublic(pub)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if _, err = UnmarshalPublic(out[1:]); err == nil {
		t.Fatal("public: expect failure to parse invalid public key")
	}

	if _, err = UnmarshalPublic(out); err != nil {
		t.Fatalf("%v", err)
	}
}

var message = []byte("Hello, world. This is a test of Encrypt.")

func TestEncryptDecrypt(t *testing.T) {
	out, ok := Encrypt(testKey.PublicKey, message)
	if !ok {
		t.Fatal("Encryption failed.")
	}

	recovered, ok := Decrypt(testKey, out)
	if !ok {
		t.Fatal("Decryption failed.")
	}

	if !bytes.Equal(message, recovered) {
		t.Fatalf("Corrupt message.\nRecovered: %x\nMessage: %x\n",
			recovered, message)
	}
}

func TestSignVerify(t *testing.T) {
	sig, ok := Sign(testKey, message)
	if !ok {
		t.Fatal("Signature failed.")
	}

	if !Verify(testKey.PublicKey, message, sig) {
		t.Fatal("Signature verification failed.")
	}
}

func TestLockKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	out, ok := EncryptAndSign(testKey, key.PublicKey, message)
	if !ok {
		t.Fatal("Failed to encrypt and sign message.")
	}

	locked, ok := LockKey(key, []byte("this is my password"))
	if !ok {
		t.Fatal("Failed to lock key.")
	}

	_, ok = UnlockKey(locked, []byte("this is my password."))
	if ok {
		t.Fatal("Unlocked with wrong passphrase.")
	}

	priv, ok := UnlockKey(locked, []byte("this is my password"))
	if !ok {
		t.Fatal("Unlocking key failed.")
	}

	recovered, ok := DecryptAndVerify(priv, testKey.PublicKey, out)
	if !ok {
		t.Fatal("Failed to decrypt and verify message.")
	}

	if !bytes.Equal(message, recovered) {
		t.Fatalf("Corrupt message.\nRecovered: %x\nMessage: %x\n",
			recovered, message)
	}
}

func TestGenerateFailure(t *testing.T) {
	b := &bytes.Buffer{}
	util.SetPRNG(b)
	_, err := GenerateKey()
	if err == nil {
		t.Fatalf("%v", err)
	}

	seed := make([]byte, 32)
	b.Write(seed)
	_, err = GenerateKey()
	if err == nil {
		t.Fatalf("%v", err)
	}

	util.SetPRNG(rand.Reader)
}

func TestExportImportPrivate(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	enc, ok := EncryptAndSign(testKey, key.PublicKey, message)
	if !ok {
		t.Fatal("Failed to encrypt and sign message.")
	}

	out, err := ExportPrivate(key, []byte("password"))
	if err != nil {
		t.Fatalf("%v", err)
	}

	priv, err := ImportPrivate(out, []byte("password"))
	if err != nil {
		t.Fatalf("%v", err)
	}

	recovered, ok := DecryptAndVerify(priv, testKey.PublicKey, enc)
	if !ok {
		t.Fatal("Failed to decrypt and verify message.")
	}

	if !bytes.Equal(message, recovered) {
		t.Fatalf("Corrupt message.\nRecovered: %x\nMessage: %x\n",
			recovered, message)
	}
}

func TestKeyExchange(t *testing.T) {
	peer, err := GenerateKey()
	if err != nil {
		t.Fatalf("%v", err)
	}

	sharedAB := KeyExchange(testKey, peer.PublicKey)
	sharedBA := KeyExchange(peer, testKey.PublicKey)

	if !bytes.Equal(sharedAB, sharedBA) {
		t.Fatal("auth: failed to perform key exchange")
	}
}

func TestEncryptFailure(t *testing.T) {
	pub := &PublicKey{}
	message := []byte("do not go gentle into that good night")

	if _, ok := Encrypt(pub, message); ok {
		t.Fatal("public: encrypt should fail with invalid public key")
	}

	util.SetPRNG(&bytes.Buffer{})
	if _, ok := Encrypt(testKey.PublicKey, message); ok {
		t.Fatal("public: encrypt should fail with PRNG failure")
	}

	util.SetPRNG(rand.Reader)
	out, ok := Encrypt(testKey.PublicKey, message)
	if !ok {
		t.Fatal("public: encrypt failed")
	}

	priv := &PrivateKey{}
	if _, ok = Decrypt(priv, out); ok {
		t.Fatal("public: decrypt should fail with invalid private key")
	}

	if _, ok = Decrypt(testKey, out[:32]); ok {
		t.Fatal("public: decrypt should fail with invalid ciphertext")
	}
}

func TestSignatureFailures(t *testing.T) {
	message := []byte("old age should burn and rave at close of day")
	if _, ok := Sign(&PrivateKey{}, message); ok {
		t.Fatal("public: signature should fail with invalid private key")
	}

	sig, ok := Sign(testKey, message)
	if !ok {
		t.Fatal("public: signature failed")
	}

	if Verify(&PublicKey{}, message, sig) {
		t.Fatal("public: verify should fail with invalid public key")
	}

	if Verify(testKey.PublicKey, message, sig[1:]) {
		t.Fatal("public: verify should fail with invalid signature")
	}

	if !Verify(testKey.PublicKey, message, sig) {
		t.Fatal("public: verification failed")
	}
}

func TestLockFailures(t *testing.T) {
	password := []byte("password")
	locked, ok := LockKey(testKey, password)
	if !ok {
		t.Fatal("public: failed to lock private key")
	}

	_, ok = UnlockKey(locked[:saltSize], password)
	if ok {
		t.Fatal("public: unlock should fail with invalid locked key")
	}
}
