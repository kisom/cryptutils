package public

import (
	"bytes"
	"testing"
)

var testKey *PrivateKey

func TestGenerateKey(t *testing.T) {
	var err error
	testKey, err = GenerateKey()
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestPrivateSerialisation(t *testing.T) {
	out, err := MarshalPrivate(testKey)
	if err != nil {
		t.Fatalf("%v", err)
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
