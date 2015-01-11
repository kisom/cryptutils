package secret

import (
	"bytes"
	"crypto/rand"
	"log"
	"os"
	"testing"

	"github.com/kisom/cryptutils/common/util"
)

var (
	password = []byte("password")
	message  = []byte("do not go gentle into that good night")
)

func TestGenerateKey(t *testing.T) {
	if k := GenerateKey(); k == nil {
		t.Fatal("secret: failed to generate new key")
	}

	var buf = new(bytes.Buffer)
	util.SetPRNG(buf)
	if k := GenerateKey(); k != nil {
		log.Printf("key: %x", k)
		t.Fatal("secret: should fail to generate new key with bad PRNG")
	}
	util.SetPRNG(rand.Reader)
}

func TestDeriveKey(t *testing.T) {
	salt := util.RandBytes(SaltSize)
	if k := DeriveKey(password, salt); k == nil {
		t.Fatal("secret: failed to derive key")
	}

	n := scryptParams.N
	scryptParams.N = 0
	if k := DeriveKey(password, salt); k != nil {
		t.Fatal("secret: should fail to derive key with invalid Scrypt params")
	}
	scryptParams.N = n
}

func TestEncrypt(t *testing.T) {
	k := GenerateKey()
	ct, ok := Encrypt(k, message)
	if !ok {
		t.Fatal("secret: encrypt fails")
	}

	pt, ok := Decrypt(k, ct)
	if !ok {
		t.Fatal("secret: decrypt fails")
	}

	if !bytes.Equal(pt, message) {
		t.Fatal("secret: decrypted plaintext doesn't match original")
	}

	util.SetPRNG(&bytes.Buffer{})
	if _, ok = Encrypt(k, message); ok {
		t.Fatal("secret: encrypt should fail with bad PRNG")
	}
	util.SetPRNG(rand.Reader)

	if _, ok = Decrypt(k, message[:nonceSize-1]); ok {
		t.Fatal("secret: encrypt should fail with bad ciphertext")
	}
}

var (
	testEncryptedFile   = "testdata/test.enc"
	testNoSuchFile      = "testdata/enoent"
	testUnencryptedFile = "testdata/test.txt"
)

func dup(in []byte) []byte {
	out := make([]byte, len(in))
	copy(out, in)
	return out
}

func TestEncryptFile(t *testing.T) {
	defer os.Remove(testEncryptedFile)
	err := EncryptFile(testEncryptedFile, password, dup(message))
	if err != nil {
		t.Fatalf("%v", err)
	}

	out, err := DecryptFile(testEncryptedFile, password)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !bytes.Equal(out, message) {
		t.Fatal("secret: decrypted file doesn't match original message")
	}

	if _, err = DecryptFile(testNoSuchFile, password); err == nil {
		t.Fatal("secret: decrypt file should fail with IO error")
	}

	if _, err = DecryptFile(testUnencryptedFile, password); err == nil {
		t.Fatal("secret: decrypt file should fail with unencrypted file")
	}

	salt := util.RandBytes(SaltSize)
	buf := &bytes.Buffer{}
	util.SetPRNG(buf)
	err = EncryptFile(testEncryptedFile, password, dup(message))
	if err == nil {
		t.Fatal("secret: encrypt file should fail with bad PRNG")
	}

	buf.Write(salt)
	err = EncryptFile(testEncryptedFile, password, dup(message))
	if err == nil {
		t.Fatal("secret: encrypt file should fail with bad PRNG")
	}
	util.SetPRNG(rand.Reader)
}
