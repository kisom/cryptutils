package util

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"regexp"
	"testing"
)

func testPrompt(prompt string) ([]byte, error) {
	return []byte(prompt), nil
}

var vRegexp = regexp.MustCompile(`^\d+\.\d+\.\d+`)

func TestVersionString(t *testing.T) {
	vs := VersionString()
	if !vRegexp.MatchString(vs) {
		t.Fatalf("util: version string '%s' is invalid", vs)
	}
}

func TestChangePassPrompter(t *testing.T) {
	PassPrompt = testPrompt
	password, err := PassPrompt("password")
	if err != nil {
		t.Fatalf("Failed to read password: %v", err)
	}

	if string(password) != "password" {
		t.Fatalf("Expected prompter to return 'password', but instead got '%s'.",
			string(password))
	}
}

func TestRandBytesSize(t *testing.T) {
	var prev []byte

	randData := RandBytes(4096)
	if randData == nil {
		t.Fatal("Failed to read random data.")
	}
	digest := sha256.Sum256(randData)
	prev = digest[:]

	for i := 0; i < 1024; i++ {
		randData := RandBytes(4096)
		if randData == nil {
			t.Fatal("Failed to read random data.")
		}
		digest := sha256.Sum256(randData)
		if bytes.Equal(digest[:], prev) {
			t.Fatal("Input wasn't random.'")
		}
		prev = digest[:]
	}
}

func TestZero(t *testing.T) {
	randData := RandBytes(4096)
	if randData == nil {
		t.Fatal("Failed to generate random data.")
	}
	Zero(randData)

	for i := range randData {
		if randData[i] != 0 {
			t.Fatalf("Element at %d is not zeroised.", i)
		}
	}
}

func TestSetNilPRNG(t *testing.T) {
	SetPRNG(nil)
	if PRNG() == nil {
		t.Fatal("util: prng should not be nil")
	}
}

func TestPRNGFails(t *testing.T) {
	SetPRNG(&bytes.Buffer{})
	r := RandBytes(16)
	if r != nil {
		t.Fatal("util: RandBytes should fail with PRNG failure")
	}

	n := NewNonce()
	if n != nil {
		t.Fatal("util: nonce generation should fail with PRNG failure")
	}
	SetPRNG(rand.Reader)
}

const (
	existingFile       = "testdata/test.txt"
	existingFileSHA256 = "43510aeb890cc65fefbf464fd2c0fc748c5b30fe53d22a907bad6a8cbdfd22d2"
	nonexistentFile    = "testdata/ENOENT"
	outputFile         = "testdata/test.out"
)

func TestExists(t *testing.T) {
	if ok, _ := Exists(existingFile); !ok {
		t.Fatal("util: Exists failed to find the test file")
	} else if ok, _ = Exists(nonexistentFile); ok {
		t.Fatal("util: Exists should fail to find the test file")
	} else if _, ok = Exists("/root/test.txt"); ok {
		t.Fatal("util: Exists should fail to check the test file")
	}
}

func TestErrorf(t *testing.T) {
	Errorf("testing Errorf")
	Errorf("testing Errorf\n")
}

func TestReadFile(t *testing.T) {
	in := os.Stdin

	data, err := ReadFile("-")
	if err != nil {
		t.Fatalf("%v", err)
	}

	os.Stdin, err = os.Open(existingFile)
	if err != nil {
		t.Fatalf("%v", err)
	}
	os.Stdin.Close()

	data, err = ReadFile("-")
	if err == nil {
		t.Fatalf("%v", err)
	}

	os.Stdin = in

	if len(data) != 0 {
		t.Fatalf("util: expected no data, but have %d bytes", len(data))
	}

	data, err = ReadFile(existingFile)
	if err != nil {
		t.Fatalf("%v", err)
	}

	h := sha256.New()
	h.Write(data)
	sum := fmt.Sprintf("%x", h.Sum(nil))
	if sum != existingFileSHA256 {
		t.Fatalf("util: expect SHA-256 digest of '%s', but have '%s'",
			existingFileSHA256, sum)
	}
}

func TestWriteFile(t *testing.T) {
	defer os.Remove(outputFile)

	data, err := ReadFile(existingFile)
	if err != nil {
		t.Fatalf("%v", err)
	}

	err = WriteFile(data, "-")
	if err != nil {
		t.Fatalf("%v", err)
	}

	out := os.Stdout
	os.Stdout, err = os.Create(outputFile)
	if err != nil {
		t.Fatalf("%v", err)
	}

	os.Stdout.Close()
	err = WriteFile(data, "-")
	os.Stdout = out
	if err == nil {
		t.Fatalf("%v", err)
	}

	err = WriteFile(data, outputFile)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestReadLineFails(t *testing.T) {
	firstLine := "Do not go gentle into that good night"

	var err error
	os.Stdin, err = os.Open(existingFile)
	if err != nil {
		t.Fatalf("%v", err)
	}

	in, err := ReadLine("test prompt: ")
	if err != nil {
		t.Fatalf("%v", err)
	}

	if firstLine != in {
		t.Fatalf("util: expected '%s', but have '%s'", firstLine, in)
	}

	_, err = ReadLine("test prompt: ")
	if err == nil {
		t.Fatalf("%v", err)
	}

	fmt.Println("")
}

func TestNonce(t *testing.T) {
	SetPRNG(nil)

	n := NewNonce()
	if n == nil {
		t.Fatal("util: failed to generate nonce")
	}
}
