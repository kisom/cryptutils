package util

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func testPrompt(prompt string) ([]byte, error) {
	return []byte(prompt), nil
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
			t.Fatalf("Element at %d is not zeroised.")
		}
	}
}
