package auth

import (
	"bytes"
	"crypto/rand"
	"testing"
)

var passwordAuth, wrongPasswordAuth *Authenticator

func TestNewPasswordAuth(t *testing.T) {
	var costs = []int{0, 5, 10, 11, 12, 32}
	for i := range costs {
		_, err := NewPasswordAuth("password", costs[i])
		if err != nil {
			t.Fatalf("%v", err)
		}
	}

	var err error
	passwordAuth, err = NewPasswordAuth("password", 0)
	if err != nil {
		t.Fatalf("%v", err)
	}

	wrongPasswordAuth, err = NewPasswordAuth("passwort", 0)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestNewPasswordAuthFailure(t *testing.T) {
	r := rand.Reader
	rand.Reader = &bytes.Buffer{}
	_, err := NewPasswordAuth("password", 10)
	if err == nil {
		t.Fatalf("auth: expect bcrypt failure on PRNG failure")
	}
	rand.Reader = r
}

func TestValidationAuth(t *testing.T) {
	upd, err := ValidatePassword(passwordAuth, "password")
	if err != nil {
		t.Fatalf("%v", err)
	} else if upd != false {
		t.Fatal("auth: password auth shouldn't require update")
	}

	_, err = ValidatePassword(wrongPasswordAuth, "password")
	if err == nil {
		t.Fatal("auth: expected password authentication to fail with bad password")
	}

	_, err = ValidatePassword(nil, "password")
	if err == nil {
		t.Fatal("auth: expected nil authenticator to fail validation")
	}
}
