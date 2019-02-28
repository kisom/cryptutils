package readpass

// This file contains utility functions for decrypting password protecting keys
// and password protecting keys.

import (
	"log"
	"os"

	"golang.org/x/crypto/ssh/terminal"
)

func SSHPasswordPrompt(prompt string) (password string, err error) {
	state, err := terminal.MakeRaw(0)
	if err != nil {
		log.Fatal(err)
	}
	defer terminal.Restore(0, state)
	term := terminal.NewTerminal(os.Stdout, ">")
	password, err = term.ReadPassword(prompt)
	if err != nil {
		log.Fatal(err)
	}
	return
}

// The PasswordPrompt function is the function that is called to prompt the user for
// a password.
var PasswordPrompt func(prompt string) (password string, err error) = DefaultPasswordPrompt

// The PasswordPromptBytes function is the same as PasswordPrompt,
// but returning a byte slice instead.
var PasswordPromptBytes func(prompt string) (password []byte, err error) = DefaultPasswordPromptBytes

// DefaultPasswordPrompt is a simple (but echoing) password entry function
// that takes a prompt and reads the password.
func DefaultPasswordPrompt(prompt string) (password string, err error) {
	state, err := terminal.MakeRaw(0)
	if err != nil {
		log.Fatal(err)
	}
	defer terminal.Restore(0, state)
	term := terminal.NewTerminal(os.Stdout, ">")
	password, err = term.ReadPassword(prompt)
	if err != nil {
		log.Fatal(err)
	}
	return
}

// DefaultPasswordPrompt is a simple (but echoing) password entry function
// that takes a prompt and reads the password.
func DefaultPasswordPromptBytes(prompt string) (password []byte, err error) {
	passwordString, err := PasswordPrompt(prompt)
	if err == nil {
		password = []byte(passwordString)
	}
	return
}
