// Package util contains utility code common to the cryptutils programs.
package util

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/gokyle/readpass"
)

// Version contains the current version of the cryptutils system. See
// semver.org for a description of this format.
var Version = struct {
	Major int
	Minor int
	Patch int
	Label string
}{1, 1, 0, ""}

// VersionString returns a formatted semver structure from Version.
func VersionString() string {
	return fmt.Sprintf("%d.%d.%d%s", Version.Major,
		Version.Minor, Version.Patch, Version.Label)
}

// A PassPrompt is a function that takes a string to display to the
// user, and returns a byte slice containing the user's input if no
// error occurred.
var PassPrompt = readpass.PasswordPromptBytes

var prng = rand.Reader

// RandBytes is a wrapper for retrieving a buffer of the requested
// size, filled with random data. On failure, it returns nil.
func RandBytes(size int) []byte {
	p := make([]byte, size)
	_, err := io.ReadFull(prng, p)
	if err != nil {
		p = nil
	}
	return p
}

// PRNG returns the current PRNG being used by the package.
func PRNG() io.Reader {
	return prng
}

// SetPRNG is used to change the PRNG. This should only be used in
// testing to validate PRNG failures. If nil is passed as the reader,
// crypto/rand.Reader will be used.
func SetPRNG(r io.Reader) {
	if r == nil {
		r = rand.Reader
	}
	prng = r
}

// Zero wipes out a byte slice. This isn't a bulletproof option, as
// there are many other factors outside the control of the program
// that come into play. For example, if memory is swapped out, or if
// the machine is put to sleep, the program has no control over what
// happens to its memory. In order to combat this, we try to wipe
// memory as soon as it is no longer used. In some cases, this will be
// done with deferred statements to ensure it's done; in other cases
// it will make sense to do it right after the secret is used.
func Zero(in []byte) {
	for i := range in {
		in[i] ^= in[i]
	}
}

// NonceSize contains the size, in bytes, of a NaCl nonce.
const NonceSize = 24

// NewNonce generates a new random nonce for use with NaCl. This is a
// 192-bit random number. In this set of utilities, only one nonce is
// ever actually used with a key in most cases.
func NewNonce() *[NonceSize]byte {
	var nonce [NonceSize]byte
	p := RandBytes(NonceSize)
	if p == nil {
		return nil
	}
	copy(nonce[:], p)
	return &nonce
}

// Exists is a convenience function that returns a pair of booleans
// indicating whether a file exists or whether an error occurred
// checking the file.
func Exists(path string) (bool, bool) {
	if _, err := os.Stat(path); err == nil {
		return true, true
	} else if os.IsNotExist(err) {
		return false, true
	}
	return false, false

}

// Errorf is a convenience function for printing errors and warnings
// in the standard format used by this project.
func Errorf(m string, args ...interface{}) {
	m = "[!] " + m
	if m[len(m)-1] != '\n' {
		m += "\n"
	}
	fmt.Fprintf(os.Stderr, m, args...)
}

// ReadFile is a convenience function that transparently handles
// reading from a file or standard input as necessary.
func ReadFile(path string) ([]byte, error) {
	if path == "-" {
		return ioutil.ReadAll(os.Stdin)
	}
	return ioutil.ReadFile(path)
}

// WriteFile is a convenience function that transparently handles
// writing to a file or stdout as necessary.
func WriteFile(data []byte, path string) error {
	if path == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}
	return ioutil.WriteFile(path, data, 0644)
}

// ReadLine reads a line of input from the user.
func ReadLine(prompt string) (line string, err error) {
	fmt.Printf(prompt)
	rd := bufio.NewReader(os.Stdin)
	line, err = rd.ReadString('\n')
	if err != nil {
		return
	}
	line = strings.TrimSpace(line)
	return
}
