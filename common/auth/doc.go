// Package auth contains one-time password authentication functionality
// for implementing authentication in a system design. An Authenticator
// contains authentication information, presumably for a user; the
// authentication token or password submitted by the user can be validated
// using the Validate function.
//
// This package currently supports password authentication (using bcrypt
// hashes), YubiKey OTPs, Google Authenticator standard TOTPs, and a
// basic session implementation.
package auth
