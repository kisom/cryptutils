package sync

import "github.com/kisom/cryptutils/common/auth"

// A User is one of the end-users in this system. They have an email
// address, which may be used for account recovery, an authenticator
// that they use to authenticate to the server, a set of blobs (e.g.
// the stores found in common/store/) to be synchronised, and a set of
// public keys used to encrypt data to the user.
type User struct {
	Login         string
	Email         string
	Authenticator *auth.Authenticator
	Blobs         map[string][]byte
	PublicKeys    map[string][]byte
}

// A RequestAuth contains the information from the user making the
// request.
type RequestAuth struct {
	Login string `json:"login"`
	OTP   string `json:"otp"`

	// The Label and Payload fields indicate which resource (i.e.
	// which blob or public key to operate on) and any data that
	// must be sent up to the server.
	Label   string `json:"label"`
	Payload []byte `json:"payload"`
}
