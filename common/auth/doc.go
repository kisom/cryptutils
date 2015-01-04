// Package auth contains one-time password authentication functionality
// for implementing OTP or 2FA in a system design. Currently supported
// are YubiKey OTPs and Google-standard TOTPs. YubiKeys are preferred,
// but Google's restricted TOTPs are supported on mobile devices.
//
// The core type used by this package is the Authenticator; the Validate
// function takes an Authenticator and a string one-time password value
// and will verify that the password is correct for the authenticator.
// For Authenticators that must be kept in sync (such as those utilising
// a counter and those tracking the last OTP), they should be updated
// after a successful call to Validate.
//
// Basic YubiKey usage looks something like this:
//
// First, the user will submit their YubiKey's secret key as a byte
// slice, and provide an initial OTP. From this, the package will
// provide an Authenticator. The authenticator can now start receiving
// OTPs from the user, and validating them.
//
// TOTP usage is more complex, depending on whether the user is
// generating a new token or importing one. The NewGoogleTOTP will
// generate a new Google-authenticator-compatible token. From this, the
// authenticator should call ExportUserTOTP to retrieve the TOTP data to
// send to the user so the user can set up their token. The TOTPProvider
// global sets the default provider for new TOTP tokens. Once the user
// has set up their TOTP token, the authenticator can start accepting
// OTPs and validating them.
package auth
