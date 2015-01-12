# common-auth

This package implements authentication using a variety of authentication
mechanisms in a manner that allows multiple schemes to be supported.


## The `Authenticator`

The `Authenticator` type carries the authentication information that
can be used to validate a submitted password or authentication token. It
contains four fields: a string identifying the type of the authenticator,
a label (for example, to specify an account name), a byte slice containing
the authentication secret, and a field for storing the last entered
password (which is used by the one-time password authenticators to store
the last OTP to prevent replay attacks).

An `Authenticator` is initialised using a constructor appropriate to
the type of authenticator to be used. Once initialised, it may be stored
as needed; for example, perhaps in a SQL table or as a map serialised
to JSON.

A loaded `Authenticator` may be used to validate an authentication token
(such as a password) using the `Validate` function:

```
shouldUpdate, err := auth.Validate(user.Auth, password)
if err != nil {
	log.Println("failed authentication from user", user.Name)
	// Handle failure in an app-appropriate way.
}
```

The `Validate` function uses the mapping from `Validators` to determine
which function to call for a given authentication type. This may be used
to add additional authentication types in a system that aren't present
in this package.

`Validate` returns a `bool` and `error` pair; the `error` indicates
whether the authentication is valid (`nil`), whether the authenticator
is invalid in some way (`ErrInvalidAuthenticator`), or whether the
authentication token is invalid (`ErrValidationFail`). The `bool`
indicates whether the `Authenticator` has changed (for example, a counter
was incremented or a new last OTP was stored). If it's true, the
authenticator should be updated in any persistent storage; in the
functions provided in this package, it will only ever be true if the
validation was succesful.

An `Authenticator` also has the method `Zero`: this will zeroise its
`Secret` field, and it's subject to the same caveats noted in the
`util.Zero` function documentation.


## Password authentication

Password authentication stores passwords as bcrypt hashes; a new
`Authenticator` for a password is created using `NewPasswordAuth`:

```
user.Auth, err = auth.NewPasswordAuth(password, 0)
if err != nil {
	log.Printf("failed to create password auth for %s: %v", user.Name, err)
	// Application-specific error handling.
}
```


## YubiKey authentication

Currently, this supports single-purpose YubiKey OTPs: where a YubiKey
is used only for this application. Support for a validation server is
planned, as is support for YubiHOTP.

A YubiKey `Authenticator` is initialised with `NewYubiKey`, which takes
the key (which should be hex-decoded into a byte slice), and the initial
OTP for syncing.

```
func readYubiAuth() (*auth.Authenticator, error) {
	k, err := util.ReadLine("Hex-encoded key: ")
	if err != nil {
		log.Printf("failed to create authenticator: %v", err)
		return nil, err
	}

	kb, err := hex.DecodeString(k)
	if err != nil {
		log.Printf("failed to create authenticator: %v", err)
		return nil, err
	}

	otp, err := util.ReadLine("OTP: ")
	if err != nil {
		log.Printf("failed to create authenticator: %v", err)
		return nil, err
	}

	a, err := auth.NewYubiKey(kb, otp)
	if err != nil {
		log.Printf("failed to create authenticator: %v", err)
		return nil, err
	}

	return a, nil
}
```

For the YubiKey in the tests, this would look like:

```
Hex-encoded key: 971ab1c6b0400448c685e650f895195a
OTP: brknecvrdjcrbvldbdffbvjuigjhjhugfcvudrndjufl
```

A YubiKey authenticator will always need to be updated, as it contains
a counter and last value.


## Google Authenticator authentication

The package also supports the TOTP tokens used by the Google Authenticator
app. There are two options for creating a new TOTP token: generating a
new token, or importing one.

Generating a random TOTP returns an `Authenticator`, the `UserTOTP`
details that should be given to the user, and an error value. If the
label passed to the `NewGoogleTOTP` function is not an empty string,
a PNG-encoded QR code will be included in the user details.

```
func createNewTOTP(username string) {
	a, ud, err := NewGoogleTOTP("demo service")
	if err != nil {
		log.Printf("failed to create new Google TOTP: %v", err)
		// App-specific error handling.
	}

	// storeAuthenticator would be some function setting up a mapping
	// between username and the newly-created authenticator in
	// persisent storage.
	storeAuthenticator(username, a)

	// sendPNG might display the QR code for the user as part of
	// the registration process.
	sendPNG(username, ud.QR)
}
```

A TOTP authenticator will always need to be updated after a successful
validation.


## Session authentication

This authenticator is intended for several specific projects and will
likely be of limited utility to other projects.

The session authenticator provides one mechanism for supporting
shared sessions based on public keys and HMAC-SHA-256. The user should
submit a public key generated using the `common/public` package of this
project. The session initialisation function will generate an ephemeral
key pair to derive a shared HMAC-SHA-256 key. The ephemeral public key
will be returned and should be sent to the user, who sets up a key
exchange. The server will send the user a "next" value. The user computes
the HMAC of this next value and sends the (next, mac) pair up to the
server as the next authentication.

The `Last` contains the last generated "next" value. This should be sent
to the user after session setup and after each validation.

Setting up the session:

```
a, sessionPublic, err := auth.NewSession(userPublic)
if err != nil {
	log.Printf("failed to set up new session: %v", err)
	// App-specific error handling.
}
```


When the user receives the public key, they set up a session:

```
session, ok := auth.KeySession(privateKey, sessionPublic)
if !ok {
	log.Println("failed to key session")
	// App-specific error handling.
}
```

When the user wants to generate a new session token, they call `OTP`. The
next value will be hex-encoded in the `Authenticator`; the user will
need to decode it before passing it to this function.

```
otp := session.OTP(next)
```

When the session is done, it can be zeroised:

```
session.Zero()
```


## Example: login

The `examples/login` package contains a demo program that simulates a
login prompt and a registration system. It stores users and their
authenticators in a JSON store file.

To register new users, use the "register" command:

```
$ go run login.go register
Login name: kyle
Supported authentication types:
        password
        yubikey
        TOTP
Authentication type: password
Password: 
2015/01/09 16:38:16 registered kyle
```

With the TOTP registration, a QR code will be stored in `qr.png`.

The authentication can be tested using the "run" command; enter an empty
user name to exit.

```
$ go run login.go run
User name: kyle
Password: password
2015/01/09 16:41:23 authentication successful
User name: kyle
Password: passwort
2015/01/09 16:41:29 authentication failed (auth: authentication failed)
User name: nouser
Password: password
2015/01/09 16:41:40 authentication failed (no such user)
User name: 
```

