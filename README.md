## cryptutils

`cryptutils` is a set of common Go packages for doing encryption using
NaCl and Ed25519 keys. It also includes a set of command line tools:

* secrets: command-line secrets manager
* otpc: command-line two-factor authentication token manager
* journal: password-backed journal
* passcrypt: password-based file encryption

The useful tools are all password-based at this time. `secrets`, `otpc`,
and `journal` are all based on a common secret storage system. The
`secrets` program provides a general-purpose secret management system;
`journal` and `otpc` provide specialised interfaces for specific types
of secrets (notes and TOTP/HOTP keys, respectively).

The programs are in the `cmd/` subdirectory; each project has its own
README.

### The cryptography

`cryptutils` uses NaCl's secretbox (Salsa20 and Poly1305) for
secret-key encryption, NaCl's box (Curve25519, Salsa20, and Poly1305)
for public-key encryption, and Ed25519 for digital
signatures. Typically, secret keys are derived in one of ways: via
Scrypt, or via an ECDH exchange. For Scrypt, the parameters N=32768,
r=8, and p=4 are used. This makes generating keys using this expensive
(typically, around half a second on my 2.6 GHz i5 machine with 8G of
RAM). When encrypting messages using public keys, an ephemeral key is
generated for the encryption and a shared key is derived from
this. The public key is prepended to the message for extraction by the
recipient. When signing and encrypting using public keys, the message
is signed before encrypting. The recipient will decrypt, then validate
the signature.

### Motivation and history

I hated depending on my phone for managing two-factor authentication
(I prefer to not carry it around), which led to the first iteration of
`otpc`. This used Scrypt and NaCl to secure the tokens. Later, I
wanted a password manager that I could use on the command-line and
send passwords to xclip (or pbcopy if I was on a Mac); the first
iteration of `password` copied the `crypto.go` file from
`otpc`. Finally, I wanted to replace `sshcrypt` with a
NaCl/Ed25519-based system; at this point, I realised that it would be
easier to refactor the crypto components into a common set of
packages. This included building a generalised keyring for `fcrypt`
and, realising that the same data structure lent itself well to
`password` and `otpc`, a common datastore for secrets. Eventually,
`passwords` was renamed to `secrets` when I began to use it for
manipulating the `otpc` store, letting me keep a lot of unnecessary
functionality out of `otpc`. At some point, I realised the datastore
could also be used for storing journal entries, and added a journaling
front end.

### Dependencies

* code.google.com/p/go.crypto
* github.com/agl/ed25519
* github.com/gokyle/twofactor
* github.com/gokyle/readpass 

### License

`cryptutils` is licensed under the ISC license.

