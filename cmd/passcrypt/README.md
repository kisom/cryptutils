## passcrypt
### password-based file encryption tool

This is a small utility for encrypting files with a passphrase. The
files are compressed with gzip and stored in an archive. Permissions
will be preserved; ownership isn't.


### Usage

```
passcrypt [-a -u -v] [-f packfile] [-o outdir] file
```

* `-a`: ASCII-armour (PEM-encode) an archive
* `-f` (default "passcrypt.out"): specify the output archive file
* `-o` (default "."): specify the output directory
* `-u`: unpack an archive
* `-v`: verbose mode


### Examples

```
passcrypt foo bar/baz/quux
```

This will pack the files into an encrypted archive file; by default,
this is `passcrypt.enc`; the output file can be specified with `-f`. An
armoured file can be produced by passing the `-a` flag:

```
passcrypt -a foo bar/baz/quux
```

will produce something along the lines of

```
-----BEGIN PASSCRYPT ARCHIVE-----
fOp4UW2CaB0dWEjo1M9w1bH8dDAijZx8wYVx6XWRrfHhMZa9WDf5O8+zVB8p6rz+
MrnGs209i+qNHc8JTn3JRGmV2pqGLYNr3BGhPw0FxPqDVHCYXAUy123feCJTx9TI
so0gdD426yAcn4Cw5KZXU90Fc+CgvgvNILxdFpcm7n7oYTsxL8KvvwMHIyPGr8GF
G1chcMe9IzV8CdXyWqT0vojYPS8bom3XhYLs4KkQQRHmVOjwtlMLrDkJa2xUXCqh
cqzu5go3TZOWjOY1A1zFMfaS9M6J8M080w0477T6ElVv7YfdJM5rVT6QPzNuiqZi
pxJQRzhb3he5MDhX3YWhj0vn9TT9EcSFtDLxYhcwrQ6nS1UJ+ynobfkCXLvojutv
1wr1GbonMWf5ZunjW7CU3uP+zl/x8vsMdX8Dm4bwiJrL4GlGfsuwrMOOmOGMKGf7
X6edR66xUxbzdPvAv5cs7RJ6f4W2sDukiHH9Ayhi+BmfbTW+eyqQMBeVrLg38MlE
JrZoFcRC7GQtPq20xHgP6OX0rTx0mvi9w9bnwJl9WQEE8YqOjAr26yQ2XWnjoCc/
rL6i2TH0upZw0T5g8UfCtAvvM/6I6x6NSi+fPjxSsGLh2A4hJiUqbIigKn96GLN2
9jbvMpOmVZHYAe8F3PLdUK7Oag==
-----END PASSCRYPT ARCHIVE-----
```

Unpacking the archive is done with the `-u` flag. Files will be
restored to their original path, with the current working directory
replacing the root. The output directory can be selected with `-o`.

```
passcrypt -o tmp passcrypt.enc
```

Verbose mode lists files as they are being packed or unpacked. For
example, while packing:

```
$ passcrypt -a -v common
Password: 
Pack directory common
Pack directory common/public
Pack file common/public/crypto.go
Pack file common/public/crypto_test.go
Pack directory common/secret
Pack file common/secret/.crypto.go.swp
Pack file common/secret/crypto.go
Pack directory common/store
Pack file common/store/doc.go
Pack file common/store/keystore.go
Pack file common/store/secretstore.go
Pack directory common/util
Pack file common/util/util.go
Pack file common/util/util_test.go
```

Alternatively, while unpacking:

```
$ passcrypt -v -u -o tmp passcrypt.out 
Password: 
Unpack common
Directory: common
Unpack common/public
Directory: public
Unpack common/public/crypto.go
Unpack common/public/crypto_test.go
Unpack common/secret
Directory: secret
Unpack common/secret/.crypto.go.swp
Unpack common/secret/crypto.go
Unpack common/store
Directory: common/store
Unpack common/store/doc.go
Unpack common/store/keystore.go
Unpack common/store/secretstore.go
Unpack common/util
Directory: common/util
Unpack common/util/util.go
Unpack common/util/util_test.go
```


### Cryptographic details

This encrypts files using the cryptutils standard cryptographic
library:

* Keys are derived from Scrypt using a 32-byte salt, N=32768,
  r=8, p=4.
* The salt is randomly generated and prepended to the ciphertext.
* The resulting gzip-compressed tar file is encrypted using NaCl's
  secretbox, using the derived key for encryption.
* The NaCl nonce is randomly generated.


### License

`passcrypt` is licensed under the ISC license. See the LICENSE file
in the project root for more details.


