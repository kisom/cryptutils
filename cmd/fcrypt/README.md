## fcrypt
### command line encryption utility

This is a tool to perform signcryption operations using Ed25519 and
NaCl. It is modeled on one key per instance; for example, I end up
having separate keys for my machines (unless I copy the keystore
around).

The first time it is run, it will generate a password-protected
private key, which consists of both a Curve25519 and Ed25519 private
key. The public key can be exported with `fcrypt -export <filename>`,
where `filename` can be "-" to dump the key to stdout.

### Adding keys

Exported keys include a signature. When exporting your own public key,
the key will be self-signed. The keystore operates on a web-of-trust,
however, and fcrypt won't import self-signed keys by default. To
bootstrap a key into the web-of-trust, you'll need to allow untrusted
keys for import.

Importing a key with a trusted signature:

```
$ fcrypt -import <file>
```

Importing a self-signed key (or a key with a signature not in the keystore):

```
$ fcrypt -u -import <file>
```

Both of these will prompt for a label to store the key under; the
special label "self" can't be used for imported keys, as it refers to
the owner's key.

A public key can be removed with the `-r` flag; a label will be
prompted for. The current public keys can be listed with the `-k`
flag:

```
$ fcrypt -k
Key store was last updated 2014-06-22 19:29 PDT
3 keys stored
Key store:
        tyrfingr
                Last update: 2014-06-22 19:26 PDT
                  Signed at: 2014-06-22 19:26 PDT
                  Signed by: self
        ono-sendai
                Last update: 2014-06-19 18:10 PDT
                  Signed at: 2014-06-19 18:10 PDT
                  Signed by: self
        straka
                Last update: 2014-06-22 19:29 PDT
                  Signed at: 2014-06-22 19:27 PDT
                  Signed by: tyrfingr
```

### Encrypting and Decrypting

Encrypting a file requires selecting a label (which defaults to
"self", i.e. because the most common operation I do is encrypting
files to myself) using the `-l` argument, and passing the `-e`
flag. For example,

```
$ fcrypt -e backup.tgz backup.tgz.enc
```

The same thing can be done with a label to encrypt a different public
key:

```
$ fcrypt -e -l tyrfingr backup.tgz remote-backup.tgz.enc
```

Alternatively, the encrypted file can be ASCII-armoured with the `-a`
flag.

```
$ fcrypt -a -e backup.tgz backup.tgz.enc
$ head backup.tgz.enc
-----BEGIN CRYPTUTIL ENCRYPTED MESSAGE-----
+c0n6J88GjiQZId7/gfUte28BrOvnvBtR35sYYI+u3mQlz9iBDP7vnh477jFhz3Z
M5oaorflqR7XrcQJhU9nJAWhu28sn4/EpBJ1XbI9GNzfv+ZrB/zVkwmuVq+ZG5eT
zUQYNpZawMzmV0RwGsTnV4JuspodHNkxHQMI/lzfK5+VgMVfmlmKFzPBD+HQyNdD
XgrKi1+TWijSz/D49o9ArOXBwAApQjTI0NidM1D6Z4EMQQaHFibTJ/ACEWeoRJ+F
JLqP/3kvhrdk/hyyMAtevLaLeRe+cXAb0/bXYUhS6uU7CBaRX93FxFwwvfqsy9RI
/wFrnrj192hED6jxb00Tvmijk6waQ3VJGkyegCN6eaY0Lcsk9zSb6+LZAZMFxU9c
k68/OyXr+yZMf19C9ePculEwFtZNZ9QLjn3LQeKPc9q26l55Se3tbyYCM1vHCR8U
2kYh7S2EnQBFig39nl4qF0eU/68womZKRokGzdBS3WDcz4mJU3zPn30c9g1zY1DB
sKkkNlc7d+EX8yb8qJPQqnj3P8wvTSQfuJi2KJTrgij+EOKkr74JBBCJEq6jzLbe
```

Encryption uses ephemeral Curve25519 keys, and doesn't require
unlocking the keystore.

Decrypting is performed with the `-d` flag. The armour flag has no
effect, as decrypt will handle armoured files transparently.

```
$ fcrypt -d backup.tgz.enc backup.2.tgz
keystore passphrase> 
$ diff backup.tgz backup.2.tgz 
$ 
```

### Signing and Verifying

A file can be signed with the `-s` flag.

```
$ fcrypt -s backup.tgz backup.tgz.sig
```

The signature can be verified with the `-v` flag:

```
$ fcrypt -v backup.tgz backup.tgz.sig
Signature: OK
```

If the file was signed by another key, the `-l` argument is needed to
identify the signing public key. For example, if I wanted to verify
the previous file on my server, I need to tell `fcrypt` to use the key
for my laptop (labeled "ono-sendai") for verification:

```
kyle@tyrfingr $ fcrypt -v -l ono-sendai backup.tgz backup.tgz.sig
Signature: OK
```

### Signcryption

The `-s` and `-e` flags can be combined to perform signcryption: the
message is signed and then encrypted to the label named by the `-l`
argument. This will automatically armour the file so that `fcrypt` can
deal with it appropriately.

```
$ fcrypt -s -e -l tyrfingr backup.tgz backup.tgz.enc
keystore passphrase>
$ head backup.tgz.enc
----BEGIN CRYPTUTIL SIGNED AND ENCRYPTED MESSAGE-----
vkjTUfVHnjFwdHd4tcknAVJtgpManHphj3YtIDoiHRe4lEoyI6gku+5EXLb5kRE2
3GL8c4AsWuyIY4BZR1kHRRivdXGTdOvEx31iIxjIGTZ9AdQB/xpUkEFyCuVDYL9f
w3jR6gGiQmM5icZZZKpW35I9wSnKgFCUCZG/wzFmHJMzWxqnU70z6uh9EkLMmz8/
p2JGmRgDzlZ+EJLyRDpD9JYLGsvVRfFqevsfU0LDVDs8cjb8rZfaEh+EwZjTOm6Z
178QQF6ykABHoWLQmrUmHL00S9Hgdc6jS/qrpk9tvAcEd8pRkL+r9ORXTZqOwYuH
cGpiHnw7ItkbbN/fuZiPS28xRx5Ir73jCZvdyacKySxjmFcs1XuvMZq1T8lg3Dw4
TYh9yxY4P+5j5MwH9nf8khsqjyDF/rGQYtEE7aYUv+qCTEVPbR9gofSb36qxh9di
kDhthilJ7mKx0QGuqS+KC5F6MjQG51JLzCcD1EotHZbTudUe4Mz4AwLwPYMboeHd
Qfcf3Fq4tGChO3646YQmfFyCanSqEzq5/hJWSX+slpJE3DXoR6VnaOkfFQU9Dq60
```

The `-d` flag will also handle this case transparently, but requires
the `-l` argument to be set appropriately to verify the signature.

### Miscellanea

The integrity of the keystore can be checked with `-check`: it will
ensure the keystore unlocks properly, ensures the keystore is valid,
and performs a key audit. Key audits ensure that every public key has
a signature chain leading back to "self".

The keystore can be changed using the `-f` option to name a file.

### License

`fcrypt` is released under the ISC license.
