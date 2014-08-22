## passcrypt
### password-based file encryption tool

This is a small utility for encrypting files with a passphrase. The
files are compressed with gzip and stored in an archive.

Encrypting several files:

```
passcrypt foo bar/baz/quux
```

This will encrypt the files into an encrypted file; by default, this
is `passcrypt.out`; the output file can be specified with `-f`. An
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
passcrypt -o tmp passcrypt.out
```
