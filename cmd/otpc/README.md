## otpc
### A command-line two-factor authentication token manager

`otpc` is a specialised `secrets` store; this tool adds new tokens and
displays the next OTP. It is assumed that `secrets` will be used to
remove or otherwise manipulate the store.

For example, adding a new Google TOTP token:

```
$ otpc -t google -s test-service
Two-factor store passphrase> 
Secret: 
Confirmation: 623972
```

The current value of the token (updated every time step) can be
displayed with

```
$ otpc test-service
Two-factor store passphrase> 
579152
Updates in 15 seconds.
444802
```

The entry can be viewed with `secrets`, making sure to select the `otpc` store:

```
$ secrets -f ~/.otpc.db -m test-service
Secrets passphrase> 
Secret: otpauth://totp/test-service?secret=ABCDEFGH
Timestamp: 1403491135 (2014-06-22 19:38 PDT)
        key: ABCDEFGH
        step: 30s
        type: TOTP-GOOGLE
        confirmation: 623972
```


### QR codes

The `otpc` tool can be used to dump a QR code of the secret suitable
for use backing up the OTP tokens to Google Authenticator or similar
apps. The `-qr` flag causes `otpc` to dump a PNG containing the QR
code:

```
 $ otpc -qr test-service test-service.png
Two-factor store passphrase> 
$ ls *.png
test-service.png
```


### Compatibility

There is a prior tool that this is inspired by, also called
[otpc](https://github.com/kisom/otpc). The data stores are not
compatible. If you were using it, and I don't think you were, contact
me for a tool to dump the previous store.

### License

`otpc` is released under the ISC license.
