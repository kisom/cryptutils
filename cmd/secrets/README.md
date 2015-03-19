## secrets
### a command line secrets manager

This a personal secrets manager, written for me, that operates on the
command line. I wrote it primarily to store and retrieve passwords
and optional metadata, but it can be used to store almost any kind of
secret. It is also a general utility for interacting with secret
stores built using the
[github.com/kisom/cryptutils/common/store](https://godoc.org/github.com/kisom/cryptutils/common/store)
By default, secret are stored to `${HOME}/.secrets.db` (you can see
this with `secrets -h`, observing the default value for the `-f`
flag). This can be changed by passing an argument to the `-f` flag.

This isn't designed for sharing secrets or anything terribly
complicated. It's essentially a password-protected key-value
store. It's not meant for using on a phone (I avoid using mine as much
as possible).

## Usage (using a password manager example):

To create a new password store *(defaults to `~/.secrets.db`)*:

```
secrets -init
```

To create a new password store specific file:
```
secrets -init -f ~/.mysecrets
```

To create a new password store with interactive scrypt work factors:
```
secrets -init -i
```
*If you specify interactive you'll need to specify it
for all other crud operations to the store.*
**This defaults to standard mode**

To add a new password (password set):

```
secrets -s label
```

To retrieve the password for *label*:

```
secrets label
```

To retrieve a password in a form suitable for exporting to the clipboard:

```
secrets -x label
```

To change the password for *label* (password set overwriting):

```
secrets -s -w label
```

To remove the password for *label* (password remove):

```
secrets -r label
```

To change the master password for the password store:

```
secrets -c
```

To add metadata to *label* (password store metadata):

```
secrets -s -m label
```

To view metadata when retrieving the password for *label* (password metadata):

```
secrets -m label
```

To enter multiple labels and passwords in the same session:

```
secrets -multi
```

Both entering metadata and multiple labels/secrets will stop when
the first empty line is entered.


## Example

For the sake of argument, let's assume you have three accounts:

* example.net with password "password1"
* example.com with password "password2"
* example.org with password "password3"

The example.com account additionally has three security questions:

* Q. "What is your name?" A. "Sir Lancelot of Camelot"
* Q. "What is your quest?" A. "To seek the Holy Grail"
* Q. "What is your favourite colour?" A. "blue"

Since you're using `secrets` for the first time, you can enter all
these passwords at once:

```
$ secrets -multi
Secrets passphrase> 
Use an empty name to indicate that you are done.
Name: example.net
Password: 
Name: example.com
Password: 
Name: example.org
Password: 
Name: 
$ 
```

If you list the accounts stored:

```
$ secrets -l
Secrets passphrase> 
Secrets store was updated  2014-06-13 15:45 PDT
3 entries

Names:
        example.com
        example.net
        example.org
```

You can enter the security questions for example.com:

```
$ secrets -s -m example.com
Secrets passphrase> 
Enter metadata; use an empty line to indicate that you are done.
key = value: What is your name? = Sir Lancelot of Camelot
key = value: What is your quest?=To seek the Holy Grail
key = value: What is your favourite colour?= blue
key = value: 
$
```

By default, `secrets` won't show metadata when retrieving a secret:

```
$ secrets example.com
Secrets passphrase> 
Secret: password2
$
```

You can show metadata with the `-m` flag:

```
$ secrets -m example.com
Secrets passphrase> 
Secret: password2
Timestamp: 1403218106 (2014-06-13 15:48 PDT)
        What is your name?: Sir Lancelot of Camelot
        What is your quest?: To seek the Holy Grail
        What is your favourite colour?: blue
```

Perhaps you want to copy the password to the clipboard on your OpenBSD machine:

```
$ secrets -x example.net | xclip
$ secrets -x example.net | xclip
Secrets passphrase> %
```

Over on your Mac, you can do the same with:

```
secrets -x example.net | pbcopy
Secrets passphrase> %
```

Meanwhile, it looks like example.org has changed their privacy policy,
and you don't like the direction they're taking. So, you've deleted
your account there. Time to remove it from `secrets`:

```
$ secrets -r example.org
Secrets passphrase> 
Removed  example.org
$
```

If you list your accounts again:

```
 $ secrets -l
Secrets passphrase> 
Secrets store was updated  2014-06-13 15:51 PDT
2 entries

Names:
        example.com
        example.net
$
```

Some time passes, and you think you should change your master password.

```
$ secrets -c
Secrets passphrase> 
New password: 
$
```

If you wanted to back up your password database, you can pass around
the binary file, or you can export to PEM.

```
$ secrets -export -
-----BEGIN SECRET STORE-----
M+HJbnBSYW9AIduxcbbm3v9HhygQ5WCLrNMehVokkVW/mepBV7ZoZtTY3356AhrP
p7pxOSIsIhWcrMAJ+c01M99RQkKlVICeA58Eg3w0vOGOLNYEhTufJO+hI76T5C+2
ohh9q23dO15ymVhUHmf95+/ZRwrnNQt/4NgcMMOAGAcHcFdqVtoMiNHhX8DaeyID
Q4xAm+J+0IiMAeb2pbq7id4K7pJzbD08IMd1PDB4biw4Oup3WWrPQ3Vv/BTkZiYp
cMeYab77qY2QempGVenZw5GXLghoHjh5+DRatmvevtL3/jzCBPvF/7DDEFvGNvac
IzhgrlHsCyFiErkz0WzRUQb1ZjagPHW+bEfBOfqWSsmwyXDev6RVi8D1DrkGehEI
mbcj6SgL4gb3vajNwpjpUoxPohLg7G3Qb9ULvGcJC4gJyZqofXsVnV3ApKvfgHoH
IBduB/jxISp7IbyarZsLrOj3IdxPBdzPBXTLn0t2x5w29aaIw/uSA0v4Sqfy9qWs
m8LILfFgw6Pfe+NUH+guOQCSJRjWvN8gUXKnduMkwPeJ4zR+wcQ33Gz/F7YjiCMJ
Y8AT6Bc1uLthT5aXGCrS08l1M7gdctVVPio4wjNTnyRK0Y3H3Zmi0j4p
-----END SECRET STORE-----
$
```

Maybe you'd rather actually store it to a file, instead of printing to
standard output:

```
$ secrets -export passwords.pem
$ cat passwords.pem 
-----BEGIN SECRET STORE-----
M+HJbnBSYW9AIduxcbbm3v9HhygQ5WCLrNMehVokkVW/mepBV7ZoZtTY3356AhrP
p7pxOSIsIhWcrMAJ+c01M99RQkKlVICeA58Eg3w0vOGOLNYEhTufJO+hI76T5C+2
ohh9q23dO15ymVhUHmf95+/ZRwrnNQt/4NgcMMOAGAcHcFdqVtoMiNHhX8DaeyID
Q4xAm+J+0IiMAeb2pbq7id4K7pJzbD08IMd1PDB4biw4Oup3WWrPQ3Vv/BTkZiYp
cMeYab77qY2QempGVenZw5GXLghoHjh5+DRatmvevtL3/jzCBPvF/7DDEFvGNvac
IzhgrlHsCyFiErkz0WzRUQb1ZjagPHW+bEfBOfqWSsmwyXDev6RVi8D1DrkGehEI
mbcj6SgL4gb3vajNwpjpUoxPohLg7G3Qb9ULvGcJC4gJyZqofXsVnV3ApKvfgHoH
IBduB/jxISp7IbyarZsLrOj3IdxPBdzPBXTLn0t2x5w29aaIw/uSA0v4Sqfy9qWs
m8LILfFgw6Pfe+NUH+guOQCSJRjWvN8gUXKnduMkwPeJ4zR+wcQ33Gz/F7YjiCMJ
Y8AT6Bc1uLthT5aXGCrS08l1M7gdctVVPio4wjNTnyRK0Y3H3Zmi0j4p
-----END SECRET STORE-----
$
```

Now, you want to import this on another machine:

```
$ secrets -import passwords.pem
$ secrets -l
Secrets passphrase> 
Secrets store was updated  2014-06-13 15:52 PDT
2 entries

Names:
        example.com
        example.net
$
```

(The password for this example store is "password!", and you can
import it on your machine from PEM to see for yourself.)

It looks like your favourite colour is now yellow, so you'll want to
remove that bit of metadata and re-add it:

```
$ secrets -r -m example.com
Secrets passphrase> 
Keys:
        What is your favourite colour?
        What is your name?
        What is your quest?
Remove key: What is your favourite colour?
Deleted key What is your favourite colour?
Keys:
        What is your name?
        What is your quest?
Remove key: 
$ secrets -s -m example.com
Secrets passphrase> 
Enter metadata; use an empty line to indicate that you are done.
key = value: What is your favourite colour? = yellow
key = value: 
$
```

One of your friends now has a hot startup at example.io, and you want
to add your account there:

```
 $ secrets -s example.io
Secrets passphrase> 
New password: 
```

Time passes, and you get an email from example.com that they've had a
database breach, and your password is compromised. As a safety
measure, `secrets` won't let you just overwrite a password:

```
$ secrets -s example.com
Secrets passphrase> 
[!] Failed: entry exists, not forcing overwrite
$
```

You can tell `secrets` to overwrite the stored passphrase with the
`-w` flag:

```
 $ password -s -w example.com
Secrets passphrase> 
[!] *** WARNING: overwriting password
New password: 
$
```

There's not much else to `secrets`.


## Import / export

The password store can be imported from PEM or exported to PEM. Pass
either "-export" or "-import", and provide the source (when importing)
or destination (when exporting) file as the only argument. If "-" is
used as a filename, `secrets` will use either standard input or
standard output, as appropriate. This might be useful, for example, in
emailing the file to yourself or storing a printed backup.


## The password store:

The secrets are stored internally using a Go map; when dumped to
disk, it is first encoded to JSON, then encrypted using NaCl's
secretbox. The key for NaCl is derived using Scrypt (N=32768, r=8,
p=4) with a 32-byte salt that is randomly generated each time the
file is saved. The salt is stored as the first 32 bytes of the file.

I've taken care to attempt zeroing memory and passphrases where I can,
but there are no guarantees this is effective.

### JSON layout

```
{
    "Version": 1,
    "Timestamp": 1400529440,
    "Store": {
        "example.net": {
            "Label": "example.net",
            "Timestamp": 1400529440,
            "Secret": "cGFzc3dvcmQ=",
            "Metadata": {
                "email": "me@example.net"
            }
        },
        "example.org": {
            "Label": "example.org",
            "Timestamp":  1400537177,
            "Secret": "cGFzc3dvcmQy"
        }
    }
}
```


## See also

* OTPC -- a specialised secret store (build using the same core as
  `secrets`) for storing and displaying two-factor authentication
  tokens.
* [apg](http://www.adel.nursat.kz/apg/) -- the automated password
  generator. It's in OpenBSD's packages, Ubuntu's repositories, and
  Homebrew (and possibly others that I didn't check). I use this for
  generating passwords.


## Compatibility

There is a [previous version](https://github.com/kisom/secrets/) that
this was inspired by; the store is nearly (but not quite)
compatible. Namely, everything but the secrets will show up. If you
were using it, and I don't think you were, contact me for a tool to
dump the previous store.


## License

`secrets` is released under the ISC license.
