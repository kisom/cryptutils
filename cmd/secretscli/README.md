## secretscli
### An interactive secrets client

This is an interactive secrets manager that acts on the same secret
stores used by the other tools in this collection. It offers a subset
of the functions provided by the `secrets` utility, but does so
interactively. To whit:

```
~/src/github.com/kisom/cryptutils/cmd/secretscli
(0) <straka:kyle> $ secrets -f secrets.db -i -init 
Secrets passphrase> 
creating store...
~/src/github.com/kisom/cryptutils/cmd/secretscli
(0) <straka:kyle> $ secretscli -f secrets.db -i 
Passphrase to unlock secrets.db: 
secrets.db command> list
Key store: 0 keys
secrets.db command> store mail db
[+] Storing secret for mail
New password: 
[+] Storing secret for db
New password: 
secrets.db command> wmeta db
Enter metadata; use an empty line to indicate that you are done.
key = value: host = db.local
key = value: user = db-user
key = value: name = blatdb 
key = value: 
secrets.db command> wmeta db 
Enter metadata; use an empty line to indicate that you are done.
key = value: name = blat-db
Note: replacing previous value of 'blatdb'
key = value: 
secrets.db command> store db
[+] Storing secret for db
db exists. Overwrite secret (y/n)? n
Not overwriting.
secrets.db command> store db
[+] Storing secret for db
db exists. Overwrite secret (y/n)? y
New password: 
secrets.db command> [+] storing secret store...
~/src/github.com/kisom/cryptutils/cmd/secretscli
(0) <straka:kyle> $ 
```

There's a help system too; enter the "help" command to see all the
supported commands.

The UI is admittedly weak for other people, but this is what I wanted.
