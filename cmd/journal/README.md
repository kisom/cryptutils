## journal
### a simple journal

This is a personal utility for journaling simple, text-only
journals. It uses the user's default editor (via the EDITOR
environment variable), falling back to the One True Editor (the Editor
of the Majestic And ClaSsy) if all else fails. Entries are encrypted
in a standard `secrets` store, and may be interacted with there as
well (i.e. to import/export journals).

New entries are created by creating a temporary file, calling the
editor on that file, reading it into the program, and removing it when
done. This is the primary weak point of the program. If this temporary
file can be accessed by other processes, its contents may be leaked
before it is secured.

Entries are displayed in plain text with no formatting; the output
could be piped elsewhere to display the entry with formatting, but I
don't find this useful and therefore haven't put it in.

To create a new password store *(defaults to `~/.cu_journal`)*:

```
journal -init
```

To create a new journal store specific file:
```
journal -init -f ~/.myjournal
```

To create a new journal store with interactive scrypt work factors:
```
journal -init -i
```
*If you specify interactive you'll need to specify it
for all other crud operations to the store.*
**This defaults to standard mode**

Writing an entry:

```
journal -w "Journal entry title"
```

Listing entries:

```
journal -l
```

Displaying an entry:

```
journal "Some entry"
```
