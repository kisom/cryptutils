## readpass
### a Go package for reading passwords safely.

`readpass` provides an interface for reading passwords from the
console securely. Thanks to code from
[Matt Silverlock](https://github.com/elithrar), it no longer requires
cgo.

An example program is included under in the `example/example.go`
program; it reads a line of text and prints the length.


### CAVEATS

* Windows may or may not supported; I don't have the resources to
  test this.

### LICENSE

Copyright (c) 2013 Kyle Isom <kyle@tyrfingr.is>

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above 
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. 
