package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/gokyle/readpass"
	"github.com/kisom/cryptutils/cmd/migrate-store/legacy"
	"github.com/kisom/cryptutils/common/secret"
	"github.com/kisom/cryptutils/common/util"
)

// migrateStore decrypts a file using the legacy settings for scrypt,
// and re-encrypts with the current settings.
func migrateStore(path string) {
	prompt := fmt.Sprintf("Password for %s: ", path)
	pass, err := readpass.PasswordPromptBytes(prompt)
	if err != nil {
		util.Errorf("%v", err)
		os.Exit(1)
	}

	blob, err := legacy.DecryptFile(path, pass)
	if err != nil {
		util.Errorf("%v", err)
		os.Exit(1)
	}
	fmt.Printf("[+] Decrypted %s.\n", path)

	err = secret.EncryptFile(path, pass, blob)
	if err != nil {
		util.Errorf("%v", err)
		os.Exit(1)
	}
	fmt.Printf("[+] Migrated %s.\n", path)
}

func main() {
	flag.Parse()

	if flag.NArg() == 0 {
		return
	}

	for _, path := range flag.Args() {
		migrateStore(path)
	}
}
