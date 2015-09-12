package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/gokyle/readpass"
	"github.com/kisom/cryptutils/common/store"
	"github.com/kisom/cryptutils/common/util"

	"golang.org/x/crypto/ssh/terminal"
)

var dispatch = map[string]func(args []string) error{
	"clear":   clearTerm,
	"help":    help,
	"list":    listSecrets,
	"quit":    quitProgram,
	"passwd":  passwd,
	"rmeta":   readMeta,
	"show":    showSecret,
	"showhex": showSecretHex,
	"store":   storeSecret,
	"wmeta":   writeMeta,
	"write":   cmdWriteStore,
}

func quitProgram(args []string) error {
	shutdown()
	os.Exit(0)
	return nil /* yes, this is required */
}

func clearTerm(args []string) error {
	fmt.Println("\033[H\033[2J")
	return nil
}

func dumpKeys(keys []string) {
	for i := range keys {
		fmt.Println(keys[i])
	}
}

func passwd(args []string) error {
	newPass, err := util.PassPrompt("New password: ")
	if err != nil {
		return err
	}

	confirmPass, err := util.PassPrompt("Confirm: ")
	if err != nil {
		return err
	}

	if !bytes.Equal(confirmPass, newPass) {
		return errors.New("passwords don't match")
	}

	util.Zero(confirmPass)

	session.Store.ChangePassword(newPass)
	fmt.Println("[+] Password updated.")
	return nil
}

func dumpFmtKeys(keys []string, w int) {
	// Two columns, indent a tab.
	split := w/2 - 8
	first := fmt.Sprintf("\t%%-%ds", split)

	for i := 1; i < len(keys)+1; i++ {
		if (i % 2) == 1 {
			fmt.Printf(first, keys[i-1])
		} else {
			fmt.Println(keys[i-1])
		}
	}
	if len(keys)%2 == 1 {
		fmt.Printf("\n")
	}
}

func listSecrets(args []string) error {
	var keys = make([]string, 0, len(session.Store.Store))

	w, _, err := terminal.GetSize(1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		w = 80
	}

	var max int
	for label := range session.Store.Store {
		if len(args) > 0 {
			var match bool
			for _, pat := range args {
				if strings.Contains(label, pat) {
					match = true
					break
				}
			}

			if !match {
				continue
			}
		}

		keys = append(keys, label)
		if len(label) > max {
			max = len(label)
		}
	}

	fmt.Printf("Key store: %d keys\n", len(keys))
	sort.Strings(keys)
	if max > w {
		dumpKeys(keys)
	} else {
		dumpFmtKeys(keys, w)
	}
	return nil
}

func showSecret(args []string) error {
	switch {
	case len(args) == 0:
		return errors.New("No labels specified.")
	case len(args) == 1:
		r, ok := session.Store.Store[args[0]]
		if !ok {
			fmt.Println("[!]", args[0], "not found.")
		} else {
			fmt.Println(string(r.Secret))
		}
	default:
		for _, label := range args {
			r, ok := session.Store.Store[label]
			if !ok {
				fmt.Println("[!]", label, "not found.")
			} else {
				fmt.Printf("%s: %s\n", label, string(r.Secret))
			}
		}
	}
	return nil
}

func showSecretHex(args []string) error {
	switch {
	case len(args) == 0:
		return errors.New("no labels specified.")
	case len(args) == 1:
		r, ok := session.Store.Store[args[0]]
		if !ok {
			fmt.Println("[!]", args[0], "not found.")
		} else {
			fmt.Printf("%x\n", r.Secret)
		}
	default:
		for _, label := range args {
			r, ok := session.Store.Store[label]
			if !ok {
				fmt.Println("[!]", label, "not found.")
			} else {
				fmt.Printf("%s: %x\n", label, r.Secret)
			}
		}
	}
	return nil
}

const timeFormat = "2006-01-02 15:04:05 MST"

func readMeta(args []string) error {
	if len(args) == 0 {
		return errors.New("no labels specified.")
	}

	for _, label := range args {
		r, ok := session.Store.Store[label]
		if !ok {
			fmt.Printf("[!] %s not found.\n", label)
			continue
		}

		fmt.Printf("Record: %s\n", label)
		fmt.Printf("\tLast modification: %s (timestamp %d)\n",
			time.Unix(r.Timestamp, 0).Format(timeFormat),
			r.Timestamp)
		if len(r.Metadata) > 0 {
			fmt.Println("\tMetadata:")
			for k, v := range r.Metadata {
				fmt.Printf("\t\t%s: %s\n", k, v)
			}
		}
	}
	return nil
}

func writeMeta(args []string) error {
	if len(args) == 0 {
		return errors.New("no label specified")
	} else if len(args) > 1 {
		return errors.New("only one label may be specified")
	}

	label := args[0]
	r, ok := session.Store.Store[label]
	if !ok {
		return errors.New("no such record")
	}

	if r.Metadata == nil {
		r.Metadata = map[string][]byte{}
	}

	fmt.Println("Enter metadata; use an empty line to indicate that you are done.")
	for {
		line, err := util.ReadLine("key = value: ")
		if err != nil {
			return err
		} else if line == "" {
			break
		}

		meta := strings.SplitN(line, "=", 2)
		if len(meta) < 2 {
			util.Errorf("Metadata should be in the form 'key=value'")
			continue
		}

		key := strings.TrimSpace(meta[0])
		val := strings.TrimSpace(meta[1])

		if prev, ok := r.Metadata[key]; ok {
			fmt.Printf("Note: replacing previous value of '%s'\n", string(prev))
		}

		r.Metadata[key] = []byte(val)
	}
	r.Timestamp = time.Now().Unix()
	session.Store.Timestamp = r.Timestamp
	session.Store.Store[label] = r
	session.Dirty = true
	return nil
}

func cmdWriteStore(args []string) error {
	if len(args) != 0 {
		return errors.New("write takes no arguments")
	}

	if !writeStore() {
		return errors.New("failed to write store")
	}

	return nil
}

func storeSingleSecret(label string) error {
	r, ok := session.Store.Store[label]
	if ok {
		answer, err := util.ReadLine(label + " exists. Overwrite secret (y/n)? ")
		if err != nil {
			return err
		}
		answer = strings.ToLower(answer)
		if answer != "y" && answer != "yes" {
			fmt.Println("Not overwriting.")
			return nil
		}
	} else {
		r = new(store.SecretRecord)
	}

	password, err := readpass.PasswordPromptBytes("New password: ")
	if err != nil {
		return err
	} else if len(password) == 0 {
		return errors.New("no password entered")
	}

	util.Zero(r.Secret)
	r.Secret = password
	r.Timestamp = time.Now().Unix()
	session.Store.Timestamp = r.Timestamp
	session.Store.Store[label] = r
	session.Dirty = true
	return nil
}

func storeSecret(args []string) error {
	if len(args) == 0 {
		return errors.New("no labels provided")
	}

	for i, label := range args {
		fmt.Println("[+] Storing secret for", label)
		err := storeSingleSecret(label)
		if err != nil {
			if i > 0 {
				writeStore()
			}
			return err
		}
	}

	return nil
}
