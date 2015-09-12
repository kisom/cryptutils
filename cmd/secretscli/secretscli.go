package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kisom/cryptutils/common/secret"
	"github.com/kisom/cryptutils/common/store"
	"github.com/kisom/cryptutils/common/util"
)

var (
	defaultTimeout = 5 * time.Minute
	maxTimeout     = 12 * time.Hour
)

func readCommands(storeName string, input chan string, proceed chan bool) {
	// Catch the case where the input channel is closed.
	defer func() {
		if err := recover(); err != nil {
			log.Printf("readCommands: %v", err)
		}
	}()

	prompt := fmt.Sprintf("%s command> ", storeName)
	for {
		line, err := util.ReadLine(prompt)
		if err != nil {
			if err == io.EOF {
				close(input)
				return
			}
			fmt.Fprintf(os.Stderr, "[!] %v", err)
		}

		if line == "" {
			continue
		}

		input <- line
		_, ok := <-proceed
		if !ok {
			fmt.Println("done")
			return
		}
	}
}

func processCommands(line string, proceed chan bool) {
	args := strings.Fields(line)
	if len(args) == 0 {
		proceed <- true
		return
	}

	cmd := args[0]
	args = args[1:]

	f, ok := dispatch[cmd]
	if !ok {
		fmt.Fprintf(os.Stderr, "[!] %s is not a valid command.\n", cmd)
	} else {
		err := f(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] command failed: %v\n", err)
		}
	}

	proceed <- true
}

func inputLoop(storeName string) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("inputLoop error: %v", err)
		}
	}()
	input := make(chan string, 0)
	proceed := make(chan bool, 0)

	go readCommands(storeName, input, proceed)
	var stop bool

	for {
		select {
		case line, ok := <-input:
			if !ok || line == "quit" {
				stop = true
				break
			}
			processCommands(line, proceed)
		case <-time.After(defaultTimeout):
			fmt.Println("\n\n[+] Locking store and exiting.")
			close(proceed)
			stop = true
			break
		}

		if stop {
			break
		}
	}
}

var session struct {
	Store  *store.SecretStore
	Path   string
	Scrypt secret.ScryptMode
	Dirty  bool
	Locked bool
}

func writeStore() bool {
	if !session.Dirty {
		return true
	}

	fmt.Printf("[+] storing secret store...\n")
	fileData, ok := store.MarshalSecretStore(session.Store, session.Scrypt)
	if !ok {
		return false
	}

	err := util.WriteFile(fileData, session.Path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] failed to write store to %s:\n",
			err)
		fmt.Fprintf(os.Stderr, "\t%v\n", err)
		return false
	}

	session.Dirty = false
	return true
}

func shutdown() {
	if !writeStore() {
		fmt.Fprintln(os.Stderr, "*** WARNING: store was NOT written to disk***")
	}
	session.Store.Zero()
}

func main() {
	baseFile := filepath.Join(os.Getenv("HOME"), ".secrets.db")
	flag.StringVar(&session.Path, "f", baseFile, "path to password store")
	flag.DurationVar(&defaultTimeout, "t", defaultTimeout, "`timeout`")
	scryptInteractive := flag.Bool("i", false, "use scrypt interactive")
	flag.Parse()

	session.Scrypt = secret.ScryptStandard
	if *scryptInteractive {
		session.Scrypt = secret.ScryptInteractive
	}

	prompt := fmt.Sprintf("Passphrase to unlock %s: ", session.Path)
	passphrase, err := util.PassPrompt(prompt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		os.Exit(1)
	}

	fileData, err := ioutil.ReadFile(session.Path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		os.Exit(1)
	}

	var ok bool
	session.Store, ok = store.UnmarshalSecretStore(fileData, passphrase,
		session.Scrypt)
	if !ok {
		fmt.Fprintf(os.Stderr, "[!] failed to unlocked store.\n")
		os.Exit(1)
	}
	defer shutdown()

	inputLoop(session.Path)
}
