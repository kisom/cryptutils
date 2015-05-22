// The login program accepts two commands: "register", to set up new users, and "run"
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/gokyle/readpass"
	"github.com/kisom/cryptutils/common/auth"
	"github.com/kisom/cryptutils/common/util"
)

// A User pairs a user name with an authenticator.
type User struct {
	Name string
	Auth *auth.Authenticator
}

var (
	// The store maps usernames to User values.
	store map[string]*User

	// The store is serialised to JSON on disk.
	storePath string
)

// login simulates a login prompt; it will ask for a user name and
// password, and attempt to validate the password against the user's
// authenticator. It returns a boolean indicating whether the program
// should ask for another user name and password pair.
func login() bool {
	login, err := util.ReadLine("User name: ")
	dieIfError(err)

	if login == "" {
		return false
	}

	password, err := util.ReadLine("Password: ")
	dieIfError(err)

	u, ok := store[login]
	if !ok {
		log.Print("authentication failed (no such user)")
		return true
	}

	shouldUpdate, err := auth.Validate(u.Auth, password)
	if err != nil {
		log.Printf("authentication failed (%v)", err)
		return true
	}

	if shouldUpdate {
		writeStore()
	}

	log.Println("authentication successful")
	return true
}

// The login program supports all of the authenticators except the
// session type.
var supported = []string{
	auth.TypePassword,
	auth.TypeYubiKey,
	auth.TypeTOTP,
}

// Registration with a password only involves storing the bcrypt hash
// of the user's password.
func regPassword() *auth.Authenticator {
	password, err := readpass.PasswordPrompt("Password: ")
	dieIfError(err)

	a, err := auth.NewPasswordAuth(password, 0)
	dieIfError(err)

	return a
}

// Registration with a TOTP generates a new Google Authenticator TOTP
// key. It will print out the key and write a PNG image containing the QR
// code to disk.
func regTOTP() *auth.Authenticator {
	a, ud, err := auth.NewGoogleTOTP("common-auth example login")
	dieIfError(err)
	err = ioutil.WriteFile("qr.png", ud.QR, 0644)
	dieIfError(err)

	log.Println("Google Authenticator TOTP key:", ud.Secret)
	log.Printf("wrote Google Authenticator PNG QR code to qr.png")
	return a
}

// Registration with a YubiKey requires the user enter their secret key
// and initial OTP.
func regYubiKey() *auth.Authenticator {
	k, err := util.ReadLine("Hex-encoded key: ")
	dieIfError(err)

	kb, err := hex.DecodeString(k)
	dieIfError(err)

	otp, err := util.ReadLine("OTP: ")
	dieIfError(err)

	a, err := auth.NewYubiKey(kb, otp)
	dieIfError(err)

	return a
}

// Registration asks the user for their username and what type of
// authentication they will be using. It then determines whether the
// authentication type is supported, and calls the appropriate
// registration function to handle setting up the authenticator.
func register() {
	rfns := map[string]func() *auth.Authenticator{
		auth.TypePassword: regPassword,
		auth.TypeTOTP:     regTOTP,
	}

	var u = &User{}
	var err error

	u.Name, err = util.ReadLine("Login name: ")
	dieIfError(err)

	fmt.Println("Supported authentication types:")
	for i := range supported {
		fmt.Printf("\t%s\n", supported[i])
	}

	for {
		authType, err := util.ReadLine("Authentication type: ")
		dieIfError(err)

		rfn, ok := rfns[authType]
		if !ok {
			fmt.Println(authType, "isn't a supported authentication type.")
			continue
		}

		u.Auth = rfn()
		break
	}

	store[u.Name] = u
	writeStore()
	log.Println("registered", u.Name)
}

func main() {
	flag.StringVar(&storePath, "f", "store.json", "path to user store")
	flag.Parse()

	if flag.NArg() == 0 {
		usage()
		os.Exit(1)
	}

	loadStore()
	cmd := flag.Arg(0)
	switch cmd {
	case "register":
		register()
	case "run":
		for {
			if !login() {
				break
			}
		}
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`Demo of the common auth code.

This program runs a simulated user registration system and login
prompt. Users should first be added using the "register" command, then
authentications validated with "run".

Usage:
	login [-f storepath] register
	login [-f storepath] run

	where storepath is the location of the user store.

	register is used to add users to the "system".

	run checks logins against the users in the "system".
`)
}

func dieIfError(err error) {
	if err != nil {
		log.Fatalf("%v", err)
	}
}

func loadStore() {
	if ok, failed := util.Exists(storePath); !failed {
		log.Fatal("can't access store file")
	} else if !ok {
		store = map[string]*User{}
		return
	}

	in, err := ioutil.ReadFile(storePath)
	dieIfError(err)

	err = json.Unmarshal(in, &store)
	dieIfError(err)
}

func writeStore() {
	out, err := json.Marshal(store)
	dieIfError(err)

	err = ioutil.WriteFile(storePath, out, 0644)
	dieIfError(err)
}
