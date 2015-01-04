// secret-sync-server is the server program for the sync service.
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gokyle/readpass"
	"github.com/kisom/cryptutils/common/auth"
	"github.com/kisom/cryptutils/common/secret"
	"github.com/kisom/cryptutils/common/sync"
	"github.com/kisom/cryptutils/common/util"
)

type intRequest struct {
	Op   string
	Ret  chan *sync.Response
	Data interface{}
}

type Session struct {
	Expires time.Time
	Session *auth.Authenticator
}

var store struct {
	Hostname string                `json:"hostname"`
	Users    map[string]*sync.User `json:"users"`
	Admin    *auth.Authenticator   `sync:"admin"`
	Invites  map[string]bool       `sync:"invites"`
	sessions map[string]*Session
	procChan chan *intRequest
	key      *[secret.KeySize]byte
	salt     []byte
	fileName string
}

// ifErrorFatal is used when an error should kill the program, for
// example when initialising a new store.
func ifErrorFatal(err error) {
	if err != nil {
		log.Fatalf("%v", err)
	}
}

// initStore sets up a data store for the server.
func initStore(filespec string) {
	authType, err := util.ReadLine("Authentication type: ")
	ifErrorFatal(err)

	switch authType {
	case auth.TypeYubiKey:
		key, err := util.ReadLine("Key: ")
		ifErrorFatal(err)

		keyBytes, err := hex.DecodeString(key)
		ifErrorFatal(err)

		initialOTP, err := util.ReadLine("OTP: ")
		ifErrorFatal(err)

		store.Admin, err = auth.NewYubiKey(keyBytes, initialOTP)
		ifErrorFatal(err)

	case auth.TypeTOTP:
		store.Admin, err = auth.NewGoogleTOTP()
		ifErrorFatal(err)

		userDetails, err := auth.ExportUserTOTP(store.Admin, "")
		ifErrorFatal(err)

		log.Println("TOTP secret:", userDetails.Secret)

	default:
		log.Fatalf("Invalid authenticator type (must be '%s' or '%s')",
			auth.TypeYubiKey, auth.TypeTOTP)
	}

	store.Hostname, err = util.ReadLine("Hostname (for TLS): ")
	ifErrorFatal(err)

	store.Users = make(map[string]*sync.User)
	out, err := json.Marshal(store)
	ifErrorFatal(err)

	var password []byte
	for {
		password, err = readpass.PasswordPromptBytes("New data store passphrase: ")
		ifErrorFatal(err)

		confirmPassword, err := readpass.PasswordPromptBytes("Confirm passphrase: ")
		ifErrorFatal(err)

		if bytes.Equal(password, confirmPassword) {
			util.Zero(confirmPassword)
			break
		}

		log.Println("Passphrases don't match.")
	}

	defer util.Zero(password)
	err = secret.EncryptFile(filespec, password, out)
	ifErrorFatal(err)

	store.salt = make([]byte, secret.SaltSize)
	copy(store.salt, out[:secret.SaltSize])

	store.key = secret.DeriveKey(password, store.salt)
	util.Zero(out)
}

// loadStore loads the data store from a file.
func loadStore(filespec string) {
	password, err := readpass.PasswordPromptBytes("Data store passphrase: ")
	ifErrorFatal(err)
	defer util.Zero(password)

	out, err := secret.DecryptFile(filespec, password)
	ifErrorFatal(err)
	defer util.Zero(out)

	err = json.Unmarshal(out, &store)
	ifErrorFatal(err)

	store.salt = make([]byte, secret.SaltSize)
	copy(store.salt, out[:secret.SaltSize])

	store.key = secret.DeriveKey(password, store.salt)
}

// setupTLSConfig creates a new TLS configuration for the server.
func setupTLSConfig(tlsKey, tlsCert string) *tls.Config {
	cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
	ifErrorFatal(err)

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   store.Hostname,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		SessionTicketsDisabled: true,
		MinVersion:             tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.CurveP521,
			tls.CurveP384,
			tls.CurveP256,
		},
	}

	return config
}

func shutdown() {
	util.Zero(store.key[:])
}

func main() {
	var address, port, tlsKey, tlsCert, storeFile string
	flag.StringVar(&address, "a", "0.0.0.0", "address to listen on")
	flag.StringVar(&tlsCert, "c", "cert.pem", "path to TLS certificate")
	flag.StringVar(&storeFile, "f", "store.db", "path to server data store")
	flag.StringVar(&tlsKey, "k", "key.pem", "path to TLS key")
	flag.StringVar(&port, "p", "4900", "port to listen on")
	flag.Parse()

	_, err := os.Stat(storeFile)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Fatalf("%v", err)
		}
		initStore(storeFile)
		log.Println("initialised new store")
	} else {
		loadStore(storeFile)
	}

	store.fileName = storeFile
	store.sessions = make(map[string]*Session)
	store.procChan = make(chan *intRequest, 0)

	tlsConfig := setupTLSConfig(tlsKey, tlsCert)
	server := &http.Server{
		Addr:         address + ":" + port,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		TLSConfig:    tlsConfig,
	}

	go processor()

	http.HandleFunc("/register", register)
	http.HandleFunc("/pull", syncdown)
	http.HandleFunc("/push", syncup)
	http.HandleFunc("/invite", addInvite)

	log.Printf("serving on %s:%s", address, port)
	log.Println(server.ListenAndServeTLS(tlsCert, tlsKey))
	close(store.procChan)
}
