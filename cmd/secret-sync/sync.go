// secret-sync is the client for the sync service.
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/gokyle/readpass"
	"github.com/kisom/cryptutils/common/auth"
	"github.com/kisom/cryptutils/common/public"
	"github.com/kisom/cryptutils/common/secret"
	"github.com/kisom/cryptutils/common/store"
	"github.com/kisom/cryptutils/common/sync"
	"github.com/kisom/cryptutils/common/util"
)

var configFile string

func defaultConfigFile() string {
	return filepath.Join(os.Getenv("HOME"), ".config", "cryptutils", "secret-sync.json")
}

const timeDisplay = "2006-01-02 15:04 MST"

var config struct {
	Server    string `json:"server"`
	Login     string `json:"login"`
	Label     string `json:"label"`
	KeyPair   []byte `json:"keypair"`
	RootCerts string `json:"root_certs"`
	roots     *x509.CertPool
}

func ifErrorDie(err error) {
	if err != nil {
		util.Errorf("%v\n", err)
		os.Exit(1)
	}
}

func extractResponse(resp *http.Response) *sync.Response {
	fmt.Printf("Server responded with HTTP %s\n", resp.Status)
	defer resp.Body.Close()

	var response sync.Response
	dec := json.NewDecoder(resp.Body)
	err := dec.Decode(&response)
	ifErrorDie(err)

	return &response
}

func setupClient(hostname string) *http.Client {
	host, _, err := net.SplitHostPort(hostname)
	ifErrorDie(err)

	config := &tls.Config{
		RootCAs:    config.roots,
		ServerName: host,
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

	tr := &http.Transport{
		TLSClientConfig:    config,
		DisableCompression: true,
	}
	return &http.Client{Transport: tr}
}

func fillInAuth(reg *sync.Registration) {
	switch reg.AuthenticationType {
	case auth.TypeYubiKey:
		var err error
		reg.AuthenticationData["key"], err = util.ReadLine("Hex-encoded YubiKey secret key (ex. deadbeefdeadbeefdeadbeefdeadbeef): ")
		ifErrorDie(err)

		reg.AuthenticationData["otp"], err = util.ReadLine("Please enter an OTP: ")
		ifErrorDie(err)
	case auth.TypeTOTP:
		// Nothing needs to happen here. The server will do all
		// the work.
	default:
		util.Errorf("%s is not a recognised authenticator\n",
			reg.AuthenticationType)
		os.Exit(1)
	}
}

func register() {
	var reg sync.Registration

	server, err := util.ReadLine("Sync server (address:port): ")
	ifErrorDie(err)

	config.RootCerts, err = util.ReadLine("Path to root certificate pool (leave empty for default): ")
	ifErrorDie(err)

	reg.Login, err = util.ReadLine("Login name: ")
	ifErrorDie(err)

	reg.Email, err = util.ReadLine("Email address: ")
	ifErrorDie(err)

	reg.Invite, err = util.ReadLine("Invite code: ")
	ifErrorDie(err)

	reg.Link.Label, err = util.ReadLine("Machine name: ")
	ifErrorDie(err)

	reg.AuthenticationType, err = util.ReadLine("Authentication type: ")
	ifErrorDie(err)

	priv, err := public.GenerateKey()
	ifErrorDie(err)

	config.KeyPair, err = public.MarshalPrivate(priv)
	ifErrorDie(err)

	reg.Link.Public, err = public.MarshalPublic(priv.PublicKey)
	ifErrorDie(err)

	client := setupClient(server)
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	err = enc.Encode(reg)
	ifErrorDie(err)
	out := buf.Bytes()

	resp, err := client.Post("https://"+server+"/register",
		"application/json", buf)
	ifErrorDie(err)

	response := extractResponse(resp)
	if !response.Success {
		util.Errorf("Registration failed: %s\n", response.Message)
		return
	}

	config.Server = server
	config.Login = reg.Login
	config.Label = reg.Link.Label

	fmt.Println("Registration succeeded.")
	if k := response.Result["key"]; k != "" {
		fmt.Println("TOTP key:", k)
	}

	dirName := filepath.Dir(configFile)
	err = os.MkdirAll(dirName, 0700)
	if err != nil {
		fmt.Printf("Failed to write config file. Here is the file:\n\n%s\n\n", out)
		os.Exit(1)
	}

	out, err = json.Marshal(config)
	ifErrorDie(err)

	err = ioutil.WriteFile(configFile, out, 0600)
	if err != nil {
		fmt.Printf("Failed to write config file. Here is the file:\n\n%s\n\n", out)
		os.Exit(1)
	}
}

func loadConfig(configFile string) {
	in, err := ioutil.ReadFile(configFile)
	ifErrorDie(err)

	err = json.Unmarshal(in, &config)
	ifErrorDie(err)
}

func syncFull(label, storeFile string) {
	fmt.Println("Pulling remote store...")
	sd := pull(label)

	session, ok := auth.KeySession(config.KeyPair, sd.Public)
	if !ok {
		err := errors.New("failed to set up session")
		ifErrorDie(err)
	}

	var syncedStore []byte

	if len(sd.Blob) > secret.SaltSize {
		fmt.Println("Syncing local store with remote...")
		syncedStore = mergeLocalWithRemote(storeFile, sd)
	} else {
		fmt.Println("No remote store.")

		var err error
		syncedStore, err = ioutil.ReadFile(storeFile)
		ifErrorDie(err)
	}

	push(label, session, sd.Next, syncedStore)
}

func mergeLocalWithRemote(storeFile string, sd *sync.SyncDown) []byte {
	// Get passwords from the user.
	localPassword, err := readpass.PasswordPromptBytes("Local store passphrase: ")
	ifErrorDie(err)
	defer util.Zero(localPassword)

	remotePassword, err := readpass.PasswordPromptBytes("Remote store passphrase: ")
	ifErrorDie(err)
	defer util.Zero(remotePassword)

	fmt.Println("Decrypt local store...")
	in, err := util.ReadFile(storeFile)
	ifErrorDie(err)

	// Next, try to open the local store.
	localStore, ok := store.UnmarshalSecretStore(in, localPassword)
	util.Zero(in)
	if !ok {
		err = errors.New("local decryption failure")
		ifErrorDie(err)
	}
	defer localStore.Zero()

	// Try to recover the remoteStore from the SyncDown blob.
	remoteStore, ok := store.UnmarshalSecretStore(sd.Blob, remotePassword)
	if !ok {
		err = errors.New("remote decryption failure")
		ifErrorDie(err)
	}
	defer remoteStore.Zero()

	// Merge the remote store into the local store, and show any changed records.
	dispTime := func(ts int64) string {
		t := time.Unix(ts, 0)
		return t.Format(timeDisplay)
	}
	fmt.Printf(" Local store last update: %s\n", dispTime(localStore.Timestamp))
	fmt.Printf("Remote store last update: %s\n", dispTime(remoteStore.Timestamp))
	updated := localStore.Merge(remoteStore)
	if len(updated) > 0 {
		sort.Strings(updated)
		fmt.Println("Updated accounts: ")
		for _, update := range updated {
			fmt.Printf("\t%s\n", update)
		}
	} else {
		fmt.Println("No updates.")
	}

	// Dump the local store to disk.
	out, ok := store.MarshalSecretStore(localStore)
	if !ok {
		err = errors.New("failed to serialise secret store")
		ifErrorDie(err)
	}

	err = ioutil.WriteFile(storeFile, out, 0644)
	ifErrorDie(err)

	// Re-load the local store so we can sync it up now.
	remoteStore, ok = store.UnmarshalSecretStore(out, localPassword)
	if !ok {
		err = errors.New("failed to prepare store for sync")
		ifErrorDie(err)
	}

	// Change the password to the remote password.
	remoteStore.ChangePassword(remotePassword)
	out, ok = store.MarshalSecretStore(remoteStore)
	if !ok {
		err = errors.New("failed to serialise store for sync")
		ifErrorDie(err)
	}

	return out
}

func pull(label string) *sync.SyncDown {
	sr := sync.SyncRequest{
		Login:   config.Login,
		Machine: config.Label,
		Label:   label,
	}

	var err error
	sr.OTP, err = util.ReadLine("Please enter your OTP: ")
	ifErrorDie(err)

	client := setupClient(config.Server)
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	err = enc.Encode(sr)
	ifErrorDie(err)

	resp, err := client.Post("https://"+config.Server+"/pull",
		"application/json", buf)
	ifErrorDie(err)

	response := extractResponse(resp)
	if !response.Success {
		util.Errorf("Syncing failed: %s\n", response.Message)
		os.Exit(1)
	}

	sd, err := sync.SyncDownFromResponse(response)
	ifErrorDie(err)

	return sd
}

func push(label string, session *auth.Session, next, blob []byte) {
	var otp string
	var err error

	if session == nil {
		otp, err = util.ReadLine("Please enter your OTP: ")
		ifErrorDie(err)
	} else {
		otp = session.OTP(next)
	}

	sr := &sync.SyncRequest{
		Login:   config.Login,
		Machine: config.Label,
		Label:   label,
		OTP:     otp,
		Blob:    blob,
	}

	client := setupClient(config.Server)
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	err = enc.Encode(sr)
	ifErrorDie(err)

	resp, err := client.Post("https://"+config.Server+"/push",
		"application/json", buf)
	ifErrorDie(err)

	response := extractResponse(resp)
	if !response.Success {
		util.Errorf("Syncing failed failed: %s\n", response.Message)
		os.Exit(1)
	}

	fmt.Println("Synced with server.")
}

func generateInvite(host string) {
	if host == "" {
		host = config.Server
	}
	otp, err := util.ReadLine("Please enter the admin OTP: ")
	ifErrorDie(err)

	body := map[string]string{
		"otp": otp,
	}

	client := setupClient(host)
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	err = enc.Encode(body)
	ifErrorDie(err)

	resp, err := client.Post("https://"+host+"/invite",
		"application/json", buf)
	ifErrorDie(err)

	response := extractResponse(resp)
	if !response.Success {
		util.Errorf("Syncing failed: %s\n", response.Message)
		os.Exit(1)
	}

	if response.Result != nil {
		if invite := response.Result["invite"]; invite != "" {
			fmt.Println("Invite code: ", invite)
		}
	}
}

func loadPool(certPool string) {
	config.roots = x509.NewCertPool()
	in, err := ioutil.ReadFile(certPool)
	ifErrorDie(err)

	if !config.roots.AppendCertsFromPEM(in) {
		util.Errorf("No suitable roots could be found!")
	}
}

func main() {
	configFile = defaultConfigFile()
	flag.StringVar(&config.RootCerts, "c", "", "path to certificate pool to use instead of the OS default")
	flag.StringVar(&configFile, "f", configFile, "path to config file")
	flag.Parse()

	if config.RootCerts != "" {
		loadPool(config.RootCerts)
	}

	if flag.NArg() == 0 {
		return
	}

	cmd := flag.Arg(0)
	switch cmd {
	case "register":
		register()
	case "sync":
		loadConfig(configFile)

		if flag.NArg() != 3 {
			util.Errorf("Please specify the store name and path to local store to sync.\n")
			return
		}

		syncFull(flag.Arg(1), flag.Arg(2))
	case "invite":
		var host string
		if flag.NArg() == 2 {
			host = flag.Arg(1)
		}
		loadConfig(configFile)
		generateInvite(host)
	default:
		util.Errorf("Unrecognised command '%s'", cmd)
		os.Exit(1)
	}
}
