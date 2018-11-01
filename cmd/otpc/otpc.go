package main

import (
	"bytes"
	"encoding/base32"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kisom/cryptutils/common/secret"
	"github.com/kisom/cryptutils/common/store"
	"github.com/kisom/cryptutils/common/util"
	"github.com/kisom/cryptutils/twofactor"
)

type command struct {
	ShouldWrite  bool
	RequiredArgc int
	Run          func(*store.SecretStore, *config) error
	Args         []string
}

var commandSet = map[string]command{
	"show":  {false, 1, showSecret, []string{"label"}},
	"store": {true, 1, addSecret, []string{"label"}},
	"qr":    {false, 2, showQR, []string{"label", "filename"}},
}

// These constants are used to identify various OTP algorithms
const (
	Unknown = 0
	HOTP    = iota + 1
	TOTP
	GoogleTOTP
)

func writeStore(ps *store.SecretStore, path string, m secret.ScryptMode) bool {
	fileData, ok := store.MarshalSecretStore(ps, m)
	if !ok {
		return false
	}

	err := util.WriteFile(fileData, path)
	if err != nil {
		util.Errorf("Write failed: %v", err)
		return false
	}
	return true
}

func loadStore(path string, m secret.ScryptMode) *store.SecretStore {
	passphrase, err := util.PassPrompt("Secrets passphrase> ")
	if err != nil {
		util.Errorf("Failed to read passphrase: %v", err)
		return nil
	}

	var passwords *store.SecretStore
	if ok, _ := util.Exists(path); ok {
		defer util.Zero(passphrase)
		fileData, err := util.ReadFile(path)
		if err != nil {
			util.Errorf("%v", err)
			return nil
		}
		var ok bool
		passwords, ok = store.UnmarshalSecretStore(fileData, passphrase, m)
		if !ok {
			return nil
		}
		return passwords
	}
	util.Errorf("could not find %s", path)
	return nil
}

func initStore(path string, m secret.ScryptMode) error {
	passphrase, err := util.PassPrompt("Secrets passphrase> ")
	if err != nil {
		util.Errorf("Failed to read passphrase: %v", err)
		return err
	}
	defer util.Zero(passphrase)
	passwords := store.NewSecretStore(passphrase)
	if passwords == nil {
		return fmt.Errorf("failed to create store")
	}

	fmt.Println("creating store...")
	fileData, ok := store.MarshalSecretStore(passwords, m)
	if !ok {
		return fmt.Errorf("failed to marshal store")
	}

	err = util.WriteFile(fileData, path)
	if err != nil {
		return err
	}

	passwords, ok = store.UnmarshalSecretStore(fileData, passphrase, m)
	if !ok {
		err = fmt.Errorf("failed to unmarshal store")
	}
	return err
}

func parseOTPKind(t string) int {
	t = strings.ToLower(t)
	switch t {
	case "totp":
		return TOTP
	case "google", "totp-google":
		return GoogleTOTP
	case "hotp":
		return HOTP
	default:
		return Unknown
	}
}

type config struct {
	Args      []string
	Updated   bool
	OTPType   int
	Overwrite bool
	WithMeta  bool
}

const timeFormat = "2006-01-2 15:04 MST"

func sanitiseSecret(in []byte) []byte {
	in = bytes.ToUpper(in)
	in = bytes.Replace(in, []byte(" "), []byte(""), -1)
	if len(in)%8 != 0 {
		padding := 8 - (len(in) % 8)
		for i := 0; i < padding; i++ {
			in = append(in, '=')
		}
	}
	return in
}

func addSecret(ps *store.SecretStore, cfg *config) error {
	label := cfg.Args[0]
	if ps.Has(label) {
		if cfg.Overwrite {
			util.Errorf("WARNING: a token already exists under this label!")
		} else {
			return errors.New("token already exists under label")
		}
	}

	// Default prompt is echoing, which we want here.
	secret, err := util.PassPrompt("Secret: ")
	if err != nil {
		return err
	}

	var rec *store.SecretRecord
	secret = sanitiseSecret(secret)
	switch cfg.OTPType {
	case HOTP:
		in, err := util.ReadLine("Initial counter (0): ")
		if err != nil {
			return err
		}
		if in == "" {
			in = "0"
		}
		d, err := strconv.Atoi(in)
		if err != nil {
			return err
		}

		in, err = util.ReadLine("Digits (6 or 8): ")
		if err != nil {
			return err
		} else if in == "" {
			in = "6"
		}

		digits, err := strconv.Atoi(in)
		if err != nil {
			return err
		}

		key, err := base32.StdEncoding.DecodeString(string(secret))
		if err != nil {
			fmt.Printf("%s", secret)
			return err
		}

		var hotp *twofactor.HOTP
		hotp = twofactor.NewHOTP(key, uint64(d), digits)
		confirmation := hotp.OTP()
		fmt.Printf("Confirmation: %s\n", confirmation)
		rec = &store.SecretRecord{
			Label:     label,
			Secret:    []byte(hotp.URL(label)),
			Timestamp: time.Now().Unix(),
			Metadata: map[string][]byte{
				"key":          secret,
				"type":         []byte("HOTP"),
				"confirmation": []byte(confirmation),
			},
		}
	case TOTP:
		in, err := util.ReadLine("Time step (30s): ")
		if err != nil {
			return err
		}
		if in == "" {
			in = "30s"
		}
		d, err := time.ParseDuration(in)
		if err != nil {
			return err
		}

		in, err = util.ReadLine("Digits (6 or 8): ")
		if err != nil {
			return err
		} else if in == "" {
			in = "6"
		}

		digits, err := strconv.Atoi(in)
		if err != nil {
			return err
		}

		key, err := base32.StdEncoding.DecodeString(string(secret))
		if err != nil {
			return err
		}

		var totp *twofactor.TOTP
		totp = twofactor.NewTOTPSHA1(key, 0, uint64(d.Seconds()), digits)
		confirmation := totp.OTP()
		fmt.Printf("Confirmation: %s\n", confirmation)
		rec = &store.SecretRecord{
			Label:     label,
			Secret:    []byte(totp.URL(label)),
			Timestamp: time.Now().Unix(),
			Metadata: map[string][]byte{
				"key":          secret,
				"type":         []byte("TOTP-SHA1"),
				"step":         []byte(d.String()),
				"confirmation": []byte(confirmation),
			},
		}
	case GoogleTOTP:
		var totp *twofactor.TOTP
		totp, err = twofactor.NewGoogleTOTP(string(secret))
		if err != nil {
			return err
		}
		confirmation := totp.OTP()
		fmt.Printf("Confirmation: %s\n", confirmation)
		rec = &store.SecretRecord{
			Label:     label,
			Secret:    []byte(totp.URL(label)),
			Timestamp: time.Now().Unix(),
			Metadata: map[string][]byte{
				"key":          secret,
				"type":         []byte("TOTP-GOOGLE"),
				"step":         []byte("30s"),
				"confirmation": []byte(confirmation),
			},
		}
	default:
		return errors.New("unrecognised OTP type")
	}
	ps.Store[label] = rec
	return nil
}

func printGTOTP(label string, otp twofactor.OTP) {
	t := time.Now()
	fmt.Println(otp.OTP())
	fmt.Println("Updates in", 30-(t.Second()%30), "seconds.")
	for {
		for {
			t = time.Now()
			if t.Second() == 0 {
				break
			} else if t.Second() == 30 {
				break
			}
			<-time.After(1 * time.Second)
		}
		fmt.Println(otp.OTP())
		<-time.After(30 * time.Second)
	}
}

func printTOTP(label string, otp twofactor.OTP) {
	last := otp.OTP()
	fmt.Println(last)
	for {
		if otp.OTP() != last {
			last = otp.OTP()
			fmt.Println(last)
		}
		<-time.After(1 * time.Second)
	}

}

func printHOTP(label string, otp twofactor.OTP) {
	fmt.Println(otp.OTP())
}

// Convert from the types used in the twofactor package to the ones used here.
func parseTwofactorType(t twofactor.Type) int {
	switch t {
	case twofactor.OATH_TOTP:
		return TOTP
	case twofactor.OATH_HOTP:
		return HOTP
	default:
		return Unknown
	}
}

func showQR(ps *store.SecretStore, cfg *config) error {
	label := cfg.Args[0]
	if !ps.Has(label) {
		return errors.New("no token found under label")
	}
	filename := cfg.Args[1]

	rec := ps.Store[label]

	otp, label, err := twofactor.FromURL(string(rec.Secret))
	if err != nil {
		return err
	}

	var qr []byte

	switch otp.Type() {
	case twofactor.OATH_HOTP:
		hotp := otp.(*twofactor.HOTP)
		qr, err = hotp.QR(label)
	case twofactor.OATH_TOTP:
		totp := otp.(*twofactor.TOTP)
		qr, err = totp.QR(label)
	default:
		err = errors.New("QR codes can only be generated for OATH OTPs")
	}

	if err != nil {
		return err
	}

	return ioutil.WriteFile(filename, qr, 0600)
}

func showSecret(ps *store.SecretStore, cfg *config) error {
	label := cfg.Args[0]
	if !ps.Has(label) {
		return errors.New("no token found under label")
	}

	rec := ps.Store[label]
	var otpType int
	otp, label, err := twofactor.FromURL(string(rec.Secret))
	if err != nil {
		return err
	}
	if _, ok := rec.Metadata["type"]; !ok {
		otpType = parseTwofactorType(otp.Type())
	} else {
		otpType = parseOTPKind(string(rec.Metadata["type"]))
	}

	switch otpType {
	case TOTP:
		printTOTP(label, otp)
	case GoogleTOTP:
		printGTOTP(label, otp)
	case HOTP:
		printHOTP(label, otp)
		cfg.Updated = true
		hotp := otp.(*twofactor.HOTP)
		rec.Secret = []byte(hotp.URL(label))
		rec.Timestamp = time.Now().Unix()
		ps.Store[label] = rec
	default:
		return errors.New("unknown OTP type")
	}
	return nil
}

func main() {
	baseFile := filepath.Join(os.Getenv("HOME"), ".otpc.db")
	doInit := flag.Bool("init", false, "initialize a new store")
	doStore := flag.Bool("s", false, "store a new two-factor token")
	storePath := flag.String("f", baseFile, "path to password store")
	otpKind := flag.String("t", "", "OTP type (TOTP, HOTP, GOOGLE)")
	doQR := flag.Bool("qr", false, "dump QR code for secret")
	doVersion := flag.Bool("V", false, "display version and exit")
	scryptInteractive := flag.Bool("i", false, "use scrypt interactive")
	flag.Parse()

	if *doVersion {
		fmt.Println("otpc version", util.VersionString())
		os.Exit(0)
	}

	scryptMode := secret.ScryptStandard
	if *scryptInteractive {
		scryptMode = secret.ScryptInteractive
	}

	var cfg = &config{
		Args:    flag.Args(),
		OTPType: parseOTPKind(*otpKind),
	}

	var cmd command
	switch {
	case *doInit:
		cmd = commandSet["init"]
		err := initStore(*storePath, scryptMode)
		if err != nil {
			util.Errorf("Failed: %v", err)
			os.Exit(1)
		}
		return
	case *doStore:
		cmd = commandSet["store"]
	case *doQR:
		cmd = commandSet["qr"]
	default:
		cmd = commandSet["show"]
	}

	if flag.NArg() < cmd.RequiredArgc {
		util.Errorf("Not enough arguments: want %d, have %d.",
			cmd.RequiredArgc, flag.NArg())
		util.Errorf("Want: %v", strings.Join(cmd.Args, ", "))
		os.Exit(1)
	}

	ps := loadStore(*storePath, scryptMode)
	if ps == nil {
		util.Errorf("Failed to open two-factor store.")
		os.Exit(1)
	}
	defer ps.Zero()

	err := cmd.Run(ps, cfg)
	if err != nil {
		util.Errorf("Failed: %v", err)
		os.Exit(1)
	}

	if cmd.ShouldWrite || cfg.Updated {
		ps.Timestamp = time.Now().Unix()
		if !writeStore(ps, *storePath, scryptMode) {
			util.Errorf("Failed to write store!")
			os.Exit(1)
		}
	}
}
