package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kisom/cryptutils/common/public"
	"github.com/kisom/cryptutils/common/store"
	"github.com/kisom/cryptutils/common/util"
)

type command struct {
	NeedsUnlock  bool
	ShouldWrite  bool
	RequiredArgc int
	Run          func(*store.KeyStore, *config) error
	Args         []string
}

type config struct {
	Args   []string
	Label  string
	Armour bool
}

var commandSet = map[string]command{
	"encrypt":       {false, false, 2, encryptFile, []string{"message", "encrypted"}},
	"cryptsign":     {true, false, 2, cryptSignFile, []string{"message", "encrypted"}},
	"decrypt":       {true, false, 2, decryptFile, []string{"encrypted", "message"}},
	"decryptsigned": {true, false, 2, decryptSignedFile, []string{"encrypted", "message"}},
	"sign":          {true, false, 2, signFile, []string{"message", "signature file"}},
	"verify":        {false, false, 2, verifyFile, []string{"message", "signature file"}},
	"check":         {true, false, 0, checkStore, nil},
	"export":        {true, false, 1, exportVerified, []string{"exported"}},
	"exportself":    {false, false, 1, exportSelf, []string{"exported"}},
	"import":        {true, true, 1, importVerified, []string{"signed key"}},
	"uimport":       {true, true, 1, importUntrusted, []string{"signed key"}},
	"remove":        {false, true, 1, removeKey, []string{"key label"}},
	"list":          {false, false, 0, keyList, nil},
}

func loadStore(path string) *store.KeyStore {
	// If keystore is newly created, we'll want to write it to
	// disk before leaving this function.
	var flush bool
	if exists, _ := util.Exists(path); !exists {
		flush = true
	}

	keystore, ok := store.LoadKeyStore(path, true)
	if !ok {
		fmt.Printf("error in LoadKeyStore")
		return nil
	}
	if !keystore.Valid(false) {
		fmt.Println("keystore not valid")
		return nil
	}

	if !flush {
		return keystore
	}
	passphrase, err := util.PassPrompt("keystore passphrase> ")
	if err != nil {
		util.Errorf("%v", err)
		return nil
	}
	defer util.Zero(passphrase)

	if !keystore.LockWith(passphrase) {
		util.Errorf("Failed to set initial passphrase.")
		return nil
	} else if !keystore.Unlock(passphrase) {
		util.Errorf("Flushing keystore failed.")
		return nil
	}

	return keystore
}

func checkStore(ks *store.KeyStore, cfg *config) error {
	if ks.Locked() {
		return errors.New("keystore is locked")
	}

	if !ks.Valid(false) {
		return errors.New("keystore is invalid")
	}

	if !ks.KeyAudit() {
		return errors.New("audit failed")
	}

	fmt.Println("Keystore is valid.")
	return nil
}

func writeStore(ks *store.KeyStore, path string) bool {
	storeData := store.DumpKeyStore(ks)
	if storeData == nil {
		util.Errorf("Failed to dump keystore.")
		return false
	}

	err := ioutil.WriteFile(path, storeData, 0644)
	if err != nil {
		util.Errorf("%v", err)
		return false
	}
	return true
}

func encryptFile(ks *store.KeyStore, cfg *config) error {
	message, err := util.ReadFile(cfg.Args[0])
	if err != nil {
		return err
	}

	out, ok := ks.EncryptTo(cfg.Label, message)
	if !ok {
		return errors.New("encryption failed")
	}

	if cfg.Armour {
		block := pem.Block{
			Type:  public.EncryptedType,
			Bytes: out,
		}
		out = pem.EncodeToMemory(&block)
	}

	err = util.WriteFile(out, cfg.Args[1])
	if err != nil {
		return err
	}
	return nil
}

func decryptFile(ks *store.KeyStore, cfg *config) error {
	message, err := util.ReadFile(cfg.Args[0])
	if err != nil {
		return err
	}

	var needVerify bool
	if len(message) > 10 {
		if bytes.Equal(message[:10], []byte("-----BEGIN")) {
			p, _ := pem.Decode(message)
			if p == nil {
				return errors.New("failed to decode PEM file")
			}

			switch p.Type {
			case public.EncryptedType:
				message = p.Bytes
			case public.SignedAndEncryptedType:
				needVerify = true
				message = p.Bytes
			default:
				return errors.New("invalid message")
			}

		}
	}

	var out []byte
	var ok bool

	if !needVerify {
		out, ok = ks.Decrypt(message)
		if !ok {
			return errors.New("decrypt failed")
		}
	} else {
		out, ok = ks.DecryptAndVerify(cfg.Label, message)
		if !ok {
			return errors.New("decrypt and verify failed")
		}
		fmt.Println("Valid signature.")
	}

	err = util.WriteFile(out, cfg.Args[1])
	if err != nil {
		return err
	}
	return nil
}

func signFile(ks *store.KeyStore, cfg *config) error {
	message, err := util.ReadFile(cfg.Args[0])
	if err != nil {
		return err
	}

	sig, ok := ks.Sign(message)
	if !ok {
		return errors.New("signing failed")
	}

	if cfg.Armour {
		block := pem.Block{
			Type:  public.SignatureType,
			Bytes: sig,
		}
		sig = pem.EncodeToMemory(&block)
	}

	return util.WriteFile(sig, cfg.Args[1])
}

func verifyFile(ks *store.KeyStore, cfg *config) error {
	message, err := util.ReadFile(cfg.Args[0])
	if err != nil {
		return err
	}

	sig, err := util.ReadFile(cfg.Args[1])
	if err != nil {
		return err
	}

	if len(sig) > 10 {
		if bytes.Equal(sig[:10], []byte("-----BEGIN")) {
			p, _ := pem.Decode(sig)
			if p == nil {
				return errors.New("failed to decode PEM file")
			}

			switch p.Type {
			case public.SignatureType:
				sig = p.Bytes
			default:
				return errors.New("invalid message")
			}

		}
	}

	if ks.Verify(cfg.Label, message, sig) {
		fmt.Println("Signature: OK")
	} else {
		fmt.Println("Signature: INVALID")
	}
	return nil
}

func cryptSignFile(ks *store.KeyStore, cfg *config) error {
	message, err := util.ReadFile(cfg.Args[0])
	if err != nil {
		util.Errorf("%v", err)
		return err
	}

	out, ok := ks.EncryptAndSignTo(cfg.Label, message)
	if !ok {
		util.Errorf("Failed to encrypt message.")
		return errors.New("signcryption failed")
	}

	if cfg.Armour {
		block := pem.Block{
			Type:  public.SignedAndEncryptedType,
			Bytes: out,
		}
		out = pem.EncodeToMemory(&block)
	}

	err = util.WriteFile(out, cfg.Args[1])
	if err != nil {
		util.Errorf("%v", err)
		return nil
	}
	return nil
}

func decryptSignedFile(ks *store.KeyStore, cfg *config) error {
	message, err := util.ReadFile(cfg.Args[0])
	if err != nil {
		return err
	}

	if len(message) > 10 {
		if bytes.Equal(message[:10], []byte("-----BEGIN")) {
			p, _ := pem.Decode(message)
			if p == nil {
				return errors.New("failed to decode PEM file")
			}

			switch p.Type {
			case public.EncryptedType:
				message = p.Bytes
			default:
				return errors.New("invalid message")
			}

		}
	}

	out, ok := ks.DecryptAndVerify(cfg.Label, message)
	if !ok {
		return errors.New("decrypt failed")
	}

	err = util.WriteFile(out, cfg.Args[1])
	if err != nil {
		return err
	}
	return nil
}

func unlockStore(ks *store.KeyStore) bool {
	if !ks.Locked() {
		return true
	}
	passphrase, err := util.PassPrompt("keystore passphrase> ")
	if err != nil {
		util.Errorf("%v", err)
		return false
	}
	defer util.Zero(passphrase)

	if !ks.Locked() && ks.PrivateKey == nil {
		if !ks.LockWith(passphrase) {
			util.Errorf("Failed to set initial passphrase.")
			return false
		}
	}

	if !ks.Unlock(passphrase) {
		util.Errorf("Unlock failed (bad passphrase?)")
		return false
	}
	return true
}

func exportSelf(ks *store.KeyStore, cfg *config) error {
	if ks.ExportKey == nil {
		return errors.New("No export key present.")
	}
	return util.WriteFile(ks.ExportKey, cfg.Args[0])
}

func exportVerified(ks *store.KeyStore, cfg *config) error {
	out, ok := ks.ExportVerified(cfg.Label)
	if !ok {
		return errors.New("failed to export verified public key")
	}

	return util.WriteFile(out, cfg.Args[0])
}

func importVerified(ks *store.KeyStore, cfg *config) error {
	keyData, err := util.ReadFile(cfg.Args[0])
	if err != nil {
		return err
	}

	if cfg.Label == "self" {
		cfg.Label, err = util.ReadLine("Label: ")
		if err != nil {
			return err
		}
	}

	if !ks.ImportVerifiedKey(cfg.Label, keyData) {
		return errors.New("verified import failed")
	}

	vkey, err := store.ParseVerifiedKey(keyData)
	if err != nil {
		return err
	}

	label, ok := ks.FindPublic(vkey.Signer)
	if !ok {
		return errors.New("invalid signer on key")

	}

	fmt.Printf("Imported public key signed by '%s'.\n", label)
	return nil
}

func importUntrusted(ks *store.KeyStore, cfg *config) error {
	fmt.Println("*****************************************")
	fmt.Println("*** WARNING: IMPORTING UNTRUSTED KEYS ***")
	fmt.Println("*****************************************")

	keyData, err := util.ReadFile(cfg.Args[0])
	if err != nil {
		return err
	}

	vkey, err := store.ParseVerifiedKey(keyData)
	if err != nil {
		return err
	}

	if vkey.IsSelfSigned() {
		fmt.Println("Key is self-signed.")
	} else {
		fmt.Println("Unrecognised signature.")
	}

	for {
		line, err := util.ReadLine("\nAre you sure you want to import this key? (yes or no) ")
		if err != nil {
			return nil
		}
		if line == "yes" {
			fmt.Println("As you wish.")
			break
		} else if line == "no" {
			return errors.New("canceled by user")
		} else {
			fmt.Println("Please enter either 'yes' or 'no'.")
		}
	}

	if cfg.Label == "self" {
		cfg.Label, err = util.ReadLine("Label: ")
		if err != nil {
			return err
		}
	}

	if !ks.AddKey(cfg.Label, vkey.Public, nil) {
		return errors.New("failed to add new key")
	}
	return nil
}

func removeKey(ks *store.KeyStore, cfg *config) error {
	cfg.Label = cfg.Args[0]

	if cfg.Label == "self" {
		return errors.New("cannot remove own key")
	} else if !ks.Has(cfg.Label) {
		return fmt.Errorf("no key was found under label %s", cfg.Label)
	}

	fmt.Println("Removing key ", cfg.Label)
	delete(ks.Keys, cfg.Label)
	return nil
}

const timeFormat = "2006-01-2 15:04 MST"

func keyList(ks *store.KeyStore, cfg *config) error {
	updated := time.Unix(ks.Timestamp, 0).Format(timeFormat)
	fmt.Println("Key store was last updated", updated)
	fmt.Printf("%d keys stored\n", len(ks.Keys))
	if len(ks.Keys) > 0 {
		fmt.Println("Key store:")
		for k, v := range ks.Keys {
			fmt.Printf("\t%s\n", k)
			ut := time.Unix(v.Timestamp, 0)
			st := time.Unix(v.SignatureTime, 0)
			signer, ok := ks.FindPublic(v.KeySigner)
			if !ok {
				signer = "<unknown>"
			}
			h := sha256.New()
			h.Write(v.Keys)
			fmt.Printf("\t\tLast update: %s\n", ut.Format(timeFormat))
			fmt.Printf("\t\t  Signed at: %s\n", st.Format(timeFormat))
			fmt.Printf("\t\t  Signed by: %s\n", signer)
			fmt.Printf("\t\tFingerprint: %x\n", h.Sum(nil))
		}
	}
	return nil
}

func main() {
	baseFile := filepath.Join(os.Getenv("HOME"), ".cukeystore.db")
	doCheck := flag.Bool("check", false, "check keystore's integrity'")
	doExport := flag.Bool("export", false, "export a verified key")
	doImport := flag.Bool("import", false, "import a key")
	doArmour := flag.Bool("a", false, "armour output")
	doDecrypt := flag.Bool("d", false, "decrypt file")
	doEncrypt := flag.Bool("e", false, "encrypt file")
	keystorePath := flag.String("f", baseFile, "path to keystore")
	doList := flag.Bool("k", false, "list keys")
	label := flag.String("l", "self", "label selecting a key")
	doRemove := flag.Bool("r", false, "remove named key")
	doSign := flag.Bool("s", false, "sign file")
	untrustedOK := flag.Bool("u", false, "accept untrusted keys when importing")
	doVerify := flag.Bool("v", false, "verify signature")
	flag.Parse()

	cfg := &config{
		Args:   flag.Args(),
		Label:  *label,
		Armour: *doArmour,
	}

	var cmd command
	switch {
	case *doCheck:
		cmd = commandSet["check"]
	case *doSign && *doEncrypt:
		cfg.Armour = true
		cmd = commandSet["cryptsign"]
	case *doSign:
		cmd = commandSet["sign"]
	case *doVerify:
		cmd = commandSet["verify"]
	case *doEncrypt:
		cmd = commandSet["encrypt"]
	case *doDecrypt:
		cmd = commandSet["decrypt"]
	case *doRemove:
		cmd = commandSet["remove"]
	case *doList:
		cmd = commandSet["list"]
	case *doExport && *label == "self":
		cmd = commandSet["exportself"]
	case *doExport:
		cmd = commandSet["export"]
	case *doImport:
		if *untrustedOK {
			cmd = commandSet["uimport"]
		} else {
			cmd = commandSet["import"]
		}
	default:
		util.Errorf("Nothing to do.")
		return
	}

	if flag.NArg() < cmd.RequiredArgc {
		util.Errorf("Not enough arguments: want %d, have %d.",
			cmd.RequiredArgc, flag.NArg())
		util.Errorf("Want: %v", strings.Join(cmd.Args, ", "))
		os.Exit(1)
	}

	ks := loadStore(*keystorePath)
	if ks == nil {
		util.Errorf("Failed to load keystore.")
		os.Exit(1)
	}
	if *doCheck && ks.ExportKey == nil {
		cmd.ShouldWrite = true
	}

	if cmd.NeedsUnlock {
		if !unlockStore(ks) {
			os.Exit(1)
		}
		defer ks.Lock()
	}

	err := cmd.Run(ks, cfg)
	if err != nil {
		util.Errorf("Failed: %v", err)
		os.Exit(1)
	}

	shouldWrite := cmd.ShouldWrite
	exists, ok := util.Exists(*keystorePath)
	if !ok {
		util.Errorf("Error checking %s", *keystorePath)
		os.Exit(1)
	}
	shouldWrite = shouldWrite || !exists
	if shouldWrite {
		ks.Timestamp = time.Now().Unix()
		fmt.Println("Writing keystore.")
		if !writeStore(ks, *keystorePath) {
			os.Exit(1)
		}
	}
}
