package main

import (
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gokyle/readpass"
	//"github.com/kisom/cryptutils/common/secret"
	"github.com/juztin/cryptutils/common/secret"
	//"github.com/kisom/cryptutils/common/store"
	"github.com/juztin/cryptutils/common/store"
	"github.com/kisom/cryptutils/common/util"
)

type command struct {
	ShouldWrite  bool
	RequiredArgc int
	Run          func(*store.SecretStore, *config, secret.ScryptParams) error
	Args         []string
}

var commandSet = map[string]command{
	"show":   {false, 1, showSecret, []string{"label"}},
	"store":  {true, 1, addSecret, []string{"label"}},
	"list":   {false, 0, list, nil},
	"passwd": {true, 0, chpass, nil},
	"remove": {true, 1, remove, []string{"label"}},
	"multi":  {true, 0, multi, nil},
	"merge":  {true, 1, merge, []string{"other store"}},
}

type config struct {
	Args      []string
	Clip      bool
	Overwrite bool
	WithMeta  bool
}

func writeStore(ps *store.SecretStore, path string, p secret.ScryptParams) bool {
	fileData, ok := store.MarshalSecretStore(ps, p)
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

func loadStore(path string, p secret.ScryptParams) *store.SecretStore {
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
		passwords, ok = store.UnmarshalSecretStore(fileData, passphrase, p)
		if !ok {
			return nil
		}
		return passwords
	}
	util.Errorf("could not find %s", path)
	return nil
}

func initStore(path string, p secret.ScryptParams) error {
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
	fileData, ok := store.MarshalSecretStore(passwords, p)
	if !ok {
		return fmt.Errorf("failed to marshal store")
	}

	err = util.WriteFile(fileData, path)
	if err != nil {
		return err
	}

	passwords, ok = store.UnmarshalSecretStore(fileData, passphrase, p)
	if !ok {
		err = fmt.Errorf("failed to unmarshal store")
	}
	return err
}

const timeFormat = "2006-01-2 15:04 MST"

func showSecret(ps *store.SecretStore, cfg *config, p secret.ScryptParams) error {
	label := cfg.Args[0]
	if !ps.Has(label) {
		return errors.New("entry not found")
	}

	r := ps.Store[label]
	if !cfg.Clip {
		fmt.Printf("Secret: %s\n", r.Secret)
	} else {
		fmt.Printf("%s", r.Secret)
		return nil
	}
	if cfg.WithMeta {
		fmt.Printf("Timestamp: %d (%s)\n", r.Timestamp,
			time.Unix(r.Timestamp, 0).Format(timeFormat))
		for k, v := range r.Metadata {
			fmt.Printf("\t%s: %s\n", k, v)
		}
	}
	return nil
}

func addMeta(ps *store.SecretStore, cfg *config, p secret.ScryptParams) error {
	label := cfg.Args[0]
	if !ps.Has(label) {
		tempConfig := *cfg
		tempConfig.WithMeta = false
		err := addSecret(ps, &tempConfig, p)
		if err != nil {
			return err
		}
	}

	rec := ps.Store[label]
	if rec.Metadata == nil {
		rec.Metadata = map[string][]byte{}
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
		rec.Metadata[key] = []byte(val)
	}
	rec.Timestamp = time.Now().Unix()
	ps.Store[label] = rec
	return nil
}

func addSecret(ps *store.SecretStore, cfg *config, p secret.ScryptParams) error {
	if cfg.WithMeta {
		return addMeta(ps, cfg, p)
	}
	label := cfg.Args[0]

	var rec *store.SecretRecord
	if ps.Has(label) {
		if !cfg.Overwrite {
			return errors.New("entry exists, not forcing overwrite")
		}
		util.Errorf("*** WARNING: overwriting password")
		rec = ps.Store[label]
	} else {
		rec = &store.SecretRecord{Label: label}
	}

	password, err := readpass.PasswordPromptBytes("New password: ")
	if err != nil {
		return err
	} else if len(password) == 0 {
		return errors.New("no password entered")
	}
	rec.Secret = password
	rec.Timestamp = time.Now().Unix()
	ps.Store[label] = rec
	return nil
}

func list(ps *store.SecretStore, cfg *config, p secret.ScryptParams) error {
	if len(ps.Store) == 0 {
		fmt.Printf("no passwords")
		return nil
	}

	fmt.Println("Secrets store was updated ",
		time.Unix(ps.Timestamp, 0).Format(timeFormat))
	fmt.Printf("%d entries\n\n", len(ps.Store))
	var names = make([]string, 0, len(ps.Store))

	fmt.Println("Names:")
	for k := range ps.Store {
		names = append(names, k)
	}
	sort.Strings(names)

	for _, name := range names {
		fmt.Printf("\t%s\n", name)
	}
	return nil
}

func chpass(ps *store.SecretStore, cfg *config, p secret.ScryptParams) error {
	password, err := readpass.PasswordPromptBytes("New password: ")
	if err != nil {
		return err
	} else if len(password) == 0 {
		return errors.New("no password entered")
	}

	ps.ChangePassword(password)
	return nil
}

func removeMeta(ps *store.SecretStore, cfg *config) error {
	label := cfg.Args[0]
	if !ps.Has(label) {
		return errors.New("entry not found")
	}

	rec := ps.Store[label]

	for {
		var keys = make([]string, 0, len(rec.Metadata))
		for k := range rec.Metadata {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Println("Keys:")
		for i := range keys {
			fmt.Printf("\t%s\n", keys[i])
		}

		key, err := util.ReadLine("Remove key: ")
		if err != nil {
			util.Errorf("Failed to read key: %v", err)
			continue
		} else if key == "" {
			break
		}
		delete(rec.Metadata, key)
		fmt.Println("Deleted key", key)
	}
	rec.Timestamp = time.Now().Unix()
	ps.Store[label] = rec
	return nil
}

func remove(ps *store.SecretStore, cfg *config, p secret.ScryptParams) error {
	if cfg.WithMeta {
		return removeMeta(ps, cfg)
	}

	label := cfg.Args[0]
	if !ps.Has(label) {
		return errors.New("entry not found")
	}

	fmt.Println("Removed ", label)
	delete(ps.Store, label)
	return nil
}

func multi(ps *store.SecretStore, cfg *config, p secret.ScryptParams) error {
	fmt.Println("Use an empty name to indicate that you are done.")
	for {
		name, err := util.ReadLine("Name: ")
		if err != nil {
			return err
		} else if name == "" {
			break
		}

		var rec *store.SecretRecord
		if ps.Has(name) {
			if !cfg.Overwrite {
				util.Errorf("Entry exists, not forcing overwrite.")
				continue
			} else {
				util.Errorf("*** WARNING: overwriting password")
			}
			rec = ps.Store[name]
		} else {
			rec = &store.SecretRecord{
				Label: name,
			}
		}

		password, err := util.PassPrompt("Password: ")
		if err != nil {
			return err
		} else if len(password) == 0 {
			util.Errorf("No password entered.")
			continue
		}
		rec.Secret = password
		rec.Timestamp = time.Now().Unix()
		ps.Store[name] = rec
	}
	return nil
}

func merge(ps *store.SecretStore, cfg *config, p secret.ScryptParams) error {
	otherPath := cfg.Args[0]
	passphrase, err := util.PassPrompt("Passphrase for other store> ")
	if err != nil {
		return err
	}

	otherData, err := util.ReadFile(otherPath)
	if err != nil {
		return err
	}

	otherStore, ok := store.UnmarshalSecretStore(otherData, passphrase, p)
	if !ok {
		return errors.New("failed to open other password store")
	}

	mergeList := ps.Merge(otherStore)
	fmt.Printf("%+v\n", mergeList)
	if len(mergeList) > 0 {
		sort.Strings(mergeList)
		for _, label := range mergeList {
			fmt.Printf("Merged '%s'\n", label)
		}
	}
	return nil
}

const pemType = "SECRET STORE"

func exportStore(storePath, outPath string) error {
	fileData, err := util.ReadFile(storePath)
	if err != nil {
		return err
	}

	var block = pem.Block{
		Type:  pemType,
		Bytes: fileData,
	}
	out := pem.EncodeToMemory(&block)
	return util.WriteFile(out, outPath)
}

func importStore(storePath, inPath string) error {
	fileData, err := util.ReadFile(inPath)
	if err != nil {
		return err
	}

	p, _ := pem.Decode(fileData)
	if p == nil {
		return errors.New("invalid PEM data")
	} else if p.Type != pemType {
		return errors.New("invalid PEM type")
	}

	return util.WriteFile(p.Bytes, storePath)
}

func parseScryptParams(strength int) (secret.ScryptParams, error) {
	switch {
	case strength == 1:
		return secret.ScryptParams{16384, 8, 1}, nil
	case strength == 2:
		return secret.ScryptParams{65536, 8, 1}, nil
	case strength == 3:
		return secret.ScryptParams{262144, 8, 1}, nil
	case strength == 4:
		return secret.ScryptParams{1048576, 8, 2}, nil
	}
	return secret.ScryptParams{1048576, 8, 2}, fmt.Errorf("Invalid or missing strength")
}

func main() {
	baseFile := filepath.Join(os.Getenv("HOME"), ".secrets.db")
	doInit := flag.Bool("init", false, "initialize a new store")
	doMerge := flag.Bool("merge", false, "merge another store into this store")
	doExport := flag.Bool("export", false, "export store to PEM")
	doImport := flag.Bool("import", false, "import store from PEM")
	doMulti := flag.Bool("multi", false, "enter multiple passwods")
	doChPass := flag.Bool("c", false, "change the store's password")
	storePath := flag.String("f", baseFile, "path to password store")
	doList := flag.Bool("l", false, "list accounts")
	withMeta := flag.Bool("m", false, "include metadata")
	doRemove := flag.Bool("r", false, "remove entries")
	doStore := flag.Bool("s", false, "store password")
	clipExport := flag.Bool("x", false, "dump secrets for clipboard")
	overWrite := flag.Bool("w", false, "overwrite existing secrets")
	doVersion := flag.Bool("V", false, "display version and exit")
	scryptStrength := flag.Int("t", 4, "scrypt time/strength (1, 2, 3, 4)")
	flag.Parse()

	if *doVersion {
		fmt.Println("secrets version", util.VersionString())
		os.Exit(0)
	}

	scryptParams, err := parseScryptParams(*scryptStrength)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}

	var cfg = &config{
		Args:      flag.Args(),
		Clip:      *clipExport,
		WithMeta:  *withMeta,
		Overwrite: *overWrite,
	}

	var cmd command
	switch {
	case *doInit:
		cmd = commandSet["init"]
		err = initStore(*storePath, scryptParams)
		if err != nil {
			util.Errorf("Failed: %v", err)
			os.Exit(1)
		}
		return
	case *doChPass:
		cmd = commandSet["passwd"]
	case *doStore:
		cmd = commandSet["store"]
	case *doRemove:
		cmd = commandSet["remove"]
	case *doList:
		cmd = commandSet["list"]
	case *doMulti:
		cmd = commandSet["multi"]
	case *doMerge:
		cmd = commandSet["merge"]
	case *doExport:
		if flag.NArg() != 1 {
			util.Errorf("No output file specified.")
		}
		err := exportStore(*storePath, flag.Arg(0))
		if err != nil {
			util.Errorf("Failed: %v", err)
			os.Exit(1)
		}
		return
	case *doImport:
		if flag.NArg() != 1 {
			util.Errorf("No input file specified.")
		}
		err := importStore(*storePath, flag.Arg(0))
		if err != nil {
			util.Errorf("Failed: %v", err)
			os.Exit(1)
		}
		return
	default:
		cmd = commandSet["show"]
	}

	if flag.NArg() < cmd.RequiredArgc {
		util.Errorf("Not enough arguments: want %d, have %d.",
			cmd.RequiredArgc, flag.NArg())
		util.Errorf("Want: %v", strings.Join(cmd.Args, ", "))
		os.Exit(1)
	}

	passwords := loadStore(*storePath, scryptParams)
	if passwords == nil {
		util.Errorf("Failed to open password store")
		os.Exit(1)
	}
	defer passwords.Zero()

	err = cmd.Run(passwords, cfg, scryptParams)
	if err != nil {
		util.Errorf("Failed: %v", err)
		os.Exit(1)
	}

	if cmd.ShouldWrite {
		passwords.Timestamp = time.Now().Unix()
		if !writeStore(passwords, *storePath, scryptParams) {
			util.Errorf("Failed to write store!")
			os.Exit(1)
		}
	}
}
