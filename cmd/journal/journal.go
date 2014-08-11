// journal is a secure journaling program.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kisom/cryptutils/common/store"
	"github.com/kisom/cryptutils/common/util"
)

const defaultEditor = "gvim -fn -i NONE"

type int64Slice []int64

func (p int64Slice) Len() int {
	return len(p)
}

func (p int64Slice) Less(i, j int) bool {
	return p[i] < p[j]
}

func (p int64Slice) Swap(i, j int) {
	t := p[i]
	p[i] = p[j]
	p[j] = t
}

func writeStore(ps *store.SecretStore, path string) bool {
	fileData, ok := store.MarshalSecretStore(ps)
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

func loadStore(path string) *store.SecretStore {
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
		passwords, ok = store.UnmarshalSecretStore(fileData, passphrase)
		if !ok {
			return nil
		}
		return passwords
	}
	return newStore(path, passphrase)
}

func newStore(path string, passphrase []byte) *store.SecretStore {
	defer util.Zero(passphrase)
	passwords := store.NewSecretStore(passphrase)
	if passwords == nil {
		return nil
	}

	fileData, ok := store.MarshalSecretStore(passwords)
	if !ok {
		return nil
	}

	err := util.WriteFile(fileData, path)
	if err != nil {
		return nil
	}

	passwords, ok = store.UnmarshalSecretStore(fileData, passphrase)
	if !ok {
		return nil
	}
	return passwords
}

const timeFormat = "2006-01-2 15:04 MST"

type command struct {
	ShouldWrite  bool
	RequiredArgc int
	Run          func(*store.SecretStore, *config) error
	Args         []string
}

var commandSet = map[string]command{
	"edit":  {true, 1, editEntry, []string{"title"}},
	"list":  {false, 0, listEntries, nil},
	"show":  {false, 1, showEntry, []string{"title"}},
	"write": {true, 1, writeNew, []string{"title"}},
}

type config struct {
	Args   []string
	Editor string
	Date   string
}

func listEntries(ps *store.SecretStore, cfg *config) error {
	var ts int64Slice
	var labels = map[int64]string{}

	for k, v := range ps.Store {
		ts = append(ts, v.Timestamp)
		labels[v.Timestamp] = k
	}

	sort.Sort(ts)

	fmt.Println("Entries:")
	for i := len(ts) - 1; i > -1; i-- {
		fmt.Printf("\t%s\t\t%s\n", time.Unix(ts[i], 0).Format(timeFormat),
			labels[ts[i]])
	}

	return nil
}

func showEntry(ps *store.SecretStore, cfg *config) error {
	title := cfg.Args[0]

	if !ps.Has(title) {
		return errors.New("entry not found")
	}

	fmt.Printf("%s\n", ps.Store[title].Secret)
	return nil
}

func writeNew(ps *store.SecretStore, cfg *config) error {
	title := strings.TrimSpace(cfg.Args[0])

	if ps.Has(title) {
		fmt.Printf("There is already an entry with the title '%s'.\n", title)
		fmt.Println("Please enter a new title (or an empty string to abort).")
		newTitle, err := util.ReadLine("Title: ")
		if err != nil {
			return err
		} else if newTitle == "" {
			return errors.New("user aborted entry")
		}
		title = newTitle
	}

	entry, err := newEntry(title, cfg.Editor)
	if err != nil {
		fmt.Println("[!] Failed to write a new entry:")
		fmt.Printf("\t%v\n", err)
		return err
	}

	ps.Store[title] = &store.SecretRecord{
		Label:     title,
		Timestamp: time.Now().Unix(),
		Secret:    entry,
	}
	return nil
}

func newEntry(title, editor string) ([]byte, error) {
	tmp, err := ioutil.TempFile("", "cu_journal")
	if err != nil {
		return nil, err
	}
	fileName := tmp.Name()
	tmp.Close()
	date := time.Now().Format(timeFormat)
	header := fmt.Sprintf("%s\n%s\n\n-----\n", title, date)
	err = ioutil.WriteFile(fileName, []byte(header), 0600)

	defer func() {
		err := os.Remove(fileName)
		if err != nil {
			fmt.Println("*** WARNING ***")
			fmt.Println("FAILED TO REMOVE TEMPORARY FILE", fileName)
			fmt.Println("You should remove this yourself.")
			fmt.Printf("\nThe reason: %v\n", err)
		}
	}()

	if editor == "" {
		editor = defaultEditor
	}

	args := strings.Split(editor, " ")
	args = append(args, fileName)
	cmd := exec.Command(args[0], args[1:]...)

	err = cmd.Run()
	if err != nil {
		return nil, err
	}

	fileData, err := ioutil.ReadFile(fileName)
	return fileData, err
}

func editEntry(ps *store.SecretStore, cfg *config) error {
	title := cfg.Args[0]
	if !ps.Has(title) {
		return errors.New("entry not found")
	}

	tmp, err := ioutil.TempFile("", "cu_journal")
	if err != nil {
		return err
	}
	fileName := tmp.Name()
	tmp.Close()
	err = ioutil.WriteFile(fileName, ps.Store[title].Secret, 0600)

	defer func() {
		err := os.Remove(fileName)
		if err != nil {
			fmt.Println("*** WARNING ***")
			fmt.Println("FAILED TO REMOVE TEMPORARY FILE", fileName)
			fmt.Println("You should remove this yourself.")
			fmt.Printf("\nThe reason: %v\n", err)
		}
	}()

	editor := cfg.Editor
	if editor == "" {
		editor = defaultEditor
	}

	args := strings.Split(editor, " ")
	args = append(args, fileName)
	cmd := exec.Command(args[0], args[1:]...)

	err = cmd.Run()
	if err != nil {
		return err
	}

	fileData, err := ioutil.ReadFile(fileName)
	if err != nil {
		return err
	}
	util.Zero(ps.Store[title].Secret)
	ps.Store[title].Secret = fileData

	return nil
}

func main() {
	baseFile := filepath.Join(os.Getenv("HOME"), ".cu_journal")
	currentEditor := os.Getenv("EDITOR")
	editor := flag.String("editor", currentEditor, "editor for writing entries")
	doEdit := flag.Bool("e", false, "edit entry")
	storePath := flag.String("f", baseFile, "path to journal")
	doList := flag.Bool("l", false, "list entries")
	doWrite := flag.Bool("w", false, "write new entry")
	flag.Parse()

	var cfg = &config{
		Args:   flag.Args(),
		Editor: *editor,
	}

	var cmd command
	switch {
	case *doEdit:
		cmd = commandSet["edit"]
	case *doList:
		cmd = commandSet["list"]
	case *doWrite:
		cmd = commandSet["write"]
	default:
		cmd = commandSet["show"]
	}

	if flag.NArg() < cmd.RequiredArgc {
		util.Errorf("Not enough arguments: want %d, have %d.",
			cmd.RequiredArgc, flag.NArg())
		util.Errorf("Want: %v", strings.Join(cmd.Args, ", "))
		os.Exit(1)
	}

	passwords := loadStore(*storePath)
	if passwords == nil {
		util.Errorf("Failed to open password store")
		os.Exit(1)
	}
	defer passwords.Zero()

	err := cmd.Run(passwords, cfg)
	if err != nil {
		util.Errorf("Failed: %v", err)
		os.Exit(1)
	}

	if cmd.ShouldWrite {
		passwords.Timestamp = time.Now().Unix()
		if !writeStore(passwords, *storePath) {
			util.Errorf("Failed to write store!")
			os.Exit(1)
		}
	}
}
