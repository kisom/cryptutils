// passcrypt is a utility for encrypting a file with a password. Files
// are packed into a tar file and gzipped before encrypting.
package main

import (
	"bytes"
	"compress/gzip"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/gokyle/readpass"
	"github.com/kisom/cryptutils/common/secret"
	"github.com/kisom/cryptutils/common/util"
)

const saltLength = 32
const header = "PASSCRYPT ARCHIVE"

var verbose bool

func dirPerm(mode int64) os.FileMode {
	if mode&7 != 0 {
		mode++
	}

	if mode&0x38 != 0 {
		mode += 8
	}

	if mode&0x1c0 != 0 {
		mode += 64
	}

	return os.FileMode(mode)
}

type File struct {
	Path string
	Mode int64
	Data []byte
}

func packFile(path string) (*File, error) {
	buf := new(bytes.Buffer)
	zbuf, err := gzip.NewWriterLevel(buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}

	fr, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fr.Close()

	fi, err := fr.Stat()
	if err != nil {
		return nil, err
	}

	_, err = io.Copy(zbuf, fr)
	if err != nil {
		return nil, err
	}

	zbuf.Close()
	file := &File{
		Path: filepath.Clean(path),
		Mode: int64(fi.Mode()),
		Data: buf.Bytes(),
	}

	return file, nil
}

func unpackFile(file File, top string) error {
	buf := bytes.NewBuffer(file.Data)
	zbuf, err := gzip.NewReader(buf)
	if err != nil {
		return err
	}

	path := filepath.Join(top, file.Path)
	fw, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY,
		os.FileMode(file.Mode))
	if err != nil {
		return err
	}

	_, err = io.Copy(fw, zbuf)
	if err != nil {
		return err
	}

	return nil
}

func packFiles(paths []string) ([]byte, error) {
	var files []File

	for _, walkPath := range paths {
		walker := func(path string, info os.FileInfo, err error) error {
			if info == nil {
				return fmt.Errorf("passcrypt: %s could not be read", path)
			}

			if info.Mode().IsDir() {
				if verbose {
					fmt.Println("Pack directory", path)
				}
				files = append(files, File{
					Path: filepath.Clean(path),
					Mode: int64(info.Mode()),
				})
				return nil
			} else if !info.Mode().IsRegular() {
				return nil
			}

			if verbose {
				fmt.Println("Pack file", path)
			}

			file, err := packFile(path)
			if err != nil {
				return err
			}
			files = append(files, *file)
			return nil
		}
		err := filepath.Walk(walkPath, walker)
		if err != nil {
			return nil, err
		}
	}

	out, err := asn1.Marshal(files)
	if err != nil {
		return nil, err
	}

	return out, nil
}

func unpackFiles(in []byte, top string) error {
	var files []File

	_, err := asn1.Unmarshal(in, &files)
	if err != nil {
		return err
	}

	if _, err := os.Stat(top); err != nil {
		if os.IsNotExist(err) {
			err = os.MkdirAll(top, 0755)
			if err != nil {
				return err
			}
		}
	}

	for _, file := range files {
		if verbose {
			fmt.Println("Unpack", file.Path)
		}
		if os.FileMode(file.Mode).IsDir() {
			fmt.Println("Directory:", file.Path)
			err = os.MkdirAll(filepath.Join(top, file.Path),
				os.FileMode(file.Mode))
			if err != nil {
				return err
			}
			continue
		}

		dir := filepath.Dir(file.Path)
		dir = filepath.Clean(filepath.Join(top, dir))
		if _, err := os.Stat(dir); err != nil {
			if os.IsNotExist(err) {
				err = os.MkdirAll(dir, dirPerm(file.Mode))
				if err != nil {
					return err
				}
			}
		}

		err = unpackFile(file, top)
		if err != nil {
			return err
		}
	}
	return nil
}

func main() {
	flArmour := flag.Bool("a", false, "armour output")
	flOutDir := flag.String("o", ".", "output directory")
	flOutfile := flag.String("f", "passcrypt.enc", "pack file")
	flShowManifest := flag.Bool("l", false, "list the files in the archive")
	flUnpack := flag.Bool("u", false, "unpack the archive")
	flag.BoolVar(&verbose, "v", false, "verbose mode")
	flVersion := flag.Bool("V", false, "display version and exit")
	flag.Parse()

	if *flVersion {
		fmt.Println("passcrypt version", util.VersionString())
		os.Exit(0)
	}

	if *flUnpack || *flShowManifest {
		if flag.NArg() != 1 {
			util.Errorf("Only one file may be unpacked at a time.\n")
			os.Exit(1)
		}

		in, err := ioutil.ReadFile(flag.Arg(0))
		if err != nil {
			util.Errorf("%v\n", err)
			os.Exit(1)
		}

		if p, _ := pem.Decode(in); p != nil {
			if p.Type != header {
				util.Errorf("Wrong header for archive.\n")
				os.Exit(1)
			}
			in = p.Bytes
		}

		if len(in) <= saltLength {
			util.Errorf("Invalid archive.\n")
			os.Exit(1)
		}
		salt := in[:saltLength]
		in = in[saltLength:]

		passphrase, err := readpass.PasswordPromptBytes("Password: ")
		if err != nil {
			util.Errorf("%v\n", err)
			os.Exit(1)
		}

		key := secret.DeriveKey(passphrase, salt)
		if key == nil {
			util.Errorf("Failed to derive key.n\n")
			os.Exit(1)
		}

		in, ok := secret.Decrypt(key, in)
		if !ok {
			util.Errorf("Decryption failed.\n")
			os.Exit(1)
		}
		defer util.Zero(in)

		if *flUnpack {
			err = unpackFiles(in, *flOutDir)
			if err != nil {
				util.Errorf("%v\n", err)
				os.Exit(1)
			}
		} else if *flShowManifest {
			var files []File
			_, err := asn1.Unmarshal(in, &files)
			if err != nil {
				util.Errorf("%v\n", err)
				os.Exit(1)
			}

			fmt.Println("Manifest for", flag.Arg(0))
			fmt.Printf("\n")
			for _, file := range files {
				fmt.Printf("\t%s", file.Path)
				if os.FileMode(file.Mode).IsDir() {
					fmt.Printf("/")
				}
				fmt.Printf("\n")
			}
		}
		return
	}

	if flag.NArg() == 0 {
		return
	}

	passphrase, err := readpass.PasswordPromptBytes("Password: ")
	if err != nil {
		util.Errorf("%v\n", err)
		os.Exit(1)
	}

	salt := util.RandBytes(saltLength)
	if salt == nil {
		util.Errorf("Failed to generate a random salt.\n")
		os.Exit(1)
	}

	key := secret.DeriveKey(passphrase, salt)
	if key == nil {
		util.Errorf("Failed to derive key.n\n")
		os.Exit(1)
	}

	out, err := packFiles(flag.Args())
	if err != nil {
		util.Errorf("%v\n", err)
		os.Exit(1)
	}

	var ok bool
	out, ok = secret.Encrypt(key, out)
	if !ok {
		util.Errorf("Encryption failed.\n")
		os.Exit(1)
	}

	out = append(salt, out...)

	if *flArmour {
		p := &pem.Block{
			Type:  header,
			Bytes: out,
		}
		out = pem.EncodeToMemory(p)
	}

	err = ioutil.WriteFile(*flOutfile, out, 0644)
	if err != nil {
		util.Errorf("%v\n", err)
		os.Exit(1)
	}
}
