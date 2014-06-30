// keysrv is a keyserver storing verified keys.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/kisom/cryptutils/common/store"
	"github.com/kisom/cryptutils/common/util"
)

var router = mux.NewRouter()

type command struct {
	op   string
	data map[string]string
	cb   chan *response
}

type response struct {
	out []byte
	err error
}

func serverPublic(w http.ResponseWriter, r *http.Request) {
	request := map[string]string{"label": "self"}

	var cmd = command{"public", request, make(chan *response, 16)}
	dispatch <- cmd
	resp, ok := <-cmd.cb
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(resp.err.Error()))
		return
	}
	w.Write(resp.out)
}

func sendCommand(w http.ResponseWriter, cmd command) {
	dispatch <- cmd
	resp, ok := <-cmd.cb
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(resp.err.Error()))
		return
	} else if resp.err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(resp.err.Error()))
		return
	}
	w.Write(resp.out)
}

func getPublic(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	request := map[string]string{"label": vars["label"]}

	var cmd = command{"public", request, make(chan *response, 16)}
	sendCommand(w, cmd)
}

func addPublic(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}
	r.Body.Close()

	var request = map[string]string{
		"public": string(body),
		"label":  vars["label"],
	}
	var cmd = command{"upload", request, make(chan *response, 1)}
	sendCommand(w, cmd)
}

var dispatch = make(chan command, 16)

func checkUpload(ks *store.KeyStore, cmd command) response {
	label := cmd.data["label"]
	pub := []byte(cmd.data["public"])
	var resp response
	if label == "self" || label == "" {
		resp.err = errors.New("invalid label")
		return resp
	}
	ok := ks.ImportVerifiedKey(label, pub)
	if !ok {
		resp.err = errors.New("failed to add public key")
	} else {
		resp.out = []byte("public key added successfully")
	}
	return resp
}

func process(ks *store.KeyStore, cmd command) *response {
	var resp response

	switch cmd.op {
	case "public":
		log.Printf("public key lookup")
		if cmd.data["label"] == "" {
			log.Printf("public key request with no label")
			resp.err = errors.New("missing label")
		}
		ok := ks.Has(cmd.data["label"])
		if !ok {
			log.Printf("keystore doesn't have key with label %s", cmd.data["label"])
			resp.err = errors.New("export failed")
		}

		if cmd.data["label"] == self {
			resp.out = ks.PublicKey
		} else {
			rec := ks.Keys[cmd.data["label"]]
			if rec == nil {
				log.Printf("keystore lookup failed")
				resp.err = errors.New("export failed")
				break
			}
			vkey := &store.VerifiedKey{
				Public:    rec.Keys,
				Signer:    rec.KeySigner,
				Timestamp: rec.SignatureTime,
				Signature: rec.KeySignature,
			}
			resp.out, resp.err = vkey.Serialise()
		}
	case "upload":
		log.Printf("upload request")
		resp = checkUpload(ks, cmd)
	case "audit":
		log.Printf("audit request")
		ok := ks.KeyAudit()
		if !ok {
			resp.err = errors.New("audit failure")
		}
	default:
		resp.err = errors.New("invalid command")
	}
	return &resp
}

func auditRunner() {
	for {
		log.Println("signaling audit")
		cmd := command{"audit", nil, make(chan *response, 1)}
		dispatch <- cmd
		resp, ok := <-cmd.cb
		if !ok {
			log.Fatal("FATAL: failed to run audit")
		} else if resp.err != nil {
			log.Fatalf("FATAL: audit failed", resp.err)
		} else if resp.out != nil {
			log.Printf("Audit complete: %s", resp.out)
		} else {
			log.Println("Audit complete: OK")
		}
		<-time.After(4 * time.Hour)
	}
}

func keystoreDispatch(ks *store.KeyStore, keystoreFile string) {
	for {
		t := time.After(10 * time.Minute)
		select {
		case cmd, ok := <-dispatch:
			if !ok {
				return
			}
			log.Println("received command for", cmd.op)
			res := process(ks, cmd)
			cmd.cb <- res
		case <-t:
			log.Printf("dumping keystore")
			t = time.After(10 * time.Minute)
			out, err := ks.Dump()
			if err != nil {
				log.Printf("WARNING: failed to dump keystore: %v", err)
				break
			}
			err = ioutil.WriteFile(keystoreFile, out, 0644)
			if err != nil {
				log.Printf("WARNING: failed to write keystore: %v", err)
			}
		}
	}
}

func loadStore(path string) *store.KeyStore {
	// If keystore is newly created, we'll want to write it to
	// disk before leaving this function.
	var flush bool
	if exists, _ := util.Exists(path); !exists {
		flush = true
	}

	passphrase, err := util.PassPrompt("keystore passphrase> ")
	if err != nil {
		util.Errorf("%v", err)
		return nil
	}
	defer util.Zero(passphrase)

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
		if !keystore.Unlock(passphrase) {
			return nil
		}
		return keystore
	}

	if !keystore.LockWith(passphrase) {
		util.Errorf("Failed to set initial passphrase.")
		return nil
	} else if !keystore.Unlock(passphrase) {
		util.Errorf("Flushing keystore failed.")
		return nil
	}

	out, err := keystore.Dump()
	if err != nil {
		log.Printf("WARNING: failed to dump keystore: %v", err)
		return nil
	}
	err = ioutil.WriteFile(path, out, 0644)
	if err != nil {
		log.Printf("WARNING: failed to write keystore: %v", err)
	}

	return keystore
}

func main() {
	address := flag.String("a", "127.0.0.1:8443", "listening address")
	keystoreFile := flag.String("f", "keystore.db", "keystore")
	keyFile := flag.String("k", "server.key", "TLS key")
	certFile := flag.String("c", "server.pem", "TLS certificate")
	flag.Parse()

	keystore := loadStore(*keystoreFile)
	if keystore == nil {
		log.Fatal("failed to open keystore file %v", *keystoreFile)
	}
	if !keystore.KeyAudit() {
		log.Fatal("keystore failed audit")
	}

	go keystoreDispatch(keystore, *keystoreFile)
	go auditRunner()
	router.HandleFunc("/public/", serverPublic)
	router.HandleFunc("/public/{label}", getPublic)
	router.HandleFunc("/upload/{label}", addPublic)
	log.Fatal(http.ListenAndServeTLS(*address, *certFile, *keyFile, router))
}
