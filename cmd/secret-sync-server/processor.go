package main

import (
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"strings"
	"time"

	"github.com/kisom/cryptutils/common/auth"
	"github.com/kisom/cryptutils/common/secret"
	"github.com/kisom/cryptutils/common/sync"
	"github.com/kisom/cryptutils/common/util"
)

func processor() {
	for {
		select {
		case in, ok := <-store.procChan:
			if !ok {
				log.Println("shutting down")
				shutdown()
				return
			}
			intRequestHandler(in)
		case _ = <-time.After(10 * time.Minute):
			writeStore()
		}
	}
}

var handlers = map[string]func(*intRequest){
	"register": registerHandler,
	"pull":     pullHandler,
	"push":     pushHandler,
	"invite":   inviteHandler,
}

func intRequestHandler(req *intRequest) {
	h, ok := handlers[req.Op]
	if !ok {
		log.Printf("Invalid request")
		req.Ret <- &sync.Response{
			Message: "invalid request",
		}
		return
	}
	h(req)
}

func registerHandler(req *intRequest) {
	var resp = &sync.Response{}
	resp.Result = make(map[string]string)

	u, ok := req.Data.(*sync.User)
	if !ok {
		log.Printf("registration request received, but data wasn't a registration")
		resp.Message = "invalid registration"
		req.Ret <- resp
		return
	}

	if u.Authenticator.Type == auth.TypeTOTP {
		uDetail, err := auth.ExportUserTOTP(u.Authenticator, "")
		if err != nil {
			log.Printf("error exporting TOTP details: %v", err)
			resp.Message = "registration failed"
			req.Ret <- resp
			return
		} else {
			resp.Result["key"] = uDetail.Secret
		}
	}

	log.Println("successfully registered", u.Login)
	resp.Success = true
	store.Users[u.Login] = u
	writeStore()

	req.Ret <- resp
}

func pullHandler(req *intRequest) {
	var resp = &sync.Response{}
	sr, ok := req.Data.(*sync.SyncRequest)
	if !ok {
		log.Printf("pull request received, but data wasn't a sync request")
		resp.Message = "invalid sync request"
		req.Ret <- resp
		return
	}

	sd, err := syncDownFromRequest(sr)
	if err != nil {
		log.Printf("sync down failed: %v", err)
		resp.Message = "sync failed"
		req.Ret <- resp
		return
	}

	resp.Success = true
	resp.Result = sd.Result()

	writeStore()
	req.Ret <- resp
}

func pushHandler(req *intRequest) {
	var resp = &sync.Response{}
	sr, ok := req.Data.(*sync.SyncRequest)
	if !ok {
		log.Printf("push request received, but data wasn't a sync request")
		resp.Message = "invalid sync request"
		req.Ret <- resp
		return
	}

	err := syncUpFromRequest(sr)
	if err != nil {
		log.Printf("push failed: %v", err)
		resp.Message = "sync failed"
		req.Ret <- resp
		return
	}

	writeStore()
	resp.Success = true
	req.Ret <- resp
}

func inviteHandler(req *intRequest) {
	var resp = &sync.Response{}
	body, ok := req.Data.(map[string]string)
	if !ok {
		log.Printf("request for invite doesn't have an OTP")
		resp.Message = "invalid request"
		req.Ret <- resp
		return
	}

	if _, err := auth.Validate(store.Admin, body["otp"]); err != nil {
		log.Printf("admin OTP failed validation")
		resp.Message = "invalid request"
		req.Ret <- resp
		return
	}

	inviteCode := util.RandBytes(12)
	if inviteCode == nil {
		log.Printf("failed to generate invite code")
		resp.Message = "request failed"
		req.Ret <- resp
		return
	}

	invite := base32.StdEncoding.EncodeToString(inviteCode)
	if store.Invites == nil {
		store.Invites = make(map[string]bool)
	}
	invite = strings.Trim(invite, "=")

	store.Invites[invite] = true
	resp.Result = map[string]string{
		"invite": invite,
	}
	resp.Success = true
	req.Ret <- resp
}

func writeStore() {
	out, err := json.Marshal(store)
	if err != nil {
		log.Printf("failed to marshal store: %v", err)
		return
	}
	defer util.Zero(out)

	salt := make([]byte, secret.SaltSize)
	copy(salt, store.salt)

	out, ok := secret.Encrypt(store.key, out)
	if !ok {
		log.Printf("failed to encrypt store")
		return
	}

	salt = append(salt, out...)
	err = ioutil.WriteFile(store.fileName, salt, 0644)
	if err != nil {
		log.Printf("failed to write store: %v", err)
	}

	log.Println("wrote store")
}

func syncDownFromRequest(sr *sync.SyncRequest) (*sync.SyncDown, error) {
	sd := &sync.SyncDown{}

	if sr == nil {
		return nil, errors.New("invalid sync request")
	}

	if sr.Login == "" || sr.Machine == "" || sr.Label == "" || sr.OTP == "" {
		return nil, errors.New("invalid sync request")
	}

	u, ok := store.Users[sr.Login]
	if !ok {
		return nil, errors.New("invalid sync request")
	}

	if !validateUser(u, sr.OTP) {
		return nil, errors.New("authentication failure")
	}

	sd.Blob = u.Blobs[sr.Label]

	s := &Session{
		Expires: time.Now().Add(5 * time.Minute),
	}

	var err error

	defer func(e error, logName string) {
		if e != nil {
			delete(store.sessions, logName)
		}
	}(err, u.Login)

	s.Session, sd.Public, err = auth.NewSession(u.PublicKeys[sr.Machine])
	if err != nil {
		return nil, err
	}

	sd.Next, err = hex.DecodeString(s.Session.Last)
	if err != nil {
		return nil, err
	}

	store.sessions[u.Login] = s
	return sd, nil
}

func validateUser(u *sync.User, otp string) bool {
	var a = u.Authenticator

	if session, ok := store.sessions[u.Login]; ok {
		log.Printf("%s has a current session", u.Login)
		if !time.Now().After(session.Expires) {
			log.Printf("session has not expired")
			session.Expires = session.Expires.Add(5 * time.Minute)
			a = session.Session
		}
	}

	shouldUpdate, err := auth.Validate(a, otp)
	if err != nil {
		if a.Type == auth.TypeSession {
			shouldUpdate, err = auth.Validate(u.Authenticator, otp)
			if err != nil {
				return false
			}
		}
	}

	if shouldUpdate {
		switch a.Type {
		case auth.TypeYubiKey, auth.TypeTOTP:
			u.Authenticator = a
		case auth.TypeSession:
			store.sessions[u.Login].Session = a
		}
	}

	return true
}

func syncUpFromRequest(sr *sync.SyncRequest) error {
	if sr == nil {
		return errors.New("invalid sync request")
	}

	if sr.Login == "" || sr.Machine == "" || sr.Label == "" || sr.OTP == "" {
		return errors.New("invalid sync request")
	}

	if len(sr.Blob) <= secret.SaltSize {
		return errors.New("invalid sync request")
	}

	u, ok := store.Users[sr.Login]
	if !ok {
		return errors.New("invalid sync request")
	}

	if !validateUser(u, sr.OTP) {
		return errors.New("authentication failure")
	}

	u.Blobs[sr.Label] = sr.Blob
	return nil
}
