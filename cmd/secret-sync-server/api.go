package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/kisom/cryptutils/common/sync"
)

func unpackRequest(r *http.Request, v interface{}) error {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	return dec.Decode(v)
}

func sendFailureResponse(w http.ResponseWriter, msg string, status int) {
	resp := &sync.Response{
		Message: msg,
	}
	out, err := json.Marshal(resp)
	if err != nil {
		log.Printf("failed to send error response: %v", err)
		return
	}

	w.WriteHeader(status)
	w.Write(out)
}

func sendResponse(w http.ResponseWriter, res *sync.Response, status int) {
	out, err := json.Marshal(res)
	if err != nil {
		log.Printf("failed to send error response: %v", err)
		return
	}

	w.WriteHeader(status)
	w.Write(out)
}

func addInvite(w http.ResponseWriter, r *http.Request) {
	body := map[string]string{}

	err := unpackRequest(r, &body)
	if err != nil {
		log.Printf("failed to unpack request: %v", err)
		sendFailureResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	request := &intRequest{
		Op:   "invite",
		Ret:  make(chan *sync.Response, 0),
		Data: body,
	}

	store.procChan <- request
	res := <-request.Ret

	var status = http.StatusBadRequest
	if res.Success {
		status = http.StatusOK
	}
	sendResponse(w, res, status)
}

func register(w http.ResponseWriter, r *http.Request) {
	var reg sync.Registration

	err := unpackRequest(r, &reg)
	if err != nil {
		log.Printf("failed to unpack request: %v", err)
		sendFailureResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	if _, ok := store.Users[reg.Login]; ok {
		log.Println("registration for existing user", reg.Login)
		sendFailureResponse(w, "username is taken", http.StatusBadRequest)
		return
	}

	if ok, err := sync.RegistrationIsValid(&reg, true); !ok {
		log.Printf("invalid registration received: %v", err)
		sendFailureResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !store.Invites[reg.Invite] {
		log.Printf("registration with invite code")
		sendFailureResponse(w, "invite required", http.StatusBadRequest)
		return
	}

	user := sync.Register(&reg)
	if user == nil {
		log.Printf("registration of user %s failed", reg.Login)
		sendFailureResponse(w, "registration failed", http.StatusBadRequest)
		return
	}

	request := &intRequest{
		Op:   "register",
		Ret:  make(chan *sync.Response, 0),
		Data: user,
	}

	store.procChan <- request
	res := <-request.Ret

	var status = http.StatusBadRequest
	if res.Success {
		status = http.StatusOK
		delete(store.Invites, reg.Invite)
	}
	sendResponse(w, res, status)
}

func syncdown(w http.ResponseWriter, r *http.Request) {
	var sr sync.SyncRequest

	err := unpackRequest(r, &sr)
	if err != nil {
		log.Printf("failed to unpack request: %v", err)
		sendFailureResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	request := &intRequest{
		Op:   "pull",
		Ret:  make(chan *sync.Response, 0),
		Data: &sr,
	}

	store.procChan <- request
	res := <-request.Ret

	var status = http.StatusBadRequest
	if res.Success {
		status = http.StatusOK
	}
	sendResponse(w, res, status)
}

func syncup(w http.ResponseWriter, r *http.Request) {
	var sr sync.SyncRequest

	err := unpackRequest(r, &sr)
	if err != nil {
		log.Printf("failed to unpack request: %v", err)
		sendFailureResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	request := &intRequest{
		Op:   "push",
		Ret:  make(chan *sync.Response, 0),
		Data: &sr,
	}

	store.procChan <- request
	res := <-request.Ret

	var status = http.StatusBadRequest
	if res.Success {
		status = http.StatusOK
	}
	sendResponse(w, res, status)
}
