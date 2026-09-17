package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
)

// See reference/safe/webauthn.go for why this stub simulates only the
// ceremony-session protocol, not real WebAuthn attestation crypto. Every
// check that file performs at finish time is missing here — see the
// numbered gaps below, each mapped to a row in docs/security-test-suite.md
// section 4.2.

const ceremonyCookieName = "sectest_webauthn_ceremony"

type webauthnCeremony struct {
	Mode         string
	Username     string
	UserHandle   string
	CredentialID string
	// GAP 2 (ceremony expiry): no CreatedAt is even recorded, since
	// nothing ever checks it.
	// GAP 1 (challenge replay): no Used flag either.
}

type webauthnCredential struct {
	UserHandle string
	Counter    uint64
}

type webauthnState struct {
	mu          sync.Mutex
	ceremonies  map[string]*webauthnCeremony
	credentials map[string]*webauthnCredential
}

func newWebAuthnState() *webauthnState {
	return &webauthnState{
		ceremonies:  make(map[string]*webauthnCeremony),
		credentials: make(map[string]*webauthnCredential),
	}
}

type webauthnBeginRequest struct {
	Mode         string `json:"mode"`
	Username     string `json:"username"`
	CredentialID string `json:"credential_id"`
}

type webauthnBeginResponse struct {
	Challenge  string `json:"challenge"`
	RPID       string `json:"rp_id"`
	UserHandle string `json:"user_handle"`
}

func (s *server) webauthnBegin(w http.ResponseWriter, r *http.Request) {
	var req webauthnBeginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, errBody("invalid JSON body"))
		return
	}

	st := s.webauthn
	st.mu.Lock()
	defer st.mu.Unlock()

	c := &webauthnCeremony{Mode: req.Mode, Username: req.Username}
	switch req.Mode {
	case "register":
		sum := sha256.Sum256([]byte(req.Username))
		c.UserHandle = hex.EncodeToString(sum[:])
	case "login":
		c.CredentialID = req.CredentialID
		if cred, ok := st.credentials[req.CredentialID]; ok {
			c.UserHandle = cred.UserHandle
		}
		// note: no 404 for an unknown credential_id, unlike reference/safe
		// — not itself one of the tested gaps, just kept minimal here.
	default:
		writeJSONStatus(w, http.StatusBadRequest, errBody(`mode must be "register" or "login"`))
		return
	}

	sessionID := randomHex(16)
	st.ceremonies[sessionID] = c

	http.SetCookie(w, &http.Cookie{Name: ceremonyCookieName, Value: sessionID, Path: "/", HttpOnly: true})
	writeJSONStatus(w, http.StatusOK, webauthnBeginResponse{
		Challenge:  randomB64(32),
		RPID:       expectedRPID,
		UserHandle: base64.StdEncoding.EncodeToString([]byte(c.UserHandle)),
	})
}

const expectedRPID = "example.com" // present so field names line up with reference/safe; never compared against anything below (GAP 4)

type webauthnFinishRequest struct {
	CredentialID         string `json:"credential_id"`
	Counter              uint64 `json:"counter"`
	Origin               string `json:"origin"`
	RPID                 string `json:"rp_id"`
	ClaimedUserHandleB64 string `json:"user_handle"`
}

func (s *server) webauthnFinish(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(ceremonyCookieName)
	if err != nil {
		writeJSONStatus(w, http.StatusUnauthorized, errBody("no ceremony session cookie"))
		return
	}
	var req webauthnFinishRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, errBody("invalid JSON body"))
		return
	}

	st := s.webauthn
	st.mu.Lock()
	defer st.mu.Unlock()

	c, ok := st.ceremonies[cookie.Value]
	if !ok {
		writeJSONStatus(w, http.StatusUnauthorized, errBody("ceremony not found"))
		return
	}

	// GAP 1 (challenge replay, 4.2 "重放 finish 请求"): the ceremony is
	// never marked used and never deleted, so the exact same cookie can be
	// replayed against /webauthn/finish indefinitely.

	// GAP 2 (ceremony expiry, 4.2 "ceremony session 过期"): no CreatedAt
	// was recorded at begin time, so there is nothing to compare against
	// — a ceremony from an hour ago is accepted identically to a fresh
	// one.

	// GAP 3 (origin/RP ID validation, 4.2 table + design doc 4.2 intro):
	// req.Origin and req.RPID are read but never compared against
	// expectedOrigin/expectedRPID. A finish request claiming any origin or
	// RP ID at all is accepted.

	// GAP 4 (user handle confusion): for a login ceremony, the
	// client-claimed user_handle is never compared against c.UserHandle
	// (the server's own record of the credential's true owner). An
	// attacker who knows another user's credential_id and user_handle
	// value can complete their ceremony and be treated as that user.

	// GAP 5 (counter rollback / cloned-authenticator detection): the new
	// counter is stored unconditionally, with no check that it increased
	// relative to the previously stored value.

	credID := req.CredentialID
	if credID == "" {
		credID = randomHex(16)
	}
	userHandle := c.UserHandle
	if userHandle == "" {
		// Trusts the client-claimed handle outright when the server has no
		// recorded owner for this ceremony — the essence of GAP 4.
		claimed, _ := base64.StdEncoding.DecodeString(req.ClaimedUserHandleB64)
		userHandle = string(claimed)
	}
	st.credentials[credID] = &webauthnCredential{UserHandle: userHandle, Counter: req.Counter}

	writeJSONStatus(w, http.StatusOK, map[string]any{"ok": true, "credential_id": credID})
}

func errBody(msg string) map[string]string { return map[string]string{"error": msg} }

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randomB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}
