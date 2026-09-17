package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// This reference stub deliberately does NOT implement real WebAuthn
// attestation/assertion cryptography (COSE keys, CBOR attestation objects,
// ECDSA signature verification over clientDataJSON). That half of WebAuthn
// is go-webauthn/webauthn's job, and per this suite's own version audit
// (see docs/security-test-suite.md section "已决事项" #3) it carries zero
// open advisories across all three target projects — there is nothing to
// regression-test there.
//
// What IS worth testing, and what this stub implements for real, is the
// ceremony-session protocol every project layers ON TOP of that library
// (go-webauthn's own docs say this part is the caller's responsibility):
// a begin/finish challenge that must be used exactly once, must not be
// used after it expires, must be presented with the origin/RP ID it was
// issued for, must not let a login ceremony claim a different user's
// discoverable credential (the "user handle confusion" case), and must
// reject a counter that goes backwards (the standard signal that a
// credential was cloned). See 4.2 in the design doc.

const webauthnCeremonyTTL = 60 * time.Second
const expectedRPID = "example.com"
const expectedOrigin = "https://example.com"
const ceremonyCookieName = "sectest_webauthn_ceremony"

type webauthnCeremony struct {
	Mode         string // "register" or "login"
	Username     string
	UserHandle   string // hex-encoded; the server's own record of whose ceremony this is, never trusted from the client at finish time
	CredentialID string // set for "login": which credential this ceremony is asserting against
	CreatedAt    time.Time
	Used         bool
}

type webauthnCredential struct {
	UserHandle string
	Counter    uint64
}

type webauthnState struct {
	mu          sync.Mutex
	ceremonies  map[string]*webauthnCeremony   // session id -> ceremony
	credentials map[string]*webauthnCredential // credential id -> credential
}

func newWebAuthnState() *webauthnState {
	return &webauthnState{
		ceremonies:  make(map[string]*webauthnCeremony),
		credentials: make(map[string]*webauthnCredential),
	}
}

type webauthnBeginRequest struct {
	Mode         string `json:"mode"` // "register" | "login"
	Username     string `json:"username"`
	CredentialID string `json:"credential_id"` // required when mode == "login"
}

type webauthnBeginResponse struct {
	Challenge       string `json:"challenge"` // base64
	RPID            string `json:"rp_id"`
	UserHandle      string `json:"user_handle"` // base64, the handle THIS ceremony is bound to server-side
	ExpiresInSecond int    `json:"expires_in_seconds"`
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

	c := &webauthnCeremony{Mode: req.Mode, Username: req.Username, CreatedAt: time.Now()}
	switch req.Mode {
	case "register":
		c.UserHandle = hex.EncodeToString(sha256Sum([]byte(req.Username)))
	case "login":
		if req.CredentialID == "" {
			writeJSONStatus(w, http.StatusBadRequest, errBody("credential_id is required for mode=login"))
			return
		}
		cred, ok := st.credentials[req.CredentialID]
		if !ok {
			writeJSONStatus(w, http.StatusNotFound, errBody("unknown credential_id"))
			return
		}
		c.CredentialID = req.CredentialID
		c.UserHandle = cred.UserHandle // the TRUE owner, as recorded at registration — never taken from the request
	default:
		writeJSONStatus(w, http.StatusBadRequest, errBody(`mode must be "register" or "login"`))
		return
	}

	sessionID := randomHex(16)
	st.ceremonies[sessionID] = c

	http.SetCookie(w, &http.Cookie{Name: ceremonyCookieName, Value: sessionID, Path: "/", HttpOnly: true})
	writeJSONStatus(w, http.StatusOK, webauthnBeginResponse{
		Challenge:       randomB64(32),
		RPID:            expectedRPID,
		UserHandle:      base64.StdEncoding.EncodeToString([]byte(c.UserHandle)),
		ExpiresInSecond: int(webauthnCeremonyTTL / time.Second),
	})
}

type webauthnFinishRequest struct {
	CredentialID         string `json:"credential_id"`
	Counter              uint64 `json:"counter"`
	Origin               string `json:"origin"`
	RPID                 string `json:"rp_id"`
	ClaimedUserHandleB64 string `json:"user_handle"` // what the client's assertion response claims — an attacker-controlled field in a discoverable-credential (usernameless) flow
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
		writeJSONStatus(w, http.StatusUnauthorized, errBody("ceremony not found or already discarded"))
		return
	}
	if c.Used {
		writeJSONStatus(w, http.StatusConflict, errBody("ceremony already used (replay rejected)"))
		return
	}
	if time.Since(c.CreatedAt) > webauthnCeremonyTTL {
		writeJSONStatus(w, http.StatusUnauthorized, errBody("ceremony expired"))
		return
	}
	if req.Origin != expectedOrigin {
		writeJSONStatus(w, http.StatusUnauthorized, errBody("origin mismatch"))
		return
	}
	if req.RPID != expectedRPID {
		writeJSONStatus(w, http.StatusUnauthorized, errBody("rp_id mismatch"))
		return
	}
	if c.Mode == "login" {
		claimed, _ := base64.StdEncoding.DecodeString(req.ClaimedUserHandleB64)
		if string(claimed) != c.UserHandle {
			writeJSONStatus(w, http.StatusUnauthorized, errBody("user handle does not match the credential's recorded owner"))
			return
		}
		if existing, ok := st.credentials[c.CredentialID]; ok && req.Counter <= existing.Counter {
			writeJSONStatus(w, http.StatusUnauthorized, errBody("signature counter did not increase — possible cloned authenticator"))
			return
		}
	}

	credID := req.CredentialID
	if credID == "" {
		credID = randomHex(16) // registration mints a fresh credential id when the (simulated) authenticator doesn't supply one
	}
	st.credentials[credID] = &webauthnCredential{UserHandle: c.UserHandle, Counter: req.Counter}
	c.Used = true

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

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}
