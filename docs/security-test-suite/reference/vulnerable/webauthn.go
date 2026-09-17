package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"sync"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// See reference/safe/webauthn.go for what this stub is (a real
// go-webauthn/webauthn relying party, not a hand-rolled crypto verifier)
// and why: go-webauthn's own cryptographic correctness is out of this
// suite's scope, so both stubs delegate to it for real. Every ceremony-
// session protection reference/safe implements ON TOP of go-webauthn is
// missing here — see the numbered gaps below, each mapped to a row in
// docs/security-test-suite.md section 4.2.

const ceremonyCookieName = "sectest_webauthn_ceremony"
const expectedRPID = "example.com"
const expectedOrigin = "https://example.com"

// wrongOrigin is a second origin this stub's relying-party config accepts
// alongside expectedOrigin — GAP 3's origin half. A real multi-tenant (or
// multi-environment) WebAuthn integration sometimes ends up with an
// RPOrigins allow-list broader than the single origin it actually serves
// (a leftover staging entry, a copy-pasted config, …); go-webauthn itself
// enforces whatever list it is configured with correctly, so the gap here
// is entirely this stub's own (over-broad) configuration, not a library
// bug. It is a fixed RFC 2606 example domain, matching what
// passkey_test.go's TestPasskey_OriginMismatchRejected uses as its
// "wrong" origin — see webauthnTestOrigin/webauthnWrongOrigin there.
const wrongOrigin = "https://attacker.example.net"

// newWebAuthn is this stub's relying-party identity for the ORIGIN half of
// GAP 3: unlike reference/safe, RPOrigins includes wrongOrigin too.
func newWebAuthn() (*webauthn.WebAuthn, error) {
	return webauthn.New(&webauthn.Config{
		RPID:          expectedRPID,
		RPDisplayName: "sectest reference/vulnerable",
		RPOrigins:     []string{expectedOrigin, wrongOrigin},
	})
}

type webauthnCredentialRecord struct {
	ID        []byte
	PublicKey []byte // CBOR-encoded COSE_Key
	SignCount uint32
	Owner     []byte // user handle
	OwnerName string
}

func (r *webauthnCredentialRecord) credential() webauthn.Credential {
	return webauthn.Credential{
		ID:        r.ID,
		PublicKey: r.PublicKey,
		Authenticator: webauthn.Authenticator{
			SignCount: r.SignCount,
		},
	}
}

type webauthnCeremony struct {
	Mode    string // "register" or "login"
	Session webauthn.SessionData
	// GAP 2 (ceremony expiry, 4.2 "ceremony session 过期"): no CreatedAt is
	// even recorded, since nothing ever checks it.
	// GAP 1 (challenge replay, 4.2 "重放 finish 请求"): no Used flag
	// either — the exact same cookie can be replayed against
	// /webauthn/finish indefinitely.
}

type webauthnState struct {
	mu          sync.Mutex
	ceremonies  map[string]*webauthnCeremony
	credentials map[string]*webauthnCredentialRecord
}

func newWebAuthnState() *webauthnState {
	return &webauthnState{
		ceremonies:  make(map[string]*webauthnCeremony),
		credentials: make(map[string]*webauthnCredentialRecord),
	}
}

type stubUser struct {
	id    []byte
	name  string
	creds []webauthn.Credential
}

func (u *stubUser) WebAuthnID() []byte                         { return u.id }
func (u *stubUser) WebAuthnName() string                       { return u.name }
func (u *stubUser) WebAuthnDisplayName() string                { return u.name }
func (u *stubUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

type webauthnBeginRequest struct {
	Mode         string `json:"mode"`
	Username     string `json:"username"`
	CredentialID string `json:"credential_id"`

	// RPID, if non-empty, is honored below (GAP 3's RP-ID half) — unlike
	// reference/safe, which never reads it. This is the vulnerability
	// this field exists to demonstrate, not an accident: a WebAuthn
	// integration that resolves which relying-party ID to bind a ceremony
	// to from unauthenticated request data (e.g. a multi-tenant deployment
	// keyed by a client-supplied tenant/RP hint, with no check that the
	// caller is authorized for that tenant) lets whoever calls begin()
	// choose the very identity boundary the ceremony is supposed to
	// enforce.
	RPID string `json:"rp_id,omitempty"`
}

type webauthnBeginResponse struct {
	PublicKey       any `json:"publicKey"`
	ExpiresInSecond int `json:"expires_in_seconds"`
}

func (s *server) webauthnBegin(w http.ResponseWriter, r *http.Request) {
	var req webauthnBeginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, errBody("invalid JSON body"))
		return
	}

	wa, err := newWebAuthn()
	if err != nil {
		writeJSONStatus(w, http.StatusInternalServerError, errBody("relying party configuration error"))
		return
	}

	st := s.webauthn
	st.mu.Lock()
	defer st.mu.Unlock()

	switch req.Mode {
	case "register":
		userHandle := sha256Sum([]byte(req.Username))
		user := &stubUser{id: userHandle, name: req.Username}

		opts := []webauthn.RegistrationOption{webauthn.WithConveyancePreference(protocol.PreferNoAttestation)}
		if req.RPID != "" {
			opts = append(opts, webauthn.WithRegistrationRelyingPartyID(req.RPID)) // GAP 3
		}

		creation, session, err := wa.BeginRegistration(user, opts...)
		if err != nil {
			writeJSONStatus(w, http.StatusInternalServerError, errBody("begin registration: "+err.Error()))
			return
		}

		sessionID := randomHex(16)
		st.ceremonies[sessionID] = &webauthnCeremony{Mode: "register", Session: *session}
		setCeremonyCookie(w, sessionID)
		writeJSONStatus(w, http.StatusOK, webauthnBeginResponse{
			PublicKey:       creation.Response,
			ExpiresInSecond: 60,
		})

	case "login":
		// note: no 404 for an unknown credential_id, unlike reference/safe
		// — not itself one of the tested gaps, just kept minimal here.
		credID, _ := base64.RawURLEncoding.DecodeString(req.CredentialID)
		rec := st.credentials[string(credID)]

		var allowed []protocol.CredentialDescriptor
		if rec != nil {
			allowed = []protocol.CredentialDescriptor{{Type: protocol.PublicKeyCredentialType, CredentialID: rec.ID}}
		}
		opts := []webauthn.LoginOption{webauthn.WithAllowedCredentials(allowed)}
		if req.RPID != "" {
			opts = append(opts, webauthn.WithLoginRelyingPartyID(req.RPID)) // GAP 3
		}

		assertion, session, err := wa.BeginDiscoverableLogin(opts...)
		if err != nil {
			writeJSONStatus(w, http.StatusInternalServerError, errBody("begin login: "+err.Error()))
			return
		}

		sessionID := randomHex(16)
		st.ceremonies[sessionID] = &webauthnCeremony{Mode: "login", Session: *session}
		setCeremonyCookie(w, sessionID)
		writeJSONStatus(w, http.StatusOK, webauthnBeginResponse{
			PublicKey:       assertion.Response,
			ExpiresInSecond: 60,
		})

	default:
		writeJSONStatus(w, http.StatusBadRequest, errBody(`mode must be "register" or "login"`))
	}
}

func (s *server) webauthnFinish(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(ceremonyCookieName)
	if err != nil {
		writeJSONStatus(w, http.StatusUnauthorized, errBody("no ceremony session cookie"))
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSONStatus(w, http.StatusBadRequest, errBody("failed to read request body"))
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

	// GAP 1 (challenge replay): the ceremony is never marked used and
	// never deleted, so the exact same cookie can be replayed against
	// /webauthn/finish indefinitely.

	// GAP 2 (ceremony expiry): no CreatedAt was recorded at begin time, so
	// there is nothing to compare against — a ceremony from an hour ago is
	// accepted identically to a fresh one.

	wa, err := newWebAuthn()
	if err != nil {
		writeJSONStatus(w, http.StatusInternalServerError, errBody("relying party configuration error"))
		return
	}

	switch c.Mode {
	case "register":
		user := &stubUser{id: c.Session.UserID}
		cred, err := wa.FinishRegistration(user, c.Session, newBodyRequest(body))
		if err != nil {
			writeJSONStatus(w, http.StatusUnauthorized, errBody("registration rejected: "+err.Error()))
			return
		}
		st.credentials[string(cred.ID)] = &webauthnCredentialRecord{
			ID:        cred.ID,
			PublicKey: cred.PublicKey,
			SignCount: cred.Authenticator.SignCount,
			Owner:     c.Session.UserID,
		}
		writeJSONStatus(w, http.StatusOK, map[string]any{
			"ok":            true,
			"credential_id": base64.RawURLEncoding.EncodeToString(cred.ID),
		})

	case "login":
		// GAP 4 (user handle confusion): identity is resolved from the
		// assertion's wire-level CLAIMED userHandle, not from the
		// credential's own recorded owner. The credential itself (and
		// therefore its real public key, needed for the signature to
		// verify at all) is still looked up correctly by rawID — only the
		// IDENTITY the ceremony completes as is wrong. Contrast with
		// reference/safe/webauthn.go's handler, which ignores
		// claimedUserHandle entirely and reports rec.Owner instead.
		handler := func(rawID, claimedUserHandle []byte) (webauthn.User, error) {
			rec, ok := st.credentials[string(rawID)]
			if !ok {
				return nil, errUnknownCredential
			}
			return &stubUser{id: claimedUserHandle, name: rec.OwnerName, creds: []webauthn.Credential{rec.credential()}}, nil
		}

		_, cred, err := wa.FinishPasskeyLogin(handler, c.Session, newBodyRequest(body))
		if err != nil {
			writeJSONStatus(w, http.StatusUnauthorized, errBody("login rejected: "+err.Error()))
			return
		}

		// GAP 5 (counter rollback / cloned-authenticator detection):
		// go-webauthn sets cred.Authenticator.CloneWarning when the new
		// counter failed to increase (see
		// webauthn.Authenticator.UpdateCounter), but leaves the
		// accept/reject decision to the caller — this handler never looks
		// at it and stores whatever counter came back unconditionally.
		if rec, ok := st.credentials[string(cred.ID)]; ok {
			rec.SignCount = cred.Authenticator.SignCount
		}
		writeJSONStatus(w, http.StatusOK, map[string]any{
			"ok":            true,
			"credential_id": base64.RawURLEncoding.EncodeToString(cred.ID),
		})

	default:
		writeJSONStatus(w, http.StatusInternalServerError, errBody("ceremony has an unknown mode"))
	}
}

func setCeremonyCookie(w http.ResponseWriter, sessionID string) {
	http.SetCookie(w, &http.Cookie{Name: ceremonyCookieName, Value: sessionID, Path: "/", HttpOnly: true})
}

var errUnknownCredential = protocol.ErrBadRequest.WithDetails("unknown credential")

func newBodyRequest(body []byte) *http.Request {
	return &http.Request{Body: io.NopCloser(bytes.NewReader(body))}
}

func errBody(msg string) map[string]string { return map[string]string{"error": msg} }

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}
