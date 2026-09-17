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
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// This reference stub performs REAL WebAuthn ceremonies through
// go-webauthn/webauthn — the same library all three target projects use —
// rather than a simplified stand-in protocol. A finish call here must
// carry an actual CBOR attestationObject (registration) or a real ECDSA
// signature over authenticatorData‖SHA-256(clientDataJSON) (login); see
// internal/authenticator for the client/authenticator implementation this
// suite's own tests use to produce one.
//
// go-webauthn's own cryptographic correctness (COSE key parsing, ECDSA
// signature verification, CBOR attestation-statement decoding, …) is out
// of this suite's scope — per its version audit, go-webauthn carries zero
// open advisories across all three target projects, so there is nothing
// to regression-test there. What IS worth testing, and what the
// difference between this file and reference/vulnerable/webauthn.go
// implements, is the ceremony-session protocol every project layers ON
// TOP of go-webauthn (its own docs leave this to the caller): a
// begin/finish challenge that must be used exactly once, must not be used
// after it expires, must not let the relying-party identity a ceremony is
// bound to be dictated by whoever calls begin, must not let a login
// ceremony report a different user than the credential's true recorded
// owner, and must reject a signature counter that goes backwards (the
// standard signal a credential was cloned). See 4.2 in the design doc.
//
// Two of those five checks — replay (GAP 1) and expiry (GAP 2) — are pure
// ceremony-store bookkeeping, unrelated to go-webauthn. The other three
// ride on real go-webauthn behavior that this file exercises correctly and
// reference/vulnerable/webauthn.go does not:
//
//   - RP ID / origin pinning (GAP 3): go-webauthn's SessionData permanently
//     records the RP ID and (when bound) the origin a ceremony was BEGUN
//     for, and its Finish* calls validate the response against exactly
//     that — never against anything the finish request itself claims. The
//     only way to get a "wrong RP ID/origin accepted" outcome is to let
//     begin() bind the ceremony to an RP identity the CALLER supplied
//     rather than one this deployment actually owns. This file never does
//     that: newWebAuthn (below) is the one, fixed relying-party identity
//     every ceremony uses, full stop.
//   - User handle attribution (part of GAP 4): go-webauthn's
//     ValidatePasskeyLogin rejects an assertion whose wire-level claimed
//     userHandle does not equal the identity the caller's
//     DiscoverableUserHandler resolved. This file's handler (see
//     webauthnFinish) resolves that identity purely from the credential's
//     own recorded owner — never from the claimed handle — so a mismatch
//     is a real rejection, not a check this file has to perform itself.
//   - Cloned-authenticator detection (GAP 5): go-webauthn flags, but does
//     not itself reject, a signature counter that fails to increase (see
//     webauthn.Authenticator.UpdateCounter's doc comment) — leaving the
//     accept/reject decision to the caller by design. This file makes
//     that decision; reference/vulnerable/webauthn.go doesn't.
const webauthnCeremonyTTL = 60 * time.Second
const expectedRPID = "example.com"
const expectedOrigin = "https://example.com"
const ceremonyCookieName = "sectest_webauthn_ceremony"

// newWebAuthn is this stub's one, fixed relying-party identity. Every
// ceremony this file begins or finishes uses it — nothing about the
// request that reaches webauthnBegin or webauthnFinish ever changes which
// RP ID or origin a ceremony is validated against.
func newWebAuthn() (*webauthn.WebAuthn, error) {
	return webauthn.New(&webauthn.Config{
		RPID:          expectedRPID,
		RPDisplayName: "sectest reference/safe",
		RPOrigins:     []string{expectedOrigin},
	})
}

// webauthnCredentialRecord is this stub's persisted view of a registered
// credential: enough to rebuild a webauthn.Credential for a later login
// ceremony, plus the true, server-recorded owner a login's claimed
// identity is checked against.
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

// webauthnCeremony is this stub's ceremony-session record: what
// reference/safe and reference/vulnerable each independently decide
// whether to enforce, on top of the real go-webauthn SessionData every
// ceremony also carries.
type webauthnCeremony struct {
	Mode      string // "register" or "login"
	Session   webauthn.SessionData
	CreatedAt time.Time
	Used      bool
}

type webauthnState struct {
	mu          sync.Mutex
	ceremonies  map[string]*webauthnCeremony
	credentials map[string]*webauthnCredentialRecord // keyed by string(credential ID)
}

func newWebAuthnState() *webauthnState {
	return &webauthnState{
		ceremonies:  make(map[string]*webauthnCeremony),
		credentials: make(map[string]*webauthnCredentialRecord),
	}
}

// stubUser is the minimal webauthn.User this stub ever needs: a handle,
// a display name, and the (at most one, for a login ceremony) credential
// relevant to the ceremony at hand.
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
	Mode         string `json:"mode"` // "register" | "login"
	Username     string `json:"username"`
	CredentialID string `json:"credential_id"` // base64url, required when mode == "login"

	// RPID, if non-empty, asks this ceremony be bound to a different
	// relying-party ID than this deployment's own. reference/safe never
	// reads this field — see newWebAuthn's doc comment — it exists only
	// so the exact same request shape can be pointed at
	// reference/vulnerable, which does honor it (GAP 3).
	RPID string `json:"rp_id,omitempty"`
}

type webauthnBeginResponse struct {
	PublicKey       any `json:"publicKey"` // protocol.PublicKeyCredentialCreationOptions or PublicKeyCredentialRequestOptions
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

		creation, session, err := wa.BeginRegistration(user, webauthn.WithConveyancePreference(protocol.PreferNoAttestation))
		if err != nil {
			writeJSONStatus(w, http.StatusInternalServerError, errBody("begin registration: "+err.Error()))
			return
		}

		sessionID := randomHex(16)
		st.ceremonies[sessionID] = &webauthnCeremony{Mode: "register", Session: *session, CreatedAt: time.Now()}
		setCeremonyCookie(w, sessionID)
		writeJSONStatus(w, http.StatusOK, webauthnBeginResponse{
			PublicKey:       creation.Response,
			ExpiresInSecond: int(webauthnCeremonyTTL / time.Second),
		})

	case "login":
		if req.CredentialID == "" {
			writeJSONStatus(w, http.StatusBadRequest, errBody("credential_id is required for mode=login"))
			return
		}
		credID, err := base64.RawURLEncoding.DecodeString(req.CredentialID)
		if err != nil {
			writeJSONStatus(w, http.StatusBadRequest, errBody("credential_id must be base64url"))
			return
		}
		rec, ok := st.credentials[string(credID)]
		if !ok {
			writeJSONStatus(w, http.StatusNotFound, errBody("unknown credential_id"))
			return
		}

		assertion, session, err := wa.BeginDiscoverableLogin(webauthn.WithAllowedCredentials([]protocol.CredentialDescriptor{
			{Type: protocol.PublicKeyCredentialType, CredentialID: rec.ID},
		}))
		if err != nil {
			writeJSONStatus(w, http.StatusInternalServerError, errBody("begin login: "+err.Error()))
			return
		}

		sessionID := randomHex(16)
		st.ceremonies[sessionID] = &webauthnCeremony{Mode: "login", Session: *session, CreatedAt: time.Now()}
		setCeremonyCookie(w, sessionID)
		writeJSONStatus(w, http.StatusOK, webauthnBeginResponse{
			PublicKey:       assertion.Response,
			ExpiresInSecond: int(webauthnCeremonyTTL / time.Second),
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

	// The finish body is real WebAuthn wire data (a CBOR attestationObject
	// or a signed assertion) that go-webauthn's own parser consumes
	// directly from an io.Reader — it is read into memory once here so
	// GAP 1/2's ceremony bookkeeping below can run before a single byte of
	// it is parsed.
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
		c.Used = true
		writeJSONStatus(w, http.StatusOK, map[string]any{
			"ok":            true,
			"credential_id": base64.RawURLEncoding.EncodeToString(cred.ID),
		})

	case "login":
		// The identity a login ceremony reports is resolved purely from
		// the credential's own recorded owner — never from the
		// assertion's wire-level claimed userHandle. go-webauthn's
		// ValidatePasskeyLogin (called via FinishPasskeyLogin below)
		// itself rejects when the claimed handle contradicts whatever
		// this handler returns; that rejection IS the enforcement, not a
		// separate check this file performs afterward.
		handler := func(rawID, claimedUserHandle []byte) (webauthn.User, error) {
			rec, ok := st.credentials[string(rawID)]
			if !ok {
				return nil, errUnknownCredential
			}
			return &stubUser{id: rec.Owner, name: rec.OwnerName, creds: []webauthn.Credential{rec.credential()}}, nil
		}

		_, cred, err := wa.FinishPasskeyLogin(handler, c.Session, newBodyRequest(body))
		if err != nil {
			writeJSONStatus(w, http.StatusUnauthorized, errBody("login rejected: "+err.Error()))
			return
		}

		if cred.Authenticator.CloneWarning {
			writeJSONStatus(w, http.StatusUnauthorized, errBody("signature counter did not increase — possible cloned authenticator"))
			return
		}

		rec := st.credentials[string(cred.ID)]
		rec.SignCount = cred.Authenticator.SignCount
		c.Used = true
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
