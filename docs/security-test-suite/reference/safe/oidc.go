package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// This reference stub bundles a trivial mock OIDC IdP alongside the RP
// (callback) logic under test — see the "/oidc/mock/*" comment in main.go.
// A real project under test would instead be pointed at an external mock
// OIDC provider (oauth2-proxy/mockoidc is the suite's recommended choice);
// this stub's built-in mock exists only so reference/safe and
// reference/vulnerable can be exercised standalone while developing test
// cases, per this deliverable's self-verification requirement.

const (
	oidcIssuer   = "https://mock-idp.example.com/"
	oidcClientID = "sectest-client"
	oidcTokenTTL = 5 * time.Minute
)

type oidcFlow struct {
	State      string
	Nonce      string
	Subject    string
	CreatedAt  time.Time
	Code       string
	CodeIssued bool
	CodeUsed   bool
	Override   *string // when set, returned verbatim as the id_token instead of minting a normal one — see oidcMockOverride
}

type oidcState struct {
	key *rsa.PrivateKey

	mu      sync.Mutex
	byState map[string]*oidcFlow
}

func newOIDCState() (*oidcState, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &oidcState{key: key, byState: make(map[string]*oidcFlow)}, nil
}

// oidcStart begins a login flow. A real RP would redirect straight to the
// external IdP's /authorize endpoint; this stub redirects to its own
// built-in mock IdP instead.
func (s *server) oidcStart(w http.ResponseWriter, r *http.Request) {
	subject := r.URL.Query().Get("user")
	if subject == "" {
		subject = "sectest-oidc-user@example.com"
	}

	flow := &oidcFlow{
		State:     randomHex(16),
		Nonce:     randomHex(16),
		Subject:   subject,
		CreatedAt: time.Now(),
	}

	st := s.oidc
	st.mu.Lock()
	st.byState[flow.State] = flow
	st.mu.Unlock()

	http.SetCookie(w, &http.Cookie{Name: "sectest_oidc_flow", Value: flow.State, Path: "/", HttpOnly: true})
	http.Redirect(w, r, "/oidc/mock/authorize?state="+flow.State, http.StatusFound)
}

// oidcMockAuthorize plays the external IdP's login page: it auto-approves
// and redirects back to this RP's callback with a fresh authorization
// code, exactly as a real IdP would after the user authenticates.
func (s *server) oidcMockAuthorize(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	st := s.oidc
	st.mu.Lock()
	flow, ok := st.byState[state]
	if ok {
		flow.Code = randomHex(16)
		flow.CodeIssued = true
	}
	st.mu.Unlock()
	if !ok {
		writeJSONStatus(w, http.StatusBadRequest, errBody("unknown state"))
		return
	}
	http.Redirect(w, r, "/oidc/callback?code="+flow.Code+"&state="+state, http.StatusFound)
}

type oidcOverrideRequest struct {
	Alg              string         `json:"alg"` // "RS256" for a validly-signed-but-bad-claims token, "none" for the classic alg=none attack, anything else to simulate an unrecognized algorithm
	Claims           map[string]any `json:"claims"`
	CorruptSignature bool           `json:"corrupt_signature"` // flips the signature bytes after signing, to test signature verification independent of alg=none
}

// oidcMockOverride lets a test replace the id_token the NEXT code exchange
// for this state will return, so tests can exercise alg=none, bad aud/iss,
// expired tokens, and bad signatures without needing their own signing
// key — see the package doc in main.go.
func (s *server) oidcMockOverride(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	st := s.oidc
	st.mu.Lock()
	flow, ok := st.byState[state]
	st.mu.Unlock()
	if !ok {
		writeJSONStatus(w, http.StatusNotFound, errBody("unknown state"))
		return
	}

	var req oidcOverrideRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, errBody("invalid JSON body"))
		return
	}

	token, err := buildJWT(req.Alg, req.Claims, req.CorruptSignature, st.key)
	if err != nil {
		writeJSONStatus(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}

	st.mu.Lock()
	flow.Override = &token
	st.mu.Unlock()

	writeJSONStatus(w, http.StatusOK, map[string]string{"id_token": token})
}

// oidcCallback is the code under test: everything a relying party must
// check before treating a code-exchange response as "the user is
// authenticated".
func (s *server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	if state == "" {
		writeJSONStatus(w, http.StatusBadRequest, errBody("missing state parameter"))
		return
	}

	st := s.oidc
	st.mu.Lock()
	flow, ok := st.byState[state]
	if !ok {
		st.mu.Unlock()
		writeJSONStatus(w, http.StatusBadRequest, errBody("unknown or expired state — rejected (also covers a forged/mismatched state, since it simply won't be found here)"))
		return
	}
	if code == "" || code != flow.Code || !flow.CodeIssued {
		st.mu.Unlock()
		writeJSONStatus(w, http.StatusBadRequest, errBody("invalid authorization code"))
		return
	}
	if flow.CodeUsed {
		st.mu.Unlock()
		writeJSONStatus(w, http.StatusBadRequest, errBody("authorization code already used (replay rejected)"))
		return
	}
	flow.CodeUsed = true // burn the code now, before token validation, same as a real token endpoint would
	override := flow.Override
	nonce := flow.Nonce
	st.mu.Unlock()

	var rawToken string
	if override != nil {
		rawToken = *override
	} else {
		minted, err := buildJWT("RS256", map[string]any{
			"iss":   oidcIssuer,
			"aud":   oidcClientID,
			"sub":   flow.Subject,
			"nonce": nonce,
			"exp":   time.Now().Add(oidcTokenTTL).Unix(),
			"iat":   time.Now().Unix(),
		}, false, st.key)
		if err != nil {
			writeJSONStatus(w, http.StatusInternalServerError, errBody("could not mint token"))
			return
		}
		rawToken = minted
	}

	claims, err := verifyIDToken(rawToken, st.key)
	if err != nil {
		writeJSONStatus(w, http.StatusUnauthorized, errBody("id_token rejected: "+err.Error()))
		return
	}
	if claims["nonce"] != nonce || nonce == "" {
		writeJSONStatus(w, http.StatusUnauthorized, errBody("nonce missing or does not match the value bound to this flow"))
		return
	}

	sub, _ := claims["sub"].(string)
	http.SetCookie(w, &http.Cookie{Name: "sectest_session", Value: "oidc:" + sub, Path: "/", HttpOnly: true})
	writeJSONStatus(w, http.StatusOK, map[string]any{"authenticated": true, "sub": sub})
}

// verifyIDToken enforces: a recognized, non-"none" signing algorithm; a
// valid signature against this mock IdP's own key; and the aud/iss/exp
// claims. Nonce is checked by the caller, which has the per-flow expected
// value verifyIDToken does not know about.
func verifyIDToken(raw string, key *rsa.PrivateKey) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"})) // explicitly excludes "none" and any other algorithm — this is the alg=none defense
	_, err := parser.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		return &key.PublicKey, nil
	})
	if err != nil {
		return nil, err
	}
	if iss, _ := claims["iss"].(string); iss != oidcIssuer {
		return nil, errClaim("iss")
	}
	if !audienceContains(claims, oidcClientID) {
		return nil, errClaim("aud")
	}
	// jwt/v5's claims validator already enforces `exp` when the claim is
	// present as part of ParseWithClaims above; a token with no `exp` at
	// all is therefore the remaining gap, closed explicitly here.
	if _, hasExp := claims["exp"]; !hasExp {
		return nil, errClaim("exp (missing)")
	}
	return claims, nil
}

func audienceContains(claims jwt.MapClaims, want string) bool {
	switch v := claims["aud"].(type) {
	case string:
		return v == want
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

type claimError string

func (e claimError) Error() string { return "claim check failed: " + string(e) }
func errClaim(field string) error  { return claimError(field) }

// buildJWT hand-builds a compact JWT rather than going through jwt/v5's
// signer, specifically so it CAN produce the attacker shapes a real
// forgery would (alg=none with an empty signature segment, or a validly
// structured-but-wrong-key signature) without the library's own safety
// rails getting in the way — this function backs the /oidc/mock/override
// test hook, not the RP's verification path.
func buildJWT(alg string, claims map[string]any, corruptSignature bool, key *rsa.PrivateKey) (string, error) {
	header := map[string]any{"typ": "JWT", "alg": alg}
	headerB64, err := jsonB64(header)
	if err != nil {
		return "", err
	}
	payloadB64, err := jsonB64(claims)
	if err != nil {
		return "", err
	}
	signingInput := headerB64 + "." + payloadB64

	switch alg {
	case "none", "":
		return signingInput + ".", nil
	case "RS256":
		method := jwt.SigningMethodRS256
		sigBytes, err := method.Sign(signingInput, key)
		if err != nil {
			return "", err
		}
		sig := base64.RawURLEncoding.EncodeToString(sigBytes)
		if corruptSignature {
			sig = flipFirstByte(sig)
		}
		return signingInput + "." + sig, nil
	default:
		// Any other declared algorithm (HS256 with a guessed secret, ES256
		// without a matching key, etc.) — emit garbage in the signature
		// position; verifyIDToken's WithValidMethods allowlist rejects the
		// header before it would even try to check this.
		return signingInput + ".invalid-signature", nil
	}
}

func jsonB64(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func flipFirstByte(s string) string {
	if s == "" {
		return "AA"
	}
	b := []byte(s)
	if b[0] == 'A' {
		b[0] = 'B'
	} else {
		b[0] = 'A'
	}
	return string(b)
}
