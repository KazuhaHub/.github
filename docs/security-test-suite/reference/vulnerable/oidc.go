package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

// See reference/safe/oidc.go for the bundled-mock-IdP design rationale.
// Every RP-side check that file performs in oidcCallback/verifyIDToken is
// either missing or stubbed out here — see the numbered gaps, each mapped
// to a row in docs/security-test-suite.md section 4.4.

const (
	oidcIssuer   = "https://mock-idp.example.com/"
	oidcClientID = "sectest-client"
)

type oidcFlow struct {
	State    string
	Nonce    string
	Subject  string
	Code     string
	Override *string
}

type oidcState struct {
	key *rsa.PrivateKey

	mu      sync.Mutex
	byState map[string]*oidcFlow
	byCode  map[string]*oidcFlow // GAP 1 support: the callback below looks a flow up BY CODE ONLY, so the `state` query parameter is never actually required to match anything.
}

func newOIDCState() (*oidcState, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &oidcState{key: key, byState: make(map[string]*oidcFlow), byCode: make(map[string]*oidcFlow)}, nil
}

func (s *server) oidcStart(w http.ResponseWriter, r *http.Request) {
	subject := r.URL.Query().Get("user")
	if subject == "" {
		subject = "sectest-oidc-user@example.com"
	}
	flow := &oidcFlow{State: randomHex(16), Nonce: randomHex(16), Subject: subject}

	st := s.oidc
	st.mu.Lock()
	st.byState[flow.State] = flow
	st.mu.Unlock()

	http.Redirect(w, r, "/oidc/mock/authorize?state="+flow.State, http.StatusFound)
}

func (s *server) oidcMockAuthorize(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	st := s.oidc
	st.mu.Lock()
	flow, ok := st.byState[state]
	if ok {
		flow.Code = randomHex(16)
		st.byCode[flow.Code] = flow
	}
	st.mu.Unlock()
	if !ok {
		writeJSONStatus(w, http.StatusBadRequest, errBody("unknown state"))
		return
	}
	http.Redirect(w, r, "/oidc/callback?code="+flow.Code+"&state="+state, http.StatusFound)
}

type oidcOverrideRequest struct {
	Alg    string         `json:"alg"`
	Claims map[string]any `json:"claims"`
}

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
	token := buildUnverifiedJWT(req.Alg, req.Claims)

	st.mu.Lock()
	flow.Override = &token
	st.mu.Unlock()

	writeJSONStatus(w, http.StatusOK, map[string]string{"id_token": token})
}

// oidcCallback: everything reference/safe's version checks, this one skips.
func (s *server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		writeJSONStatus(w, http.StatusBadRequest, errBody("missing code"))
		return
	}

	st := s.oidc
	st.mu.Lock()
	// GAP 1 (4.4 "state 缺失" / "state 不匹配"): looked up by CODE alone.
	// The `state` query parameter is read by oidcMockAuthorize above but
	// this handler never checks it against anything — a request with no
	// state at all, or a state copied from a completely different flow,
	// authenticates exactly as successfully as the correct one, as long as
	// the (guessable-if-short, but here just unchecked) code is right.
	flow, ok := st.byCode[code]
	// GAP 2 (4.4 "授权码重放"): `code` is never deleted from byCode and no
	// CodeUsed flag exists, so the exact same code authenticates every
	// time it is replayed.
	st.mu.Unlock()
	if !ok {
		writeJSONStatus(w, http.StatusBadRequest, errBody("unknown code"))
		return
	}

	var rawToken string
	if flow.Override != nil {
		rawToken = *flow.Override
	} else {
		rawToken = mintUnverifiedValidLookingToken(flow, s.oidc.key)
	}

	// GAP 3 (4.4 "alg=none 伪造 id_token"): parseClaimsWithoutVerifying
	// below does exactly what its name says — it reads the payload segment
	// and NEVER checks the signature segment or the alg header at all. An
	// unsigned (alg=none) token is accepted identically to a validly
	// signed one.
	claims, err := parseClaimsWithoutVerifying(rawToken)
	if err != nil {
		writeJSONStatus(w, http.StatusBadRequest, errBody("malformed token"))
		return
	}

	// GAP 4 (4.4 "aud 不匹配" / "iss 不匹配" / "exp 已过期"): none of iss,
	// aud, or exp are checked against anything below.

	// GAP 5 (4.4 "nonce 缺失" / "nonce 重放"): claims["nonce"] is never
	// compared against flow.Nonce.

	sub, _ := claims["sub"].(string)
	http.SetCookie(w, &http.Cookie{Name: "sectest_session", Value: "oidc:" + sub, Path: "/", HttpOnly: true})
	writeJSONStatus(w, http.StatusOK, map[string]any{"authenticated": true, "sub": sub})
}

func mintUnverifiedValidLookingToken(flow *oidcFlow, key *rsa.PrivateKey) string {
	return buildUnverifiedJWT("RS256", map[string]any{
		"iss":   oidcIssuer,
		"aud":   oidcClientID,
		"sub":   flow.Subject,
		"nonce": flow.Nonce,
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
	})
}

// buildUnverifiedJWT constructs a compact JWT string. Unlike
// reference/safe's buildJWT (a test-hook helper feeding a real verifier),
// this one backs both the mock IdP's normal minting path AND is trivially
// producible by an attacker via /oidc/mock/override — because the
// verification side (parseClaimsWithoutVerifying) never checks the
// signature, the signature segment's contents are irrelevant, which is
// itself GAP 3.
func buildUnverifiedJWT(alg string, claims map[string]any) string {
	header := map[string]any{"typ": "JWT", "alg": alg}
	headerB64, _ := jsonB64(header)
	payloadB64, _ := jsonB64(claims)
	return headerB64 + "." + payloadB64 + "." // signature segment left empty — nothing ever inspects it
}

func jsonB64(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// parseClaimsWithoutVerifying decodes the payload segment of a compact JWT
// and returns its claims, performing NO signature check and NO inspection
// of the alg header at all — this is GAP 3/4/5 rolled into one function.
func parseClaimsWithoutVerifying(raw string) (map[string]any, error) {
	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return nil, errBadToken
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

type tokenError string

func (e tokenError) Error() string { return string(e) }

const errBadToken = tokenError("malformed compact JWT")
