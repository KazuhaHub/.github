// Package securitytest holds the section-4 black-box test cases described
// in ../security-test-suite.md. This file covers section 4.4 (OIDC state /
// nonce / claims validation) against whatever instance SECTEST_BASE_URL
// points at — normally one of this module's own reference/safe or
// reference/vulnerable stubs while developing/self-checking these cases,
// and a real project's test instance once one is wired up (see the
// README's "Route alignment" table for how each project's actual OIDC
// callback path differs from the reference stub's simplified /oidc/*
// shape used below).
package securitytest

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/KazuhaHub/security-test-suite/internal/harness"
)

// ---------------------------------------------------------------------
// Flow-driving helpers
// ---------------------------------------------------------------------
//
// Both reference stubs (reference/safe/oidc.go, reference/vulnerable/oidc.go)
// bundle their own auto-approving mock IdP behind /oidc/mock/*, so a full,
// attacker-observable login flow looks like:
//
//   1. GET  /oidc/start?user=<subject>    -> 302 Location: /oidc/mock/authorize?state=S
//   2. GET  /oidc/mock/authorize?state=S  -> 302 Location: /oidc/callback?code=C&state=S
//   3. GET  /oidc/callback?code=C&state=S -> 200 on a legitimate exchange
//
// Every value used below (state, code) is read back from the target's OWN
// Location headers, never guessed or hard-coded, so a test that later
// tampers with one of them is provably tampering with something the
// target itself issued moments earlier — not failing because the harness
// fed it a malformed value to begin with.
//
// /oidc/mock/override additionally lets a test replace the id_token the
// NEXT code exchange for a given state will return, which is how the
// alg=none / bad-aud / bad-iss / expired / missing-or-foreign-nonce attack
// payloads below are built without this suite owning the mock IdP's own
// signing key.

// mockIssuer and mockClientID must match the values the reference stubs'
// bundled mock IdP and RP use (see reference/safe/oidc.go and
// reference/vulnerable/oidc.go). A test pointed at a different mock IdP
// instance would need these adjusted accordingly — they are not something
// this black-box suite can discover on its own.
const (
	mockIssuer   = "https://mock-idp.example.com/"
	mockClientID = "sectest-client"
)

// beginOIDCFlow starts a login flow for subject (the stub defaults to a
// fixed test subject when empty) and returns the `state` value the target
// itself generated and is now tracking. Every failure here is a fixture
// problem, not a security finding, so it fails the test immediately.
func beginOIDCFlow(t *testing.T, base, subject string) string {
	t.Helper()
	startURL := base + "/oidc/start"
	if subject != "" {
		startURL += "?user=" + url.QueryEscape(subject)
	}
	resp, err := harness.NewClient().Get(startURL)
	if err != nil {
		t.Fatalf("GET %s: request never reached the target: %v", startURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("GET %s: expected a 302 redirect to the mock IdP, got %s (%d) — fixture is broken",
			startURL, harness.StatusClass(resp.StatusCode), resp.StatusCode)
	}
	state := resolveQueryParam(t, base, resp.Header.Get("Location"), "state")
	if state == "" {
		t.Fatalf("GET %s: redirect Location %q carried no state parameter — fixture is broken",
			startURL, resp.Header.Get("Location"))
	}
	return state
}

// authorizeOIDCFlow drives the mock IdP's auto-approving login page for an
// already-started flow and returns the authorization code and state the
// target's own redirect hands back for the callback step.
func authorizeOIDCFlow(t *testing.T, base, state string) (code, returnedState string) {
	t.Helper()
	authorizeURL := base + "/oidc/mock/authorize?state=" + url.QueryEscape(state)
	resp, err := harness.NewClient().Get(authorizeURL)
	if err != nil {
		t.Fatalf("GET %s: request never reached the target: %v", authorizeURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("GET %s: expected a 302 redirect to the callback, got %s (%d) — fixture is broken",
			authorizeURL, harness.StatusClass(resp.StatusCode), resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	code = resolveQueryParam(t, base, loc, "code")
	returnedState = resolveQueryParam(t, base, loc, "state")
	if code == "" {
		t.Fatalf("GET %s: redirect Location %q carried no authorization code — fixture is broken",
			authorizeURL, loc)
	}
	return code, returnedState
}

// resolveQueryParam resolves loc (which the HTTP spec allows to be
// relative) against base and returns the named query parameter, or "" if
// absent.
func resolveQueryParam(t *testing.T, base, loc, param string) string {
	t.Helper()
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("could not parse redirect Location %q: %v", loc, err)
	}
	if !parsed.IsAbs() {
		baseURL, err := url.Parse(base)
		if err != nil {
			t.Fatalf("could not parse base URL %q: %v", base, err)
		}
		parsed = baseURL.ResolveReference(parsed)
	}
	return parsed.Query().Get(param)
}

// callbackRequest issues the raw GET a browser would make when redirected
// back from the IdP, with caller-controlled query parameters so every
// test case below can omit, mismatch, or replay code/state freely without
// a separate helper signature per variant.
func callbackRequest(base string, query url.Values) (*http.Response, error) {
	return harness.NewClient().Get(base + "/oidc/callback?" + query.Encode())
}

// overrideNextIDToken replaces the id_token the NEXT code exchange for
// `state` will return with one built from the given header `alg` and
// claim set (see /oidc/mock/override in both reference stubs). This is
// this suite's only way to produce attacker-controlled id_token contents
// (alg=none, a bad aud/iss, an expired exp, a missing/foreign nonce)
// without the suite owning the mock IdP's signing key.
func overrideNextIDToken(t *testing.T, base, state, alg string, claims map[string]any) {
	t.Helper()
	body := map[string]any{"alg": alg, "claims": claims}
	overrideURL := base + "/oidc/mock/override?state=" + url.QueryEscape(state)
	resp, err := harness.PostJSON(overrideURL, body, nil)
	if err != nil {
		t.Fatalf("POST %s: request never reached the target: %v", overrideURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		t.Fatalf("POST %s: the mock IdP itself rejected building the forged token (status %d) — "+
			"this is a fixture problem, not a finding", overrideURL, resp.StatusCode)
	}
}

// validClaims returns a correctly-shaped id_token claim set for the mock
// IdP's own issuer/audience with a future expiry, so each attack test
// below only has to deviate the ONE field it is actually probing — an
// aud-mismatch test, for example, must not also be rejected for an
// incidentally-wrong nonce or a stale exp, or it would no longer isolate
// what it claims to test.
func validClaims(nonce, subject string) map[string]any {
	return map[string]any{
		"iss":   mockIssuer,
		"aud":   mockClientID,
		"sub":   subject,
		"nonce": nonce,
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
	}
}

// ---------------------------------------------------------------------
// 4.4.1 / 4.4.2 — state
// ---------------------------------------------------------------------

// TestOIDC_StateMissingRejected sends a callback request carrying a valid,
// freshly-issued authorization code but no `state` parameter at all, and
// expects rejection. This is the CSRF-protection baseline: a callback
// implementation that authenticates on the code alone (ignoring state
// entirely, as reference/vulnerable does — see its GAP 1 comment) makes
// the login flow forgeable by anyone who can get a victim to load a URL
// carrying an attacker-obtained code.
func TestOIDC_StateMissingRejected(t *testing.T) {
	base := harness.MustBaseURL(t)

	state := beginOIDCFlow(t, base, "sectest-state-missing@example.com")
	code, _ := authorizeOIDCFlow(t, base, state)

	resp, err := callbackRequest(base, url.Values{"code": {code}}) // no "state" key at all
	harness.AssertRejected(t, resp, err, "callback with a valid code but no state parameter")
}

// TestOIDC_StateMismatchRejected sends a callback request combining a
// valid authorization code from one flow with the `state` value of a
// completely different, independently-started flow. The target must not
// authenticate the request unless code and state both belong to the SAME
// flow it issued them for — otherwise `state` is decorative and the
// callback is trivially CSRF-able by pairing any observed/guessed code
// with any state value the attacker can supply (e.g. their own, freshly
// obtained one).
func TestOIDC_StateMismatchRejected(t *testing.T) {
	base := harness.MustBaseURL(t)

	stateA := beginOIDCFlow(t, base, "sectest-state-mismatch-a@example.com")
	codeA, _ := authorizeOIDCFlow(t, base, stateA)

	stateB := beginOIDCFlow(t, base, "sectest-state-mismatch-b@example.com")
	_, _ = authorizeOIDCFlow(t, base, stateB) // just to make stateB a real, currently-tracked flow

	resp, err := callbackRequest(base, url.Values{"code": {codeA}, "state": {stateB}})
	harness.AssertRejected(t, resp, err, "callback with flow A's code paired with flow B's state")
}

// ---------------------------------------------------------------------
// 4.4.3 / 4.4.4 — nonce
// ---------------------------------------------------------------------

// TestOIDC_NonceMissingRejected forges an id_token that is otherwise
// perfectly valid (correct iss/aud/exp, validly signed by the mock IdP)
// but carries no `nonce` claim at all for a flow that DID request one.
// The callback must reject it — accepting a nonce-less token defeats the
// entire point of binding an id_token to the specific authorization
// request that solicited it.
func TestOIDC_NonceMissingRejected(t *testing.T) {
	base := harness.MustBaseURL(t)

	state := beginOIDCFlow(t, base, "sectest-nonce-missing@example.com")
	claims := validClaims("", "sectest-nonce-missing@example.com")
	delete(claims, "nonce") // absent, not merely empty — an empty-string nonce is a different (also-invalid) case
	overrideNextIDToken(t, base, state, "RS256", claims)
	code, returnedState := authorizeOIDCFlow(t, base, state)

	resp, err := callbackRequest(base, url.Values{"code": {code}, "state": {returnedState}})
	harness.AssertRejected(t, resp, err, "id_token with no nonce claim, for a flow that requested one")
}

// TestOIDC_NonceCrossFlowReplayRejected simulates an attacker who
// captured a real nonce value from one login attempt (e.g. by observing
// network traffic between the RP and the IdP) and replays it into a
// SECOND, unrelated flow's id_token.
//
// Honesty note on methodology: this reference design (correctly) never
// exposes a flow's server-generated nonce over any HTTP-observable
// channel — it lives only in the RP's internal flow record and inside the
// signed id_token the mock IdP itself never returns to the caller during
// a normal exchange. That means a literal "harvest flow A's real nonce,
// then paste it into flow B" cannot be demonstrated through pure black-box
// HTTP without a channel this suite deliberately does not have (a MITM
// tap on the IdP<->RP leg, out of scope for a zero-coupling test suite).
// What CAN be demonstrated, and is exactly the security property that
// makes true cross-flow nonce replay impossible, is this: the callback
// must reject any nonce value that is not the one it itself generated and
// stored for THIS flow — including a value that is well-formed and could
// plausibly have been a real nonce from somewhere else. That is what this
// test forges via /oidc/mock/override below.
func TestOIDC_NonceCrossFlowReplayRejected(t *testing.T) {
	base := harness.MustBaseURL(t)

	const foreignNonce = "captured-nonce-from-a-different-oidc-flow"

	state := beginOIDCFlow(t, base, "sectest-nonce-cross-flow@example.com")
	claims := validClaims(foreignNonce, "sectest-nonce-cross-flow@example.com")
	overrideNextIDToken(t, base, state, "RS256", claims)
	code, returnedState := authorizeOIDCFlow(t, base, state)

	resp, err := callbackRequest(base, url.Values{"code": {code}, "state": {returnedState}})
	harness.AssertRejected(t, resp, err, "id_token whose nonce belongs to a different flow than the one being completed")
}

// ---------------------------------------------------------------------
// 4.4.5 — alg=none
// ---------------------------------------------------------------------

// TestOIDC_AlgNoneForgedTokenRejected forges an id_token with header
// {"alg":"none"} and an empty signature segment — the classic JWT
// "alg confusion" attack — and expects outright rejection regardless of
// which JWT library sits underneath. A verifier that merely base64-decodes
// the payload without checking (and pinning) the algorithm accepts this
// identically to a validly signed token.
func TestOIDC_AlgNoneForgedTokenRejected(t *testing.T) {
	base := harness.MustBaseURL(t)

	state := beginOIDCFlow(t, base, "sectest-alg-none@example.com")
	claims := validClaims("irrelevant-if-alg-is-rejected-first", "attacker-controlled-subject")
	overrideNextIDToken(t, base, state, "none", claims)
	code, returnedState := authorizeOIDCFlow(t, base, state)

	resp, err := callbackRequest(base, url.Values{"code": {code}, "state": {returnedState}})
	harness.AssertRejected(t, resp, err, "id_token with header alg=none and no signature")
}

// ---------------------------------------------------------------------
// 4.4.6 / 4.4.7 / 4.4.8 — aud / iss / exp
// ---------------------------------------------------------------------

// TestOIDC_AudienceMismatchRejected forges a validly-signed id_token whose
// `aud` claim names a DIFFERENT client than this RP's own client_id — as
// if a token minted for some other application at the same IdP were
// replayed here. A verifier that checks the signature but never checks
// `aud` accepts a token that was never actually intended for it.
func TestOIDC_AudienceMismatchRejected(t *testing.T) {
	base := harness.MustBaseURL(t)

	state := beginOIDCFlow(t, base, "sectest-aud-mismatch@example.com")
	claims := validClaims("irrelevant-aud-check-happens-first", "sectest-aud-mismatch@example.com")
	claims["aud"] = "some-other-clients-id"
	overrideNextIDToken(t, base, state, "RS256", claims)
	code, returnedState := authorizeOIDCFlow(t, base, state)

	resp, err := callbackRequest(base, url.Values{"code": {code}, "state": {returnedState}})
	harness.AssertRejected(t, resp, err, "id_token whose aud names a different client")
}

// TestOIDC_IssuerMismatchRejected forges a validly-signed (by the SAME
// mock IdP key this RP trusts) id_token whose `iss` claim names a
// different issuer than the one this RP is configured to trust. A
// verifier that checks the signature but never checks `iss` cannot tell
// this apart from a legitimate token — which matters most once a target
// trusts more than one signing key/issuer combination.
func TestOIDC_IssuerMismatchRejected(t *testing.T) {
	base := harness.MustBaseURL(t)

	state := beginOIDCFlow(t, base, "sectest-iss-mismatch@example.com")
	claims := validClaims("irrelevant-iss-check-happens-first", "sectest-iss-mismatch@example.com")
	claims["iss"] = "https://not-the-configured-issuer.example.com/"
	overrideNextIDToken(t, base, state, "RS256", claims)
	code, returnedState := authorizeOIDCFlow(t, base, state)

	resp, err := callbackRequest(base, url.Values{"code": {code}, "state": {returnedState}})
	harness.AssertRejected(t, resp, err, "id_token whose iss names an untrusted issuer")
}

// TestOIDC_ExpiredTokenRejected forges a validly-signed id_token whose
// `exp` claim is already in the past. A verifier that checks the
// signature but never checks token freshness accepts a token forever,
// long after the IdP itself would consider it stale.
func TestOIDC_ExpiredTokenRejected(t *testing.T) {
	base := harness.MustBaseURL(t)

	state := beginOIDCFlow(t, base, "sectest-exp-expired@example.com")
	claims := validClaims("irrelevant-exp-check-happens-first", "sectest-exp-expired@example.com")
	claims["exp"] = time.Now().Add(-5 * time.Minute).Unix()
	overrideNextIDToken(t, base, state, "RS256", claims)
	code, returnedState := authorizeOIDCFlow(t, base, state)

	resp, err := callbackRequest(base, url.Values{"code": {code}, "state": {returnedState}})
	harness.AssertRejected(t, resp, err, "id_token whose exp is already in the past")
}

// ---------------------------------------------------------------------
// 4.4.9 — authorization code replay
// ---------------------------------------------------------------------

// TestOIDC_AuthorizationCodeReplayRejected exchanges the same
// authorization code twice and expects the second exchange to fail. The
// first call establishes a baseline (must succeed) so a failure there
// means the test fixture itself is broken, not the target — exactly the
// pattern the design doc's own 4.1.1 skeleton uses for assertion replay.
func TestOIDC_AuthorizationCodeReplayRejected(t *testing.T) {
	base := harness.MustBaseURL(t)

	state := beginOIDCFlow(t, base, "sectest-code-replay@example.com")
	code, returnedState := authorizeOIDCFlow(t, base, state)
	query := url.Values{"code": {code}, "state": {returnedState}}

	first, err := callbackRequest(base, query)
	harness.AssertAccepted(t, first, err, "baseline code exchange")

	second, err := callbackRequest(base, query)
	harness.AssertRejected(t, second, err, "replaying the same authorization code a second time")
}
