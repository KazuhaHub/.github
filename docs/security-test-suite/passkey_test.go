// This file covers design doc section 4.2: WebAuthn/passkey
// ceremony-session handling — challenge replay, ceremony expiry, RP
// identity (origin/RP ID) pinning, user-handle confusion between the
// wire-claimed and the credential's true recorded owner, and
// signature-counter rollback (cloned-authenticator detection).
//
// Every ceremony in this file is a REAL WebAuthn ceremony: the begin step
// returns go-webauthn/webauthn's actual PublicKeyCredentialCreationOptions
// / PublicKeyCredentialRequestOptions, and the finish step carries a real
// CBOR attestationObject (registration) or a real ECDSA signature over
// authenticatorData‖SHA-256(clientDataJSON) (login), produced by
// internal/authenticator — a software WebAuthn authenticator with
// deliberate attack toggles (wrong RP ID, wrong origin, replayed
// challenge, counter rollback, forged claimed user handle, corrupted
// signature). This file no longer talks to a simplified, non-standard
// JSON ceremony protocol; it drives the same wire format
// go-webauthn/webauthn expects from any real client, which is what makes
// pointing it at a real target's passkey endpoints (see the "Route
// alignment" table in README.md) meaningful.
//
// go-webauthn/webauthn's own cryptographic correctness (COSE key parsing,
// ECDSA signature verification, CBOR attestation decoding, …) is
// deliberately NOT what these test cases probe — per this suite's version
// audit, it carries zero open advisories across all three target
// projects, so there is nothing to regression-test there. What every case
// here targets is the ceremony-SESSION protocol layer each project
// implements ON TOP of go-webauthn/webauthn (its own docs leave this
// entirely to the caller) — see reference/safe/webauthn.go's package doc
// for exactly which behaviors that is and how reference/safe and
// reference/vulnerable differ on each.
//
// Route shapes here match reference/{safe,vulnerable}/webauthn.go
// (POST /webauthn/begin, POST /webauthn/finish). Pointing SECTEST_BASE_URL
// at a real project instead means swapping in its actual passkey paths —
// see the "Route alignment" table in README.md: Passwall-Sub-Panel's
// POST /api/auth/passkey/{begin,finish}, AlertHub's
// POST /api/auth/passkey/login/{begin,finish} and
// /api/auth/passkey/register/{begin,finish}, Report-Portal's
// POST /api/login/passkey/{begin,finish} and
// /api/me/passkeys/register/{begin,finish} — and that the enrollment
// endpoints are session-authenticated on all three real projects, unlike
// this suite's intentionally unauthenticated reference stubs.
//
// Every test in this file is written to pass against reference/safe and
// FAIL against reference/vulnerable — see this task's report for the
// actual output of both. None of the six cases required a "version gate"
// or "needs white-box" placeholder: all six are observable purely from
// HTTP status codes on a black-box client, including ceremony expiry,
// which this file resolves to a wait duration either from the target's
// own declared `expires_in_seconds` (as reference/safe returns) or from
// an operator-supplied override — see webauthnCeremonyWait below — rather
// than assuming every project shares the same window (they don't:
// reference/safe uses 60s, while all three real projects' passkey
// ceremony sessions use 5 minutes).
package securitytest

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/KazuhaHub/security-test-suite/internal/authenticator"
	"github.com/KazuhaHub/security-test-suite/internal/harness"
)

// Values the reference stubs use as the "correct" RP ID/origin for their
// single simulated relying party (see reference/safe/webauthn.go's
// expectedRPID/expectedOrigin). "Wrong" values below use other RFC
// 2606-reserved example domains, never a real one, precisely so the
// mismatch tests exercise real go-webauthn/webauthn RP-identity
// validation instead of tautologically matching whatever the target
// happens to expect. wrongOrigin also has to match
// reference/vulnerable/webauthn.go's own wrongOrigin constant exactly —
// see that file's doc comment for why.
const (
	webauthnTestOrigin  = "https://example.com"
	webauthnTestRPID    = "example.com"
	webauthnWrongOrigin = "https://attacker.example.net"
	webauthnWrongRPID   = "attacker.example.org"
)

// webauthnCeremonyTTLEnvVar overrides the wait duration
// TestPasskey_CeremonyExpiryRejected uses, for pointing this suite at a
// real project whose declared ceremony TTL isn't observable via the begin
// response body the way reference/safe's is (it returns
// expires_in_seconds; a real project's begin response may not). Per the
// design doc's own note that the three projects' declared expiry windows
// are themselves a piece of data this suite is supposed to surface, this
// suite does not hardcode one project's TTL as if it were universal.
const webauthnCeremonyTTLEnvVar = "SECTEST_WEBAUTHN_CEREMONY_TTL_SECONDS"

// webauthnBeginReq is what this file POSTs to /webauthn/begin. RPID is an
// optional target-RP-ID override: reference/safe never reads it (its
// ceremonies are always bound to its own, fixed RP identity);
// reference/vulnerable honors it (GAP 3) — see that file's doc comment on
// webauthnBeginRequest.RPID for why that is a realistic vulnerability
// class and not an artificial hook.
type webauthnBeginReq struct {
	Mode         string `json:"mode"`
	Username     string `json:"username,omitempty"`
	CredentialID string `json:"credential_id,omitempty"` // base64url, required for mode=login
	RPID         string `json:"rp_id,omitempty"`
}

// webauthnBeginResp decodes the union of what a register-begin and a
// login-begin response carry. Only the fields a given ceremony mode
// populates are non-zero; register uses PublicKey.RP.ID and
// PublicKey.User.ID, login uses PublicKey.RPID.
type webauthnBeginResp struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
		RPID string `json:"rpId"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	} `json:"publicKey"`
	ExpiresInSecond int `json:"expires_in_seconds"`
}

type webauthnFinishResp struct {
	OK           bool   `json:"ok"`
	CredentialID string `json:"credential_id"` // base64url
}

// webauthnBeginRaw posts a begin request and returns the raw response
// (caller closes the body, directly or via requireWebauthnBeginOK)
// together with any cookies it set — the ceremony session cookie every
// finish call in this file must carry back.
func webauthnBeginRaw(t *testing.T, base string, req webauthnBeginReq) (*http.Response, []*http.Cookie) {
	t.Helper()
	resp, err := harness.PostJSON(base+"/webauthn/begin", req, nil)
	resp = harness.RequireReachable(t, resp, err, "webauthn begin (mode="+req.Mode+")")
	return resp, resp.Cookies()
}

// webauthnFinishRaw posts a real, already wire-encoded finish body (from
// an internal/authenticator RegistrationResult/AssertionResult) carrying
// the ceremony cookies captured from the matching begin call. Unlike a
// typed POST, this never re-marshals body — the exact bytes
// internal/authenticator produced are what has to reach the target,
// since those bytes (the CBOR attestation object or the ECDSA signature)
// are themselves what is under test.
func webauthnFinishRaw(t *testing.T, base string, body []byte, cookies []*http.Cookie) *http.Response {
	t.Helper()
	resp, err := harness.PostRawJSON(base+"/webauthn/finish", body, cookies)
	return harness.RequireReachable(t, resp, err, "webauthn finish")
}

// requireWebauthnBeginOK asserts a begin call succeeded — this is fixture
// sanity (every test case here needs a live ceremony to attack), not
// something under test — and decodes its body, closing resp either way.
func requireWebauthnBeginOK(t *testing.T, resp *http.Response, what string) webauthnBeginResp {
	t.Helper()
	if resp.StatusCode >= http.StatusBadRequest {
		resp.Body.Close()
		t.Fatalf("%s: baseline ceremony begin failed, fixture is broken: %s (%d)",
			what, harness.StatusClass(resp.StatusCode), resp.StatusCode)
	}
	var body webauthnBeginResp
	harness.DecodeJSON(t, resp, &body)
	return body
}

// requireWebauthnFinishOK is requireWebauthnBeginOK's counterpart for a
// finish call that must succeed for the test's later steps to mean
// anything (e.g. registering the credential a subsequent login ceremony
// will target).
func requireWebauthnFinishOK(t *testing.T, resp *http.Response, what string) webauthnFinishResp {
	t.Helper()
	if resp.StatusCode >= http.StatusBadRequest {
		resp.Body.Close()
		t.Fatalf("%s: baseline ceremony finish failed, fixture is broken: %s (%d)",
			what, harness.StatusClass(resp.StatusCode), resp.StatusCode)
	}
	var body webauthnFinishResp
	harness.DecodeJSON(t, resp, &body)
	return body
}

// decodeB64URL base64url-decodes a wire value from a begin/finish
// response, failing the test (fixture problem, not something under test)
// if the target's own response is malformed.
func decodeB64URL(t *testing.T, value, what string) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("%s: %q is not valid base64url: %v", what, value, err)
	}
	return raw
}

var webauthnUsernameSeq int

// uniquePasskeyUsername returns a fresh test username per call. The
// reference stubs keep ceremony/credential state in an in-memory map for
// the lifetime of the process with no reset between test runs, and a
// registered user's handle is derived from their username — reusing a
// name across test cases would let one test's leftover state quietly
// satisfy another test's preconditions.
func uniquePasskeyUsername(tag string) string {
	webauthnUsernameSeq++
	return fmt.Sprintf("sectest-passkey-%s-%d-%d", tag, time.Now().UnixNano(), webauthnUsernameSeq)
}

// newTestAuthenticator returns a fresh software WebAuthn authenticator
// (internal/authenticator) for one test case. Each test gets its own so
// that one test's registered credentials never leak into another's.
func newTestAuthenticator(t *testing.T) *authenticator.Authenticator {
	t.Helper()
	auth, err := authenticator.New()
	if err != nil {
		t.Fatalf("construct software authenticator: %v", err)
	}
	return auth
}

// registerCeremony drives a full registration ceremony's client/
// authenticator half: it decodes the begin response's challenge and user
// handle and asks auth to produce the finish body, binding the ceremony
// to rpID/origin (which a caller deliberately mismatches against what
// begin actually declared, for the RP-identity test cases; every other
// caller passes webauthnTestRPID/webauthnTestOrigin, i.e. behaves
// honestly).
func registerCeremony(t *testing.T, auth *authenticator.Authenticator, begin webauthnBeginResp, rpID, origin string, opts ...authenticator.Option) *authenticator.RegistrationResult {
	t.Helper()
	challenge := decodeB64URL(t, begin.PublicKey.Challenge, "begin response challenge")
	userHandle := decodeB64URL(t, begin.PublicKey.User.ID, "begin response user handle")

	reg, err := auth.Register(authenticator.RegistrationInput{
		RPID:       rpID,
		Origin:     origin,
		Challenge:  challenge,
		UserHandle: userHandle,
	}, opts...)
	if err != nil {
		t.Fatalf("authenticator: register: %v", err)
	}
	return reg
}

// authenticateCeremony is registerCeremony's counterpart for a login
// ceremony's client/authenticator half.
func authenticateCeremony(t *testing.T, auth *authenticator.Authenticator, begin webauthnBeginResp, credentialID []byte, rpID, origin string, opts ...authenticator.Option) *authenticator.AssertionResult {
	t.Helper()
	challenge := decodeB64URL(t, begin.PublicKey.Challenge, "begin response challenge")

	asrt, err := auth.Authenticate(authenticator.AssertionInput{
		RPID:         rpID,
		Origin:       origin,
		Challenge:    challenge,
		CredentialID: credentialID,
	}, opts...)
	if err != nil {
		t.Fatalf("authenticator: authenticate: %v", err)
	}
	return asrt
}

// webauthnCeremonyWait decides how long TestPasskey_CeremonyExpiryRejected
// should wait past the ceremony's issue time before attempting a finish
// that must by then be rejected. It prefers, in order: an explicit
// operator override (for a real project whose TTL this suite can't
// observe from the begin response itself), the target's own declared
// expires_in_seconds (reference/safe reports this; a project that
// doesn't is exactly the kind of behavioral gap section 6's report is
// supposed to record), and only then a bundled default that matches this
// suite's OWN reference stubs — not a guess at what a real project uses.
func webauthnCeremonyWait(t *testing.T, declaredSeconds int) time.Duration {
	t.Helper()
	if v := os.Getenv(webauthnCeremonyTTLEnvVar); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			t.Fatalf("%s=%q must be a positive integer number of seconds", webauthnCeremonyTTLEnvVar, v)
		}
		return time.Duration(n)*time.Second + 2*time.Second
	}
	if declaredSeconds > 0 {
		return time.Duration(declaredSeconds)*time.Second + 2*time.Second
	}
	t.Logf("target's begin response did not declare expires_in_seconds and %s is unset; "+
		"falling back to reference/safe's own 60s ceremony TTL. When pointing this suite at "+
		"a real project, set %s explicitly — Passwall-Sub-Panel, AlertHub and Report-Portal "+
		"all declare a 5-minute (300s) passkey ceremony window, not 60s.",
		webauthnCeremonyTTLEnvVar, webauthnCeremonyTTLEnvVar)
	return 60*time.Second + 2*time.Second
}

// TestPasskey_ChallengeReplayRejected replays the exact same, real
// ceremony-finish payload (the identical CBOR attestationObject and
// clientDataJSON bytes an honest client would have sent exactly once)
// twice against the same begin challenge. The ceremony session must be
// single-use: GAP 1 in reference/vulnerable/webauthn.go never marks a
// ceremony used, so the identical finish call succeeds a second time
// there.
func TestPasskey_ChallengeReplayRejected(t *testing.T) {
	base := harness.MustBaseURL(t)
	username := uniquePasskeyUsername("replay")
	auth := newTestAuthenticator(t)

	beginResp, cookies := webauthnBeginRaw(t, base, webauthnBeginReq{
		Mode:     "register",
		Username: username,
	})
	begin := requireWebauthnBeginOK(t, beginResp, "challenge-replay setup")

	reg := registerCeremony(t, auth, begin, webauthnTestRPID, webauthnTestOrigin)

	first := webauthnFinishRaw(t, base, reg.Body, cookies)
	requireWebauthnFinishOK(t, first, "baseline registration")

	second := webauthnFinishRaw(t, base, reg.Body, cookies)
	harness.AssertRejected(t, second, nil,
		"replaying the identical ceremony-finish payload against the same begin challenge")
}

// TestPasskey_CeremonyExpiryRejected begins a ceremony, builds its (valid)
// finish payload immediately, waits past the ceremony's declared (or
// configured) TTL, and only then submits that still-otherwise-valid
// payload. GAP 2 in reference/vulnerable/webauthn.go never records when a
// ceremony was created, so nothing there is ever "too old" to finish.
func TestPasskey_CeremonyExpiryRejected(t *testing.T) {
	base := harness.MustBaseURL(t)
	username := uniquePasskeyUsername("expiry")
	auth := newTestAuthenticator(t)

	beginResp, cookies := webauthnBeginRaw(t, base, webauthnBeginReq{
		Mode:     "register",
		Username: username,
	})
	begin := requireWebauthnBeginOK(t, beginResp, "expiry setup")

	reg := registerCeremony(t, auth, begin, webauthnTestRPID, webauthnTestOrigin)

	wait := webauthnCeremonyWait(t, begin.ExpiresInSecond)
	t.Logf("waiting %s for the ceremony session to age past its TTL before attempting finish", wait)
	time.Sleep(wait)

	finishResp := webauthnFinishRaw(t, base, reg.Body, cookies)
	harness.AssertRejected(t, finishResp, nil, "finishing a ceremony after its TTL has elapsed")
}

// TestPasskey_OriginMismatchRejected finishes a ceremony with a real,
// correctly signed attestation object whose clientDataJSON nonetheless
// declares a different origin than the one this ceremony's Relying Party
// actually serves — the wire-accurate equivalent of a phished or
// compromised client completing the ceremony from attacker.example.net.
// reference/safe's relying-party config accepts only webauthnTestOrigin;
// reference/vulnerable's accepts webauthnWrongOrigin too (GAP 3's origin
// half — see that file's wrongOrigin doc comment).
func TestPasskey_OriginMismatchRejected(t *testing.T) {
	base := harness.MustBaseURL(t)
	username := uniquePasskeyUsername("origin")
	auth := newTestAuthenticator(t)

	beginResp, cookies := webauthnBeginRaw(t, base, webauthnBeginReq{
		Mode:     "register",
		Username: username,
	})
	begin := requireWebauthnBeginOK(t, beginResp, "origin-mismatch setup")

	reg := registerCeremony(t, auth, begin, webauthnTestRPID, webauthnWrongOrigin) // not webauthnTestOrigin

	finishResp := webauthnFinishRaw(t, base, reg.Body, cookies)
	harness.AssertRejected(t, finishResp, nil, "finish claiming an origin the ceremony was not issued for")
}

// TestPasskey_RPIDMismatchRejected is TestPasskey_OriginMismatchRejected's
// counterpart for the RP ID half of GAP 3. Unlike origin, go-webauthn
// pins a ceremony's expected RP ID from its BEGIN step permanently into
// the session (SessionData.RelyingPartyID always wins over whatever a
// finish call's own data might claim), so the only way to reach a
// "wrong RP ID accepted" outcome is to let begin() bind the ceremony to a
// non-default RP ID in the first place — which is exactly what this test
// asks for via webauthnBeginReq.RPID.
// reference/safe's begin handler ignores that field outright;
// reference/vulnerable's honors it.
func TestPasskey_RPIDMismatchRejected(t *testing.T) {
	base := harness.MustBaseURL(t)
	username := uniquePasskeyUsername("rpid")
	auth := newTestAuthenticator(t)

	beginResp, cookies := webauthnBeginRaw(t, base, webauthnBeginReq{
		Mode:     "register",
		Username: username,
		RPID:     webauthnWrongRPID, // honored only by reference/vulnerable
	})
	begin := requireWebauthnBeginOK(t, beginResp, "rp-id-mismatch setup")

	// The authenticator signs for whatever RP ID the (possibly malicious)
	// begin response bound the ceremony to — self-consistent with what
	// was actually requested, isolating this test to whether the target
	// should ever have let a caller pick that RP ID at all.
	reg := registerCeremony(t, auth, begin, webauthnWrongRPID, webauthnTestOrigin)

	finishResp := webauthnFinishRaw(t, base, reg.Body, cookies)
	harness.AssertRejected(t, finishResp, nil, "finish claiming an RP ID the ceremony was not issued for")
}

// TestPasskey_UserHandleConfusionRejected completes user B's login
// ceremony with a cryptographically VALID assertion — signed by B's own
// registered credential, over B's own real challenge — that nonetheless
// claims user A's user_handle in its wire-level userHandle field. A's
// handle is harvested from A's own register-begin response (exactly what
// A's own client would see), not derived by reversing the stub's hashing
// scheme: the point is to test whether the target checks the claimed
// handle against the ceremony's true, server-recorded owner, not to
// exploit an implementation detail of how that owner is computed.
//
// go-webauthn/webauthn's own ValidatePasskeyLogin rejects a claimed
// userHandle that doesn't match the identity the caller's
// DiscoverableUserHandler resolves — reference/safe's handler resolves
// that identity from the credential's true recorded owner (rawID), so
// this mismatch is a real rejection there. reference/vulnerable's handler
// resolves identity from the CLAIMED handle instead (GAP 4), which makes
// the check tautologically pass while still using B's genuine credential
// (and therefore a genuinely valid signature) to do it.
func TestPasskey_UserHandleConfusionRejected(t *testing.T) {
	base := harness.MustBaseURL(t)
	userA := uniquePasskeyUsername("handle-confusion-a")
	userB := uniquePasskeyUsername("handle-confusion-b")
	auth := newTestAuthenticator(t)

	// Harvest A's own user_handle from A's own register-begin response —
	// this is what A's own client legitimately observes, not a value
	// derived from B's ceremony. A's registration is never completed.
	aBeginResp, _ := webauthnBeginRaw(t, base, webauthnBeginReq{Mode: "register", Username: userA})
	aBegin := requireWebauthnBeginOK(t, aBeginResp, "user A handle harvest")
	aUserHandle := decodeB64URL(t, aBegin.PublicKey.User.ID, "user A's user handle")

	// Register B for real, so a subsequent login ceremony against B's
	// credential_id is legitimate on both stubs.
	bBeginResp, bRegCookies := webauthnBeginRaw(t, base, webauthnBeginReq{Mode: "register", Username: userB})
	bBegin := requireWebauthnBeginOK(t, bBeginResp, "user B registration begin")
	bReg := registerCeremony(t, auth, bBegin, webauthnTestRPID, webauthnTestOrigin)
	bFinishResp := webauthnFinishRaw(t, base, bReg.Body, bRegCookies)
	bFinish := requireWebauthnFinishOK(t, bFinishResp, "user B registration finish")
	bCredentialID := decodeB64URL(t, bFinish.CredentialID, "user B's credential ID")

	// Begin a LOGIN ceremony against B's own credential — the ceremony is
	// legitimately bound to B, server-side, at this point.
	loginBeginResp, loginCookies := webauthnBeginRaw(t, base, webauthnBeginReq{
		Mode:         "login",
		CredentialID: bFinish.CredentialID,
	})
	loginBegin := requireWebauthnBeginOK(t, loginBeginResp, "user B login begin")

	// Sign a genuinely valid assertion with B's own credential, but claim
	// A's user_handle instead of the one this authenticator actually
	// recorded for B at registration.
	asrt := authenticateCeremony(t, auth, loginBegin, bCredentialID, webauthnTestRPID, webauthnTestOrigin,
		authenticator.WithUserHandle(aUserHandle))

	loginFinishResp := webauthnFinishRaw(t, base, asrt.Body, loginCookies)
	harness.AssertRejected(t, loginFinishResp, nil,
		"finishing user B's login ceremony while claiming user A's user_handle")
}

// TestPasskey_CounterRollbackRejected registers a credential whose
// authenticator data reports a given signature counter, then completes a
// login ceremony against that same credential with a genuinely valid
// signature but a LOWER counter — the standard signal a physical
// authenticator was cloned. go-webauthn/webauthn itself only flags this
// (Credential.Authenticator.CloneWarning), never rejects it outright,
// leaving the accept/reject decision to the caller by design — see
// reference/safe/webauthn.go's package doc. reference/safe checks the
// flag and rejects; reference/vulnerable (GAP 5) never looks at it.
func TestPasskey_CounterRollbackRejected(t *testing.T) {
	base := harness.MustBaseURL(t)
	username := uniquePasskeyUsername("counter-rollback")
	auth := newTestAuthenticator(t)

	regBeginResp, regCookies := webauthnBeginRaw(t, base, webauthnBeginReq{Mode: "register", Username: username})
	regBegin := requireWebauthnBeginOK(t, regBeginResp, "registration begin")
	reg := registerCeremony(t, auth, regBegin, webauthnTestRPID, webauthnTestOrigin, authenticator.WithCounter(5))

	regFinishResp := webauthnFinishRaw(t, base, reg.Body, regCookies)
	regFinish := requireWebauthnFinishOK(t, regFinishResp, "registration finish (counter=5)")
	credentialID := decodeB64URL(t, regFinish.CredentialID, "registered credential ID")

	loginBeginResp, loginCookies := webauthnBeginRaw(t, base, webauthnBeginReq{
		Mode:         "login",
		CredentialID: regFinish.CredentialID,
	})
	loginBegin := requireWebauthnBeginOK(t, loginBeginResp, "login begin")

	asrt := authenticateCeremony(t, auth, loginBegin, credentialID, webauthnTestRPID, webauthnTestOrigin,
		authenticator.WithCounter(3)) // < 5 — a signature counter that went BACKWARDS

	loginFinishResp := webauthnFinishRaw(t, base, asrt.Body, loginCookies)
	harness.AssertRejected(t, loginFinishResp, nil,
		"finishing a login ceremony whose signature counter (3) is lower than the credential's last recorded counter (5)")
}
