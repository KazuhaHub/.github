// This file covers design doc section 4.2: WebAuthn/passkey
// ceremony-session handling — challenge replay, ceremony expiry,
// origin/RP ID validation, user-handle confusion between two concurrent
// ceremonies, and signature-counter rollback (cloned-authenticator
// detection).
//
// Every case here targets the ceremony-SESSION protocol layer described
// in reference/safe/webauthn.go's package doc: the begin/finish challenge
// exchange each of the three target projects implements on top of
// go-webauthn/webauthn, which that library's own documentation leaves
// entirely to the caller. It does not exercise WebAuthn
// attestation/assertion cryptography (COSE keys, CBOR attestation
// objects, ECDSA signatures over clientDataJSON) — per this suite's
// version audit, go-webauthn/webauthn carries zero open advisories across
// all three target projects, so there is nothing to regression-test
// there. See reference/safe/webauthn.go for the full reasoning.
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
// FAIL against reference/vulnerable — see the two real runs recorded in
// this task's report for the actual output of both. None of the six
// cases required a "version gate" or "needs white-box" placeholder: all
// six are observable purely from HTTP status codes on a black-box client,
// including ceremony expiry, which this file resolves to a wait duration
// either from the target's own declared `expires_in_seconds` (as
// reference/safe returns) or from an operator-supplied override — see
// webauthnCeremonyWait below — rather than assuming every project shares
// the same window (they don't: reference/safe uses 60s, while all three
// real projects' passkey ceremony sessions use 5 minutes).
package securitytest

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/KazuhaHub/security-test-suite/internal/harness"
)

// Values the reference stubs hardcode as the "correct" origin/RP ID for
// their single simulated relying party (see reference/safe/webauthn.go's
// expectedOrigin/expectedRPID). "Wrong" values below use other RFC
// 2606-reserved example domains, never a real one, precisely so the
// mismatch tests exercise real origin/RP-ID comparisons instead of
// tautologically matching whatever the target happens to expect.
const (
	webauthnTestOrigin  = "https://example.com"
	webauthnTestRPID    = "example.com"
	webauthnWrongOrigin = "https://attacker.example.net"
	webauthnWrongRPID   = "attacker.example.org"
)

// webauthnCeremonyTTLEnvVar overrides the wait duration
// TestPasskey_CeremonyExpiryRejected uses, for pointing this suite at a
// real project whose declared ceremony TTL isn't observable via the
// begin response body the way reference/safe's is (it returns
// expires_in_seconds; a real project's begin response may not). Per the
// design doc's own note that the three projects' declared expiry windows
// are themselves a piece of data this suite is supposed to surface, this
// suite does not hardcode one project's TTL as if it were universal.
const webauthnCeremonyTTLEnvVar = "SECTEST_WEBAUTHN_CEREMONY_TTL_SECONDS"

type webauthnBeginReq struct {
	Mode         string `json:"mode"`
	Username     string `json:"username"`
	CredentialID string `json:"credential_id"`
}

type webauthnBeginResp struct {
	Challenge       string `json:"challenge"`
	RPID            string `json:"rp_id"`
	UserHandle      string `json:"user_handle"` // base64, the ceremony's server-recorded owner
	ExpiresInSecond int    `json:"expires_in_seconds"`
}

type webauthnFinishReq struct {
	CredentialID string `json:"credential_id"`
	Counter      uint64 `json:"counter"`
	Origin       string `json:"origin"`
	RPID         string `json:"rp_id"`
	UserHandle   string `json:"user_handle"` // base64, CLIENT-claimed — attacker-controlled input
}

type webauthnFinishResp struct {
	OK           bool   `json:"ok"`
	CredentialID string `json:"credential_id"`
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

// webauthnFinishRaw posts a finish request carrying the ceremony cookies
// captured from the matching begin call.
func webauthnFinishRaw(t *testing.T, base string, req webauthnFinishReq, cookies []*http.Cookie) *http.Response {
	t.Helper()
	resp, err := harness.PostJSON(base+"/webauthn/finish", req, cookies)
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

// TestPasskey_ChallengeReplayRejected replays the exact same
// ceremony-finish payload twice against the same begin challenge. The
// ceremony session must be single-use: GAP 1 in
// reference/vulnerable/webauthn.go never marks a ceremony used, so the
// identical finish call succeeds a second time there.
func TestPasskey_ChallengeReplayRejected(t *testing.T) {
	base := harness.MustBaseURL(t)
	username := uniquePasskeyUsername("replay")

	beginResp, cookies := webauthnBeginRaw(t, base, webauthnBeginReq{
		Mode:     "register",
		Username: username,
	})
	requireWebauthnBeginOK(t, beginResp, "challenge-replay setup")

	finishReq := webauthnFinishReq{
		Counter: 1,
		Origin:  webauthnTestOrigin,
		RPID:    webauthnTestRPID,
	}

	first := webauthnFinishRaw(t, base, finishReq, cookies)
	requireWebauthnFinishOK(t, first, "baseline registration")

	second := webauthnFinishRaw(t, base, finishReq, cookies)
	harness.AssertRejected(t, second, nil,
		"replaying the identical ceremony-finish payload against the same begin challenge")
}

// TestPasskey_CeremonyExpiryRejected begins a ceremony, waits past its
// declared (or configured) TTL, and then attempts to finish it. GAP 2 in
// reference/vulnerable/webauthn.go never records when a ceremony was
// created, so nothing there is ever "too old" to finish.
func TestPasskey_CeremonyExpiryRejected(t *testing.T) {
	base := harness.MustBaseURL(t)
	username := uniquePasskeyUsername("expiry")

	beginResp, cookies := webauthnBeginRaw(t, base, webauthnBeginReq{
		Mode:     "register",
		Username: username,
	})
	begin := requireWebauthnBeginOK(t, beginResp, "expiry setup")

	wait := webauthnCeremonyWait(t, begin.ExpiresInSecond)
	t.Logf("waiting %s for the ceremony session to age past its TTL before attempting finish", wait)
	time.Sleep(wait)

	finishResp := webauthnFinishRaw(t, base, webauthnFinishReq{
		Counter: 1,
		Origin:  webauthnTestOrigin,
		RPID:    webauthnTestRPID,
	}, cookies)
	harness.AssertRejected(t, finishResp, nil, "finishing a ceremony after its TTL has elapsed")
}

// TestPasskey_OriginMismatchRejected finishes a ceremony claiming an
// origin different from the one it was issued for. GAP 3 in
// reference/vulnerable/webauthn.go reads req.Origin but never compares
// it against anything.
func TestPasskey_OriginMismatchRejected(t *testing.T) {
	base := harness.MustBaseURL(t)
	username := uniquePasskeyUsername("origin")

	beginResp, cookies := webauthnBeginRaw(t, base, webauthnBeginReq{
		Mode:     "register",
		Username: username,
	})
	requireWebauthnBeginOK(t, beginResp, "origin-mismatch setup")

	finishResp := webauthnFinishRaw(t, base, webauthnFinishReq{
		Counter: 1,
		Origin:  webauthnWrongOrigin, // not webauthnTestOrigin — the ceremony's real origin
		RPID:    webauthnTestRPID,
	}, cookies)
	harness.AssertRejected(t, finishResp, nil, "finish claiming an origin the ceremony was not issued for")
}

// TestPasskey_RPIDMismatchRejected is TestPasskey_OriginMismatchRejected's
// counterpart for the RP ID field. Same GAP 3, second half of the check
// reference/vulnerable/webauthn.go never performs.
func TestPasskey_RPIDMismatchRejected(t *testing.T) {
	base := harness.MustBaseURL(t)
	username := uniquePasskeyUsername("rpid")

	beginResp, cookies := webauthnBeginRaw(t, base, webauthnBeginReq{
		Mode:     "register",
		Username: username,
	})
	requireWebauthnBeginOK(t, beginResp, "rp-id-mismatch setup")

	finishResp := webauthnFinishRaw(t, base, webauthnFinishReq{
		Counter: 1,
		Origin:  webauthnTestOrigin,
		RPID:    webauthnWrongRPID, // not webauthnTestRPID — the ceremony's real RP ID
	}, cookies)
	harness.AssertRejected(t, finishResp, nil, "finish claiming an RP ID the ceremony was not issued for")
}

// TestPasskey_UserHandleConfusionRejected completes user B's login
// ceremony while claiming user A's user_handle — "用 A 的 handle 完成 B 的
// ceremony" from the design doc's 4.2 table. A's handle is obtained
// legitimately (A's own register-begin response, exactly what A's own
// client would see), not derived by reversing the stub's hashing scheme:
// the point is to test whether the target checks the claimed handle
// against the ceremony's true, server-recorded owner, not to exploit an
// implementation detail of how that owner is computed.
//
// GAP 4 in reference/vulnerable/webauthn.go only ever falls back to the
// client-claimed handle when the ceremony has NO recorded owner; here the
// ceremony DOES have one (B, via a known credential_id), so the bug this
// test actually reaches is narrower but still real: the vulnerable finish
// handler accepts (200) a finish call whose claimed identity contradicts
// the ceremony's own record, instead of rejecting it the way
// reference/safe does.
func TestPasskey_UserHandleConfusionRejected(t *testing.T) {
	base := harness.MustBaseURL(t)
	userA := uniquePasskeyUsername("handle-confusion-a")
	userB := uniquePasskeyUsername("handle-confusion-b")

	// Harvest A's own user_handle from A's own register-begin response —
	// this is what A's own client legitimately observes, not a value
	// derived from B's ceremony.
	aBeginResp, _ := webauthnBeginRaw(t, base, webauthnBeginReq{Mode: "register", Username: userA})
	aBegin := requireWebauthnBeginOK(t, aBeginResp, "user A handle harvest")
	if aBegin.UserHandle == "" {
		t.Fatalf("user A's register-begin response did not include a user_handle, cannot construct the attack input")
	}

	// Register B for real, so a subsequent login ceremony against B's
	// credential_id is legitimate on both stubs.
	bBeginResp, bRegCookies := webauthnBeginRaw(t, base, webauthnBeginReq{Mode: "register", Username: userB})
	requireWebauthnBeginOK(t, bBeginResp, "user B registration begin")
	bFinishResp := webauthnFinishRaw(t, base, webauthnFinishReq{
		Counter: 1,
		Origin:  webauthnTestOrigin,
		RPID:    webauthnTestRPID,
	}, bRegCookies)
	bReg := requireWebauthnFinishOK(t, bFinishResp, "user B registration finish")

	// Begin a LOGIN ceremony against B's own credential — the ceremony is
	// legitimately bound to B, server-side, at this point.
	loginBeginResp, loginCookies := webauthnBeginRaw(t, base, webauthnBeginReq{
		Mode:         "login",
		CredentialID: bReg.CredentialID,
	})
	requireWebauthnBeginOK(t, loginBeginResp, "user B login begin")

	// Finish B's ceremony while claiming A's user_handle, and a counter
	// that clears the (unrelated) rollback check so this test isolates
	// the handle check specifically.
	loginFinishResp := webauthnFinishRaw(t, base, webauthnFinishReq{
		CredentialID: bReg.CredentialID,
		Counter:      2, // > the 1 stored at registration
		Origin:       webauthnTestOrigin,
		RPID:         webauthnTestRPID,
		UserHandle:   aBegin.UserHandle, // attacker-claimed: A, not B
	}, loginCookies)
	harness.AssertRejected(t, loginFinishResp, nil,
		"finishing user B's login ceremony while claiming user A's user_handle")
}

// TestPasskey_CounterRollbackRejected registers a credential with a given
// signature counter, then completes a login ceremony against that same
// credential with a LOWER counter — the standard signal a physical
// authenticator was cloned. The correct (true) user_handle is used so
// this test isolates the counter check from the handle check covered by
// TestPasskey_UserHandleConfusionRejected. GAP 5 in
// reference/vulnerable/webauthn.go stores whatever counter it's given,
// unconditionally.
func TestPasskey_CounterRollbackRejected(t *testing.T) {
	base := harness.MustBaseURL(t)
	username := uniquePasskeyUsername("counter-rollback")

	regBeginResp, regCookies := webauthnBeginRaw(t, base, webauthnBeginReq{Mode: "register", Username: username})
	requireWebauthnBeginOK(t, regBeginResp, "registration begin")
	regFinishResp := webauthnFinishRaw(t, base, webauthnFinishReq{
		Counter: 5,
		Origin:  webauthnTestOrigin,
		RPID:    webauthnTestRPID,
	}, regCookies)
	reg := requireWebauthnFinishOK(t, regFinishResp, "registration finish (counter=5)")

	loginBeginResp, loginCookies := webauthnBeginRaw(t, base, webauthnBeginReq{
		Mode:         "login",
		CredentialID: reg.CredentialID,
	})
	loginBegin := requireWebauthnBeginOK(t, loginBeginResp, "login begin")

	loginFinishResp := webauthnFinishRaw(t, base, webauthnFinishReq{
		CredentialID: reg.CredentialID,
		Counter:      3, // < 5 — a signature counter that went BACKWARDS
		Origin:       webauthnTestOrigin,
		RPID:         webauthnTestRPID,
		UserHandle:   loginBegin.UserHandle, // correct owner, isolates this test to the counter check
	}, loginCookies)
	harness.AssertRejected(t, loginFinishResp, nil,
		"finishing a login ceremony whose signature counter (3) is lower than the credential's last recorded counter (5)")
}
