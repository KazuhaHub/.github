// Package securitytest holds the section-4 black-box test cases for
// docs/security-test-suite.md. This file covers section 4.5: rate limiting
// and the X-Forwarded-For trusted-proxy boundary.
//
// Every case here talks to SECTEST_BASE_URL's GET /limited endpoint (see
// reference/{safe,vulnerable}/ratelimit.go and README.md's route table).
// That endpoint's own rate-limit math (a small fixed window) is
// deliberately identical and trivial in both reference stubs — it is NOT
// what section 4.5 tests. What differs between the two stubs, and what
// every test function below is built to catch, is the answer to a single
// question: does the target trust an X-Forwarded-For value written by
// whoever is directly connecting to it, or only from a connecting peer
// address that was explicitly configured as a trusted proxy?
//
// reference/safe answers that correctly (see its clientIP doc comment):
// X-Forwarded-For is read ONLY when the actual TCP peer address falls
// inside the configured -trusted-proxies CIDR list, and the test client in
// this file — an ordinary Go http.Client dialing over loopback — is never
// inside that list (the default is the RFC 5737 range 203.0.113.0/24, and
// the peer address the reference stubs observe here is 127.0.0.1).
// reference/vulnerable answers it incorrectly: it trusts the header from
// any peer, with no allowlist at all (see its clientIP doc comment).
// Because the test client's real peer address is always untrusted in this
// self-check setup, every case below that forges X-Forwarded-For is
// exercising exactly the "connecting from outside the trusted-proxy range"
// scenario from the design doc's 4.5 table — the one marked as the core
// case ("核心用例") — and, per that same table, the "可信代理边界配置过宽"
// question and the "未配置可信代理时 XFF 应被完全忽略" question collapse
// into it from this vantage point too: whether the target treats an
// untrusted peer's forged header as authoritative because the trust list
// is misconfigured too wide, or because it is empty and empty was wrongly
// treated as "trust everyone", or because there is no allowlist logic at
// all, the SAME externally observable symptom results — the forged value
// gets honored — and the same assertions below catch all three causes.
// What none of these cases can distinguish from black-box HTTP alone is
// WHICH of those three misconfigurations is the specific cause; that
// requires reading the target's actual startup configuration (see the
// "not automated" note at the bottom of this file for the one case in the
// 4.5 table that the design doc itself already classifies as a config
// review, not a runtime attack case).
package securitytest

import (
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/KazuhaHub/security-test-suite/internal/harness"
)

// These two constants mirror reference/{safe,vulnerable}/ratelimit.go's
// rateLimitMax and rateLimitWindow exactly — they are NOT a property of
// the trusted-proxy logic under test, just the fixed tuning of the two
// self-check stubs this file is written to run against first. Pointing
// SECTEST_BASE_URL at one of the three real target projects instead means
// discovering THAT project's actual configured limit and window before
// reusing these test bodies (see the design doc's own
// discoverConfiguredLimit() note in its 4.5 skeleton) — hardcoding these
// two numbers against an unknown target would silently turn a security
// test into a flaky timing test.
const (
	refRateLimitMax      = 5
	refRateLimitWindow   = 10 * time.Second
	windowRecoveryBuffer = 1 * time.Second
	forgedRequestMargin  = 5
)

// limitedResponse decodes both response shapes GET /limited can return:
// {"ok":true,"counted_as":"..."} on success and
// {"error":"...","counted_as":"..."} on 429. counted_as is the load-bearing
// field for every assertion in this file: it is what lets a black-box test
// tell "the server counted this request against the real peer address"
// apart from "the server counted it against whatever X-Forwarded-For value
// I sent" without needing any access to the target's internal state.
type limitedResponse struct {
	OK        bool   `json:"ok"`
	Error     string `json:"error"`
	CountedAs string `json:"counted_as"`
}

// forgedXFF returns a single-value X-Forwarded-For payload that rotates
// through the RFC 5737 192.0.2.0/24 documentation range, never a real
// public address. A different value on every call is the point: a limiter
// that (incorrectly) trusts this header from an untrusted peer will see
// what looks like a brand new client on every request and never throttle
// it, which is exactly the bypass this file's core case is built to catch.
func forgedXFF(i int) string {
	return fmt.Sprintf("192.0.2.%d", (i%254)+1)
}

// forgedMultiHopXFF returns a multi-value X-Forwarded-For payload — the
// shape a request passing through a real proxy chain would have — built
// entirely from RFC 5737 documentation ranges, with a different value on
// every call. It exists to probe a variant of the same bug: an
// implementation that parses out and trusts SOME position in a
// comma-separated XFF list (rather than trusting the whole header, or
// none of it) based on a configured proxy hop count. Neither reference
// stub implements hop-position parsing (both read the header verbatim,
// see clientIP in reference/{safe,vulnerable}/ratelimit.go), so this case
// cannot exercise an actual "wrong hop count" bug here — see the
// "not automated" note at the end of this file for what a full check of
// that specific misconfiguration requires against a real target. What it
// DOES verify, on both stubs, is that prepending extra attacker-controlled
// hops to the header doesn't change the outcome for a peer that was never
// trusted to begin with — the same trust-boundary property the core case
// checks, restated against a more realistic multi-hop header shape.
func forgedMultiHopXFF(i int) string {
	return fmt.Sprintf("198.51.100.%d, 192.0.2.%d, 203.0.113.%d",
		(i%254)+1, ((i*7)%254)+1, ((i*13)%254)+1)
}

// getLimited issues one GET /limited carrying the given X-Forwarded-For
// value (empty means "send no XFF header at all", i.e. a plain request
// from the test client's real peer address) and decodes the response. It
// never treats a transport error as any kind of pass/fail on its own —
// callers get a *testing.T failure with the iteration number attached, so
// a target that goes unreachable mid-loop is reported as exactly that,
// not misread as "every remaining request was rejected".
func getLimited(t *testing.T, endpoint, xffValue string, iteration int) (*http.Response, limitedResponse) {
	t.Helper()
	headers := http.Header{}
	if xffValue != "" {
		headers.Set("X-Forwarded-For", xffValue)
	}
	resp, err := harness.GetWithCookies(endpoint, nil, headers)
	resp = harness.RequireReachable(t, resp, err, fmt.Sprintf("GET /limited (request #%d)", iteration))
	var body limitedResponse
	harness.DecodeJSON(t, resp, &body)
	return resp, body
}

// TestRateLimit_XFFTrustBoundary is the whole of section 4.5, run as one
// test with ordered subtests. It is deliberately a single Test function
// rather than several independent ones: GET /limited's rate-limit state is
// keyed, on a correctly implemented target, by the test client's one real
// peer address — there is no way for a black-box HTTP client to obtain a
// second, independent "real" identity to isolate subtests from one
// another the way separate Test functions normally are. Ordering the
// subtests explicitly, and documenting what quota state each one leaves
// behind for the next, is what keeps every assertion below deterministic
// instead of depending on how fast the test binary happens to run.
func TestRateLimit_XFFTrustBoundary(t *testing.T) {
	base := harness.MustBaseURL(t)
	endpoint := base + "/limited"

	// --- subtest 1: forged X-Forwarded-For from an untrusted peer must
	// not open a fresh bucket, and the real peer must still be throttled
	// once it exceeds the limit (design doc 4.5: "反例：不可信来源伪造
	// XFF" + "超配额被拒", combined — see the file-level doc comment for
	// why these two rows collapse into one observable behavior here).
	//
	// State this leaves behind: on a correct implementation, the real
	// peer's bucket now holds exactly refRateLimitMax timestamps (allow()
	// in both reference stubs trims-but-does-not-grow a bucket once it is
	// full, so running MORE than the limit here does not overflow it) —
	// i.e. the real peer is now inside its active rate-limit window. On
	// the vulnerable implementation the real peer's bucket is untouched
	// (every request here resolved to a distinct forged key instead), so
	// it remains at zero.
	t.Run("forged_xff_from_untrusted_peer_cannot_open_new_bucket", func(t *testing.T) {
		total := refRateLimitMax + forgedRequestMargin
		countedAsSeen := map[string]bool{}
		var lastStatus int

		for i := 0; i < total; i++ {
			forged := forgedXFF(i)
			resp, body := getLimited(t, endpoint, forged, i)
			lastStatus = resp.StatusCode
			countedAsSeen[body.CountedAs] = true

			if body.CountedAs == forged {
				t.Errorf("request %d: server reported counted_as=%q — it counted the request "+
					"against the FORGED X-Forwarded-For value it was sent from a peer that was "+
					"never declared as a trusted proxy. An untrusted client can set this header to "+
					"anything, so trusting it here means the rate limit can be evaded entirely by "+
					"rotating it.", i, body.CountedAs)
			}
		}

		if lastStatus != http.StatusTooManyRequests {
			t.Errorf("sent %d requests (limit is %d) from the same real connection, each with a "+
				"DIFFERENT forged X-Forwarded-For value; expected the connection to eventually be "+
				"throttled (429) once keyed correctly by its real address, but the last request "+
				"returned %s (%d) — this means an untrusted client can dodge the rate limit "+
				"indefinitely just by rotating X-Forwarded-For",
				total, refRateLimitMax, harness.StatusClass(lastStatus), lastStatus)
		}

		if len(countedAsSeen) != 1 {
			t.Errorf("expected every one of these %d requests to be counted against the SAME key "+
				"(the one real peer address, since none of the forged X-Forwarded-For values should "+
				"have been trusted), but observed %d distinct counted_as values: %v — each forged "+
				"value opened its own independent bucket",
				total, len(countedAsSeen), countedAsSeen)
		}
	})

	// --- subtest 2: the same property, restated against a multi-hop XFF
	// header shape (design doc 4.5: "可信代理跳数配置过宽/过窄" adjacent
	// risk — see forgedMultiHopXFF's doc comment for exactly what this
	// does and does not cover against these two particular stubs).
	//
	// State this leaves behind: on a correct implementation the real
	// peer's bucket is already at its cap from subtest 1 and stays there
	// (every request here is rejected immediately, which is still the
	// correct, asserted outcome — see the comment on the assertion below).
	// On the vulnerable implementation the real peer's bucket remains
	// untouched at zero, same as after subtest 1.
	t.Run("multi_hop_forged_xff_from_untrusted_peer_cannot_open_new_bucket", func(t *testing.T) {
		total := refRateLimitMax + forgedRequestMargin
		var lastStatus int
		var lastBody limitedResponse

		for i := 0; i < total; i++ {
			forged := forgedMultiHopXFF(i)
			resp, body := getLimited(t, endpoint, forged, i)
			lastStatus = resp.StatusCode
			lastBody = body
		}

		// Unlike subtest 1, this does not also assert "exactly one
		// counted_as value was seen": subtest 1 may already have used up
		// the real peer's entire quota, in which case EVERY request here
		// is rejected before ever recording a fresh timestamp, and the
		// single value seen throughout is trivially uniform either way.
		// What is load-bearing, and still fully discriminating, is that
		// the FINAL request — after refRateLimitMax+forgedRequestMargin
		// attempts, several requests beyond what a correct implementation
		// would ever allow through on a still-fresh key — is rejected.
		if lastStatus != http.StatusTooManyRequests {
			t.Errorf("sent %d requests with a rotating, multi-hop, comma-separated forged "+
				"X-Forwarded-For value (limit is %d); expected the final request to be throttled "+
				"(429), got %s (%d) with counted_as=%q — a multi-hop forged header opened a fresh "+
				"bucket exactly like a single-hop one would",
				total, refRateLimitMax, harness.StatusClass(lastStatus), lastStatus, lastBody.CountedAs)
		}
	})

	// --- subtest 3: the real peer's own window is still active and a
	// fresh forged X-Forwarded-For cannot bypass it mid-window; after the
	// window naturally elapses, the real peer recovers (design doc 4.5:
	// "窗口滚动后恢复", combined with a final restatement of the same
	// forged-XFF-must-not-bypass property so this subtest keeps
	// discriminating rather than becoming a no-op on the vulnerable stub).
	t.Run("window_expiry_recovers_real_peer_after_forged_xff_still_blocked", func(t *testing.T) {
		// This does not need to re-exhaust the real peer's bucket: on a
		// correct implementation subtests 1 and 2 above already drove it
		// to its cap, and well under refRateLimitWindow ago (a few dozen
		// loopback HTTP round trips, not seconds). A fresh forged value
		// here must still fail to get its own bucket.
		freshForged := forgedXFF(9001)
		resp, body := getLimited(t, endpoint, freshForged, 0)
		if resp.StatusCode != http.StatusTooManyRequests {
			t.Errorf("the real peer's rate-limit window should still be active (limit %d, window "+
				"%s) after the previous subtests, and a brand new forged X-Forwarded-For value "+
				"must not grant it a fresh bucket mid-window; expected 429, got %s (%d) with "+
				"counted_as=%q", refRateLimitMax, refRateLimitWindow, harness.StatusClass(resp.StatusCode),
				resp.StatusCode, body.CountedAs)
		}

		t.Logf("waiting %s for the reference stubs' rate-limit window to elapse before checking "+
			"recovery — this duration is specific to reference/{safe,vulnerable}'s hardcoded "+
			"tuning (see the const block at the top of this file); adapting this subtest to a real "+
			"project means discovering ITS configured window first, not reusing this sleep",
			refRateLimitWindow+windowRecoveryBuffer)
		time.Sleep(refRateLimitWindow + windowRecoveryBuffer)

		// Recovery after the window elapses is plain fixed-window
		// bookkeeping — reference/safe and reference/vulnerable share the
		// exact same allow() implementation (see both ratelimit.go files),
		// so this assertion is expected to hold on BOTH stubs. It is not
		// a trust-boundary check; it exists so this file also guards
		// against a regression that breaks the window itself (e.g. a
		// bucket that never empties), which would be a real bug even
		// though it is not what section 4.5 is primarily about.
		recovered, err := harness.GetWithCookies(endpoint, nil, nil)
		harness.AssertAccepted(t, recovered, err, "request from the real peer after its rate-limit window elapsed")
	})
}

// trustedProxyBaseURLEnvVar points at a SEPARATE instance — same binary,
// different -trusted-proxies configuration — whose configured trusted-proxy
// CIDR includes the address this test process actually connects FROM
// (typically 127.0.0.1/32 for a loopback test client). This cannot be the
// same instance SECTEST_BASE_URL names: that instance is deliberately
// configured (reference/safe's default -trusted-proxies=203.0.113.0/24, see
// main.go) so that TestRateLimit_XFFTrustBoundary's own test client is NEVER
// a trusted peer — that is what makes its assertions meaningful. Testing the
// design doc's 4.5 "正例" row ("可信代理范围内的 XFF 生效") needs the
// opposite configuration, so it needs its own target.
const trustedProxyBaseURLEnvVar = "SECTEST_TRUSTED_PROXY_BASE_URL"

// TestRateLimit_TrustedProxyXFFHonoredGate is design doc 4.5's first table
// row — "正例：可信代理范围内的 XFF 生效" — the one property none of the
// subtests in TestRateLimit_XFFTrustBoundary can exercise, because they are
// all deliberately run from a peer address that is NOT trusted (see that
// test's own doc comment). This is why this case is a separate, explicitly
// OPTIONAL test rather than a subtest there: proving XFF is honored FROM a
// trusted peer needs a target configured to trust the address this test
// process actually connects from, which SECTEST_BASE_URL is not (and must
// not be, for the negative cases above to mean anything).
//
// This is a documented "Gate" in the same sense as *VersionGate in
// saml_test.go: it PASSES on both reference/safe and reference/vulnerable
// when exercised, and selfcheck.sh treats it accordingly (see its *Gate
// case). That is not a bug in this test — it is inherent to what "positive
// trust is honored" means: reference/vulnerable trusts X-Forwarded-For from
// literally every peer (see its clientIP doc comment), so it necessarily
// also satisfies "a trusted peer's XFF is honored" — trivially and for the
// wrong reason. What makes reference/vulnerable actually vulnerable is
// covered by TestRateLimit_XFFTrustBoundary's negative cases above, not by
// this one; this test's only job is to confirm the positive path is not
// simply broken (e.g. a target that rejects ALL X-Forwarded-For, trusted
// peer or not, would also incorrectly break this).
//
// Unlike harness.MustBaseURL (the suite's normal, one-and-only skip point
// for "target not configured"), an unset trustedProxyBaseURLEnvVar here does
// NOT mean SECTEST_BASE_URL is missing — the primary target may be fully
// configured and every other test in this file may be running fine. It
// means this ONE optional, differently-configured second target was not
// supplied. Per the same non-Skip rationale as the *VersionGate tests, this
// logs what to set and passes rather than skipping, so a reuse report never
// has to distinguish "the operator forgot to point this suite at anything"
// from "the operator chose not to stand up the extra trusted-proxy
// variant" — both look identical under t.Skip, and only the former should
// ever produce that in this suite.
func TestRateLimit_TrustedProxyXFFHonoredGate(t *testing.T) {
	base, ok := os.LookupEnv(trustedProxyBaseURLEnvVar)
	if !ok || base == "" {
		t.Logf("GATE CHECK (optional, design doc 4.5 \"正例\" row) — %s is not set, so this "+
			"suite cannot verify that a request from a peer INSIDE the configured trusted-proxy "+
			"range actually gets its X-Forwarded-For value honored (as opposed to only verifying, "+
			"via TestRateLimit_XFFTrustBoundary, that an UNTRUSTED peer's forged header is "+
			"correctly ignored). To exercise this: start a second instance of the target, "+
			"configured to trust the address this test process connects FROM (for "+
			"reference/safe: `go run ./reference/safe -addr 127.0.0.1:0 "+
			"-trusted-proxies=127.0.0.1/32`), and set %s to its base URL. selfcheck.sh does this "+
			"automatically for reference/safe/vulnerable — see start_stub's second invocation "+
			"there.", trustedProxyBaseURLEnvVar, trustedProxyBaseURLEnvVar)
		return
	}
	base = trimTrailingSlash(base)
	endpoint := base + "/limited"

	const forged = "192.0.2.200" // RFC 5737 documentation address, distinct from any peer this suite dials from
	resp, body := getLimited(t, endpoint, forged, 0)
	defer resp.Body.Close()

	if body.CountedAs != forged {
		t.Errorf("%s=%s: expected a request from a peer inside the configured trusted-proxy range "+
			"to be counted against its X-Forwarded-For value %q, got counted_as=%q (status %d) — "+
			"trusted-proxy configuration is not taking effect even when it should",
			trustedProxyBaseURLEnvVar, base, forged, body.CountedAs, resp.StatusCode)
	}
}

func trimTrailingSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

// --- Not automated: 可信代理 CIDR 范围本身是否过宽（例如 0.0.0.0/0）或跳数配置是否与部署的真实代理链层数一致 ---
//
// The design doc's own 4.5 table marks the "可信代理边界配置过宽" row as
// "配置审查用例，不是运行时攻击用例" (a config-review case, not a runtime
// attack case), and this file agrees with that classification rather than
// writing a fake HTTP test for it: every subtest above already shows what
// happens when a request arrives from a peer OUTSIDE whatever is
// configured — that is a real, black-box-observable property. Whether the
// configured range itself is dangerously wide (e.g. 0.0.0.0/0, or a CIDR
// broad enough to include addresses an attacker could plausibly reach),
// or whether a hop-count-based parser (like the
// go-chi/httprate/middleware.ClientIPFromXFFTrustedProxies option named in
// the design doc's section 4.5 intro, which neither reference stub
// implements — see forgedMultiHopXFF's doc comment above) is set to a
// number of hops that does not match the real number of trusted proxies
// actually in front of a given deployment, is not something an outside
// HTTP client can determine: the test client has no way to tell "the
// server trusts my peer address because it's rightly configured" apart
// from "the server trusts my peer address because the range is far wider
// than it should be" — both look identical from here (in fact if either
// were true, this file's own subtests above would already be failing, so
// this file's REJECTION of a request is already the affirmative signal
// this specific risk has NOT materialized, whatever the actual boundary
// looks like — the affirmative check that the boundary is TIGHT is what's
// missing).
//
// This is a white-box check: read the target project's actual startup
// configuration (trusted-proxy CIDR list, and, for a project using
// hop-count-based parsing instead of an allowlist, its configured hop
// count) and confirm it matches the real network topology in front of
// that specific deployment — grep for the flag/env var per project (see
// this suite's README "Route alignment" table for where each project's
// identity code lives) rather than adding a test function here that could
// only ever pass or fail by coincidence.
