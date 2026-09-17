package harness

import (
	"net/http"
	"testing"
)

// RequireReachable fails the test with a message that clearly states the
// request never reached the target (as opposed to reaching it and being
// rejected) and returns the response for chaining. Every test in this suite
// that expects a *baseline* success (the first, unmodified request in a
// replay test, for example) should route through this so a broken fixture
// or an unreachable target is never misreported as "the target correctly
// rejected the baseline request".
func RequireReachable(t testing.TB, resp *http.Response, err error, what string) *http.Response {
	t.Helper()
	if err != nil {
		t.Fatalf(
			"%s: request never reached the target: %v\n"+
				"this is a connectivity/fixture problem, not a security finding — "+
				"confirm SECTEST_BASE_URL points at a live instance",
			what, err,
		)
	}
	return resp
}

// AssertRejected asserts resp represents an HTTP-level rejection (status
// >= 400) of an attack/malformed input. A transport error (err != nil) is
// treated as "unreachable", not as a rejection — a target that is down
// proves nothing about whether it *would* reject the attack, so this fails
// loudly with a distinct message rather than silently counting a network
// failure as a pass.
func AssertRejected(t testing.TB, resp *http.Response, err error, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf(
			"%s: request never reached the target (%v) — cannot conclude anything "+
				"about whether the attack is rejected; this counts as inconclusive, "+
				"not as a pass",
			what, err,
		)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusBadRequest {
		t.Errorf("%s: expected rejection (status >= 400), got %d", what, resp.StatusCode)
	}
}

// AssertAccepted asserts resp represents an HTTP-level success (status <
// 400). Used for baseline/legitimate-flow steps where the *next* step of
// the test depends on this one having actually worked.
func AssertAccepted(t testing.TB, resp *http.Response, err error, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: request never reached the target: %v", what, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		t.Errorf("%s: expected success (status < 400), got %d", what, resp.StatusCode)
	}
}

// StatusClass renders a status code as a short human label, useful in test
// failure messages that need to say what kind of outcome was observed
// rather than just the bare number.
func StatusClass(code int) string {
	switch {
	case code == 0:
		return "no response"
	case code < 300:
		return "success"
	case code < 400:
		return "redirect"
	case code < 500:
		return "client error (rejected)"
	default:
		return "server error"
	}
}
