// Package harness provides the shared, dependency-light HTTP plumbing used
// by every test file in this module: how to find the target under test, how
// to talk to it without a client that "helpfully" follows redirects out from
// under a test, and how to tell "the attack was rejected" apart from "the
// request never reached anything".
//
// Nothing in this package imports any of the three target projects. It only
// ever talks to SECTEST_BASE_URL over HTTP, exactly as a black-box attacker
// would.
package harness

import (
	"os"
	"strings"
	"testing"
)

// BaseURLEnvVar is the environment variable every test in this suite reads
// to find the black-box target. It intentionally has no default: a missing
// value must skip loudly, not silently probe localhost:8080 or similar.
const BaseURLEnvVar = "SECTEST_BASE_URL"

// MustBaseURL returns the configured target base URL with any trailing
// slash trimmed. If SECTEST_BASE_URL is unset or blank, it calls t.Skip
// with a message that tells the operator exactly what to set and why —
// this is the one and only place in the suite that is allowed to skip a
// test, per the suite's own rule that "target not configured" is not the
// same thing as "test not applicable".
func MustBaseURL(t testing.TB) string {
	t.Helper()
	raw := os.Getenv(BaseURLEnvVar)
	if strings.TrimSpace(raw) == "" {
		t.Skipf(
			"%s is not set — skipping. Point it at a running test instance, e.g.:\n"+
				"  %s=http://127.0.0.1:8080 go test ./...\n"+
				"See reference/safe and reference/vulnerable in this module for two "+
				"runnable stubs you can point this at while developing test cases.",
			BaseURLEnvVar, BaseURLEnvVar,
		)
	}
	return strings.TrimRight(raw, "/")
}

// OptionalBaseURL is like MustBaseURL but never skips; it returns "" and ok
// == false when unset. Use it only in helpers that need to decide *how* to
// skip themselves (e.g. with additional context) rather than delegating to
// MustBaseURL directly.
func OptionalBaseURL() (url string, ok bool) {
	raw := strings.TrimSpace(os.Getenv(BaseURLEnvVar))
	if raw == "" {
		return "", false
	}
	return strings.TrimRight(raw, "/"), true
}
