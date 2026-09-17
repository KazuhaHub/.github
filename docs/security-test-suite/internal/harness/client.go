package harness

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"
)

// DefaultTimeout bounds every request this package issues. A target that
// hangs (e.g. while decompressing an oversized deflate payload, see the
// 4.1.6 deflate-bomb case) must not be allowed to hang the test run too —
// a timeout in that situation is itself evidence worth reporting, not a
// harness bug.
const DefaultTimeout = 15 * time.Second

// NewClient returns an *http.Client tuned for black-box security testing:
//   - a hard timeout, so an unresponsive target fails the test instead of
//     the test run.
//   - redirects are NOT followed. Tests routinely need to inspect a 302's
//     Location header (a SAML/OIDC login redirect, a post-ACS redirect,
//     etc.) and a client that transparently follows it would throw that
//     evidence away and report the *second* response's status instead of
//     the first — silently changing what a test is actually checking.
func NewClient() *http.Client {
	return &http.Client{
		Timeout: DefaultTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// PostForm posts application/x-www-form-urlencoded values with the shared
// client. It never follows redirects (see NewClient) and never fails the
// test on a network error — it returns the error so the caller can decide,
// via RequireReachable or AssertRejected, whether "could not connect" means
// "the fixture is broken" or "the attack was rejected before the socket
// even opened" (both are real possibilities and tests should tell them
// apart, not conflate them into a t.Fatalf here).
func PostForm(rawURL string, form url.Values) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, rawURL, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return NewClient().Do(req)
}

// PostSAMLResponse base64-encodes samlResponseXML (SAML's wire encoding for
// the HTTP-POST binding) and posts it to acsURL as the standard
// "SAMLResponse" form field, optionally alongside a RelayState.
func PostSAMLResponse(acsURL, samlResponseXML, relayState string) (*http.Response, error) {
	form := url.Values{
		"SAMLResponse": {base64.StdEncoding.EncodeToString([]byte(samlResponseXML))},
	}
	if relayState != "" {
		form.Set("RelayState", relayState)
	}
	return PostForm(acsURL, form)
}

// GetWithCookies issues a GET carrying the given cookies (typically the
// Set-Cookie values captured from a previous response in the same flow,
// e.g. an OIDC or WebAuthn ceremony cookie) and any extra headers such as a
// forged X-Forwarded-For.
func GetWithCookies(rawURL string, cookies []*http.Cookie, headers http.Header) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	return NewClient().Do(req)
}

// PostJSON marshals body as JSON and posts it, again never following
// redirects and never auto-failing the test on a transport error.
func PostJSON(rawURL string, body any, cookies []*http.Cookie) (*http.Response, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, rawURL, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return NewClient().Do(req)
}

// PostRawJSON posts an already-encoded JSON body verbatim — unlike
// PostJSON, it never re-marshals its input. This exists for callers that
// build wire-exact bytes themselves (e.g. internal/authenticator's
// WebAuthn attestation/assertion responses, whose byte-for-byte shape is
// the very thing under test) and must not risk a marshal step silently
// reordering or reformatting them.
func PostRawJSON(rawURL string, body []byte, cookies []*http.Cookie) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return NewClient().Do(req)
}

// DecodeJSON decodes resp.Body into v and closes the body. It is a test
// helper (takes testing.TB) because a malformed response body is itself a
// test failure worth reporting with t.Fatalf, not a Go error to thread
// through every caller by hand.
func DecodeJSON(t testing.TB, resp *http.Response, v any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("decode JSON response (status %d): %v", resp.StatusCode, err)
	}
}
