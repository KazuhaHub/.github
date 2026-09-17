// This file covers design doc section 4.1: SAML assertion replay and the
// applicable subset of the five crewjam/saml security advisories.
//
// Scope decided by the design doc and already verified before this file was
// written (see docs/security-test-suite.md section 4.1.7 and the harness's
// own README "Route alignment" section, produced by an earlier pass over
// this module):
//
//   - 4.1.1 replay of an identical assertion, 4.1.2 window-boundary +
//     concurrent replay, 4.1.4 multi-Assertion signature bypass, and 4.1.6
//     the Redirect-binding deflate bomb are all real, automated, black-box
//     HTTP test cases below (TestSAML_ReplaySameAssertionRejected,
//     TestSAML_ReplayAfterWindowExpiryStillRejected,
//     TestSAML_ConcurrentReplayOnlyOneSucceeds,
//     TestSAML_MultipleAssertionsSignatureBypass, TestSAML_DeflateBombRejected).
//   - 4.1.3 (GHSA-rrfw-hg9m-j47h) and 4.1.5 (GHSA-4hq8-gmxx-h6w9) are
//     library-internal type-confusion / XML-round-trip bugs tied to
//     specific historical dependency versions; the design doc is explicit
//     that fabricating a payload that "works" against current
//     Go/crewjam/goxmldsig versions would not actually exercise the
//     original vulnerability and must not be reported as if it were an
//     automated exploit test. TestSAML_GoxmldsigVersionGate and
//     TestSAML_XMLRoundTripVersionGate below are gate checks: they never
//     call SECTEST_BASE_URL, they log what a human needs to go verify
//     against each target project's own go.sum, and they always pass —
//     see each test's doc comment for why they don't use t.Skip.
//   - 4.1.7 (GHSA-267v-3v32-g6q5) is NOT APPLICABLE and deliberately has no
//     test function here. It lives in crewjam/saml's IdP role validating a
//     third-party SP's registered ACS Location; all three target projects
//     (Passwall-Sub-Panel, AlertHub, Report-Portal) are confirmed SP-only —
//     `grep -rn 'saml\.IdentityProvider|samlidp\.' --include='*.go' .`
//     returns zero matches in all three repositories (checked 2026-09-16,
//     see the design doc). Writing a test for an entry point that does not
//     exist in any target would not distinguish reference/safe from
//     reference/vulnerable (neither stands up a *saml.IdentityProvider
//     either — see reference/safe/saml.go's package doc) and would just be
//     manufactured coverage, which the design doc explicitly forbids.
//
// Self-check discipline (design doc, "★ 规格里没有、但必须做的：自验证"):
// every test below that asserts a security property is written so that it
// PASSES against reference/safe and FAILS against reference/vulnerable —
// see each test's comment for exactly which gap in
// reference/vulnerable/saml.go it is catching. A test that cannot be made
// to fail against reference/vulnerable over black-box HTTP is not written
// as a pass/fail test at all (that is the 4.1.3/4.1.5 gate checks above).
package securitytest

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/KazuhaHub/security-test-suite/internal/harness"
)

// Fixture identities. These must line up exactly with what
// fixtures/generate.go writes into fixtures/idp-metadata.xml and
// fixtures/sp-metadata.xml, and with the *saml.ServiceProvider config
// reference/safe/saml.go's newSAMLState builds from that metadata — see
// that file's own comment on why the Destination/EntityID values below are
// fixed strings rather than derived from SECTEST_BASE_URL.
const (
	testIdPEntityID = "https://idp.example.com/sectest-idp/metadata"
	testSPEntityID  = "https://sp.example.com/sectest-sp/metadata"
	testACSURL      = "https://sp.example.com/sectest-sp/saml/acs"
)

// {goxmldsig,crewjamSaml}PinnedVersion are this module's own go.mod pins
// (see the require block in go.mod), quoted here only so the two version
// gate tests below can print them without duplicating the literal string
// in two places. They describe what reference/safe is built against —
// never any real target project's dependency version. runtime/debug's
// ReadBuildInfo().Deps is deliberately not used for this: it comes back
// empty inside a `go test` binary in this toolchain, unlike a plain
// `go build` binary.
const (
	goxmldsigPinnedVersion   = "v1.4.0"
	crewjamSamlPinnedVersion = "v0.5.1"
)

// samlACSResult mirrors the JSON body both reference/safe's and
// reference/vulnerable's POST /saml/acs handlers return, success or
// failure alike (see reference/{safe,vulnerable}/saml.go's samlResult
// type) — this lets a test read back which identity a response
// authenticated as without needing a separate whoami call or session
// cookie decode.
type samlACSResult struct {
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
	NameID string `json:"name_id,omitempty"`
}

// ---------------------------------------------------------------------
// Fixture plumbing: loading the TEST ONLY IdP key/cert (see
// fixtures/generate.go's banner — none of this is a real credential) and
// building signed SAML Responses/Assertions with them, the way an actual
// IdP holding that key would.
// ---------------------------------------------------------------------

// fixturesDir resolves the fixtures/ directory relative to THIS source
// file (via runtime.Caller), not the process's working directory, so
// `go test ./...` works the same regardless of where it's invoked from —
// mirroring reference/safe/saml.go's own fixturePath helper.
func fixturesDir(t testing.TB) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed — cannot locate fixtures/ relative to this test file")
	}
	return filepath.Join(filepath.Dir(thisFile), "fixtures")
}

// fixtureIdPKeyPair loads the TEST ONLY SAML IdP signing key and
// self-signed certificate fixtures/generate.go produces. Every assertion
// this file signs is signed with this key, exactly mirroring what a real
// IdP holding fixtures/idp-metadata.xml's embedded certificate would
// produce — an attacker who captured a legitimate response, or forged one
// from scratch, would be handed exactly this: a validly-signed-by-the-IdP
// XML document to replay or mutate.
func fixtureIdPKeyPair(t testing.TB) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	dir := fixturesDir(t)

	keyPEM, err := os.ReadFile(filepath.Join(dir, "idp-test-key.pem"))
	if err != nil {
		t.Fatalf("read fixtures/idp-test-key.pem: %v (run `go run ./fixtures` from the module root first)", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Fatalf("fixtures/idp-test-key.pem does not contain a PEM block")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("parse fixtures/idp-test-key.pem: %v", err)
	}

	certPEM, err := os.ReadFile(filepath.Join(dir, "idp-test-cert.pem"))
	if err != nil {
		t.Fatalf("read fixtures/idp-test-cert.pem: %v", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		t.Fatalf("fixtures/idp-test-cert.pem does not contain a PEM block")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("parse fixtures/idp-test-cert.pem: %v", err)
	}
	return key, cert
}

// randomAssertionID returns a fresh SAML-legal ID (a string starting with
// a letter, per the xsd:ID type) for use as an Assertion or Response ID.
func randomAssertionID(t testing.TB) string {
	t.Helper()
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("generate random assertion ID: %v", err)
	}
	return fmt.Sprintf("id-%x", b)
}

// samlAssertionParams is the small set of knobs the test cases below vary;
// everything else is filled in with values that satisfy
// crewjam/saml's ServiceProvider.ParseResponse validation as configured in
// reference/safe/saml.go's newSAMLState (EntityID/AcsURL/IDPMetadata).
type samlAssertionParams struct {
	id           string    // defaults to a fresh random ID
	nameID       string    // required
	notBefore    time.Time // defaults to 1 minute before issueInstant
	notOnOrAfter time.Time // required
	issueInstant time.Time // defaults to time.Now()
}

// buildAssertion builds an *saml.Assertion satisfying every check
// sp.parseAssertion performs (see crewjam/saml's service_provider.go):
// Issuer matching the fixture IdP's entity ID, SubjectConfirmationData
// Recipient matching the fixture SP's ACS URL, and an AudienceRestriction
// matching the fixture SP's entity ID. It is NOT signed — callers sign it
// (or don't, for the 4.1.4 unsigned-assertion case) with signAssertion.
func buildAssertion(t testing.TB, p samlAssertionParams) *saml.Assertion {
	t.Helper()
	if p.nameID == "" {
		t.Fatalf("samlAssertionParams.nameID is required")
	}
	if p.notOnOrAfter.IsZero() {
		t.Fatalf("samlAssertionParams.notOnOrAfter is required")
	}

	id := p.id
	if id == "" {
		id = randomAssertionID(t)
	}
	issueInstant := p.issueInstant
	if issueInstant.IsZero() {
		issueInstant = time.Now().UTC()
	}
	notBefore := p.notBefore
	if notBefore.IsZero() {
		notBefore = issueInstant.Add(-1 * time.Minute)
	}

	return &saml.Assertion{
		ID:           id,
		IssueInstant: issueInstant,
		Version:      "2.0",
		Issuer: saml.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  testIdPEntityID,
		},
		Subject: &saml.Subject{
			NameID: &saml.NameID{
				Format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
				Value:  p.nameID,
			},
			SubjectConfirmations: []saml.SubjectConfirmation{
				{
					Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
					SubjectConfirmationData: &saml.SubjectConfirmationData{
						NotOnOrAfter: p.notOnOrAfter,
						Recipient:    testACSURL,
					},
				},
			},
		},
		Conditions: &saml.Conditions{
			NotBefore:    notBefore,
			NotOnOrAfter: p.notOnOrAfter,
			AudienceRestrictions: []saml.AudienceRestriction{
				{Audience: saml.Audience{Value: testSPEntityID}},
			},
		},
		AuthnStatements: []saml.AuthnStatement{
			{
				AuthnInstant: issueInstant,
				AuthnContext: saml.AuthnContext{
					AuthnContextClassRef: &saml.AuthnContextClassRef{
						Value: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
					},
				},
			},
		},
	}
}

// newIdPSigningContext builds a goxmldsig signing context using the
// fixture IdP's TEST ONLY key/cert. This mirrors exactly what
// crewjam/saml's own IdpAuthnRequest.signingContext does internally (see
// identity_provider.go in the crewjam/saml module: same canonicalizer,
// same RSA-SHA256 signature method) — just pointed at our own fixture key
// instead of driving a *saml.IdentityProvider, since standing one up would
// exercise the IdP role this suite deliberately does not test (4.1.7 is
// not applicable — see the package doc above).
func newIdPSigningContext(t testing.TB, key *rsa.PrivateKey, cert *x509.Certificate) *dsig.SigningContext {
	t.Helper()
	ctx, err := dsig.NewSigningContext(key, [][]byte{cert.Raw})
	if err != nil {
		t.Fatalf("build signing context: %v", err)
	}
	// The canonicalizer prefix list MUST be empty — see crewjam/saml's own
	// canonicalizerPrefixList constant and its comment in identity_provider.go.
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		t.Fatalf("set signature method: %v", err)
	}
	return ctx
}

// signAssertion signs a's XML representation with the fixture IdP key and
// returns the resulting <saml:Assertion> element, following the same
// extract-then-re-render pattern crewjam/saml's own
// IdpAuthnRequest.MakeAssertionEl uses: sign the unsigned element, pull the
// <ds:Signature> that SignEnveloped appended as the last child, assign it
// to the Assertion struct's own Signature field, and re-render so the
// signature lands in its schema-correct position (right after Issuer)
// rather than trailing after AttributeStatements.
func signAssertion(t testing.TB, a *saml.Assertion, key *rsa.PrivateKey, cert *x509.Certificate) *etree.Element {
	t.Helper()
	ctx := newIdPSigningContext(t, key, cert)
	signed, err := ctx.SignEnveloped(a.Element())
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}
	sigEl, ok := signed.Child[len(signed.Child)-1].(*etree.Element)
	if !ok {
		t.Fatalf("signed assertion's last child is not an element")
	}
	a.Signature = sigEl
	return a.Element()
}

// buildResponseElement wraps the given, already-built (and possibly
// signed, possibly not — see TestSAML_MultipleAssertionsSignatureBypass)
// Assertion elements in an unsigned <samlp:Response>, exactly as an
// IdP-initiated HTTP-POST binding response looks on the wire.
//
// The Response itself is deliberately left unsigned by every test in this
// file: crewjam/saml then requires each individual Assertion to carry its
// own valid signature (see service_provider.go's parseResponse — "the
// request has no signature, so assertions must be signed"), which is
// exactly the property TestSAML_MultipleAssertionsSignatureBypass needs to
// probe, and matches how a bearer-only, IdP-initiated POST binding
// response is commonly produced in practice.
//
// saml.Response.Element() only ever serializes a single r.Assertion field
// — the Go struct doesn't model more than one (see its own "more than one
// Assertion is allowed" TODO comment in crewjam/saml's schema.go) — so
// assertions are appended by hand here instead of through that field. That
// gives this helper the same "attach any number of Assertion elements"
// freedom a raw, attacker-constructed Response has, which callers need for
// the multi-Assertion case.
func buildResponseElement(t testing.TB, assertions ...*etree.Element) *etree.Element {
	t.Helper()
	resp := &saml.Response{
		ID:           randomAssertionID(t),
		Version:      "2.0",
		IssueInstant: time.Now().UTC(),
		Destination:  testACSURL,
		Issuer: &saml.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  testIdPEntityID,
		},
		Status: saml.Status{StatusCode: saml.StatusCode{Value: saml.StatusSuccess}},
	}
	el := resp.Element()
	for _, a := range assertions {
		el.AddChild(a)
	}
	return el
}

func elementToXML(t testing.TB, el *etree.Element) string {
	t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot(el)
	out, err := doc.WriteToString()
	if err != nil {
		t.Fatalf("serialize XML: %v", err)
	}
	return out
}

// mustSignedSAMLResponse builds a single-Assertion SAML Response, signed
// with the fixture IdP key, satisfying everything reference/safe's
// ServiceProvider expects. This is the "legitimate IdP response an
// attacker captured" every replay-style case in this file starts from.
func mustSignedSAMLResponse(t testing.TB, p samlAssertionParams) string {
	t.Helper()
	key, cert := fixtureIdPKeyPair(t)
	assertion := buildAssertion(t, p)
	signedEl := signAssertion(t, assertion, key, cert)
	responseEl := buildResponseElement(t, signedEl)
	return elementToXML(t, responseEl)
}

func decodeSAMLResult(t testing.TB, resp *http.Response) samlACSResult {
	t.Helper()
	var result samlACSResult
	harness.DecodeJSON(t, resp, &result)
	return result
}

// ---------------------------------------------------------------------
// 4.1.1 — replay of an identical, unmodified assertion.
// ---------------------------------------------------------------------

// TestSAML_ReplaySameAssertionRejected posts the exact same signed SAML
// Response twice and expects the second attempt to be rejected. The first
// call establishes a baseline (must succeed) so a failure there means the
// test fixture itself is broken, not the target.
//
// Catches: reference/vulnerable/saml.go GAP 4 — no assertion-ID replay
// cache exists there, so the identical Response is accepted every time.
// reference/safe's samlState.seenID map rejects the second POST with 409.
func TestSAML_ReplaySameAssertionRejected(t *testing.T) {
	base := harness.MustBaseURL(t)
	acsURL := base + "/saml/acs"

	xmlResp := mustSignedSAMLResponse(t, samlAssertionParams{
		nameID:       "replay-test@example.com",
		notOnOrAfter: time.Now().UTC().Add(5 * time.Minute),
	})

	first, err := harness.PostSAMLResponse(acsURL, xmlResp, "")
	first = harness.RequireReachable(t, first, err, "baseline SAML login")
	if first.StatusCode >= http.StatusBadRequest {
		body, _ := io.ReadAll(first.Body)
		first.Body.Close()
		t.Fatalf("baseline login failed (status %d), fixture is broken, not a security finding: %s", first.StatusCode, body)
	}
	first.Body.Close()

	second, err := harness.PostSAMLResponse(acsURL, xmlResp, "")
	harness.AssertRejected(t, second, err, "replayed identical SAML assertion")
}

// ---------------------------------------------------------------------
// 4.1.2 — replay window boundary and concurrent replay.
// ---------------------------------------------------------------------

// TestSAML_ReplayAfterWindowExpiryStillRejected builds an assertion with a
// short-lived NotOnOrAfter, uses it once inside that window (must
// succeed), waits for the window to lapse, then replays the identical
// assertion and expects it to still be rejected.
//
// Note on why this differs from simply waiting: crewjam/saml's own
// MaxClockSkew (180s, see service_provider.go) is added on top of
// NotOnOrAfter before the library itself calls an assertion "expired", so
// a short window plus a short sleep does NOT rely on crewjam's built-in
// time check catching the second POST — at this timescale that check
// hasn't fired yet either way. The only thing that CAN catch this replay
// is an application-level assertion-ID cache, i.e. the exact same
// protection 4.1.1 probes. That is intentional: this case exists to catch
// a target whose "replay protection" is actually just a short-lived
// assertion combined with hoping nobody replays it fast enough — if
// that's genuinely all a target has, this test (like 4.1.1) still finds
// it, because there is no cache underneath either window.
//
// Catches: the same reference/vulnerable/saml.go gaps as 4.1.1 (GAP 3 —
// NotBefore/NotOnOrAfter are parsed but never compared against time.Now()
// at all; GAP 4 — no replay cache). reference/safe rejects via its
// seenID cache regardless of whether the window has technically lapsed.
func TestSAML_ReplayAfterWindowExpiryStillRejected(t *testing.T) {
	base := harness.MustBaseURL(t)
	acsURL := base + "/saml/acs"

	const window = 2 * time.Second
	xmlResp := mustSignedSAMLResponse(t, samlAssertionParams{
		nameID:       "window-boundary@example.com",
		notOnOrAfter: time.Now().UTC().Add(window),
	})

	first, err := harness.PostSAMLResponse(acsURL, xmlResp, "")
	first = harness.RequireReachable(t, first, err, "baseline SAML login (within window)")
	if first.StatusCode >= http.StatusBadRequest {
		body, _ := io.ReadAll(first.Body)
		first.Body.Close()
		t.Fatalf("baseline login failed (status %d), fixture is broken, not a security finding: %s", first.StatusCode, body)
	}
	first.Body.Close()

	time.Sleep(window + 2*time.Second) // cross NotOnOrAfter with margin for scheduling jitter

	second, err := harness.PostSAMLResponse(acsURL, xmlResp, "")
	if err != nil {
		t.Fatalf("post-window replay: request never reached the target: %v — inconclusive, not a pass", err)
	}
	defer second.Body.Close()
	if second.StatusCode < http.StatusBadRequest {
		t.Errorf("assertion replayed after its NotOnOrAfter window lapsed was still accepted (status %d) — "+
			"no assertion-ID replay protection", second.StatusCode)
	}
}

// TestSAML_ConcurrentReplayOnlyOneSucceeds fires the same assertion twice
// concurrently and expects exactly one acceptance. This targets a
// check-then-write race in the replay store (an implementation that reads
// "have I seen this ID" and writes "mark it seen" as two separate,
// non-atomic steps could let both concurrent requests read "not seen"),
// not the replay logic's existence, which 4.1.1 already covers.
//
// Catches: reference/vulnerable/saml.go GAP 4 (no cache at all — both
// requests trivially succeed). reference/safe's samlState guards the
// check-then-write with a sync.Mutex around both the read and the write,
// so exactly one of the two concurrent requests observes "not yet seen".
func TestSAML_ConcurrentReplayOnlyOneSucceeds(t *testing.T) {
	base := harness.MustBaseURL(t)
	acsURL := base + "/saml/acs"

	xmlResp := mustSignedSAMLResponse(t, samlAssertionParams{
		nameID:       "concurrent-replay@example.com",
		notOnOrAfter: time.Now().UTC().Add(5 * time.Minute),
	})

	const attempts = 2
	type outcome struct {
		status int
		err    error
	}
	results := make(chan outcome, attempts)
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := harness.PostSAMLResponse(acsURL, xmlResp, "")
			if err != nil {
				results <- outcome{err: err}
				return
			}
			defer resp.Body.Close()
			results <- outcome{status: resp.StatusCode}
		}()
	}
	wg.Wait()
	close(results)

	successes := 0
	var statuses []int
	for r := range results {
		if r.err != nil {
			t.Fatalf("concurrent replay attempt never reached the target: %v — inconclusive, not a pass", r.err)
		}
		statuses = append(statuses, r.status)
		if r.status < http.StatusBadRequest {
			successes++
		}
	}
	if successes != 1 {
		t.Errorf("expected exactly 1 success out of %d concurrent identical assertions, got %d; statuses observed: %v",
			attempts, successes, statuses)
	}
}

// ---------------------------------------------------------------------
// 4.1.3 — GHSA-rrfw-hg9m-j47h / CVE-2020-27812: goxmldsig signature-type
// confusion. Gate check, not an exploit replay.
// ---------------------------------------------------------------------

// TestSAML_GoxmldsigVersionGate documents how to verify the target's
// resolved russellhaering/goxmldsig version is >= 0.4.2 (the fix for
// GHSA-rrfw-hg9m-j47h / CVE-2020-27812, a CWE-347 type-confusion bug in
// signature verification). Per the design doc section 4.1.3, this is a
// library-internal bug that depends on precisely triggering a type
// confusion in code this suite does not control the internals of — a
// generic payload built against a current, already-patched goxmldsig would
// not actually exercise the original vulnerability, so fabricating one
// here would be manufactured coverage, not a real test.
//
// This test intentionally never calls SECTEST_BASE_URL and never calls
// t.Skip: harness.MustBaseURL is this suite's one and only permitted skip
// point (see its doc comment in internal/harness/baseurl.go — "target not
// configured" must never be confused with "test not applicable"). A gate
// check that cannot be automated against an arbitrary black-box target is
// a different situation from a missing target, so it is represented as an
// unconditional pass that logs a loud manual-action message, not a skip.
// Per the design doc, do not report this line in the reuse report as a
// test pass/fail — report "version verified: yes/no + version number" per
// target project instead.
func TestSAML_GoxmldsigVersionGate(t *testing.T) {
	t.Log("GATE CHECK (not an automated exploit) — GHSA-rrfw-hg9m-j47h / CVE-2020-27812: " +
		"github.com/russellhaering/goxmldsig < 0.4.2 has a signature-verification type-confusion bug. " +
		"Verify manually per target project: `go list -m -json github.com/russellhaering/goxmldsig` " +
		"against that project's own go.sum, and record 'version verified: yes/no + version' in the " +
		"reuse report — not a test pass/fail outcome.")

	t.Logf("FYI: this suite's own pinned version (go.mod, what reference/safe is built against) is %s — "+
		"resolved via `go list -m -json github.com/russellhaering/goxmldsig` against THIS module's go.sum, "+
		"not runtime.debug.ReadBuildInfo (go test binaries do not reliably embed dependency versions there). "+
		"This is NOT any target project's version and tells you nothing about SECTEST_BASE_URL — do not "+
		"copy it into the reuse report as if it were.", goxmldsigPinnedVersion)
}

// ---------------------------------------------------------------------
// 4.1.4 — GHSA-j2jp-wvqg-wc2g / CVE-2022-41912: multiple-Assertion
// signature bypass.
// ---------------------------------------------------------------------

// TestSAML_MultipleAssertionsSignatureBypass builds a Response containing
// two Assertion elements: an unsigned, attacker-controlled one claiming an
// admin identity, placed FIRST, followed by a validly signed one for a
// low-privilege test account. The target must not authenticate the caller
// as the admin identity from the unsigned assertion — either by rejecting
// the Response outright, or by authenticating as the signed identity only.
//
// Catches: reference/vulnerable/saml.go GAP 1 (no XML-DSig verification of
// any kind) and GAP 2 (unconditionally trusts the FIRST Assertion element,
// with no per-assertion signature requirement) — it returns
// "admin@example.com". reference/safe uses crewjam/saml v0.5.1's
// ServiceProvider.ParseResponse, which is past the CVE-2022-41912 fix: it
// individually validates each Assertion's signature and returns the first
// one that has a VALID signature, excluding the unsigned admin assertion
// entirely — it returns "low-priv-test@example.com".
func TestSAML_MultipleAssertionsSignatureBypass(t *testing.T) {
	base := harness.MustBaseURL(t)
	acsURL := base + "/saml/acs"

	key, cert := fixtureIdPKeyPair(t)
	notOnOrAfter := time.Now().UTC().Add(5 * time.Minute)

	unsignedAdmin := buildAssertion(t, samlAssertionParams{
		nameID:       "admin@example.com",
		notOnOrAfter: notOnOrAfter,
	})
	unsignedAdminEl := unsignedAdmin.Element() // deliberately left unsigned

	signedLowPriv := buildAssertion(t, samlAssertionParams{
		nameID:       "low-priv-test@example.com",
		notOnOrAfter: notOnOrAfter,
	})
	signedLowPrivEl := signAssertion(t, signedLowPriv, key, cert)

	// Attacker-controlled unsigned assertion FIRST, validly-signed one
	// SECOND — this ordering is what reference/vulnerable's GAP 2 ("trusts
	// the FIRST Assertion element") is built to fall for.
	responseEl := buildResponseElement(t, unsignedAdminEl, signedLowPrivEl)
	xmlResp := elementToXML(t, responseEl)

	resp, err := harness.PostSAMLResponse(acsURL, xmlResp, "")
	if err != nil {
		t.Fatalf("multi-assertion POST never reached the target: %v — inconclusive, not a pass", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		return // rejected outright — acceptable and the safest outcome
	}

	result := decodeSAMLResult(t, resp)
	if result.NameID == "admin@example.com" {
		t.Fatalf("session was established as the UNSIGNED assertion's identity %q — "+
			"multiple-Assertion signature bypass reproduced (GHSA-j2jp-wvqg-wc2g / CVE-2022-41912)", result.NameID)
	}
	if result.NameID != "low-priv-test@example.com" {
		t.Errorf("expected the session identity to be the validly signed assertion's NameID "+
			"(low-priv-test@example.com), got %q", result.NameID)
	}
}

// ---------------------------------------------------------------------
// 4.1.5 — GHSA-4hq8-gmxx-h6w9 / CVE-2020-29509/29510/29511: XML
// round-trip inconsistency. Gate check, not an exploit replay.
// ---------------------------------------------------------------------

// TestSAML_XMLRoundTripVersionGate documents how to verify the target's
// resolved crewjam/saml version is >= 0.4.3 (the fix for
// GHSA-4hq8-gmxx-h6w9). Per the design doc section 4.1.5, the root cause is
// three historical Go stdlib encoding/xml round-trip bugs whose trigger
// conditions are tied to the encoding/xml version in use at the time;
// reliably reproducing the original payload against this suite's pinned Go
// 1.26 toolchain and an already-patched crewjam/saml is not realistic, and
// a payload that merely "gets rejected" against a patched target proves
// nothing about whether it ever exercised the actual bug. See the design
// doc for the alternative it points at instead (pulling the official
// regression-test payload from crewjam/saml's own fix commit) if a future
// maintainer wants to upgrade this from a gate check to a real exploit
// replay — this suite does not fabricate that payload.
//
// Same non-Skip rationale as TestSAML_GoxmldsigVersionGate above.
func TestSAML_XMLRoundTripVersionGate(t *testing.T) {
	t.Log("GATE CHECK (not an automated exploit) — GHSA-4hq8-gmxx-h6w9 / CVE-2020-29509/29510/29511: " +
		"github.com/crewjam/saml < 0.4.3 inherits Go stdlib encoding/xml round-trip inconsistencies that " +
		"can let a signature cover different bytes than what business logic reads. Verify manually per " +
		"target project: `go list -m -json github.com/crewjam/saml` against that project's own go.sum, " +
		"and record 'version verified: yes/no + version' in the reuse report — not a test pass/fail outcome.")

	t.Logf("FYI: this suite's own pinned version (go.mod, what reference/safe is built against) is %s — "+
		"this is NOT any target project's version and tells you nothing about SECTEST_BASE_URL — do not "+
		"copy it into the reuse report as if it were.", crewjamSamlPinnedVersion)
}

// ---------------------------------------------------------------------
// 4.1.6 — GHSA-5mqj-xc49-246p / CVE-2023-28119: Redirect-binding deflate
// decompression bomb.
// ---------------------------------------------------------------------

// TestSAML_DeflateBombRejected sends a small, highly compressible deflate
// payload as an HTTP-Redirect-binding SAMLResponse query parameter and
// expects the target to reject it outright (or at minimum stay
// responsive) rather than decompressing an unbounded amount of data.
//
// EXECUTION WARNING (design doc section 4.1.6): only run this against a
// disposable, single-purpose test instance, never a shared dev environment
// or production — a target with GAP 5 below can be made to allocate far
// more memory than the 10MB used here by simply raising rawSize.
//
// Catches: reference/vulnerable/saml.go's samlRedirectBinding GAP 5 —
// io.ReadAll(fr) with no size bound, so it happily decompresses and
// accepts the full 10MB. reference/safe's samlRedirectBinding wraps the
// inflate reader in io.LimitReader(fr, maxDeflateBombOutput+1) and returns
// 413 once that 512KiB cap is exceeded, well before finishing decompression.
func TestSAML_DeflateBombRejected(t *testing.T) {
	base := harness.MustBaseURL(t)
	// GET /saml/acs is this suite's stand-in HTTP-Redirect binding entry
	// point (see reference/safe/saml.go's package doc and README's route
	// table). None of the three target projects expose Redirect binding on
	// the ACS URL itself (POST-only, per the SAML spec), but
	// crewjam/saml's decompression bomb lives in the Redirect-binding
	// decoder shared by any endpoint that accepts a compressed
	// SAMLRequest/SAMLResponse query parameter — point redirectURL at that
	// project's actual Redirect-binding SSO endpoint when adapting this
	// case to a real project instead of this reference stub.
	redirectURL := base + "/saml/acs"

	const rawSize = 10 * 1024 * 1024 // 10MB of zero bytes — compresses to a tiny wire payload
	bomb := buildDeflateBomb(t, rawSize)
	q := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString(bomb)}}

	client := harness.NewClient()
	resp, err := client.Get(redirectURL + "?" + q.Encode())
	if err != nil {
		// Unlike this suite's other cases, a transport error here IS
		// itself the finding, not an inconclusive result: a target that
		// hangs or drops the connection while decompressing an oversized
		// payload has just demonstrated the DoS this case probes for (see
		// harness.NewClient's DefaultTimeout — a target that doesn't even
		// respond within 15s has failed this test, not the harness).
		t.Fatalf("target became unresponsive decompressing a %d-byte wire payload that expands to %d bytes "+
			"— treat this as a reproduced DoS (GHSA-5mqj-xc49-246p / CVE-2023-28119), not a "+
			"harness/connectivity problem: %v", len(bomb), rawSize, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusBadRequest {
		t.Errorf("deflate bomb (%d wire bytes -> %d decompressed bytes) was accepted (status %d), expected "+
			"it to be rejected as oversized before being fully inflated", len(bomb), rawSize, resp.StatusCode)
	}
}

// buildDeflateBomb compresses rawSize zero bytes with flate.BestCompression
// and returns the (much smaller) compressed wire payload — zero bytes
// compress at a very high ratio, which is exactly the property a real
// deflate-bomb attack exploits: a tiny request forcing large server-side
// work.
func buildDeflateBomb(t testing.TB, rawSize int) []byte {
	t.Helper()
	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		t.Fatalf("create flate writer: %v", err)
	}
	if _, err := fw.Write(make([]byte, rawSize)); err != nil {
		t.Fatalf("write zero payload: %v", err)
	}
	if err := fw.Close(); err != nil {
		t.Fatalf("close flate writer: %v", err)
	}
	return buf.Bytes()
}
