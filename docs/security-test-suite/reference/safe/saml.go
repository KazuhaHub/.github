package main

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/crewjam/saml"
)

// Route shape and behavior notes, aligned against the three target
// projects' real endpoints (see README.md "Route alignment" table):
//   - POST /saml/acs        — matches PSP's /api/auth/saml/acs, AlertHub's
//     /api/auth/saml/acs, and (modulo the {slug} tenant segment)
//     Report-Portal's /api/auth/saml/{slug}/acs.
//   - GET  /saml/acs        — HTTP-Redirect binding entry point, used only
//     by the 4.1.6 deflate-bomb case; none of the three projects expose
//     Redirect-binding on the ACS URL itself (POST-only per the SAML spec),
//     but crewjam/saml's flate-bomb vulnerability (GHSA-5mqj-xc49-246p) is
//     in its shared Redirect-binding decoder, reachable from any endpoint
//     that accepts a compressed SAMLRequest/SAMLResponse query parameter.
//     Point a real project's redirect-binding SSO endpoint at the same
//     test case instead of this path when adapting these cases.
//
// The ACS URL identity used for SAML's `Destination` check is the fixed
// logical value baked into fixtures/generate.go (spACSURL,
// https://sp.example.com/sectest-sp/saml/acs) — NOT this process's actual
// listen address. A test builds a signed assertion with that Destination
// regardless of which host:port `go run ./reference/safe` happens to bind.

// maxSAMLResponseBody bounds the raw (base64-decoded) size of an ACS POST
// body. This is a coarse, unconditional guard independent of the
// Redirect-binding deflate-bomb defense in samlRedirectBinding below — a
// well-behaved SP should never need to buffer an unbounded POST body just
// to find out it's garbage.
const maxSAMLResponseBody = 1 << 20 // 1 MiB

// maxDeflateBombOutput bounds how much decompressed data
// samlRedirectBinding will read from a Redirect-binding SAMLResponse
// before giving up — this is the fix for GHSA-5mqj-xc49-246p (CVE-2023-28119).
const maxDeflateBombOutput = 512 * 1024 // 512 KiB — generous for any real AuthnRequest/Response, tiny next to a zip-bomb payload

type samlState struct {
	sp *saml.ServiceProvider

	mu     sync.Mutex
	seenID map[string]time.Time // assertion ID -> first-seen time; the replay cache crewjam/saml intentionally does not provide (see package doc)
}

func newSAMLState() (*samlState, error) {
	metaPath, err := fixturePath("idp-metadata.xml")
	if err != nil {
		return nil, err
	}
	metaBytes, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, err
	}
	var idpMeta saml.EntityDescriptor
	if err := xml.Unmarshal(metaBytes, &idpMeta); err != nil {
		return nil, err
	}

	acsURL, err := url.Parse("https://sp.example.com/sectest-sp/saml/acs")
	if err != nil {
		return nil, err
	}

	sp := &saml.ServiceProvider{
		EntityID:          "https://sp.example.com/sectest-sp/metadata",
		AcsURL:            *acsURL,
		IDPMetadata:       &idpMeta,
		AllowIDPInitiated: true, // these tests post assertions directly to the ACS URL, as an attacker replaying a captured response would — there is no SP-initiated AuthnRequest to correlate against
	}

	return &samlState{sp: sp, seenID: make(map[string]time.Time)}, nil
}

// fixturePath resolves a file under fixtures/ relative to THIS source
// file's location (via runtime.Caller), not the process's working
// directory — so `go run ./reference/safe` works the same whether invoked
// from the module root or from inside reference/safe/.
func fixturePath(name string) (string, error) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", os.ErrNotExist
	}
	dir := filepath.Dir(thisFile) // .../reference/safe
	return filepath.Join(dir, "..", "..", "fixtures", name), nil
}

type samlResult struct {
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
	NameID string `json:"name_id,omitempty"`
}

func (s *server) samlACS(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxSAMLResponseBody)
	if err := r.ParseForm(); err != nil {
		writeJSONStatus(w, http.StatusRequestEntityTooLarge, samlResult{Error: "body too large or malformed form: " + err.Error()})
		return
	}

	assertion, err := s.saml.sp.ParseResponse(r, nil)
	if err != nil {
		// crewjam/saml itself rejects: invalid/missing signatures,
		// expired/not-yet-valid assertions, and — as of the version pinned
		// in go.mod (>= the fix for GHSA-j2jp-wvqg-wc2g /
		// CVE-2022-41912) — an unsigned Assertion smuggled alongside a
		// validly signed one in a multi-Assertion Response.
		writeJSONStatus(w, http.StatusUnauthorized, samlResult{Error: "SAML response rejected: " + friendlyParseError(err)})
		return
	}

	assertionID := assertion.ID
	s.saml.mu.Lock()
	_, replay := s.saml.seenID[assertionID]
	if !replay {
		s.saml.seenID[assertionID] = time.Now()
	}
	s.saml.mu.Unlock()
	if replay {
		writeJSONStatus(w, http.StatusConflict, samlResult{Error: "assertion already used (replay rejected)"})
		return
	}

	nameID := ""
	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		nameID = assertion.Subject.NameID.Value
	}
	http.SetCookie(w, &http.Cookie{Name: "sectest_session", Value: "saml:" + nameID, Path: "/", HttpOnly: true})
	writeJSONStatus(w, http.StatusOK, samlResult{OK: true, NameID: nameID})
}

// samlRedirectBinding accepts a compressed SAMLResponse/SAMLRequest query
// parameter the way the HTTP-Redirect binding does, and defends against
// GHSA-5mqj-xc49-246p by capping how much decompressed output it will
// accept before rejecting the request outright.
func (s *server) samlRedirectBinding(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("SAMLResponse")
	if raw == "" {
		raw = r.URL.Query().Get("SAMLRequest")
	}
	if raw == "" {
		writeJSONStatus(w, http.StatusBadRequest, samlResult{Error: "missing SAMLResponse/SAMLRequest"})
		return
	}
	compressed, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		writeJSONStatus(w, http.StatusBadRequest, samlResult{Error: "invalid base64"})
		return
	}

	fr := flate.NewReader(bytes.NewReader(compressed))
	defer fr.Close()
	limited := io.LimitReader(fr, maxDeflateBombOutput+1)
	decoded, err := io.ReadAll(limited)
	if err != nil {
		writeJSONStatus(w, http.StatusBadRequest, samlResult{Error: "could not inflate payload"})
		return
	}
	if len(decoded) > maxDeflateBombOutput {
		writeJSONStatus(w, http.StatusRequestEntityTooLarge, samlResult{Error: "decompressed payload exceeds size limit — rejected before fully inflating"})
		return
	}

	// A real SP would go on to parse `decoded` as XML here. For this
	// reference stub, surviving the decompression guard without hanging or
	// exhausting memory IS the behavior under test (see 4.1.6), so a
	// well-formed-enough response is sufficient.
	writeJSONStatus(w, http.StatusOK, samlResult{OK: true})
}

func friendlyParseError(err error) string {
	if err == nil {
		return ""
	}
	// crewjam/saml's InvalidResponseError.Error() deliberately returns a
	// static string to avoid leaking parse internals to an attacker; we
	// pass it through unchanged rather than reaching into PrivateErr,
	// mirroring how a real SP should respond.
	return err.Error()
}

func writeJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
