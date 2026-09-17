package main

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
)

// Every check reference/safe's saml.go performs is either missing or
// stubbed out here. Each gap below is commented with the test case (see
// docs/security-test-suite.md section 4.1) it exists to be caught by.

type samlResult struct {
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
	NameID string `json:"name_id,omitempty"`
}

// naiveAssertion/naiveResponse deliberately do NOT model
// <ds:Signature> at all — the XML decoder just skips elements it has no
// field for, so a Signature block present in the wire XML is silently
// ignored rather than verified. This is the parser a project would end up
// with if it hand-rolled SAML XML parsing instead of using a vetted
// library (or used a library but never wired up signature verification).
type naiveAssertion struct {
	ID      string `xml:"ID,attr"`
	Subject struct {
		NameID struct {
			Value string `xml:",chardata"`
		} `xml:"NameID"`
	} `xml:"Subject"`
	// NotBefore/NotOnOrAfter are read but — see the handler below —
	// never actually checked against the current time.
	Conditions struct {
		NotBefore    string `xml:"NotBefore,attr"`
		NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
	} `xml:"Conditions"`
}

type naiveResponse struct {
	XMLName    xml.Name         `xml:"Response"`
	Assertions []naiveAssertion `xml:"Assertion"`
}

// samlState carries no replay cache, unlike reference/safe's samlState —
// see GAP 4 in samlACS below.
type samlState struct{}

func newSAMLState() (*samlState, error) { return &samlState{}, nil }

func (s *server) samlACS(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, samlResult{Error: "malformed form: " + err.Error()})
		return
	}
	raw := r.PostForm.Get("SAMLResponse")
	if raw == "" {
		writeJSONStatus(w, http.StatusBadRequest, samlResult{Error: "missing SAMLResponse"})
		return
	}
	xmlBytes, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		writeJSONStatus(w, http.StatusBadRequest, samlResult{Error: "invalid base64"})
		return
	}

	var resp naiveResponse
	if err := xml.Unmarshal(xmlBytes, &resp); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, samlResult{Error: "invalid XML"})
		return
	}
	if len(resp.Assertions) == 0 {
		writeJSONStatus(w, http.StatusBadRequest, samlResult{Error: "no Assertion present"})
		return
	}

	// GAP 1 (4.1.3/4.1.4/4.1.5 — signature bypass, CVE-2020-27812 /
	// CVE-2022-41912 / CVE-2020-29509 et al.): no XML-DSig verification of
	// ANY kind is performed. naiveAssertion has no field for
	// <ds:Signature>, so it is decoded and thrown away by the XML decoder.
	// An attacker can submit a completely unsigned Response and it is
	// trusted exactly as if a real IdP had signed it.

	// GAP 2 (4.1.4 — CVE-2022-41912, multiple-Assertion bypass):
	// unconditionally trusts the FIRST Assertion element, with no check
	// for whether additional Assertions are present and no per-assertion
	// signature requirement. An attacker can prepend an unsigned
	// admin-identity Assertion ahead of (or instead of) a validly signed
	// one and it wins.
	chosen := resp.Assertions[0]

	// GAP 3 (4.1.2 — replay / window-boundary case): NotBefore /
	// NotOnOrAfter are parsed into the struct above but never compared
	// against time.Now() anywhere in this handler. An expired assertion
	// (or one dated arbitrarily in the future) is accepted identically to
	// a fresh one.

	// GAP 4 (4.1.1/4.1.2 — the core replay case): no assertion-ID replay
	// cache exists (contrast reference/safe's samlState.seenID). The exact
	// same Response, byte for byte, is accepted every single time it is
	// replayed.

	http.SetCookie(w, &http.Cookie{Name: "sectest_session", Value: "saml:" + chosen.Subject.NameID.Value, Path: "/", HttpOnly: true})
	writeJSONStatus(w, http.StatusOK, samlResult{OK: true, NameID: chosen.Subject.NameID.Value})
}

// samlRedirectBinding — GAP 5 (4.1.6 — CVE-2023-28119, deflate-bomb DoS):
// decompresses the ENTIRE payload with no output-size limit whatsoever, in
// contrast to reference/safe's maxDeflateBombOutput-bounded io.LimitReader.
// A small, highly compressible payload can force this handler to allocate
// an unbounded amount of memory.
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
	decoded, err := io.ReadAll(fr) // <-- no io.LimitReader here; this is the vulnerability
	if err != nil {
		writeJSONStatus(w, http.StatusBadRequest, samlResult{Error: "could not inflate payload"})
		return
	}

	writeJSONStatus(w, http.StatusOK, samlResult{OK: true, Error: ""}) // decoded is intentionally unused past this point — reaching here at all, for an oversized payload, is the failure this test detects
	_ = decoded
}

func writeJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
