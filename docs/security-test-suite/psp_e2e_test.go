// This file is not part of the reference-stub suite. Every other *_test.go here
// runs against reference/safe and reference/vulnerable over SECTEST_BASE_URL;
// this one drives a REAL Passwall-Sub-Panel, over the same software WebAuthn
// authenticator, and exists because the two halves of the passkey path are
// verified in different places and never together.
//
// Passwall-Sub-Panel#102 moved the server onto go-webauthn 0.18.1 and #113 moved
// the browser onto @simplewebauthn/browser 14. Each was verified on its own —
// #102 by compiling and by unit tests over the ceremony session, #113 by the
// web suite. Nothing exercised a real ceremony end to end across both, because
// the suite had no way to reach a real panel. It does now.
//
// It is skipped unless PSP_E2E_BASE_URL, PSP_E2E_UPN and PSP_E2E_PASSWORD are
// set, because it needs a running panel and it MUTATES that panel's settings and
// the account's credentials. Point it only at a throwaway instance.
//
//	PSP_E2E_BASE_URL=http://localhost:18788 \
//	PSP_E2E_UPN=admin PSP_E2E_PASSWORD=... \
//	go test -run TestPSPE2E -v ./...
//
// Use a HOST NAME, not an IP. The relying party ID is derived from the
// subscription base URL, and go-webauthn 0.18.1 rejects an IP outright before
// the ceremony starts ("field 'RPID' is not a valid domain string"). A panel
// configured with http://127.0.0.1:... gets a 500 from the begin endpoint and
// no passkey can be enrolled at all -- reproducing, on demand, the behaviour
// change the handoff listed as reasoned-but-unmeasured.
//
// What it proves, in order, against one fresh panel:
//
//  1. A passkey can be REGISTERED against a real panel — real CBOR attestation,
//     accepted, stored.
//  2. That credential completes a DISCOVERABLE (usernameless) login and mints a
//     usable session. This is the path #102's LoginOption change touched, since
//     it is the one ceremony that forces UserVerification=Required — so the
//     assertion has to carry the UV flag, exactly as a real authenticator would
//     after a PIN or a fingerprint.
//  3. Enrolling a passkey opts the account into 2FA, so the password step then
//     stops at a gate and the SAME credential clears it as a second factor.
//
// Steps 2 and 3 are the server half of the pairing that #102 and #113 form. #113
// is the browser half and is not exercised here: the assertion is built by
// internal/authenticator, not by @simplewebauthn/browser. What this rules out is
// the server half being broken, which is the half a browser failure would
// otherwise be blamed for.
//
// It needs a FRESH panel database. Step 3 leaves the account requiring 2FA, and
// the authenticator that could satisfy that gate died with the test process, so
// a second run against the same panel skips rather than failing. The recovery
// codes returned on first enrollment are the only way back into an account left
// in that state — which is worth knowing before running this anywhere real.
package securitytest

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/KazuhaHub/security-test-suite/internal/authenticator"
)

type pspE2E struct {
	base  string
	token string
	http  *http.Client
}

// pspPublicKey is the subset of go-webauthn's PublicKeyCredential*Options this
// file needs. The panel returns the library's own struct under "publicKey", so
// the JSON names are the library's.
type pspPublicKey struct {
	Challenge string `json:"challenge"`
	// go-webauthn spells the relying party two different ways and both reach
	// this struct: CREATION options carry `rp` as an object, AUTHENTICATION
	// options carry `rpId` as a bare string. Reading only one of them made the
	// authenticator hash an empty RP ID, and the panel rejected the assertion
	// with "RP Hash mismatch ... Received e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	// -- the SHA-256 of the empty string. Same ceremony, different JSON shape.
	RPID string `json:"rpId"`
	RP   struct {
		ID string `json:"id"`
	} `json:"rp"`
	User struct {
		ID string `json:"id"`
	} `json:"user"`
}

// rpID returns whichever spelling this response used.
func (p pspPublicKey) rpID() string {
	if p.RPID != "" {
		return p.RPID
	}
	return p.RP.ID
}

// pspDecodeB64URL accepts the unpadded base64url go-webauthn emits, and tolerates
// padding, because a mismatch there is a decoding detail rather than the thing
// under test.
func pspDecodeB64URL(t *testing.T, s string) []byte {
	t.Helper()
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b
		}
	}
	t.Fatalf("challenge/user id %q is not base64url", s)
	return nil
}

func (e *pspE2E) do(t *testing.T, method, path string, body []byte, auth bool) (*http.Response, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, e.base+path, rdr)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth {
		req.Header.Set("Authorization", "Bearer "+e.token)
	}
	resp, err := e.http.Do(req)
	if err != nil {
		t.Fatalf("%s %s: request failed: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

func TestPSPE2E_PasskeyCeremonyEndToEnd(t *testing.T) {
	base := strings.TrimRight(os.Getenv("PSP_E2E_BASE_URL"), "/")
	upn := os.Getenv("PSP_E2E_UPN")
	pass := os.Getenv("PSP_E2E_PASSWORD")
	if base == "" || upn == "" || pass == "" {
		t.Skip("set PSP_E2E_BASE_URL, PSP_E2E_UPN and PSP_E2E_PASSWORD to run this against a throwaway panel")
	}
	if !strings.HasPrefix(base, "http://") {
		// A passkey ceremony is origin-bound, so the origin the authenticator
		// reports has to be the one the panel serves from. Keep it simple and
		// refuse anything else rather than silently testing the wrong origin.
		t.Fatalf("PSP_E2E_BASE_URL must be a plain http:// origin for this test, got %q", base)
	}

	e := &pspE2E{base: base, http: &http.Client{}}

	// ---- 1. log in with the password to reach the authenticated settings and
	//         enrollment routes -------------------------------------------------
	loginBody, _ := json.Marshal(map[string]string{"upn": upn, "password": pass})
	resp, raw := e.do(t, http.MethodPost, "/api/auth/local/login", loginBody, false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("password login = %d: %s", resp.StatusCode, raw)
	}
	var login struct {
		AccessToken string `json:"access_token"`
		Status      string `json:"status"`
	}
	if err := json.Unmarshal(raw, &login); err != nil {
		t.Fatalf("password login returned non-JSON: %v\n%s", err, raw)
	}
	if login.AccessToken == "" {
		// A passkey IS a second factor, so once one is enrolled the account no
		// longer logs in on a password alone. That is correct, and it means this
		// test has already run against this panel -- the authenticator it would
		// need to satisfy the gate was discarded with the previous process.
		t.Skipf("this account already requires 2FA (%s), so it has a passkey from a previous run.\n"+
			"Point this test at a panel with a fresh database: it enrolls a credential and cannot\n"+
			"recover one it did not create. The recovery codes printed on first enrollment are the\n"+
			"only way back into an account in this state.", login.Status)
	}
	e.token = login.AccessToken

	// ---- 2. point the panel at an origin and turn the passkey paths on. The
	//         WebAuthn RP ID is derived from the subscription base URL, so an
	//         unset one makes the ceremony fail before it starts.
	//
	//         The settings endpoint replaces the whole object rather than
	//         patching it, so read the current one and change only these three
	//         fields -- sending a partial body is rejected, and sending a
	//         hand-built one would silently reset everything else. -------------
	resp, raw = e.do(t, http.MethodGet, "/api/admin/settings/ui", nil, true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET settings = %d: %s", resp.StatusCode, raw)
	}
	var settings map[string]any
	if err := json.Unmarshal(raw, &settings); err != nil {
		t.Fatalf("GET settings returned non-JSON: %v", err)
	}
	settings["sub_base_url"] = base
	settings["passkey_enabled"] = true
	settings["passkey_passwordless"] = true
	settingsBody, _ := json.Marshal(settings)
	resp, raw = e.do(t, http.MethodPut, "/api/admin/settings/ui", settingsBody, true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT settings = %d: %s", resp.StatusCode, raw)
	}

	auth, err := authenticator.New()
	if err != nil {
		t.Fatalf("authenticator.New: %v", err)
	}

	// ---- 3. register a real passkey -----------------------------------------
	resp, raw = e.do(t, http.MethodPost, "/api/user/me/passkeys/begin", nil, true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("passkeys/begin = %d: %s", resp.StatusCode, raw)
	}
	var begin struct {
		SessionID string       `json:"session_id"`
		PublicKey pspPublicKey `json:"publicKey"`
	}
	if err := json.Unmarshal(raw, &begin); err != nil {
		t.Fatalf("passkeys/begin returned something this test cannot parse: %v\n%s", err, raw)
	}
	if begin.SessionID == "" {
		t.Fatalf("passkeys/begin returned no session_id: %s", raw)
	}
	if begin.PublicKey.rpID() == "" {
		t.Fatalf("passkeys/begin declared no rp id: %s", raw)
	}

	reg, err := auth.Register(authenticator.RegistrationInput{
		RPID:       begin.PublicKey.rpID(),
		Origin:     base,
		Challenge:  pspDecodeB64URL(t, begin.PublicKey.Challenge),
		UserHandle: pspDecodeB64URL(t, begin.PublicKey.User.ID),
	})
	if err != nil {
		t.Fatalf("authenticator.Register: %v", err)
	}

	resp, raw = e.do(t, http.MethodPost,
		"/api/user/me/passkeys/finish?session="+begin.SessionID+"&name=e2e-smoke", reg.Body, true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("passkeys/finish = %d: %s", resp.StatusCode, raw)
	}

	// ---- 4. passwordless (discoverable) login with that credential ----------
	resp, raw = e.do(t, http.MethodPost, "/api/auth/passkey/begin", nil, false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("passkey/begin = %d: %s", resp.StatusCode, raw)
	}
	var loginBegin struct {
		SessionID string       `json:"session_id"`
		PublicKey pspPublicKey `json:"publicKey"`
	}
	if err := json.Unmarshal(raw, &loginBegin); err != nil {
		t.Fatalf("passkey/begin returned something this test cannot parse: %v\n%s", err, raw)
	}
	if loginBegin.SessionID == "" {
		t.Fatalf("passkey/begin returned no session_id: %s", raw)
	}

	assertion, err := auth.Authenticate(authenticator.AssertionInput{
		RPID:      loginBegin.PublicKey.rpID(),
		Origin:    base,
		Challenge: pspDecodeB64URL(t, loginBegin.PublicKey.Challenge),
		// The credential registered above: a discoverable login is supposed to
		// find it from the user handle alone, but the authenticator has to be
		// told which of its keys to sign with either way.
		CredentialID: reg.CredentialID,
	},
		// The panel forces UserVerification=Required on the passwordless path
		// (Passwall-Sub-Panel#102's change), so the assertion has to carry the UV
		// flag a real authenticator sets after a PIN or a fingerprint. Without
		// it go-webauthn rejects the assertion -- which is the requirement
		// working, not a bug to route around.
		authenticator.WithUserVerified(true),
		authenticator.WithUserPresent(true),
	)
	if err != nil {
		t.Fatalf("authenticator.Authenticate: %v", err)
	}

	resp, raw = e.do(t, http.MethodPost,
		"/api/auth/passkey/finish?session="+loginBegin.SessionID, assertion.Body, false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("passkey/finish = %d: %s\n"+
			"the server half of the passkey path rejected a real assertion", resp.StatusCode, raw)
	}
	var minted struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(raw, &minted); err != nil || minted.AccessToken == "" {
		t.Fatalf("passwordless login did not mint a session: %s", raw)
	}
	// Assert the session WORKS rather than that its token differs: a JWT signed
	// for the same account in the same second is byte-identical to the one the
	// password login minted, so comparing the strings proves nothing (and an
	// earlier version of this test failed on exactly that). Using it does.
	func() {
		saved := e.token
		e.token = minted.AccessToken
		defer func() { e.token = saved }()
		me, body := e.do(t, http.MethodGet, "/api/user/me/passkeys", nil, true)
		if me.StatusCode != http.StatusOK {
			t.Fatalf("the session minted by passwordless login was not accepted: %d %s", me.StatusCode, body)
		}
	}()

	// ---- 5. passkey as a SECOND FACTOR. Enrolling one opts the account into
	//         2FA, so the password step must now stop at a gate and the passkey
	//         must be what clears it. This leg only exists because step 3
	//         succeeded: it is the same credential, used the other way round. --
	resp, raw = e.do(t, http.MethodPost, "/api/auth/local/login", loginBody, false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("second password login = %d: %s", resp.StatusCode, raw)
	}
	var gate struct {
		Status       string   `json:"status"`
		PendingToken string   `json:"pending_token"`
		Methods      []string `json:"methods"`
	}
	if err := json.Unmarshal(raw, &gate); err != nil {
		t.Fatalf("second password login returned non-JSON: %v\n%s", err, raw)
	}
	if gate.Status != "2fa_required" || gate.PendingToken == "" {
		t.Fatalf("after enrolling a passkey the password step must stop at 2FA, got status=%q pending_token=%v",
			gate.Status, gate.PendingToken != "")
	}

	twoFABody, _ := json.Marshal(map[string]string{"pending_token": gate.PendingToken})
	resp, raw = e.do(t, http.MethodPost, "/api/auth/2fa/passkey/begin", twoFABody, false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("2fa/passkey/begin = %d: %s", resp.StatusCode, raw)
	}
	var twoFABegin struct {
		SessionID string       `json:"session_id"`
		PublicKey pspPublicKey `json:"publicKey"`
	}
	if err := json.Unmarshal(raw, &twoFABegin); err != nil {
		t.Fatalf("2fa/passkey/begin returned something this test cannot parse: %v\n%s", err, raw)
	}

	twoFA, err := auth.Authenticate(authenticator.AssertionInput{
		RPID:         twoFABegin.PublicKey.rpID(),
		Origin:       base,
		Challenge:    pspDecodeB64URL(t, twoFABegin.PublicKey.Challenge),
		CredentialID: reg.CredentialID,
	},
		authenticator.WithUserVerified(true),
		authenticator.WithUserPresent(true),
	)
	if err != nil {
		t.Fatalf("authenticator.Authenticate (2FA): %v", err)
	}

	resp, raw = e.do(t, http.MethodPost,
		"/api/auth/2fa/passkey/finish?pending_token="+gate.PendingToken+"&session="+twoFABegin.SessionID,
		twoFA.Body, false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("2fa/passkey/finish = %d: %s\n"+
			"the passkey was accepted as a login but rejected as a second factor", resp.StatusCode, raw)
	}
	var final struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(raw, &final); err != nil || final.AccessToken == "" {
		t.Fatalf("passkey 2FA did not complete the login: %s", raw)
	}
}
