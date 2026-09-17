package authenticator

import (
	"bytes"
	"crypto/rand"
	"io"
	"net/http"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Every test in this file verifies this package's output the same way a
// real go-webauthn-based Relying Party would: by feeding it straight into
// *webauthn.WebAuthn's own Begin/Finish calls, never by hand-inspecting the
// bytes this package produces. If go-webauthn accepts a legitimate
// ceremony and rejects a forged one for the expected reason, this
// package's encoding is correct — that's the only claim these tests need
// to make, since go-webauthn's own cryptographic correctness is out of
// scope (see doc.go and reference/safe/webauthn.go).

const (
	testRPID   = "example.com"
	testOrigin = "https://example.com"
)

func newTestRelyingParty(t *testing.T, rpID string, origins []string) *webauthn.WebAuthn {
	t.Helper()
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: "authenticator package self-test",
		RPOrigins:     origins,
	})
	if err != nil {
		t.Fatalf("webauthn.New: %v", err)
	}
	return wa
}

type testUser struct {
	id    []byte
	name  string
	creds []webauthn.Credential
}

func (u *testUser) WebAuthnID() []byte                         { return u.id }
func (u *testUser) WebAuthnName() string                       { return u.name }
func (u *testUser) WebAuthnDisplayName() string                { return u.name }
func (u *testUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func requestWithBody(body []byte) *http.Request {
	return &http.Request{Body: io.NopCloser(bytes.NewReader(body))}
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return b
}

// registerHonestly drives a full, non-adversarial registration ceremony
// through go-webauthn and this package, and fails the test if go-webauthn
// does not accept the result — every other test case in this file depends
// on this succeeding, so a failure here means this package's basic
// encoding is broken, not that some attack was (correctly) rejected.
func registerHonestly(t *testing.T, wa *webauthn.WebAuthn, auth *Authenticator, userHandle []byte, userName string) (*webauthn.Credential, *RegistrationResult) {
	t.Helper()

	user := &testUser{id: userHandle, name: userName}
	creation, session, err := wa.BeginRegistration(user, webauthn.WithConveyancePreference(protocol.PreferNoAttestation))
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}

	reg, err := auth.Register(RegistrationInput{
		RPID:       testRPID,
		Origin:     testOrigin,
		Challenge:  creation.Response.Challenge,
		UserHandle: userHandle,
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	cred, err := wa.FinishRegistration(user, *session, requestWithBody(reg.Body))
	if err != nil {
		t.Fatalf("FinishRegistration rejected an honest registration: %v", err)
	}
	return cred, reg
}

func TestRegisterAcceptedByGoWebAuthn_SelfTest(t *testing.T) {
	wa := newTestRelyingParty(t, testRPID, []string{testOrigin})
	auth, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	userHandle := randomBytes(t, 16)
	cred, reg := registerHonestly(t, wa, auth, userHandle, "alice")

	if !bytes.Equal(cred.ID, reg.CredentialID) {
		t.Errorf("go-webauthn recorded credential ID %x, want %x", cred.ID, reg.CredentialID)
	}
	if cred.Authenticator.SignCount != 1 {
		t.Errorf("SignCount = %d, want 1 (this package's default initial counter)", cred.Authenticator.SignCount)
	}
}

func TestAuthenticateAcceptedByGoWebAuthn_SelfTest(t *testing.T) {
	wa := newTestRelyingParty(t, testRPID, []string{testOrigin})
	auth, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	userHandle := randomBytes(t, 16)
	cred, _ := registerHonestly(t, wa, auth, userHandle, "alice")

	handler := func(rawID, userHandleClaim []byte) (webauthn.User, error) {
		return &testUser{id: userHandle, creds: []webauthn.Credential{*cred}}, nil
	}

	assertion, session, err := wa.BeginDiscoverableLogin(webauthn.WithAllowedCredentials([]protocol.CredentialDescriptor{
		{Type: protocol.PublicKeyCredentialType, CredentialID: cred.ID},
	}))
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin: %v", err)
	}

	asrt, err := auth.Authenticate(AssertionInput{
		RPID:         testRPID,
		Origin:       testOrigin,
		Challenge:    assertion.Response.Challenge,
		CredentialID: cred.ID,
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	_, gotCred, err := wa.FinishPasskeyLogin(handler, *session, requestWithBody(asrt.Body))
	if err != nil {
		t.Fatalf("FinishPasskeyLogin rejected an honest assertion: %v", err)
	}
	if gotCred.Authenticator.SignCount != 2 {
		t.Errorf("SignCount after one login = %d, want 2", gotCred.Authenticator.SignCount)
	}
	if gotCred.Authenticator.CloneWarning {
		t.Errorf("CloneWarning set on a monotonically increasing counter")
	}
}

// The remaining tests each flip exactly one Option and confirm go-webauthn
// itself rejects (or, for the two flag-forgery cases, silently accepts —
// see doc.go) the resulting ceremony, for the specific reason that option
// claims to produce.

func TestAuthenticate_WrongRPIDRejected_SelfTest(t *testing.T) {
	wa := newTestRelyingParty(t, testRPID, []string{testOrigin})
	auth, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	userHandle := randomBytes(t, 16)
	cred, _ := registerHonestly(t, wa, auth, userHandle, "alice")
	handler := func(rawID, userHandleClaim []byte) (webauthn.User, error) {
		return &testUser{id: userHandle, creds: []webauthn.Credential{*cred}}, nil
	}
	assertion, session, err := wa.BeginDiscoverableLogin(webauthn.WithAllowedCredentials([]protocol.CredentialDescriptor{
		{Type: protocol.PublicKeyCredentialType, CredentialID: cred.ID},
	}))
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin: %v", err)
	}

	asrt, err := auth.Authenticate(AssertionInput{
		RPID:         testRPID,
		Origin:       testOrigin,
		Challenge:    assertion.Response.Challenge,
		CredentialID: cred.ID,
	}, WithRPID("attacker.example.org"))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if _, _, err := wa.FinishPasskeyLogin(handler, *session, requestWithBody(asrt.Body)); err == nil {
		t.Error("FinishPasskeyLogin accepted an assertion signed for the wrong RP ID")
	}
}

func TestAuthenticate_WrongOriginRejected_SelfTest(t *testing.T) {
	wa := newTestRelyingParty(t, testRPID, []string{testOrigin})
	auth, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	userHandle := randomBytes(t, 16)
	cred, _ := registerHonestly(t, wa, auth, userHandle, "alice")
	handler := func(rawID, userHandleClaim []byte) (webauthn.User, error) {
		return &testUser{id: userHandle, creds: []webauthn.Credential{*cred}}, nil
	}
	assertion, session, err := wa.BeginDiscoverableLogin(webauthn.WithAllowedCredentials([]protocol.CredentialDescriptor{
		{Type: protocol.PublicKeyCredentialType, CredentialID: cred.ID},
	}))
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin: %v", err)
	}

	asrt, err := auth.Authenticate(AssertionInput{
		RPID:         testRPID,
		Origin:       testOrigin,
		Challenge:    assertion.Response.Challenge,
		CredentialID: cred.ID,
	}, WithOrigin("https://attacker.example.net"))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if _, _, err := wa.FinishPasskeyLogin(handler, *session, requestWithBody(asrt.Body)); err == nil {
		t.Error("FinishPasskeyLogin accepted an assertion claiming the wrong origin")
	}
}

func TestAuthenticate_ReplayedChallengeRejected_SelfTest(t *testing.T) {
	wa := newTestRelyingParty(t, testRPID, []string{testOrigin})
	auth, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	userHandle := randomBytes(t, 16)
	cred, _ := registerHonestly(t, wa, auth, userHandle, "alice")
	handler := func(rawID, userHandleClaim []byte) (webauthn.User, error) {
		return &testUser{id: userHandle, creds: []webauthn.Credential{*cred}}, nil
	}
	assertion, session, err := wa.BeginDiscoverableLogin(webauthn.WithAllowedCredentials([]protocol.CredentialDescriptor{
		{Type: protocol.PublicKeyCredentialType, CredentialID: cred.ID},
	}))
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin: %v", err)
	}

	staleChallenge := randomBytes(t, 32) // a challenge from some OTHER, earlier ceremony
	asrt, err := auth.Authenticate(AssertionInput{
		RPID:         testRPID,
		Origin:       testOrigin,
		Challenge:    assertion.Response.Challenge,
		CredentialID: cred.ID,
	}, WithChallenge(staleChallenge))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if _, _, err := wa.FinishPasskeyLogin(handler, *session, requestWithBody(asrt.Body)); err == nil {
		t.Error("FinishPasskeyLogin accepted an assertion carrying a different ceremony's challenge")
	}
}

func TestAuthenticate_CounterRollbackFlaggedAsCloneWarning_SelfTest(t *testing.T) {
	wa := newTestRelyingParty(t, testRPID, []string{testOrigin})
	auth, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	userHandle := randomBytes(t, 16)
	cred, _ := registerHonestly(t, wa, auth, userHandle, "alice")
	// Simulate the credential having already been used at counter 5.
	cred.Authenticator.SignCount = 5

	handler := func(rawID, userHandleClaim []byte) (webauthn.User, error) {
		return &testUser{id: userHandle, creds: []webauthn.Credential{*cred}}, nil
	}
	assertion, session, err := wa.BeginDiscoverableLogin(webauthn.WithAllowedCredentials([]protocol.CredentialDescriptor{
		{Type: protocol.PublicKeyCredentialType, CredentialID: cred.ID},
	}))
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin: %v", err)
	}

	asrt, err := auth.Authenticate(AssertionInput{
		RPID:         testRPID,
		Origin:       testOrigin,
		Challenge:    assertion.Response.Challenge,
		CredentialID: cred.ID,
	}, WithCounter(3)) // < 5: signature counter went backwards
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	_, gotCred, err := wa.FinishPasskeyLogin(handler, *session, requestWithBody(asrt.Body))
	if err != nil {
		t.Fatalf("FinishPasskeyLogin rejected a cryptographically valid (if suspicious) assertion: %v", err)
	}
	// go-webauthn itself never rejects on a lower counter (see
	// webauthn.Authenticator.UpdateCounter's doc comment) — it only flags
	// CloneWarning and leaves the accept/reject decision to the caller.
	// This is exactly why reference/safe and reference/vulnerable differ
	// on this check rather than on go-webauthn's own behavior.
	if !gotCred.Authenticator.CloneWarning {
		t.Error("CloneWarning not set for a signature counter that went backwards")
	}
}

func TestAuthenticate_ClaimedUserHandleMismatchRejected_SelfTest(t *testing.T) {
	wa := newTestRelyingParty(t, testRPID, []string{testOrigin})
	auth, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	trueOwner := randomBytes(t, 16)
	attackerClaimed := randomBytes(t, 16)
	cred, _ := registerHonestly(t, wa, auth, trueOwner, "bob")

	// A handler that resolves identity purely from the credential's true
	// recorded owner — this is reference/safe's shape (see
	// reference/safe/webauthn.go) — never from the wire-level claimed
	// userHandle parameter.
	handler := func(rawID, claimedUserHandle []byte) (webauthn.User, error) {
		return &testUser{id: trueOwner, creds: []webauthn.Credential{*cred}}, nil
	}
	assertion, session, err := wa.BeginDiscoverableLogin(webauthn.WithAllowedCredentials([]protocol.CredentialDescriptor{
		{Type: protocol.PublicKeyCredentialType, CredentialID: cred.ID},
	}))
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin: %v", err)
	}

	asrt, err := auth.Authenticate(AssertionInput{
		RPID:         testRPID,
		Origin:       testOrigin,
		Challenge:    assertion.Response.Challenge,
		CredentialID: cred.ID,
	}, WithUserHandle(attackerClaimed))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if _, _, err := wa.FinishPasskeyLogin(handler, *session, requestWithBody(asrt.Body)); err == nil {
		t.Error("FinishPasskeyLogin accepted an assertion whose claimed user handle contradicted the credential's true owner")
	}
}

func TestAuthenticate_CorruptSignatureRejected_SelfTest(t *testing.T) {
	wa := newTestRelyingParty(t, testRPID, []string{testOrigin})
	auth, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	userHandle := randomBytes(t, 16)
	cred, _ := registerHonestly(t, wa, auth, userHandle, "alice")
	handler := func(rawID, userHandleClaim []byte) (webauthn.User, error) {
		return &testUser{id: userHandle, creds: []webauthn.Credential{*cred}}, nil
	}
	assertion, session, err := wa.BeginDiscoverableLogin(webauthn.WithAllowedCredentials([]protocol.CredentialDescriptor{
		{Type: protocol.PublicKeyCredentialType, CredentialID: cred.ID},
	}))
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin: %v", err)
	}

	asrt, err := auth.Authenticate(AssertionInput{
		RPID:         testRPID,
		Origin:       testOrigin,
		Challenge:    assertion.Response.Challenge,
		CredentialID: cred.ID,
	}, WithCorruptSignature())
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if _, _, err := wa.FinishPasskeyLogin(handler, *session, requestWithBody(asrt.Body)); err == nil {
		t.Error("FinishPasskeyLogin accepted a corrupted assertion signature")
	}
}

func TestRegister_WrongRPIDRejected_SelfTest(t *testing.T) {
	wa := newTestRelyingParty(t, testRPID, []string{testOrigin})
	auth, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	userHandle := randomBytes(t, 16)
	user := &testUser{id: userHandle, name: "alice"}
	creation, session, err := wa.BeginRegistration(user, webauthn.WithConveyancePreference(protocol.PreferNoAttestation))
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}

	reg, err := auth.Register(RegistrationInput{
		RPID:       testRPID,
		Origin:     testOrigin,
		Challenge:  creation.Response.Challenge,
		UserHandle: userHandle,
	}, WithRPID("attacker.example.org"))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if _, err := wa.FinishRegistration(user, *session, requestWithBody(reg.Body)); err == nil {
		t.Error("FinishRegistration accepted attested credential data signed for the wrong RP ID")
	}
}

func TestAuthenticate_ForgedFlagsAreNotByThemselvesDetectable_SelfTest(t *testing.T) {
	// This test documents, rather than defends, a real WebAuthn property:
	// UP/UV are self-asserted by the authenticator (§6.1), so a target
	// that does not itself require UV cannot distinguish a genuinely
	// verified user from a forged claim by cryptography alone. Both
	// WithUserPresent(false) and WithUserVerified(true) below are
	// therefore expected to be ACCEPTED by go-webauthn when the Relying
	// Party's session does not set UserVerification=required — the
	// forgery is only catchable by RP-side policy, which is exactly what
	// WithUserVerified/WithUserPresent exist to let a test probe.
	wa := newTestRelyingParty(t, testRPID, []string{testOrigin})
	auth, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	userHandle := randomBytes(t, 16)
	cred, _ := registerHonestly(t, wa, auth, userHandle, "alice")
	handler := func(rawID, userHandleClaim []byte) (webauthn.User, error) {
		return &testUser{id: userHandle, creds: []webauthn.Credential{*cred}}, nil
	}
	assertion, session, err := wa.BeginDiscoverableLogin(webauthn.WithAllowedCredentials([]protocol.CredentialDescriptor{
		{Type: protocol.PublicKeyCredentialType, CredentialID: cred.ID},
	}))
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin: %v", err)
	}
	if session.UserVerification == protocol.VerificationRequired {
		t.Fatalf("test setup: this test needs a session that does NOT require UV")
	}

	asrt, err := auth.Authenticate(AssertionInput{
		RPID:         testRPID,
		Origin:       testOrigin,
		Challenge:    assertion.Response.Challenge,
		CredentialID: cred.ID,
	}, WithUserVerified(true)) // forged: no real user verification happened
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if _, _, err := wa.FinishPasskeyLogin(handler, *session, requestWithBody(asrt.Body)); err != nil {
		t.Errorf("FinishPasskeyLogin rejected a forged-but-otherwise-valid UV claim when UV was not required: %v", err)
	}
}
