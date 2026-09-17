// Package authenticator implements a software WebAuthn authenticator for
// this suite's own black-box HTTP tests. It plays both roles a browser
// normally hides behind navigator.credentials.{create,get}(): the WebAuthn
// "client" that assembles clientDataJSON, and the authenticator itself,
// which holds an ES256 (P-256) key pair per credential and produces a real
// CBOR attestationObject (registration) or a real authenticatorData +
// ECDSA signature (assertion).
//
// This exists because the suite's earlier passkey test cases talked to a
// simplified, non-standard JSON ceremony protocol that no real project
// implements — go-webauthn/webauthn (used by all three target projects)
// expects the actual wire format: a CBOR-encoded attestationObject built
// from real authenticator data (rpIdHash, flags, signCount, attested
// credential data, COSE public key) for registration, and a real ECDSA
// signature over authenticatorData‖SHA-256(clientDataJSON) for
// authentication. A test harness that cannot produce these cannot drive a
// real target's passkey endpoints at all.
//
// Every wire structure this package builds is one of go-webauthn's own
// exported protocol types (protocol.CredentialCreationResponse,
// protocol.CredentialAssertionResponse, protocol.URLEncodedBase64, …) so
// the JSON this package emits is byte-for-byte what that library expects
// to parse — this package does not maintain its own parallel encoding.
// CBOR encoding uses github.com/fxamacker/cbor/v2, the same library
// go-webauthn itself depends on for the same purpose.
//
// # Attack surface
//
// Register and Authenticate accept functional Options that let a test
// deliberately produce a ceremony an honest client never would:
//
//   - WithRPID:          embeds the hash of a different RP ID than the one
//     the ceremony was actually issued for.
//   - WithOrigin:        embeds a different origin in clientDataJSON.
//   - WithChallenge:     embeds a different (e.g. stale or replayed)
//     challenge in clientDataJSON instead of the one from the begin
//     response.
//   - WithCounter:       sets an arbitrary signature counter, including one
//     that goes backwards relative to this authenticator's own last-used
//     value for the credential (cloned-authenticator simulation).
//   - WithUserPresent / WithUserVerified: forge the UP/UV flags —
//     WebAuthn's own spec makes these self-asserted by the authenticator,
//     so a Relying Party can only catch a forged claim by policy
//     (requiring UV and getting none), never by cryptography.
//   - WithUserHandle:    (assertion only) claims a different credential
//     owner's user handle than the one this authenticator actually
//     recorded at registration.
//   - WithCorruptSignature: (assertion only) flips a bit of the final
//     ECDSA signature, so a target that skips signature verification
//     entirely is the only kind that accepts it.
//   - WithAAGUID:        (registration only) substitutes a different
//     authenticator model identifier.
//
// None of these require reimplementing the parts of WebAuthn this suite
// deliberately does not re-test (attestation format policy, metadata
// service checks, …) — every option changes exactly one input to the same
// real encoding/signing path every legitimate ceremony goes through.
package authenticator
