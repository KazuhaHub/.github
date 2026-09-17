package authenticator

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
)

// signAssertion computes the ECDSA (ES256) signature a WebAuthn assertion
// carries: over authenticatorData ‖ SHA-256(clientDataJSON), per §7.2 step
// 16 (go-webauthn/webauthn/protocol.ParsedCredentialAssertionData.Verify
// builds and verifies against exactly this concatenation). The result is
// ASN.1 DER-encoded, as ecdsa.SignASN1 produces and as
// webauthncose.EC2PublicKeyData.Verify requires.
func signAssertion(priv *ecdsa.PrivateKey, authData, clientDataJSON []byte) ([]byte, error) {
	clientDataHash := sha256.Sum256(clientDataJSON)

	sigInput := make([]byte, 0, len(authData)+len(clientDataHash))
	sigInput = append(sigInput, authData...)
	sigInput = append(sigInput, clientDataHash[:]...)

	digest := sha256.Sum256(sigInput)

	return ecdsa.SignASN1(rand.Reader, priv, digest[:])
}
