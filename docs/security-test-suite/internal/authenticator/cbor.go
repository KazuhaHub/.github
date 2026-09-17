package authenticator

import (
	"crypto/ecdsa"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// coseEncodePublicKey CBOR-encodes an ES256 (P-256) public key in COSE_Key
// format (RFC 9052 §7), using go-webauthn's own webauthncose.EC2PublicKeyData
// struct so the field layout (COSE integer labels 1/3/-1/-2/-3 for
// kty/alg/crv/x/y) is exactly what go-webauthn's verifier expects — this
// package does not maintain a second, parallel definition of that layout.
func coseEncodePublicKey(pub *ecdsa.PublicKey) ([]byte, error) {
	x := make([]byte, 32)
	y := make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)

	key := webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   2,  // COSE key type EC2
			Algorithm: -7, // COSE algorithm ES256
		},
		Curve:  1, // COSE curve P-256
		XCoord: x,
		YCoord: y,
	}
	return cbor.Marshal(key)
}

// buildAttestationObjectNone CBOR-encodes an attestationObject (§6.5.4)
// using the "none" attestation statement format (§8.7): an empty attStmt
// map and no signature over the attested key at all. This is the
// registration analogue of a real, unmodified authenticator that was not
// asked to prove its own provenance — go-webauthn accepts it exactly like
// every other conformant client does, and it is the only format that
// requires no attestation CA/certificate machinery this package would
// otherwise need to fabricate.
func buildAttestationObjectNone(authData []byte) ([]byte, error) {
	obj := map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData,
	}
	return cbor.Marshal(obj)
}
