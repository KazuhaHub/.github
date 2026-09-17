package authenticator

import "encoding/binary"

// Authenticator data flag bits, per WebAuthn §6.1.
const (
	flagUserPresent            byte = 1 << 0 // UP
	flagUserVerified           byte = 1 << 2 // UV
	flagAttestedCredentialData byte = 1 << 6 // AT
)

// buildAuthData encodes the fixed-format prefix of authenticatorData
// (rpIdHash ‖ flags ‖ signCount, §6.1) and appends attestedCredentialData
// verbatim when present (registration) or omits it (assertion, where the
// AT flag must be clear). rpIDHash must be exactly 32 bytes — the
// SHA-256 output size §6.1 mandates.
func buildAuthData(rpIDHash []byte, userPresent, userVerified bool, signCount uint32, attestedCredentialData []byte) []byte {
	var flags byte
	if userPresent {
		flags |= flagUserPresent
	}
	if userVerified {
		flags |= flagUserVerified
	}
	if attestedCredentialData != nil {
		flags |= flagAttestedCredentialData
	}

	buf := make([]byte, 0, 37+len(attestedCredentialData))
	buf = append(buf, rpIDHash...)
	buf = append(buf, flags)

	var counterBytes [4]byte
	binary.BigEndian.PutUint32(counterBytes[:], signCount)
	buf = append(buf, counterBytes[:]...)

	if attestedCredentialData != nil {
		buf = append(buf, attestedCredentialData...)
	}

	return buf
}

// buildAttestedCredentialData encodes attestedCredentialData (§6.5.2):
// aaguid ‖ credentialIdLength (uint16 big-endian) ‖ credentialId ‖
// credentialPublicKey (already CBOR-encoded COSE_Key bytes).
func buildAttestedCredentialData(aaguid [16]byte, credentialID, publicKeyCOSE []byte) []byte {
	buf := make([]byte, 0, 16+2+len(credentialID)+len(publicKeyCOSE))
	buf = append(buf, aaguid[:]...)

	var idLen [2]byte
	binary.BigEndian.PutUint16(idLen[:], uint16(len(credentialID)))
	buf = append(buf, idLen[:]...)

	buf = append(buf, credentialID...)
	buf = append(buf, publicKeyCOSE...)

	return buf
}
