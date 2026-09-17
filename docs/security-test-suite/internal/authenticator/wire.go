package authenticator

import (
	"encoding/base64"
	"encoding/json"

	"github.com/go-webauthn/webauthn/protocol"
)

// buildCredentialCreationResponse renders the response body a real client's
// navigator.credentials.create() call resolves to, using go-webauthn's own
// protocol.CredentialCreationResponse type — the exact shape
// protocol.ParseCredentialCreationResponse on the server side decodes —
// so this package's output is byte-for-byte wire compatible without a
// second, parallel JSON schema to keep in sync.
func buildCredentialCreationResponse(credentialID, clientDataJSON, attestationObject []byte) ([]byte, error) {
	resp := protocol.CredentialCreationResponse{
		PublicKeyCredential: protocol.PublicKeyCredential{
			Credential: protocol.Credential{
				ID:   base64.RawURLEncoding.EncodeToString(credentialID),
				Type: string(protocol.PublicKeyCredentialType),
			},
			RawID: protocol.URLEncodedBase64(credentialID),
		},
		AttestationResponse: protocol.AuthenticatorAttestationResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{
				ClientDataJSON: protocol.URLEncodedBase64(clientDataJSON),
			},
			AttestationObject: protocol.URLEncodedBase64(attestationObject),
		},
	}
	return json.Marshal(resp)
}

// buildCredentialAssertionResponse is buildCredentialCreationResponse's
// counterpart for navigator.credentials.get(), using
// protocol.CredentialAssertionResponse.
func buildCredentialAssertionResponse(credentialID, clientDataJSON, authenticatorData, signature, userHandle []byte) ([]byte, error) {
	resp := protocol.CredentialAssertionResponse{
		PublicKeyCredential: protocol.PublicKeyCredential{
			Credential: protocol.Credential{
				ID:   base64.RawURLEncoding.EncodeToString(credentialID),
				Type: string(protocol.PublicKeyCredentialType),
			},
			RawID: protocol.URLEncodedBase64(credentialID),
		},
		AssertionResponse: protocol.AuthenticatorAssertionResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{
				ClientDataJSON: protocol.URLEncodedBase64(clientDataJSON),
			},
			AuthenticatorData: protocol.URLEncodedBase64(authenticatorData),
			Signature:         protocol.URLEncodedBase64(signature),
			UserHandle:        protocol.URLEncodedBase64(userHandle),
		},
	}
	return json.Marshal(resp)
}
