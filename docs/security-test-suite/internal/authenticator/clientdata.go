package authenticator

import (
	"encoding/base64"
	"encoding/json"
)

// collectedClientData mirrors the wire shape of WebAuthn's
// CollectedClientData dictionary (§5.8.1) exactly as a real client
// produces it: the fields a Relying Party's clientDataJSON parsing and
// origin/challenge verification depend on. It is intentionally a local,
// minimal type rather than go-webauthn's protocol.CollectedClientData,
// since that type only decodes clientDataJSON — nothing in the upstream
// library encodes one, because a real browser (not this library) is
// always the one producing it.
type collectedClientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

const (
	ceremonyTypeCreate = "webauthn.create"
	ceremonyTypeGet    = "webauthn.get"
)

// buildClientDataJSON serializes clientDataJSON the way a browser's
// WebAuthn client does: challenge is base64url (no padding) encoded, as
// required by §5.8.1.
func buildClientDataJSON(typ string, challenge []byte, origin string, crossOrigin bool) []byte {
	ccd := collectedClientData{
		Type:        typ,
		Challenge:   base64.RawURLEncoding.EncodeToString(challenge),
		Origin:      origin,
		CrossOrigin: crossOrigin,
	}
	// A json.Marshal of a fixed struct with no user-controlled map
	// ordering never fails on these field types.
	b, _ := json.Marshal(ccd)
	return b
}
