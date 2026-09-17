package authenticator

// ceremonyConfig collects the attack/behavior toggles applied to a single
// Register or Authenticate call. Every field is a deliberate deviation from
// what an honest client/authenticator would do; the zero value always
// means "behave honestly, using the corresponding RegistrationInput or
// AssertionInput field".
type ceremonyConfig struct {
	rpidOverride       *string
	originOverride     *string
	challengeOverride  []byte
	counter            *uint32
	userPresent        *bool
	userVerified       *bool
	userHandleOverride []byte
	corruptSignature   bool
	aaguidOverride     *[16]byte
}

// Option is a functional attack/behavior toggle for Register or
// Authenticate. Options not meaningful for a given ceremony (e.g.
// WithUserHandle during Register, which has no userHandle field on the
// wire) are silently ignored rather than rejected, so a test can share one
// option list shape across both calls where convenient.
type Option func(*ceremonyConfig)

// WithRPID overrides the RP ID whose SHA-256 hash is embedded as
// authData.rpIdHash, independent of the RPID the ceremony's begin step
// actually declared. Use this to simulate a client/authenticator that
// signed for the wrong relying party.
func WithRPID(rpid string) Option {
	return func(c *ceremonyConfig) { c.rpidOverride = &rpid }
}

// WithOrigin overrides the origin embedded in clientDataJSON, independent
// of the origin the ceremony was actually begun for.
func WithOrigin(origin string) Option {
	return func(c *ceremonyConfig) { c.originOverride = &origin }
}

// WithChallenge overrides the (raw, not base64url-encoded) challenge bytes
// embedded in clientDataJSON, instead of the one carried in the
// RegistrationInput/AssertionInput this call was given — e.g. to replay a
// stale challenge from an earlier, already-answered ceremony.
func WithChallenge(raw []byte) Option {
	cp := append([]byte(nil), raw...)
	return func(c *ceremonyConfig) { c.challengeOverride = cp }
}

// WithCounter sets the authData signature counter to an explicit value,
// including one at or below this authenticator's own last-used counter for
// the credential — the standard signal of a cloned authenticator.
func WithCounter(n uint32) Option {
	return func(c *ceremonyConfig) { c.counter = &n }
}

// WithUserPresent forges the UP (user present) flag. WebAuthn makes this
// flag self-asserted by the authenticator; forging it demonstrates that no
// cryptographic check alone can catch a lying (or compromised) client —
// only an RP-side presence/verification policy can.
func WithUserPresent(present bool) Option {
	return func(c *ceremonyConfig) { c.userPresent = &present }
}

// WithUserVerified forges the UV (user verified) flag, for the same reason
// WithUserPresent forges UP.
func WithUserVerified(verified bool) Option {
	return func(c *ceremonyConfig) { c.userVerified = &verified }
}

// WithUserHandle overrides the userHandle an assertion response reports,
// independent of the handle this authenticator actually recorded for the
// credential at registration — simulating a client that claims to be a
// different account than the one the credential belongs to.
func WithUserHandle(handle []byte) Option {
	cp := append([]byte(nil), handle...)
	return func(c *ceremonyConfig) { c.userHandleOverride = cp }
}

// WithCorruptSignature flips the final byte of the ECDSA assertion
// signature after it is computed, producing a syntactically well-formed
// but cryptographically invalid signature. Only a target that has stopped
// verifying assertion signatures altogether accepts the result.
func WithCorruptSignature() Option {
	return func(c *ceremonyConfig) { c.corruptSignature = true }
}

// WithAAGUID overrides the authenticator model identifier a registration's
// attested credential data reports, independent of this Authenticator
// instance's own AAGUID.
func WithAAGUID(id [16]byte) Option {
	return func(c *ceremonyConfig) { c.aaguidOverride = &id }
}

func newCeremonyConfig(opts []Option) *ceremonyConfig {
	c := &ceremonyConfig{}
	for _, opt := range opts {
		opt(c)
	}
	return c
}
