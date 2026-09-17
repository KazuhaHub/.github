# security-test-suite

A cross-project, black-box security regression suite for the identity code
(SAML, WebAuthn/passkey, OIDC, audit hash chain, rate limiting/XFF) shared
in spirit — but not in code — by three projects:

- **Passwall-Sub-Panel** (`internal/service/auth/{oidc,saml,saml_replay}.go`,
  `internal/service/passkey/`, `internal/service/audit/`)
- **Report-Portal** (`internal/app/{saml,oidc,passkey,audit}.go`)
- **AlertHub** (`server/internal/{sso,passkey,api}/...`)

This is the design document's "阶段 -1" deliverable: see
[`../security-test-suite.md`](../security-test-suite.md) for the full
rationale, the CVE gates, and the report template. It is a **separate Go
module** — it does not, and must not, import any of the three projects'
internal packages. Every test talks to a running instance purely over
HTTP, exactly as an external attacker would.

## Layout

```
go.mod                      independent module, github.com/KazuhaHub/security-test-suite
internal/harness/           shared HTTP plumbing every *_test.go file uses
fixtures/                   TEST ONLY SAML IdP key/cert + metadata, regenerable
reference/safe/             a minimal, CORRECT reference implementation
reference/vulnerable/       the same route shapes, each protection removed on purpose
```

`saml_test.go`, `passkey_test.go`, `audit_test.go`, `oidc_test.go`, and
`ratelimit_test.go` (the actual section-4 test cases) are added on top of
this skeleton in a later pass; this module already builds, vets, and runs
without them.

## Quick start

Run the target-independent smoke path — start a reference stub, point
`SECTEST_BASE_URL` at it, run the suite:

```sh
go run ./reference/safe -addr 127.0.0.1:8080        # in one terminal
SECTEST_BASE_URL=http://127.0.0.1:8080 go test ./...  # in another, once *_test.go files exist
```

Do the same against `./reference/vulnerable` — **every test case must pass
against safe and fail against vulnerable**. A test that passes against
both is not testing anything real and must be rewritten (see the design
doc's self-verification section). This module's `Selfcheck` phase
automates that comparison once the section-4 test files exist.

`SECTEST_BASE_URL` has no default. Unset, every test in this suite skips
with a message telling you what to set — this is the only situation this
suite ever allows a `t.Skip`.

## The two reference stubs

Both are real, runnable HTTP servers (`go run ./reference/safe -addr
127.0.0.1:0` picks a free port and prints it) implementing the identical
route table:

| Route | Behavior under test |
|---|---|
| `POST /saml/acs` | SAML assertion consumer — signature verification, replay, multi-Assertion handling |
| `GET /saml/acs` | HTTP-Redirect binding entry point — deflate-bomb size guard (4.1.6) |
| `POST /webauthn/begin` | Starts a registration or login ceremony |
| `POST /webauthn/finish` | Completes it — challenge replay/expiry/origin/RP ID/user-handle/counter checks |
| `GET /oidc/start` | Begins an OIDC login (redirects to the bundled mock IdP) |
| `GET /oidc/callback` | RP-side validation — state, nonce, alg, aud/iss/exp, code replay |
| `GET /oidc/mock/authorize` | Test-only: the bundled mock IdP's login page (auto-approves) |
| `POST /oidc/mock/override` | Test-only: replace the next id_token a code exchange returns, to forge attack payloads |
| `GET /limited` | Rate-limited endpoint; response body echoes the key it counted the request against |
| `GET /audit`, `POST /audit` | Hash-chain audit log; `GET /audit?verify=1` walks the chain |
| `POST /audit/tamper` | Test-only: simulates a direct-DB edit bypassing the application |

`reference/safe` implements every one of those correctly (using
`crewjam/saml` and `golang-jwt/jwt/v5` where a mature library applies —
see "Library choices" below). `reference/vulnerable` implements the same
shapes with each protection removed; every removal is commented in place
with which 4.x test case it exists to be caught by. Read
`reference/vulnerable/{saml,webauthn,oidc,ratelimit,audit}.go` top to
bottom for the full, numbered list — the short version:

- **SAML**: no signature verification at all; trusts the first
  `<Assertion>` in a multi-assertion Response with no per-assertion
  signature requirement (CVE-2022-41912 shape); ignores
  `NotBefore`/`NotOnOrAfter`; no assertion-ID replay cache; unbounded
  deflate decompression on the Redirect binding (CVE-2023-28119 shape).
- **WebAuthn ceremony**: no single-use enforcement (`finish` replays
  freely); no expiry; origin and RP ID are read but never compared; a
  login ceremony trusts the client-claimed `user_handle` instead of the
  server's own record of the credential's owner; a lower/equal signature
  counter is accepted instead of flagged as a possible cloned
  authenticator.
- **OIDC**: the callback looks a flow up **by authorization code alone**,
  so `state` is never actually required to match anything; the code is
  never invalidated after one use; the id_token's signature, `alg`,
  `aud`, `iss`, `exp`, and `nonce` are never checked — the payload segment
  is decoded and trusted as-is.
- **Rate limiting / XFF**: `X-Forwarded-For` is trusted from *any*
  connecting peer, with no trusted-proxy allowlist.
- **Audit**: plain rows with no chain fields; `?verify=1` unconditionally
  reports `ok:true`, because there is nothing to recompute.

### Library choices

- **SAML**: `github.com/crewjam/saml` v0.5.1 (`ServiceProvider.ParseResponse`)
  handles signature verification, the `Destination` check, and — at this
  version — the multi-Assertion signature-bypass fix (CVE-2022-41912).
  This suite's own version audit (see the design doc) found all three
  target projects already on patched versions of this library, so
  `reference/safe` deliberately reuses it rather than re-implementing
  XML-DSig verification: the assertion-ID **replay cache** and the
  Redirect-binding **decompression size limit** are this suite's own
  additions on top, since `crewjam/saml` intentionally does not provide
  either.
- **OIDC**: `github.com/golang-jwt/jwt/v5`, with `jwt.WithValidMethods`
  pinned to `RS256` — this is what makes `alg=none` (and any other
  algorithm) rejected by construction, not by an ad hoc string check.
- **WebAuthn**: deliberately **no** `go-webauthn/webauthn` dependency, and
  no COSE/CBOR/attestation cryptography at all. Per the design doc's
  version audit, `go-webauthn/webauthn` carries zero open advisories
  across all three target projects — there is nothing to regression-test
  there, and that library's own docs say the ceremony-*session* handling
  (challenge single-use, expiry, origin/RP ID checks, user-handle
  ownership, counter-rollback detection) is entirely the caller's
  responsibility. That is exactly the surface every 4.2 test case probes,
  so `reference/{safe,vulnerable}/webauthn.go` implement a focused
  simulation of just that protocol layer. See the package doc at the top
  of `reference/safe/webauthn.go` for the full reasoning.

## `internal/harness`

Shared, dependency-light HTTP plumbing every `*_test.go` file is expected
to use:

- `harness.MustBaseURL(t) string` — reads `SECTEST_BASE_URL`; the only
  place in this suite allowed to `t.Skip`.
- `harness.NewClient() *http.Client` — timeout set, redirects **not**
  followed (tests routinely need a raw 302's `Location` header).
- `harness.PostForm(url, form) (*http.Response, error)`
- `harness.PostSAMLResponse(acsURL, samlResponseXML, relayState) (*http.Response, error)`
- `harness.GetWithCookies(url, cookies, headers) (*http.Response, error)`
- `harness.PostJSON(url, body, cookies) (*http.Response, error)`
- `harness.DecodeJSON(t, resp, v)`
- `harness.RequireReachable(t, resp, err, what) *http.Response` /
  `harness.AssertRejected(t, resp, err, what)` /
  `harness.AssertAccepted(t, resp, err, what)` — these are the "distinguish
  a rejection from an unreachable target" helpers the design doc calls
  for: a transport error is never silently counted as either a pass or a
  fail, it fails loudly as inconclusive.

## `fixtures/`

`go run ./fixtures` (re)generates, fresh, every time it runs:

- `idp-test-key.pem` / `idp-test-cert.pem` — a 2048-bit RSA key and
  self-signed certificate standing in for a real SAML IdP's signing
  material.
- `idp-metadata.xml` / `sp-metadata.xml` — synthetic SAML metadata
  embedding that certificate, at the `https://idp.example.com/...` /
  `https://sp.example.com/...` identities `reference/safe`'s
  `ServiceProvider` is configured to trust (RFC 2606 reserved domain,
  never a real host).

Every file this program writes carries a **"TEST ONLY — not a real
credential"** banner. Nothing here is derived from, or resembles, any
production secret. When the three consumer projects copy this directory
into their own CI per the design doc's section 5.3, they keep that banner
and add a "copied from / last synced" comment header on top, per the same
section.

## Route alignment with the real projects

The reference stubs' routes are the simplified shapes named in the design
doc; when pointing `SECTEST_BASE_URL` at a real project instead, the
actual paths differ as follows (found by reading each project's route
wiring before writing this module):

| Behavior | reference stub | Passwall-Sub-Panel | AlertHub | Report-Portal |
|---|---|---|---|---|
| SAML ACS | `POST /saml/acs` | `POST /api/auth/saml/acs` | `POST /api/auth/saml/acs` | `POST /api/auth/saml/{slug}/acs` |
| SAML metadata | — | `GET /api/auth/saml/metadata` | `GET /api/auth/saml/metadata` | `GET /api/auth/saml/{slug}/metadata` |
| OIDC callback | `GET /oidc/callback` | `GET /api/auth/oidc/callback` | `GET /api/auth/oidc/callback` | `GET /api/auth/oidc/{slug}/callback` |
| Passkey login begin/finish | `POST /webauthn/begin` `/finish` | `POST /api/auth/passkey/begin` `/finish` | `POST /api/auth/passkey/login/begin` `/finish` | `POST /api/login/passkey/begin` `/finish` |
| Passkey enroll begin/finish | — | `POST /api/user/me/passkeys/begin` `/finish` (session-authenticated) | `POST /api/auth/passkey/register/begin` `/finish` (session-authenticated) | `POST /api/me/passkeys/register/begin` `/finish` (session-authenticated) |
| Audit read | `GET /audit` | `GET /api/admin/audit` (staff-authenticated) | `GET /api/audit` (perm-authenticated) | `GET /api/admin/audit` (perm-authenticated) |
| Audit verify | `GET /audit?verify=1` | *(no hash chain — n/a, see 4.3)* | `GET /api/audit/verify` (super-admin) | *(no hash chain — n/a, see 4.3)* |

Report-Portal's `{slug}` segment identifies a configured SSO provider
(multi-tenant); the reference stub has no equivalent since it only ever
speaks for one. Adapting a section-4 test case to hit a real project is
expected to mean swapping in that project's path and, where the endpoint
is session/permission-gated, first establishing that session — the
reference stubs intentionally leave every route unauthenticated so this
skeleton and the *_test.go files built on it can be developed without
also standing up each project's user/permission model.

## Verifying this skeleton

```sh
go build ./...
go vet ./...
go run ./reference/safe -addr 127.0.0.1:18081 &
curl -s http://127.0.0.1:18081/healthz
```

Both `go build ./...` and `go vet ./...` must be clean, and both
`reference/safe` and `reference/vulnerable` must start and answer
`GET /healthz` with `200 ok`.

## Self-check: proof this suite actually tests something

The design doc's own rule (section "★ 规格里没有、但必须做的：自验证"): a
test case that passes against both `reference/safe` and
`reference/vulnerable` has proven nothing — it is false confidence and
must be rewritten. `selfcheck.sh` (`make selfcheck`) automates the check:

1. Builds `reference/safe` and `reference/vulnerable`.
2. Starts each on an OS-assigned free port (never a hardcoded one — an
   earlier draft of this workflow hardcoded ports and was fooled by a
   stale server left running from a previous session; `net.Listen`'s
   "address already in use" error went to a log file nobody was watching,
   while the old process kept answering requests with dirty in-memory
   state from earlier test runs).
3. Runs the full suite (`go test ./...`) against each, with
   `SECTEST_BASE_URL` pointed at that instance.
4. Prints the table below and exits non-zero if any test case does not
   match its expected pattern.

Two documented exceptions are recognized by name suffix and are *not*
required to discriminate the two stubs:

- `*VersionGate` — a manual "go check the pinned library version" note
  (GHSA-rrfw-hg9m-j47h / GHSA-4hq8-gmxx-h6w9), not an automated exploit.
  Expected: **PASS on both**.
- `*_NeedsWhiteBox` — a documented gap this suite's black-box HTTP surface
  cannot force either reference stub to distinguish yet (see the doc
  comments on `TestAudit_DeletedEntryBreaksChain_NeedsWhiteBox` and
  `TestAudit_AnchorSemantics_NeedsWhiteBox` in `audit_test.go` for the
  full, cited reasoning). Expected: **SKIP on both**.
- `*Gate` (the broader suffix, matched after the more specific
  `*VersionGate` above) — a check that is inherently unable to
  discriminate the two stubs even though it makes a real assertion. The
  one case today is `TestRateLimit_TrustedProxyXFFHonoredGate`
  (`ratelimit_test.go`, design doc 4.5's "正例：可信代理范围内的 XFF 生效"
  row): it needs a target configured to trust the peer address this test
  process connects from — the opposite configuration from
  `SECTEST_BASE_URL` in `TestRateLimit_XFFTrustBoundary`, which must
  *not* trust that peer for its own assertions to mean anything — and
  `reference/vulnerable` trusts X-Forwarded-For from *every* peer
  unconditionally, so it necessarily also satisfies "a trusted peer's XFF
  is honored," trivially. `selfcheck.sh` supplies this via a THIRD
  instance (`reference/safe -trusted-proxies=127.0.0.1/32,::1/128`) and
  `SECTEST_TRUSTED_PROXY_BASE_URL`; see `start_stub`'s third invocation
  there. Expected: **PASS on both**.

Every other test case must **PASS against safe and FAIL against
vulnerable**. Anything else — passes both, fails against safe, or skips
outside a documented gate — is an invalid test and `selfcheck.sh` reports
it as such.

### Latest run (real output, `./selfcheck.sh`, exit 0)

| Test case | safe | vulnerable | Effective? |
|---|---|---|---|
| TestAudit_AnchorSemantics_NeedsWhiteBox | SKIP | SKIP | gate (needs white-box, by design) |
| TestAudit_DeletedEntryBreaksChain_NeedsWhiteBox | SKIP | SKIP | gate (needs white-box, by design) |
| TestAudit_NormalChainThenTamperedMiddleEntryDetected | PASS | FAIL | yes — discriminates |
| TestOIDC_AlgNoneForgedTokenRejected | PASS | FAIL | yes — discriminates |
| TestOIDC_AudienceMismatchRejected | PASS | FAIL | yes — discriminates |
| TestOIDC_AuthorizationCodeReplayRejected | PASS | FAIL | yes — discriminates |
| TestOIDC_ExpiredTokenRejected | PASS | FAIL | yes — discriminates |
| TestOIDC_IssuerMismatchRejected | PASS | FAIL | yes — discriminates |
| TestOIDC_NonceCrossFlowReplayRejected | PASS | FAIL | yes — discriminates |
| TestOIDC_NonceMissingRejected | PASS | FAIL | yes — discriminates |
| TestOIDC_StateMismatchRejected | PASS | FAIL | yes — discriminates |
| TestOIDC_StateMissingRejected | PASS | FAIL | yes — discriminates |
| TestPasskey_CeremonyExpiryRejected | PASS | FAIL | yes — discriminates |
| TestPasskey_ChallengeReplayRejected | PASS | FAIL | yes — discriminates |
| TestPasskey_CounterRollbackRejected | PASS | FAIL | yes — discriminates |
| TestPasskey_OriginMismatchRejected | PASS | FAIL | yes — discriminates |
| TestPasskey_RPIDMismatchRejected | PASS | FAIL | yes — discriminates |
| TestPasskey_UserHandleConfusionRejected | PASS | FAIL | yes — discriminates |
| TestRateLimit_TrustedProxyXFFHonoredGate | PASS | PASS | gate (config-dependent check, by design) |
| TestRateLimit_XFFTrustBoundary (3 subtests) | PASS | FAIL | yes — discriminates |
| TestSAML_ConcurrentReplayOnlyOneSucceeds | PASS | FAIL | yes — discriminates |
| TestSAML_DeflateBombRejected | PASS | FAIL | yes — discriminates |
| TestSAML_GoxmldsigVersionGate | PASS | PASS | gate (manual check, by design) |
| TestSAML_MultipleAssertionsSignatureBypass | PASS | FAIL | yes — discriminates |
| TestSAML_ReplayAfterWindowExpiryStillRejected | PASS | FAIL | yes — discriminates |
| TestSAML_ReplaySameAssertionRejected | PASS | FAIL | yes — discriminates |
| TestSAML_XMLRoundTripVersionGate | PASS | PASS | gate (manual check, by design) |

27 top-level test cases: **22 discriminate** (green on safe, red on
vulnerable, one row per attack area with a failure — 4.1 SAML, 4.2
passkey, 4.3 audit, 4.4 OIDC, 4.5 rate limit all represented), **2 are
documented version-check gates** (informational, pass on both by design),
**1 is a documented config-dependent gate** (pass on both by design — see
above), **2 are documented white-box gates** (skip on both, with a cited
reason — see their doc comments in `audit_test.go`). Zero invalid ("passes
both" outside a documented gate) tests remain.

### A real coverage gap found by review and fixed

An external review of this suite (2026-09-17) found that design doc
section 4.5's first table row — "正例：可信代理范围内的 XFF 生效", the
*positive* case proving a trusted proxy's X-Forwarded-For value actually
takes effect — had no test at all. `ratelimit_test.go` covered only the
negative cases (an untrusted peer's forged header must be ignored), which
is real and correct, but incomplete against the design doc: a target that
rejected X-Forwarded-For unconditionally, from every peer including
correctly configured proxies, would have passed every existing test in
this file while breaking a legitimate deployment. `TestRateLimit_XFFTrust
Boundary`'s own test client can never demonstrate the positive case
either, by design — it deliberately connects from a peer address that is
NOT trusted (see that test's doc comment), which is what makes its
assertions meaningful.

Fixed by adding `TestRateLimit_TrustedProxyXFFHonoredGate`, an optional
test gated on a second environment variable
(`SECTEST_TRUSTED_PROXY_BASE_URL`) that names a target configured to
trust the peer this test process actually connects from — a
configuration `SECTEST_BASE_URL` must not have, for the negative cases to
mean anything. `selfcheck.sh` supplies this automatically by starting a
third `reference/safe` process with `-trusted-proxies=127.0.0.1/32,::1/128`
(see its third `start_stub`-style invocation). When adapting this suite
to a real project, set `SECTEST_TRUSTED_PROXY_BASE_URL` to an instance of
that project configured to trust whatever address the CI runner actually
connects from — if there is no such reachable configuration (e.g. the
real trusted proxy is an internal reverse proxy the test runner cannot
dial directly), leave it unset; the test logs why it is not exercised and
passes, the same as the `*VersionGate` cases, rather than reporting a
false gap.

### An invalid test was caught and fixed during this check

The first `selfcheck.sh` run flagged `TestSAML_GoxmldsigVersionGate` and
`TestSAML_XMLRoundTripVersionGate` as `NO — passes both, tests nothing`.
This was **not** a real gap — both tests are intentionally-informational
version gates (a CVE gate you verify by reading `go.mod`/`go.sum`, not an
automated exploit; see their own log output for the manual-verification
instructions) and were always supposed to pass on both stubs. The bug was
in `selfcheck.sh`'s own classifier: its exemption pattern was
`*_VersionGate` (requiring a literal underscore before the suffix), but
the real test names are `TestSAML_GoxmldsigVersionGate` and
`TestSAML_XMLRoundTripVersionGate` — "VersionGate" appended directly with
no underscore. Fixed by loosening the pattern to `*VersionGate`. No
test file changed; this was purely a false positive in the checker.

A separate, real false-positive was caught and fixed *before* writing
`selfcheck.sh`, during manual verification: an early comparison run
reported `TestAudit_NormalChainThenTamperedMiddleEntryDetected` failing
its own baseline-verifies-clean precondition against `reference/safe`.
The cause was not a bug in the test or in `reference/safe` — it was
leftover state. A `reference/safe` instance from an earlier development
session was still bound to the same fixed port (`127.0.0.1:18091`) this
session reused; the freshly-built instance's `net.Listen` failed with
"address already in use" (logged, but to a file nobody was reading), so
every request actually landed on the *old* process, which still held
audit rows tampered by a previous test run. Killing every stray
`safe`/`vulnerable` process and re-running against a verified-fresh
instance made the baseline pass cleanly. This is exactly why
`selfcheck.sh` asks the OS for a free port (`-addr 127.0.0.1:0`) and reads
the bound address back from the process's own stdout rather than
hardcoding one — see the comment above `start_stub()` in `selfcheck.sh`.

### Running it yourself

```sh
make selfcheck
# or directly:
./selfcheck.sh              # prints the table to stdout, progress/verdict to stderr
./selfcheck.sh --keep-logs   # also leaves the raw `go test -v` logs in the temp workdir
```

Re-run this after touching any `*_test.go` file, any `reference/{safe,vulnerable}/*.go`
file, or `internal/harness/*.go` — a change to any of those is exactly the
kind of change that can silently turn a real test into a dead one.
