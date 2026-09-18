# Handoff — dependency batch, two security fixes, and the shared-module endgame

**Written 2026-09-17.** Everything below is cross-repository, which is why it lives here rather
than in any one project.

Nothing in this document is merged-and-forgotten state you could recover by reading the code. It is
the decisions, the constraints that only showed up when someone actually ran the builds, and the
things that were **not** verified. Read §1 and §3 before touching anything.

---

## 0. Status after the merge session (added later on 2026‑09‑17)

Everything below this section is the **original handoff, kept unedited as the record of what was
true when it was written.** This section says what has since changed. Where the two disagree, this
one is newer.

### The batch was merged

All seven "open and green" PRs, the whole triaged PSP Dependabot batch, the AlertHub batch,
`authcore#1`/`#2`, and the handoff PR itself are on `main`. All four repositories' `main` builds are
green. Nothing was force-merged, and no required check was bypassed.

- **Report-Portal** — `#12`, `#13`, `#14`, `#15`.
- **AlertHub** — `#18` (the security fix), `#9`, `#12`, `#10`, `#11`, `#13` (actions), `#8`, `#6`,
  `#7`, `#16` (Go/npm deps), `#17`, `#14` (web-admin).
- **Passwall-Sub-Panel** — `#117`, `#106`, `#107`, `#103`, `#104`, `#105`, `#100`, `#102`, `#108`,
  `#109`, `#110`, `#114`, `#116`, `#113`, `#111`, `#115`, plus `#119`.
- **authcore** — `#10`, `#1`, `#2`; `v0.1.0` is tagged.
- `KazuhaHub/.github#3` — this document.

### §3.1's documented path was not executable, and the pair was landed a better way

§3.1 says to merge `#111` and then let Dependabot rebase `#112`. That path cannot be walked through
branch protection: **each half fails its own `web` job**, because `#111` bumps only `vitest` and
`#112` only `@vitest/coverage-v8`, and each leaves the other's exact peer pin unsatisfied. Merging
either one first would have meant force-merging a red PR.

Instead the coverage bump was carried **into `#111`**, making the change atomic. `npm` then resolves
both to 5.0.1 in one step, `npm ci` succeeds, and Dependabot closed `#112` on its own as
"up-to-date now". **`main` never sat in the red state §3.1 predicted.** Verified locally before
pushing: `npm ci`, `npm run build`, and 533/533 vitest across 51 files.

One knock-on effect §3.1 did not record: the `Docker source and release runtime baselines` job also
fails on `#111`/`#112`, because the Dockerfile builds the web bundle. So constraint 1 reddens **two**
required checks, not one.

### `#115` landed, with a prerequisite it needed first

`§4.3` was right that the three generated files had to be untracked first, and that `"types":
["node"]` was needed. Both are done: `#119` untracked
`web-react/vite.config.{js,d.ts}` and `tsconfig.node.tsbuildinfo` (verified nothing referenced them,
and that a build regenerates all three and leaves the tree clean), then `#115` added
`"types": ["node"]`. Confirmed by reproducing the 9 `capabilities.test.ts` errors first, then
watching them clear.

**Still not done, and §4.3 is right to flag it:** `"types": ["node"]` puts Node globals in scope for
browser code, so a stray `process.env` in a component now typechecks and fails at runtime. The clean
shape is a separate tsconfig for `*.test.ts(x)`. Also still open: the PR widens the range to
`^7.0.2`, so future 7.x minors are accepted automatically — consider pinning.

### `#101` and `#112` were closed by Dependabot, correctly

Both groups became redundant once their members landed individually. `#101`'s updates are visibly
present in `main`'s `go.mod` (`x/crypto 0.57.0`, `x/text 0.42.0`, `oidc 3.21.0`, `webauthn 0.18.1`,
`saml 0.5.1`). Nothing was lost.

### Two things that needed a code change the original plan did not name

- **AlertHub `#14` and `#17` were not mergeable as bumps.** `server/internal/webadmin/dist/index.html`
  is committed while `dist/assets/` is gitignored, so the Go jobs embed the committed index against
  assets CI builds fresh. Changing a runtime dependency changes the bundle, and the committed index
  named chunks the build no longer emitted —
  `TestCachePolicy_HashedAssetsAreImmutable` failed with `GET /admin/assets/index-BVPgLNKy.js = 404`.
  Regenerating the index is the intended maintenance step (CI's own comment says so). Determinism was
  checked before trusting a local build: rebuilding `main` on Node 26/darwin-arm64 reproduced the
  committed `index.html`, `favicon.svg` and `icons.svg` **byte for byte**, so a local regeneration is
  CI's output on Node 22/linux-x64.
- **`authcore#1`/`#2` were red on a stale base**, not on the action bumps: both failed the same
  `captcha` test they do not touch, inherited from the initial commit. A rebase fixed both. The
  verdict recorded in the first triage was right.

### The Report-Portal commit trailers were corrected by rewriting `main`

Report-Portal's `CLAUDE.md` forbids `Co-Authored-By` trailers. Four commits merged that session
carried one, inherited from PR bodies. `main` was rewritten to strip only those trailers and the
tree came out **byte-identical** (`894bd67e…` before and after), then `main` was force-pushed with
the ruleset and classic protection lifted for the push and restored immediately afterwards.

The local clone was realigned with `git reset --hard origin/main` afterwards, because a rewritten
base makes a plain `git pull` create a merge. **Anyone with another clone of that repository should
re-clone or hard-reset rather than pull.**

### Report-Portal now has Dependabot, and it flushed a backlog

Merging `#14` added `.github/dependabot.yml` to a repository that had none, so Dependabot immediately
opened 9 catch-up PRs (`#16`–`#24`). The config is already tuned (weekly, grouped,
`open-pull-requests-limit: 10`), so this is a one-time backlog flush rather than an ongoing rate. The
owner closed those 9 by hand.

### Still open

- **`Passwall-Sub-Panel#99`** — deferred by decision (§1) until Node 26 is LTS.
- **`AlertHub#15`** — genuinely blocked, and it is not a mechanical fix. `npm ci` fails because
  `i18next@26.3.1` declares `peerOptional typescript@"^5 || ^6"` and the PR installs TypeScript
  7.0.2. It needs an i18next release that widens the range, or a deliberate decision to override.
- **New Dependabot PRs** appeared after the batch: `Passwall-Sub-Panel#118`, `AlertHub#19`. Not
  triaged.
- **`authcore#11`** — ADR 0003, proposing to remove `ratelimit` and extract `clientip`. **Proposed,
  not decided.**
- **`§6` is still the list of what is not verified.** Nothing in this section changes it. In
  particular no Docker build was run, no passkey ceremony was performed end to end, and no signed
  SAML assertion was exercised — `#102` and `#113` are now both on `main`, so the manual
  *register → passwordless login → passkey second factor* pass §6.5 asks for is now possible and has
  still not been done.

---

These came from the repository owner on 2026-09-17. They are not derivable from the code.

| Question | Decision |
|---|---|
| **PSP #99** — Docker base image `node:24-alpine` → `26-alpine` | **Defer.** Node 26 is `lts: false`; v24 "Krypton" is Active LTS and v26 is scheduled to become LTS in 2026‑10. Revisit then, and when you do, change the four `node-version: "24"` pins in `test.yml` and `release.yml` in the *same* PR. |
| **PSP #100** — Docker base image Go 1.26.8 → 1.27.1 | **Merge, together with a `go.mod` `toolchain` bump.** See §4.2 — merging #100 alone breaks two things. |
| **PSP #115** — TypeScript 5.9.3 → 7.0.2 | **Last in the batch, and only after the generated files are untracked.** See §4.3. |
| Merge execution | **Not done in this session.** Handed off deliberately; see §2 for exactly what is open. |

---

## 2. Where each repository stands

### Merged on 2026‑09‑17

| PR | What |
|---|---|
| `Passwall-Sub-Panel#97` | goxmldsig → v1.6.1, per-IP limiter added to `/api/auth/saml/acs`, regression test |
| `Passwall-Sub-Panel#98` | Dependabot version updates (this is what produced #99–#116) |
| `AlertHub#2` | goxmldsig → v1.6.1 |
| `AlertHub#3` | Dependabot version updates (produced #5–#17) |
| `AlertHub#4` | Restored a green build on `main`, red since 2026‑08‑16 |

### Open and green, waiting only on a decision to merge

| PR | What | Checks |
|---|---|---|
| `StockAnalysisPrediction-Report-Portal#12` | **SAML moved onto `authcore/saml`** — the last shared-module migration | 10/10 |
| `StockAnalysisPrediction-Report-Portal#13` | npm advisories cleared in `web/` | 12/12 |
| `StockAnalysisPrediction-Report-Portal#14` | Dependabot version updates | 12/12 |
| `StockAnalysisPrediction-Report-Portal#15` | **Forwarded-for walk ends at an unparseable hop** (§5.2) | green |
| `AlertHub#18` | **Rate limiter keys on the real client behind a proxy** (§5.1) | 5/5 |
| `authcore#10` | The `saml` measurement written into `FRICTION.md` | 2/2 |
| `Passwall-Sub-Panel#117` | Setup-action guards accept a newer major — **prerequisite for #108/#109** | pending at handoff |

### Open Dependabot batches

- **`Passwall-Sub-Panel#99`–`#116`** — 18 PRs, fully triaged. §3 and §4.
- **`AlertHub#5`–`#17`** — 13 PRs, **not triaged**. §7.
- **`authcore#1`, `#2`** — two action bumps, not triaged.

---

## 3. Constraints that only appeared when the builds were actually run

Each of these was reproduced. None is visible from a changelog.

### 3.1 `Passwall-Sub-Panel#111` and `#112` must land in the same batch — but cannot be merged back to back

`@vitest/coverage-v8@5.0.1` pins its peer to **exactly** `vitest: 5.0.1`. Checking out either PR
alone and running `npm ci` fails with `ERESOLVE`, and the `web` job's **first step is `npm ci`** —
so merging either one alone turns `main` red immediately.

They also cannot be merged one after the other: `git merge pr-111` fast-forwards cleanly, then
`git merge pr-112` conflicts in `package-lock.json`.

**The path that works:** merge #111 → let Dependabot rebase #112 and regenerate the lock → merge
#112, **with no other push in between**. Do not hand-edit the lock.

Note the resolved version is **5.0.1**, not the 5.0.0 in the PR titles.

### 3.2 `Passwall-Sub-Panel#102` does not compile, and its fix cannot land first

go-webauthn 0.18.1 requires a custom `LoginOption` to return an `error`
(upstream `MIGRATION.md` §1.2). As-is the PR fails with:

```
internal/service/passkey/passkey.go:279:55: cannot use requireUV ... as webauthn.LoginOption
```

The one-line fix is at `internal/service/passkey/passkey.go:276`. **It must go in with #102, not
before it** — under the current 0.17.4 the `LoginOption` signature takes no error, so landing the
fix on `main` first breaks the build.

### 3.3 `Passwall-Sub-Panel#100` is not a one-line `FROM` change

`go.mod`'s `toolchain go1.26.8` is the single source of truth, and `internal/version/build_baseline_test.go`
enforces that the Dockerfile agrees with it. Merging #100 alone breaks **both** that test and
`docker build` (the Dockerfile sets `GOTOOLCHAIN=local`, so there is no automatic switch to rescue
it).

**No PR in #99–#116 bumps `go.mod`.** Whoever merges #100 writes that change.

### 3.4 Go PRs are strictly serial

`#101`, `#102`, `#103`, `#104`, `#105` all rewrite `go.mod`/`go.sum` in the same
`golang.org/x/*` region. Measured conflicts: #103 × #105 (adjacent `require` lines), and #101 ×
#102 × #104 among themselves (`x/crypto` 0.55 vs 0.57, `x/oauth2` 0.36 vs 0.37, `x/sys` 0.47 vs
0.48, `x/text` 0.41 vs 0.42, mysql 1.10.0 vs 1.10.1). Every merge forces the rest to rebase —
Dependabot does it, at the cost of one CI round each.

### 3.5 `#107` conflicts with `#109`

`compat-watch.yml`, `node-reinstall-acceptance.yml` and `test.yml`, purely because
`- uses: actions/checkout@v6` sits directly above `- uses: actions/setup-go@v6`. Mechanical to
resolve (keep v7 on both); #109 needs a Dependabot rebase after #107.

### 3.6 `#108` and `#109` are blocked until `#117` lands

Both guards pinned the setup actions to exactly v6. Merging **one** of #108/#109 leaves the `.mjs`
guard passing while it silently inspects less than it claims (`pass 8, fail 1`, caught only by the
meta-test); merging **both** degrades it to a hard `require publisher setup actions` failure.
`Passwall-Sub-Panel#117` fixes both guards to accept a newer major while still rejecting v5.

---

## 4. Merge plan for `Passwall-Sub-Panel#99`–`#116`

Triage outcome: **12 safe, 3 need code changes, 3 needed a human decision** (all three now decided,
§1).

### 4.1 Order

```
prerequisite   #117                     (guards; already open, independent)

batch A        #106 → #107              GitHub Actions; orthogonal to everything else
batch B        #103 → #105 → #104 → #101 → #102(+source fix)      strictly serial, see §3.4
batch C        #110 → #114 → #116 → #113 → (#111 then #112)       see §3.1
batch D        #108 → #109              only after #117; #109 rebases after #107

deferred       #99                      until Node 26 is LTS (§1)
separate       #100                     with the go.mod toolchain bump (§4.2)
last           #115                     after §4.3
```

Why these positions:

- **#106 first in batch A** — `upload-artifact@v4` is the repository's last `node20` action, so
  #106 is the one that actually clears the Node 20 deprecation warnings.
- **#103 leads batch B** — it is the only PR with a real API-surface story (`ServiceProvider.Key`
  becomes `crypto.Signer`, `ParseXMLResponse` gains a parameter, Destination validation relaxed).
  Give it its own CI round.
- **#104 before #102** — #104's contents are a strict subset of #102's. Merging #104 first shrinks
  #102, after rebase, to the webauthn change alone. Reversed, #104 becomes an empty PR.
- **#101 fourth** — despite the "minor-and-patch" name it carries **SQLite 3.51.2 → 3.53.3**
  through the modernc chain. Land it once the others are stable so a regression is easy to locate.
- **#110 first in batch C** — #110–#116 all rewrite `web-react/package-lock.json`; whichever lands
  first forces the rest to rebase. #110 is the cheapest one to put first.
- **#116 before #111/#112, with a caveat** — jsdom 30 was verified on vitest 4, and vitest 5 was
  verified on jsdom 29. **The jsdom 30 × vitest 5 combination has never been run.** Re-run #111/#112's
  CI once #116 is on `main`.

### 4.2 `#100` — the Go 1.27 adoption (decided: do it)

Merge #100 **and** change `go.mod`'s `toolchain go1.26.8` → `go1.27.1` in the same merge. Verified:
that combination gives `go test ./internal/version/...` → `ok` and all 72 packages green. Go 1.27's
language changes are additions only, under the Go 1 compatibility promise.

Side effects to accept knowingly: CI runners must be able to fetch 1.27, and this is a deliberate
toolchain adoption rather than a mechanical base-image follow.

### 4.3 `#115` — TypeScript 7 (decided: last, after untracking generated files)

Two separate problems.

**First, a clean prerequisite.** TS 7 changes the default for `types` from `["*"]` to `[]`, so
`@types/node` is no longer implicitly loaded and `src/utils/capabilities.test.ts` reports 9 errors.
Adding `"types": ["node"]` to `web-react/tsconfig.json` fixes it, is the migration Microsoft
documents, and is verified clean under **both** 5.9.3 and 7.0.2 — so it can land ahead of time.

**Second, the actual reason for deferring.** TS 7's default `target` moves from ES5 to latest.
`tsconfig.node.json` sets no `target` and is a `composite` project that **emits**. After #115,
anyone running `npm run build` silently modifies three git-tracked files —
`web-react/vite.config.js`, `vite.config.d.ts`, `tsconfig.node.tsbuildinfo` — and Vite's resolution
order means the **generated `vite.config.js` is the one actually loaded**. CI has no dirty-tree
check, so this drifts unnoticed.

The decided fix is to untrack those three generated files (remove from git, add to `.gitignore`)
before #115. Confirm nothing else depends on the committed `vite.config.js` first.

Two further notes when you get there: the PR widens the range to `^7.0.2`, so future 7.x minors are
accepted automatically — consider pinning. And `"types": ["node"]` on the app project pulls Node
globals into browser-code scope, so a stray `process.env` in a component would type-check and then
fail at runtime; the clean shape is a separate tsconfig for `*.test.ts(x)`. **Neither was done.**

---

## 5. The two security fixes open right now

### 5.1 `AlertHub#18` — the rate limiter inverted into a lockout lever

`SECURITY.md:47` tells operators to terminate TLS at a reverse proxy. `docs/API.md:58` promises the
five credential endpoints share a limiter of **10 per minute per IP**. `clientIP()` read only
`r.RemoteAddr`, so behind that proxy every request shared one address and the limit collapsed to
**10 per minute in total**.

That is not a weakened defence, it is an inverted one: one attacker spending the shared budget locks
**every other user** out of `/api/auth/login`, `/api/auth/2fa/verify`,
`/api/auth/passkey/login/finish`, `/api/auth/oidc/exchange` and `/api/auth/saml/acs`.

Proven before any fix was written — this failed on `main`:

```
--- FAIL: TestRateLimit_BehindReverseProxy_KeepsPerClientBudgets
    a second client was locked out by the first client's attempts
```

The existing `TestRateLimit_LoginReturns429` could not catch it; its own comment explains why —
*"httptest requests share a fixed RemoteAddr"* — it runs entirely inside the collapsed case.

Same root cause hit the audit trail: `clientIP()` is also used by `audit.go:58` and `:129`, so every
entry recorded the proxy address.

**`ALERTHUB_TRUSTED_PROXIES` now defaults to `loopback`, which is a behaviour change.** `none`
restores the old behaviour exactly. The zero value of `TrustedProxies` is also the old behaviour, so
embedders that do not set it are unaffected.

### 5.2 `StockAnalysisPrediction-Report-Portal#15` — forwarded-for walk stepped over an unparseable hop

`clientIP` skipped a hop that failed to parse (`continue`) and carried on into addresses nobody had
vouched for. Reaching that state means the request came from **inside** `trusted_proxies` — which
this project's own `docker-compose.yml:88` suggests setting to `172.16.0.0/12`, a whole Docker
network. Probed against the real function:

```
X-Forwarded-For: 9.9.9.9, garbage, 10.0.0.5   →   clientIP = "9.9.9.9"
```

Narrow, not remotely reachable, one keyword to close.

---

## 6. What was NOT verified — do not read these as passing

1. **`docker build` was never run.** No Docker on the machine. #99/#100 image existence was checked
   through the Docker Hub API; the in-Dockerfile guard failures are reasoned from source and
   `GOTOOLCHAIN=local` semantics, not executed.
2. **musl/linux rolldown native bindings were never executed.** They resolve in the lock, but #99
   was exercised on darwin/arm64.
3. **`npm run smoke:dist` could not run locally** — no Chrome/Chromium. Counts as *not verified*,
   not as passing.
4. **All web units were run on Node v26.3.1 locally; CI runs Node 24.**
5. **No passkey ceremony was run end to end** — no fixtures, no real authenticator. #102's
   migration-guide items §2.4/§2.5/§2.9 are reasoned, not measured. #102 and #113 are the server and
   browser halves of the same path: after both land, do one manual *register → passwordless login →
   passkey second factor* pass.
6. **No signed SAML assertion was exercised end to end.** #103's probes deliberately stop short of
   minting one. After it lands, do a smoke login against a real Entra tenant and check the NameID/UPN
   claim — a behaviour this repository has had silently break before.
7. **jsdom 30 × vitest 5 was never run** (§4.1).
8. **`#111`/`#112` were measured at 5.0.1, not the 5.0.0 in the titles.**
9. **`#109`'s `sqlite (full suite, race)` failure was reproduced locally**, not observed in CI —
   CI had not reached that job.

One more, from #102: `rpFromBaseURL` takes `u.Hostname()` from `SubBaseURL` without validating it.
Under 0.18.1 a bare IP, a bracketed IPv6 literal, or a trailing-dot host makes `webauthn.New` error
outright, where 0.17.4 returned nil and let the browser reject it. Not a regression for any working
deployment — browsers never accepted an IP as RP ID — but the failure moves from browser to server
and the message changes. A self-hoster putting a bare IP in the base URL is plausible.

---

## 7. Not started

- **`AlertHub#5`–`#17` (13 Dependabot PRs) have not been triaged at all.** Two things to know before
  someone does: **#9 bumps `actions/download-artifact` 4 → 8**, which is the action `AlertHub#4`
  introduced for the SPA-assets artifact — checked, and safe, because the download steps use `name:`
  rather than `artifact-ids:` (v5's breaking change is ID-only) and v7's `if-no-files-found` and
  `retention-days` inputs still exist. **#9 and #12 should move together** to keep the upload and
  download halves aligned.
- **`authcore#1`, `#2`** — untriaged action bumps.
- **`authcore` has never been tagged.** Six measurement data points are in; `v0.1.0` is a reasonable
  moment, and `authcore#10` is the record that closes the series.

---

## 8. The open architectural question: `ratelimit` → `clientip`

A read-only preflight (no code written) concluded **MIGRATE**, with AlertHub first, on the strength
of exactly one argument: AlertHub had a live X-Forwarded-For defect that a shared library would fix.

**`AlertHub#18` then fixed that defect directly, so that argument is spent.** But the picture it
leaves behind is sharper, and this is the part worth picking up:

| | Implementation | Has | Lacks |
|---|---|---|---|
| Report-Portal | own, `throttle.go` | **notices misconfiguration** (`proxySeen`), fatals on a bad config | skipped unparseable hops (fixed in #15) |
| Passwall-Sub-Panel | gin `SetTrustedProxies` | also honours `CF-Connecting-IP`, `X-Real-IP` | no misconfiguration detection |
| AlertHub | own, added in #18 | unparseable hop ends the chain | no misconfiguration detection |
| `authcore/ratelimit` | delegates to chi | — | **zero consumers** |

Four implementations of the same security-critical logic, and they **diverge on adversarial input**
— measured, not argued (§5.2).

The proposal, which the owner has **not** yet decided on:

> The shareable unit is *client-IP resolution behind a proxy, plus misconfiguration detection* —
> not the rate limiter. The bug fixed in AlertHub was a client-IP bug; the limiter itself was fine.
> Report-Portal's `proxySeen` is the one thing that would have surfaced AlertHub's defect early, and
> the other two do not have it. `authcore/ratelimit` bundles the valuable half with the half nobody
> uses.
>
> So: **delete `ratelimit`** (following the `audit` precedent — zero consumers, designed without
> reading any consumer's code, production source unchanged since the day it landed) and extract a
> focused **`authcore/clientip`** instead.

If that is taken up, write the exit criteria into an ADR at the same time. The preflight's were: if
the migrated consumer still cannot bucket by real client IP behind a proxy, delete; and if only one
service ends up adopting it, it is not a shared package, it is private code in the wrong repository.

Corroboration worth keeping: Report-Portal's `parseTrustedProxies(nil)` already defaults to
loopback — `TestUnsetTrustsLoopbackOnly`, whose comment reads *"Loopback is the default the sibling
panel uses"*. AlertHub's new default in #18 was chosen independently and landed on the same answer.

---

## 9. Problems in the repositories themselves, found in passing

Both will redden unrelated PRs and invite reviewers to blame a dependency. **Neither was changed** —
out of scope for the batch.

1. **`Passwall-Sub-Panel` — `TestLinuxMigrationStubRuntime` flakes under load.**
   `internal/pkg/nodebootstrap/bootstrap_runtime_test.go:183` wraps a real `bash` subprocess in a
   hardcoded `context.WithTimeout(context.Background(), 30*time.Second)`. A different subtest fails each time, always
   at 30–48s, always as `success=false, want true` rather than an assertion mismatch. It cannot be
   dependency-related: `go list -deps -test` shows the binary links only stdlib, `internal/domain`
   and `passwall-node/deployment`. Reproducible at load average 87, passes at 25–28. Six separate
   triage units each hit it and each investigated it independently.

2. **`Passwall-Sub-Panel` — the web suite's default 5s `testTimeout` flakes systematically.**
   `web-react/vitest.config.ts` leaves it at 5s while individual tests in `ServersView`,
   `SettingsView` and `NodeIssues` routinely take 3–10s under CPU pressure. On **unmodified `main`**
   this produces anywhere from 33/533 to 146/533 failures. Every web triage unit had to re-run with
   `--testTimeout=60000` to get a signal. Related: `ServersView.updates.test.tsx` failed once in CI
   on `Passwall-Sub-Panel#97` and passed 8/8 locally in isolation; a rerun was green.

---

## 10. Where the evidence is

- `authcore/FRICTION.md` — per-migration friction reports, including the `saml` entry and its
  retracted claims. `docs/adr/0001` and `0002` hold the scope rule and the reason `audit` was
  deleted.
- `StockAnalysisPrediction-Report-Portal/docs/adr/0023-sso-saml-oidc.md` — the portal's SSO design.
- Each PR body carries its own measurements; the security ones carry the failing-test output from
  before the fix.

---

## 11. How this work was done — conventions worth keeping

These are not house style for its own sake. Each one is here because ignoring it cost something
during this batch.

### 11.1 Method

- **Reproduce before claiming.** Every defect in §5 was demonstrated with a failing test *before* a
  fix was written, and every "this upstream change does not affect us" was checked against the
  source rather than the changelog. Two conclusions flipped under that rule: the `goxmldsig`
  advisory turned out to be invisible to both scanners, and `ratelimit`'s only argument for
  existing evaporated once the defect behind it was fixed directly.
- **A test that cannot fail is not a test.** Every fix here was verified by breaking it again and
  confirming the test goes red — in both directions where the mistake has two sides. `AlertHub#18`
  has four tests: three fail if `ClientIP` stops honouring the header, one fails if it starts
  honouring it from an untrusted peer. A guard that only catches under-trusting would have let the
  more dangerous mistake through.
- **Check the data layer before writing migration code.** This is the `audit` lesson: AlertHub's
  `canonicalAudit` hashes `OrgID` as its second field while `authcore/audit.Event` forbids tenant
  fields, so no amount of adapter code could have bridged it. Finding that in a read-only preflight
  saved a wasted migration. §8's preflight followed the same shape.
- **Do not take a subagent's report at face value.** Earlier in this project a subagent reported
  writing 508 lines across 8 sections; the file on disk had 111 lines and no code. In this batch a
  triage report named two sites for a hardcoded timeout and there is only one (§9.1), and the
  `saml` migration report claimed a TTL clamp was "carried over unchanged" when it moved from
  `now+34min` to `now+30min`. Verify load-bearing numbers yourself.
- **Record retractions, do not delete them.** `authcore/FRICTION.md` keeps a P0 that turned out to
  be wrong, with the measurement that disproved it, because the reasoning behind the mistake is
  worth more than a clean document.

### 11.2 Conventions

- Comments and identifiers in **English**. No AI attribution inside source files.
- Branch names must not contain `claude` or `codex`.
- Commit messages end with `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`;
  PR descriptions end with `🤖 Generated with [Claude Code](https://claude.com/claude-code)`.
- **Do not merge without being asked.** Everything in §2 is deliberately left open.
- **Workflow subagents run on Sonnet.** Pass `model: 'sonnet'` on every `agent()` call — omitting it
  inherits the session model, which is how two workflows in this batch ran on Opus by accident. Do
  not kill a running workflow to correct this: resume caches on `(prompt, opts)`, so adding `model`
  re-runs every agent and loses the finished ones.

### 11.3 Environment traps that cost time here

- **The shell is zsh, not bash.** Unquoted parameters do **not** word-split, so `for r in $repos`
  silently iterates once — use `repos=(a b c)` and `"${repos[@]}"`. Glob characters must be quoted:
  `--include='*.go'` and `"…/commits?per_page=1"`, or zsh fails with `no matches found`.
- **Every Go command needs `GOWORK=off`.**
- **`git stash` on a clean tree creates nothing**, so a paired `git stash pop` pops whatever was
  already on the stack — someone else's work. This happened once here, against
  `Passwall-Sub-Panel`. **That repository currently holds two of the owner's own stashes**
  (`codex: CI race change before main sync`, `codex: PSP Node docs before main sync`). Leave them
  alone; check `git stash list` before any pop.
- **Test durations to plan around:** Report-Portal's `internal/app` takes 140–210s. Passwall-Sub-Panel's
  web suite needs `--testTimeout=60000` (and often `--maxWorkers`) before its results mean anything
  — see §9.2.
- Repositories: `~/Codes/Passwall-Sub-Panel`, `~/Codes/StockAnalysisPrediction-Report-Portal`,
  `~/Codes/AlertHub`, `~/Codes/authcore`, `~/Codes/kazuhahub-github` (this one, `KazuhaHub/.github`).

### 11.4 `authcore`'s design rules

Breaking these is what turns a shared library into a distributed monolith. From
`docs/adr/0001-scope-of-authcore.md`:

- **Share mechanism, not policy.** No `User`, `Account`, `Tenant`, `Org`, `Role` or `Principal`
  types. A caller that needs a tenant supplies an opaque key.
- **No web framework types** (`gin.`, `echo.`, `fiber.`) in any public signature.
- **No cross-package imports inside the library.** `passkey` does not import `saml`.
- Import aliases only on a real collision — when the consuming file's own package name matches the
  authcore package — and then prefixed, e.g. `authcoregeoip`.
- A package earns its place by taking over a **nameable class of mistake**, not by line count.
  `audit` was deleted at +195 lines because it transferred nothing; `passkey` was kept at +181
  because it moved the responsibility for getting ceremony orchestration right.
