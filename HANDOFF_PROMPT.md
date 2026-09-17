# Handoff prompt

Paste the block below into a fresh session to pick this work up. It is written to stand on its own:
it names the state, the traps, and the one thing not to do, and it points at `HANDOFF.md` for
everything else.

---

```
You are taking over a cross-repository batch of dependency and security work in the KazuhaHub
organisation. The previous session stopped deliberately, with everything staged and nothing merged.

START HERE: read HANDOFF.md at the root of KazuhaHub/.github (locally ~/Codes/kazuhahub-github).
It is the source of truth for state, decisions and constraints. Read §1 (decisions already made),
§3 (constraints that only appear when the builds are actually run) and §6 (what was NOT verified)
before touching anything. §11 has the working conventions and the environment traps.

The five repositories, all cloned locally:
  ~/Codes/Passwall-Sub-Panel                      (PSP)
  ~/Codes/StockAnalysisPrediction-Report-Portal   (Report-Portal / RP)
  ~/Codes/AlertHub
  ~/Codes/authcore                                (the shared identity library)
  ~/Codes/kazuhahub-github                        (KazuhaHub/.github — org docs, HANDOFF.md)

WHERE THINGS STAND

Seven PRs are open, green, and waiting only on a decision to merge:
  Report-Portal#12  SAML moved onto authcore/saml — the last shared-module migration
  Report-Portal#13  npm advisories cleared in web/
  Report-Portal#14  Dependabot version updates
  Report-Portal#15  security: forwarded-for walk ends at an unparseable hop
  AlertHub#18       security: rate limiter keys on the real client behind a proxy
  authcore#10       the saml measurement written into FRICTION.md
  PSP#117           setup-action guards accept a newer major (prerequisite for PSP#108/#109)

Three Dependabot batches are open:
  PSP#99–#116    18 PRs, fully triaged. Merge plan and order in HANDOFF.md §4.
  AlertHub#5–#17 13 PRs, NOT triaged. See §7 — #9 and #12 should move together.
  authcore#1, #2 two action bumps, not triaged.

DO NOT MERGE, PUSH TO main, OR CLOSE ANY PR WITHOUT BEING ASKED. The owner chose to hand this off
rather than have it merged. Ask before the first merge, then follow whatever scope they give.

THE THREE CONSTRAINTS THAT WILL BITE YOU (each reproduced, none visible from a changelog)

1. PSP#111 and #112 must land in the same batch but cannot be merged back to back.
   @vitest/coverage-v8@5.0.1 pins its peer to exactly vitest 5.0.1, and the web job's first step is
   `npm ci`, so merging either alone turns main red. Merging them in sequence conflicts in the lock.
   Working path: merge #111, let Dependabot rebase #112 and regenerate the lock, then merge #112,
   with no other push in between. Do not hand-edit the lock.

2. PSP#102 does not compile as-is, and its fix cannot land first.
   go-webauthn 0.18.1 needs the custom LoginOption to return an error; that signature does not exist
   under the current 0.17.4, so putting the fix on main ahead of the bump breaks the build. The fix
   is one line at internal/service/passkey/passkey.go:276 and must go in WITH #102.

3. PSP#100 is not a one-line FROM change.
   go.mod's `toolchain go1.26.8` is the single source of truth and no PR in the batch moves it.
   Merging #100 alone breaks both internal/version's guard and `docker build`. The owner has decided
   to adopt Go 1.27 — so whoever merges #100 also writes the go.mod bump to go1.27.1.

DECISIONS ALREADY MADE — do not re-open these
  PSP#99  (Node 26): deferred until Node 26 is LTS, expected 2026-10. When you do it, change the
          four `node-version: "24"` pins in the same PR.
  PSP#100 (Go 1.27): merge, together with the go.mod toolchain bump.
  PSP#115 (TypeScript 7): last in the batch, and only after web-react/vite.config.js,
          vite.config.d.ts and tsconfig.node.tsbuildinfo are untracked from git. Details in §4.3.

HOW TO WORK

- Reproduce before you claim. Do not take a changelog's or a subagent's word for anything
  load-bearing — in this batch a triage report named two sites for a timeout that exists at one, and
  a migration report described a TTL clamp as unchanged when it had moved by four minutes.
- Verify every test you write by breaking the fix and confirming it goes red. Where a mistake has
  two sides, test both: AlertHub#18's guard has to fail if it stops honouring X-Forwarded-For AND if
  it starts honouring it from an untrusted peer.
- The shell is zsh. Unquoted parameters do not word-split — use arrays. Quote globs:
  --include='*.go', and quote ? in URLs. Every Go command needs GOWORK=off.
- `git stash` on a clean tree creates nothing, so a paired `git stash pop` pops someone else's work.
  PSP currently holds two of the owner's own stashes. Check `git stash list` before any pop.
- Report-Portal's internal/app tests take 140-210s. PSP's web suite is meaningless without
  --testTimeout=60000 — see §9 for the two flaky tests that will otherwise make you blame a
  dependency.
- Workflow subagents run on Sonnet: pass model: 'sonnet' on every agent() call.
- Comments and identifiers in English, no AI attribution in source, no `claude`/`codex` in branch
  names.

THE OPEN ARCHITECTURAL QUESTION

HANDOFF.md §8. The shared-module project is finished except for one package: authcore/ratelimit has
zero consumers and was designed without reading any consumer's code. A preflight kept it on the
strength of a live X-Forwarded-For defect in AlertHub — which AlertHub#18 then fixed directly, so
that argument is spent. What is left is four divergent implementations of client-IP-behind-a-proxy
across the org, which points at a different package boundary: extract authcore/clientip and delete
ratelimit. That is written up as a proposal, NOT a decision. The owner has not ruled on it.
Also still open: authcore has never been tagged, and v0.1.0 is a reasonable moment now that the six
measurement data points are in.
```

---

## What this prompt deliberately leaves out

It does not restate `HANDOFF.md`. The prompt's job is to get the next session oriented, stop it from
merging something the owner wanted to look at first, and warn it about the three constraints and the
handful of environment traps that cost real time. Everything else — per-PR verdicts, the evidence
behind each one, the nine unverified items, the two repository-level flaky tests — is one file away
and does not belong in a prompt.
