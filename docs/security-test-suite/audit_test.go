// Section 4.3 of docs/security-test-suite.md: audit hash-chain tamper
// detection. Every test here talks to SECTEST_BASE_URL exactly like the
// rest of this suite (see internal/harness) — the target's own HTTP API is
// used to write entries and to trigger a verification pass, and the
// test-only POST /audit/tamper hook (present on both reference/safe and
// reference/vulnerable — see reference/{safe,vulnerable}/audit.go) stands
// in for "an operator with direct database access edited a row", per the
// design doc's own `mustTestOnlyDB`/tamper skeleton in section 4.3.
//
// Self-check discipline (design doc, "★ 规格里没有、但必须做的：自验证"):
// every test function below that asserts a security property must pass
// against reference/safe and fail against reference/vulnerable. Where a
// sub-case from the design doc's bullet list cannot actually be forced to
// distinguish the two stubs over this suite's black-box HTTP surface, it is
// written as an explicit, reasoned t.Skip (a "gate"/"needs white-box" case,
// same pattern as the design doc's own TestSAML_GoxmldsigVersionNotVulnerable
// skeleton in section 4.1.3) rather than as a test that would pass against
// both stubs and prove nothing.
package securitytest

import (
	"fmt"
	"testing"

	"github.com/KazuhaHub/security-test-suite/internal/harness"
)

// auditEntry mirrors the JSON shape both reference stubs' GET/POST /audit
// return (reference/safe/audit.go and reference/vulnerable/audit.go use
// identical field names for the fields they share; vulnerable's version
// simply has no PrevHash/Hash — decoding those into this superset struct
// just leaves them as the zero value, which is fine, this test never reads
// them directly).
type auditEntry struct {
	ID       int64  `json:"id"`
	Actor    string `json:"actor"`
	Action   string `json:"action"`
	Detail   string `json:"detail"`
	Time     string `json:"time"`
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

type auditAppendRequest struct {
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Detail string `json:"detail"`
}

// auditVerifyResult mirrors both stubs' GET /audit?verify=1 response.
// BrokenAt is 0/absent when OK; otherwise it is the ID of the first entry
// verification flagged.
type auditVerifyResult struct {
	OK       bool   `json:"ok"`
	BrokenAt int64  `json:"broken_at"`
	Entries  int    `json:"entries"`
	Reason   string `json:"reason,omitempty"`
}

type auditTamperRequest struct {
	ID     int64  `json:"id"`
	Detail string `json:"detail"`
}

// appendAuditEntry posts one normal, harmless audit event via the target's
// own HTTP API — the same shape a real authenticated action (login, alert
// publish, service-account create, ...) would produce — and returns the
// entry the target reports back, including whatever ID it assigned.
func appendAuditEntry(t *testing.T, base, actor, action, detail string) auditEntry {
	t.Helper()
	resp, err := harness.PostJSON(base+"/audit", auditAppendRequest{
		Actor:  actor,
		Action: action,
		Detail: detail,
	}, nil)
	resp = harness.RequireReachable(t, resp, err, "append audit entry")
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		t.Fatalf("append audit entry: unexpected status %d (%s) — fixture is broken",
			resp.StatusCode, harness.StatusClass(resp.StatusCode))
	}
	var e auditEntry
	harness.DecodeJSON(t, resp, &e)
	return e
}

// verifyAuditChain hits GET /audit?verify=1, which both reference stubs
// implement (safe: recomputes and reports the first broken link;
// vulnerable: has no chain fields, so it unconditionally reports ok:true —
// see reference/vulnerable/audit.go).
func verifyAuditChain(t *testing.T, base string) auditVerifyResult {
	t.Helper()
	resp, err := harness.GetWithCookies(base+"/audit?verify=1", nil, nil)
	resp = harness.RequireReachable(t, resp, err, "verify audit chain")
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		t.Fatalf("verify audit chain: unexpected status %d — fixture is broken", resp.StatusCode)
	}
	var res auditVerifyResult
	harness.DecodeJSON(t, resp, &res)
	return res
}

// tamperAuditEntry calls the test-only POST /audit/tamper hook both
// reference stubs expose, which edits a row's Detail field in place
// without going through the application's append path — the black-box
// stand-in for "someone ran an UPDATE statement directly against the
// database", per the design doc's 4.3 "直连数据库改一行" case. On
// reference/safe this deliberately does NOT recompute the row's stored
// Hash (a real out-of-band UPDATE wouldn't either); on reference/vulnerable
// there is no Hash field to recompute in the first place.
func tamperAuditEntry(t *testing.T, base string, id int64, newDetail string) {
	t.Helper()
	resp, err := harness.PostJSON(base+"/audit/tamper", auditTamperRequest{
		ID:     id,
		Detail: newDetail,
	}, nil)
	resp = harness.RequireReachable(t, resp, err, "tamper audit entry (test-only DB-bypass hook)")
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		t.Fatalf("tamper audit entry: unexpected status %d — fixture is broken", resp.StatusCode)
	}
}

// TestAudit_NormalChainThenTamperedMiddleEntryDetected covers the first two
// bullets of design doc 4.3: "正常写入后链可校验" and "篡改中间一条记录后
// 校验必须失败", as one test — exactly the "baseline via t.Fatalf, security
// assertion via t.Errorf" shape the design doc's own SAML replay skeleton
// (4.1.1) uses, and for the same reason: the baseline-verifies-clean check
// on its own does NOT distinguish safe from vulnerable (vulnerable's
// ?verify=1 reports ok:true unconditionally, tampered or not — see
// reference/vulnerable/audit.go), so it must never be its own test case; it
// is only meaningful as a precondition for the tamper assertion that
// follows it in the same run.
func TestAudit_NormalChainThenTamperedMiddleEntryDetected(t *testing.T) {
	base := harness.MustBaseURL(t)

	// A handful of normal, harmless writes via the target's own HTTP API —
	// design doc 4.3: "若干条正常业务操作触发的审计事件".
	actions := []string{"auth.login", "alert.publish", "service_account.create", "auth.login", "alert.cancel"}
	entries := make([]auditEntry, 0, len(actions))
	for i, action := range actions {
		e := appendAuditEntry(t, base,
			fmt.Sprintf("sectest-actor-%d@example.com", i), action,
			fmt.Sprintf(`{"seq":%d}`, i))
		entries = append(entries, e)
	}

	// Baseline: untouched writes must verify clean. Fatalf, not Errorf —
	// this is a fixture-sanity precondition ("正常写入后链可校验"), not
	// the security assertion itself (see the doc comment above).
	before := verifyAuditChain(t, base)
	if !before.OK {
		t.Fatalf("baseline verify failed before any tampering — fixture is broken: %+v", before)
	}
	if before.Entries < len(entries) {
		t.Fatalf("baseline verify reports %d entries, expected at least %d written — fixture is broken",
			before.Entries, len(entries))
	}

	// Tamper a MIDDLE row (neither the first nor the last — design doc
	// 4.3: "篡改中间一条记录"), bypassing the application entirely.
	target := entries[2]
	tamperAuditEntry(t, base, target.ID, `{"tampered":true}`)

	after := verifyAuditChain(t, base)
	if after.OK {
		t.Errorf("hash chain verification reported ok:true after row id=%d (action=%q) was edited "+
			"out-of-band — tamper detection failed to catch it", target.ID, target.Action)
		return
	}
	if after.BrokenAt != target.ID {
		t.Errorf("verification detected a break, but flagged id=%d — want the tampered row's id=%d",
			after.BrokenAt, target.ID)
	}
}

// TestAudit_DeletedEntryBreaksChain_NeedsWhiteBox is design doc 4.3's third
// bullet: "删除一条记录后必须失败". This is GATED, not exercised, and here
// is why: mechanically, deleting row N breaks exactly the same invariant
// the tamper test above already exercises — a later row's stored PrevHash
// no longer matches a fresh recomputation of its actual (now missing or
// different) predecessor. AlertHub's real VerifyAuditChain
// (server/internal/store/audit.go, the `if e.PrevHash != prev` check around
// line 190) does not special-case edit vs. delete; both are caught by the
// same comparison. But reproducing literal row DELETION over this suite's
// black-box HTTP surface needs a delete primitive, and neither reference
// stub exposes one — reference/{safe,vulnerable}/audit.go's only test-only
// mutation hook is POST /audit/tamper, which edits a row's Detail in place.
// Adding a delete hook would mean modifying reference/*, which is out of
// scope for this file (audit_test.go may only add itself and
// testdata/audit/ fixtures, per the task boundary). Exercising this for
// real needs either (a) a delete hook added to the reference stubs (a
// decision for whoever owns reference/*, not this file), or (b) a direct,
// test-only DB connection to a real project's test database, per the
// design doc's own `mustTestOnlyDB` skeleton in 4.3 — which is a step this
// suite only takes once an actual project test instance + disposable DB
// exists to point it at (not yet, per the design doc's own section 7: "不
// 要求三个项目同时具备测试环境"). Flagged as a gate, not silently folded
// into the tamper test above and not silently passed.
func TestAudit_DeletedEntryBreaksChain_NeedsWhiteBox(t *testing.T) {
	t.Skip("GATE — needs a delete primitive this reference stub does not expose over HTTP " +
		"(only POST /audit/tamper, which edits in place), or a direct test-only DB connection " +
		"to a real project's test database (design doc 4.3's mustTestOnlyDB). See the doc " +
		"comment on this test for the full reasoning and why the tamper test above already " +
		"exercises the same underlying chain invariant that a deletion would also break.")
}

// TestAudit_AnchorSemantics_NeedsWhiteBox is design doc 4.3's anchor bullet:
// once a table that already had rows is migrated to ADD a hash chain, the
// pre-migration rows have no PrevHash/Hash (NULL, or in AlertHub's actual
// schema the empty-string zero value) because they predate the chain
// entirely. Correct behavior is to verify only from a recorded anchor point
// forward and NOT treat the unhashed legacy rows before it as a broken
// link — naively verifying the WHOLE table (as if every row, including
// pre-migration ones, must satisfy the hash formula from row 1) reports a
// false break at the first legacy row even though nothing was tampered
// with. This is GATED, not exercised, and here is why:
//
//  1. AlertHub already has a real, verified anchor mechanism, but it is for
//     PRUNING, not migration: PruneAudit (server/internal/store/audit_prune.go)
//     records the hash of the last row it removes as an anchor in a
//     `settings` table (key "audit_chain_anchor"), and VerifyAuditChain
//     (server/internal/store/audit.go:180, `s.getSetting(auditAnchorKey)`)
//     starts its walk from that anchor instead of from genesis, so a
//     pruned-but-untampered log still verifies clean.
//  2. That mechanism has no HTTP surface to black-box test against even on
//     a real AlertHub instance: PruneAudit is only ever invoked from an
//     internal retention cron job (server/main.go:299), never from an HTTP
//     handler — server/internal/api/audit.go wires up only
//     GET /api/audit and GET /api/audit/verify, no prune endpoint.
//  3. The specific scenario this bullet describes — pre-existing rows with
//     NULL/absent chain fields because the chain was added by a later
//     migration — does not currently exist in ANY of the three target
//     projects: AlertHub's audit_log.prev_hash/hash columns are
//     declared NOT NULL with an empty-string default from that table's very first migration
//     (server/internal/store/store.go:219/321) — there was never a
//     pre-chain table to retrofit — and PSP/Report-Portal
//     (internal/service/audit/audit.go, internal/app/audit.go) have no
//     hash-chain columns at all yet, so there is nothing to anchor. This is
//     a forward-looking correctness property for the P1 shared audit
//     package's eventual migration path, not a behavior any live instance
//     exhibits today.
//  4. reference/{safe,vulnerable}/audit.go mirror that same reality: an
//     in-memory list with no anchor concept, no NULL-prefixed history, and
//     ?verify=1 always walking from prevHash="". There is no way to seed
//     the NULL-historical-row scenario, or to ask verification to start
//     from an anchor, over the routes those stubs expose.
//
// Exercising this case for real needs either a reference stub extended
// with an anchor primitive (e.g. a seed hook for pre-chain rows plus a
// `?verify=1&since=<anchor id>` parameter — out of scope for this file,
// same boundary as the delete case above) or a live project instance that
// has actually been through such a migration, which none currently have.
func TestAudit_AnchorSemantics_NeedsWhiteBox(t *testing.T) {
	t.Skip("GATE — the migration-anchor scenario (pre-chain rows with NULL prev_hash/hash, " +
		"verification starting from a recorded anchor rather than genesis) exists in none of " +
		"the three target projects yet and has no reachable primitive on either reference " +
		"stub (no seed-legacy-row hook, no anchor-aware verify parameter). AlertHub's real " +
		"anchor mechanism (store.PruneAudit + VerifyAuditChain's getSetting(auditAnchorKey), " +
		"see the doc comment on this test) is for pruning, not migration, and has no HTTP " +
		"surface even on a live instance. See the doc comment on this test for the full, " +
		"cited reasoning. This is pinned down as a forward-looking design requirement, not " +
		"silently skipped without explanation.")
}
