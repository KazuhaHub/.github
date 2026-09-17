package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// auditEntry mirrors the shape of the target projects' audit rows closely
// enough for a test to construct realistic-looking entries, plus the two
// fields (PrevHash, Hash) that make this a chain rather than a plain
// append-only table — the exact property AlertHub has and PSP/Report-Portal
// (per shared-modules-plan.md) do not, which is what 4.3 sets out to
// confirm.
type auditEntry struct {
	ID       int64  `json:"id"`
	Actor    string `json:"actor"`
	Action   string `json:"action"`
	Detail   string `json:"detail"`
	Time     string `json:"time"`
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

type auditState struct {
	mu      sync.Mutex
	entries []auditEntry
}

func newAuditState() *auditState {
	return &auditState{}
}

// hashEntry computes the chain-link hash the same way both at append time
// and at verify time: SHA-256 over the previous entry's hash concatenated
// with this entry's own fields. Changing ANY field of ANY entry after the
// fact — not just Detail — changes that entry's hash and therefore breaks
// every subsequent link, which is the whole point of a hash chain over a
// plain "checksum this one row" scheme.
func hashEntry(prevHash string, e auditEntry) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%d|%s|%s|%s|%s", prevHash, e.ID, e.Actor, e.Action, e.Detail, e.Time)
	return hex.EncodeToString(h.Sum(nil))
}

type auditAppendRequest struct {
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Detail string `json:"detail"`
}

func (st *auditState) append(w http.ResponseWriter, r *http.Request) {
	var req auditAppendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, errBody("invalid JSON body"))
		return
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	prevHash := ""
	if n := len(st.entries); n > 0 {
		prevHash = st.entries[n-1].Hash
	}
	e := auditEntry{
		ID:       int64(len(st.entries)) + 1,
		Actor:    req.Actor,
		Action:   req.Action,
		Detail:   req.Detail,
		Time:     time.Now().UTC().Format(time.RFC3339Nano),
		PrevHash: prevHash,
	}
	e.Hash = hashEntry(prevHash, e)
	st.entries = append(st.entries, e)

	writeJSONStatus(w, http.StatusOK, e)
}

type auditVerifyResult struct {
	OK       bool   `json:"ok"`
	BrokenAt int64  `json:"broken_at"` // 0 when OK; otherwise the ID of the first entry whose hash no longer matches its recorded fields/chain position
	Entries  int    `json:"entries"`
	Reason   string `json:"reason,omitempty"`
}

// list serves GET /audit — plain listing with ?verify=1 additionally
// walking the chain and reporting the first broken link, mirroring
// AlertHub's real GET /api/audit/verify (see the design doc's audit.go
// excerpt from that project).
func (st *auditState) list(w http.ResponseWriter, r *http.Request) {
	st.mu.Lock()
	defer st.mu.Unlock()

	if r.URL.Query().Get("verify") == "" {
		writeJSONStatus(w, http.StatusOK, st.entries)
		return
	}

	result := auditVerifyResult{OK: true, Entries: len(st.entries)}
	prevHash := ""
	for _, e := range st.entries {
		if e.PrevHash != prevHash {
			result.OK = false
			result.BrokenAt = e.ID
			result.Reason = "prev_hash does not match the preceding entry's hash — chain link broken"
			break
		}
		want := hashEntry(prevHash, e)
		if want != e.Hash {
			result.OK = false
			result.BrokenAt = e.ID
			result.Reason = "recorded hash does not match a fresh recomputation from this entry's own fields — row was tampered with after being written"
			break
		}
		prevHash = e.Hash
	}
	writeJSONStatus(w, http.StatusOK, result)
}

type auditTamperRequest struct {
	ID     int64  `json:"id"`
	Detail string `json:"detail"`
}

// tamper is a test-only hook simulating an operator with direct database
// access editing a row in place, bypassing the application entirely (see
// 4.3's "直连数据库改一行" case) — it deliberately does NOT recompute the
// hash, because that is exactly what a real out-of-band UPDATE statement
// would not do either.
func (st *auditState) tamper(w http.ResponseWriter, r *http.Request) {
	var req auditTamperRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, errBody("invalid JSON body"))
		return
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	for i := range st.entries {
		if st.entries[i].ID == req.ID {
			st.entries[i].Detail = req.Detail // Hash is deliberately left untouched
			writeJSONStatus(w, http.StatusOK, map[string]any{"ok": true, "tampered_id": req.ID})
			return
		}
	}
	writeJSONStatus(w, http.StatusNotFound, errBody("no such entry id"))
}
