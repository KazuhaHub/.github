package main

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// auditEntry — GAP (4.3 "PSP / Report-Portal：同样直连 DB 篡改一行"): a
// plain row with no PrevHash/Hash fields at all, matching PSP's and
// Report-Portal's current audit tables per the design doc's findings.
// There is nothing here for a verify step to recompute and compare
// against, so tampering with a row after it's written is undetectable —
// on purpose, to prove out that gap rather than to hide it.
type auditEntry struct {
	ID     int64  `json:"id"`
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Detail string `json:"detail"`
	Time   string `json:"time"`
}

type auditState struct {
	mu      sync.Mutex
	entries []auditEntry
}

func newAuditState() *auditState { return &auditState{} }

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

	e := auditEntry{
		ID:     int64(len(st.entries)) + 1,
		Actor:  req.Actor,
		Action: req.Action,
		Detail: req.Detail,
		Time:   time.Now().UTC().Format(time.RFC3339Nano),
	}
	st.entries = append(st.entries, e)
	writeJSONStatus(w, http.StatusOK, e)
}

type auditVerifyResult struct {
	OK       bool   `json:"ok"`
	BrokenAt int64  `json:"broken_at"`
	Entries  int    `json:"entries"`
	Reason   string `json:"reason,omitempty"`
}

// list serves GET /audit and, with ?verify=1, the "verify" endpoint — GAP:
// there is no hash chain to walk, so verification unconditionally reports
// ok:true regardless of any tampering. This is the precise behavior 4.3's
// "PSP / Report-Portal" row expects to observe and record as a real,
// current gap (not a test bug) — see docs/security-test-suite.md.
func (st *auditState) list(w http.ResponseWriter, r *http.Request) {
	st.mu.Lock()
	defer st.mu.Unlock()

	if r.URL.Query().Get("verify") == "" {
		writeJSONStatus(w, http.StatusOK, st.entries)
		return
	}
	writeJSONStatus(w, http.StatusOK, auditVerifyResult{
		OK:      true,
		Entries: len(st.entries),
		Reason:  "no hash chain implemented — tamper detection is not possible",
	})
}

type auditTamperRequest struct {
	ID     int64  `json:"id"`
	Detail string `json:"detail"`
}

// tamper is the same test-only "simulate direct DB access" hook as
// reference/safe's, for symmetry — here it simply has nothing to break,
// since there was never a chain to break in the first place.
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
			st.entries[i].Detail = req.Detail
			writeJSONStatus(w, http.StatusOK, map[string]any{"ok": true, "tampered_id": req.ID})
			return
		}
	}
	writeJSONStatus(w, http.StatusNotFound, errBody("no such entry id"))
}
