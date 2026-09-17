package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	rateLimitMax    = 5
	rateLimitWindow = 10 * time.Second
)

type rateLimitState struct {
	mu     sync.Mutex
	counts map[string][]time.Time
}

func newRateLimitState() *rateLimitState {
	return &rateLimitState{counts: make(map[string][]time.Time)}
}

// clientIP — GAP (4.5 "反例：不可信来源伪造 XFF"): trusts
// X-Forwarded-For unconditionally, from ANY connecting peer, with no
// trusted-proxy allowlist at all (contrast reference/safe's CIDR check
// against the actual TCP peer address). Any client can set this header to
// whatever value it likes and the limiter will key on that instead of the
// real connection.
func (st *rateLimitState) clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first := strings.TrimSpace(strings.Split(xff, ",")[0])
		if net.ParseIP(first) != nil {
			return first
		}
	}
	peerHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return peerHost
}

func (st *rateLimitState) allow(key string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rateLimitWindow)
	kept := st.counts[key][:0]
	for _, t := range st.counts[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= rateLimitMax {
		st.counts[key] = kept
		return false
	}
	st.counts[key] = append(kept, now)
	return true
}

func (st *rateLimitState) handle(w http.ResponseWriter, r *http.Request) {
	key := st.clientIP(r)
	if !st.allow(key) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = fmt.Fprintf(w, `{"error":"rate limited","counted_as":%q}`, key)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `{"ok":true,"counted_as":%q}`, key)
}
