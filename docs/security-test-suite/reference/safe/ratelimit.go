package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// The rate limiter itself (fixed window, small limit) is intentionally
// trivial — a real project's actual limiter (token bucket, sliding window,
// go-chi/httprate, ...) is not what 4.5 is testing. What's under test is
// the boundary around it: which address does the limiter key on, and does
// it trust X-Forwarded-For only from a configured, narrow set of proxy
// addresses — or from anyone, which lets any client rotate the header and
// evade the limit entirely.
const (
	rateLimitMax    = 5
	rateLimitWindow = 10 * time.Second
)

type rateLimitState struct {
	trusted []*net.IPNet

	mu     sync.Mutex
	counts map[string][]time.Time // client key -> recent request timestamps within the window
}

func newRateLimitState(cidrCSV string) (*rateLimitState, error) {
	var nets []*net.IPNet
	for _, part := range strings.Split(cidrCSV, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		_, n, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("invalid -trusted-proxies CIDR %q: %w", part, err)
		}
		nets = append(nets, n)
	}
	return &rateLimitState{trusted: nets, counts: make(map[string][]time.Time)}, nil
}

// clientIP returns the address the rate limiter should key on:
// X-Forwarded-For's left-most value IF AND ONLY IF the actual TCP peer
// (r.RemoteAddr) falls inside a configured trusted-proxy CIDR — otherwise
// the peer address itself, ignoring any XFF header entirely. This is the
// correct trust boundary: XFF is only meaningful when it was appended by a
// proxy the operator actually deployed and trusts, never when it arrives
// verbatim from the public internet.
func (st *rateLimitState) clientIP(r *http.Request) string {
	peerHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peerHost = r.RemoteAddr
	}
	peerIP := net.ParseIP(peerHost)

	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" || peerIP == nil || !st.isTrustedProxy(peerIP) {
		return peerHost
	}

	first := strings.TrimSpace(strings.Split(xff, ",")[0])
	if net.ParseIP(first) == nil {
		return peerHost // malformed XFF value — fall back rather than key on garbage
	}
	return first
}

func (st *rateLimitState) isTrustedProxy(ip net.IP) bool {
	for _, n := range st.trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
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

// handle serves GET /limited: a stand-in for any rate-limited endpoint
// (login, ACS, token exchange, ...). It reports the key it counted the
// request against in the response body, which is what lets a test
// distinguish "limited by the real peer address" from "limited by a
// forged X-Forwarded-For value".
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
