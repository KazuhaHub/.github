// Command safe is a minimal, deliberately CORRECT reference implementation
// of every behavior this suite's test cases probe: SAML ACS signature +
// replay handling, a WebAuthn/passkey ceremony store, an OIDC
// authorization-code callback, IP-based rate limiting with a trusted-proxy
// boundary, and an append-only audit log protected by a hash chain.
//
// It is NOT a real identity provider or a real relying party. It exists
// only so that every test case in this module has something to pass
// against — see reference/vulnerable for its evil twin, which has the same
// route shapes but each protection deliberately removed and commented.
//
// Run it directly:
//
//	go run ./reference/safe -addr 127.0.0.1:0
//
// It prints the address it actually bound (the default asks the OS for a
// free port) and then serves until killed.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "listen address (host:port; port 0 picks a free port)")
	trustedProxies := flag.String("trusted-proxies", "203.0.113.0/24", "comma-separated CIDR blocks allowed to set X-Forwarded-For (RFC 5737 documentation range by default)")
	flag.Parse()

	srv, err := newServer(*trustedProxies)
	if err != nil {
		log.Fatalf("configure server: %v", err)
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen on %s: %v", *addr, err)
	}
	fmt.Printf("reference/safe listening on http://%s\n", ln.Addr().String())

	httpSrv := &http.Server{Handler: srv.routes()}
	go func() {
		if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Fatalf("serve: %v", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
}

// server holds every reference-stub subsystem's state. Each subsystem
// (saml.go, webauthn.go, oidc.go, ratelimit.go, audit.go) attaches its
// handlers to it via routes().
type server struct {
	saml     *samlState
	webauthn *webauthnState
	oidc     *oidcState
	limiter  *rateLimitState
	audit    *auditState
}

func newServer(trustedProxiesCIDR string) (*server, error) {
	samlSt, err := newSAMLState()
	if err != nil {
		return nil, fmt.Errorf("saml state: %w", err)
	}
	oidcSt, err := newOIDCState()
	if err != nil {
		return nil, fmt.Errorf("oidc state: %w", err)
	}
	limiterSt, err := newRateLimitState(trustedProxiesCIDR)
	if err != nil {
		return nil, fmt.Errorf("rate limit state: %w", err)
	}
	return &server{
		saml:     samlSt,
		webauthn: newWebAuthnState(),
		oidc:     oidcSt,
		limiter:  limiterSt,
		audit:    newAuditState(),
	}, nil
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()

	// 4.1 SAML
	mux.HandleFunc("POST /saml/acs", s.samlACS)
	mux.HandleFunc("GET /saml/acs", s.samlRedirectBinding) // HTTP-Redirect binding entry point, used by the 4.1.6 deflate-bomb case

	// 4.2 WebAuthn / passkey ceremony
	mux.HandleFunc("POST /webauthn/begin", s.webauthnBegin)
	mux.HandleFunc("POST /webauthn/finish", s.webauthnFinish)

	// 4.4 OIDC
	mux.HandleFunc("GET /oidc/start", s.oidcStart)
	mux.HandleFunc("GET /oidc/callback", s.oidcCallback)
	// Test-only plumbing: this reference stub bundles its own mock IdP
	// rather than requiring a separate process, since it only exists to
	// validate this suite's own test cases. /oidc/mock/authorize plays the
	// external IdP's login page (auto-approves); /oidc/mock/override lets a
	// test replace the id_token the NEXT code exchange returns, which is
	// how the alg=none / bad-aud / bad-iss / expired-token cases are built
	// without needing a second signing key the test doesn't control.
	mux.HandleFunc("GET /oidc/mock/authorize", s.oidcMockAuthorize)
	mux.HandleFunc("POST /oidc/mock/override", s.oidcMockOverride)

	// 4.5 rate limiting / XFF trusted-proxy boundary
	mux.HandleFunc("GET /limited", s.limiter.handle)

	// 4.3 audit hash chain
	mux.HandleFunc("GET /audit", s.audit.list)
	mux.HandleFunc("POST /audit", s.audit.append)
	// Test-only plumbing: simulates "someone with direct DB access edited a
	// row", which is the premise of the 4.3 tamper-detection case (a real
	// black-box test can't run arbitrary SQL against the target, but it CAN
	// ask this reference stub to do the equivalent to itself).
	mux.HandleFunc("POST /audit/tamper", s.audit.tamper)

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	return mux
}
