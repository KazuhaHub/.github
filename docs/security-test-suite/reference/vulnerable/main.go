// Command vulnerable is reference/safe's evil twin: the exact same route
// shapes, but with every protection this suite's test cases probe
// deliberately removed. Each removal is commented at its call site with
// what was left out and which section of docs/security-test-suite.md it
// corresponds to.
//
// This exists so every test case in this module has something it MUST
// fail against — a test that passes against both reference/safe and
// reference/vulnerable is not testing anything and must be rewritten (see
// the design doc's "★ 规格里没有、但必须做的：自验证" section).
//
// Run it directly:
//
//	go run ./reference/vulnerable -addr 127.0.0.1:0
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
	// -trusted-proxies is accepted for command-line compatibility with
	// reference/safe, but deliberately IGNORED — see ratelimit.go.
	_ = flag.String("trusted-proxies", "203.0.113.0/24", "accepted for CLI compatibility with reference/safe; ignored (see ratelimit.go)")
	flag.Parse()

	srv, err := newServer()
	if err != nil {
		log.Fatalf("configure server: %v", err)
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen on %s: %v", *addr, err)
	}
	fmt.Printf("reference/vulnerable listening on http://%s\n", ln.Addr().String())

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

type server struct {
	saml     *samlState
	webauthn *webauthnState
	oidc     *oidcState
	limiter  *rateLimitState
	audit    *auditState
}

func newServer() (*server, error) {
	samlSt, err := newSAMLState()
	if err != nil {
		return nil, fmt.Errorf("saml state: %w", err)
	}
	oidcSt, err := newOIDCState()
	if err != nil {
		return nil, fmt.Errorf("oidc state: %w", err)
	}
	return &server{
		saml:     samlSt,
		webauthn: newWebAuthnState(),
		oidc:     oidcSt,
		limiter:  newRateLimitState(),
		audit:    newAuditState(),
	}, nil
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /saml/acs", s.samlACS)
	mux.HandleFunc("GET /saml/acs", s.samlRedirectBinding)

	mux.HandleFunc("POST /webauthn/begin", s.webauthnBegin)
	mux.HandleFunc("POST /webauthn/finish", s.webauthnFinish)

	mux.HandleFunc("GET /oidc/start", s.oidcStart)
	mux.HandleFunc("GET /oidc/callback", s.oidcCallback)
	mux.HandleFunc("GET /oidc/mock/authorize", s.oidcMockAuthorize)
	mux.HandleFunc("POST /oidc/mock/override", s.oidcMockOverride)

	mux.HandleFunc("GET /limited", s.limiter.handle)

	mux.HandleFunc("GET /audit", s.audit.list)
	mux.HandleFunc("POST /audit", s.audit.append)
	mux.HandleFunc("POST /audit/tamper", s.audit.tamper)

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	return mux
}
