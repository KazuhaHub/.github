// Command testidp is a self-contained SAML Identity Provider for exercising a
// real Service Provider's ACS endpoint over HTTP.
//
// It exists because the suite's other cases drive reference stubs, and the one
// question those cannot answer is whether a signed assertion survives a REAL
// project's validation path. Passwall-Sub-Panel#103 moved the panel to
// crewjam/saml 0.5.1 and relaxed Destination validation along the way; nothing
// had exercised a signed Response against the panel since.
//
// This is crewjam/saml's own IdentityProvider -- the same library the panel
// validates WITH, at the version it validates with -- so a Response it produces
// is one the panel is meant to accept. Nothing here mocks the protocol; only the
// identity is fixed.
//
//	go run ./cmd/testidp &
//	# then configure the target's SAML settings to fetch this IdP's metadata
//
// Configuration, all by environment:
//
//	IDP_ADDR     listen address, default 127.0.0.1:18080
//	SP_ENTITY_ID the target's SP entity ID (it must match exactly)
//	SP_ACS_URL   the target's ACS URL
//	IDP_UPN      the single principal this IdP will assert, default sso-user@example.test
//
// ONE THING WILL BITE YOU: bind this to a PRIVATE LAN address, not loopback.
// Passwall-Sub-Panel refuses to fetch IdP metadata from loopback, link-local and
// unspecified addresses -- an SSRF guard against the cloud metadata endpoints --
// while deliberately allowing 10/8, 172.16/12 and 192.168/16, because internal
// corporate IdPs legitimately live there. On loopback the panel logs
// "refusing connection to non-public address 127.0.0.1" and the SP never builds.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/xml"
	"errors"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/crewjam/saml"
)

func main() {
	addr := envOr("IDP_ADDR", "127.0.0.1:18080")
	base, _ := url.Parse("http://" + addr)
	spEntity := os.Getenv("SP_ENTITY_ID")
	spACS := os.Getenv("SP_ACS_URL")
	upn := envOr("IDP_UPN", "sso-user@example.test")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "idp.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatalf("cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)

	idp := &saml.IdentityProvider{
		Key:                     key,
		Certificate:             cert,
		MetadataURL:             *resolve(base, "/metadata"),
		SSOURL:                  *resolve(base, "/sso"),
		SessionProvider:         &sessionProvider{upn: upn},
		ServiceProviderProvider: spProvider{entity: spEntity, acs: spACS},
		SignatureMethod:         "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/metadata", func(w http.ResponseWriter, r *http.Request) {
		buf, err := xml.MarshalIndent(idp.Metadata(), "", "  ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		_, _ = w.Write(buf)
	})
	mux.HandleFunc("/sso", idp.ServeSSO)

	log.Printf("testidp listening on %s -- metadata /metadata, sso /sso, asserting %s", addr, upn)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func resolve(base *url.URL, path string) *url.URL {
	return base.ResolveReference(&url.URL{Path: path})
}

// sessionProvider satisfies saml.SessionProvider for one fixed principal: this
// IdP has no user database, it has a single test identity.
type sessionProvider struct{ upn string }

func (s *sessionProvider) GetSession(_ http.ResponseWriter, _ *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
	now := req.Now
	return &saml.Session{
		ID:           "session-" + req.Request.ID,
		CreateTime:   now,
		ExpireTime:   now.Add(time.Hour),
		Index:        "index-" + req.Request.ID,
		NameID:       s.upn,
		NameIDFormat: string(saml.EmailAddressNameIDFormat),
		UserName:     s.upn,
		UserEmail:    s.upn,
	}
}

// spProvider hands crewjam the SP's metadata without a metadata fetch: the target
// is the only service provider, and its ACS URL is not reachable as a URL from
// inside this process.
type spProvider struct{ entity, acs string }

func (p spProvider) GetServiceProvider(_ *http.Request, serviceProviderID string) (*saml.EntityDescriptor, error) {
	if p.entity == "" || serviceProviderID != p.entity {
		return nil, os.ErrNotExist
	}
	if p.acs == "" {
		return nil, errors.New("SP_ACS_URL is not set")
	}
	return &saml.EntityDescriptor{
		EntityID: p.entity,
		SPSSODescriptors: []saml.SPSSODescriptor{{
			SSODescriptor: saml.SSODescriptor{
				RoleDescriptor: saml.RoleDescriptor{
					ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
				},
			},
			AssertionConsumerServices: []saml.IndexedEndpoint{{
				Binding:  saml.HTTPPostBinding,
				Location: p.acs,
				Index:    0,
			}},
		}},
	}, nil
}
