package middleware

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/wheelsdown/spivot-server/internal/platform/proxy"
	"github.com/wheelsdown/spivot-server/internal/platform/storage"
)

// fakeStore is a hand-rolled IdentityStore used by tests that only
// need to exercise the middleware logic. Backed by a serial→identity
// map; serials missing from the map produce ErrCertNotEnrolled.
type fakeStore struct {
	identities map[string]storage.CertIdentity
	err        error
}

func (f *fakeStore) IdentityBySerial(_ context.Context, serial string) (storage.CertIdentity, error) {
	if f.err != nil {
		return storage.CertIdentity{}, f.err
	}
	id, ok := f.identities[serial]
	if !ok {
		return storage.CertIdentity{}, storage.ErrCertNotEnrolled
	}
	return id, nil
}

func TestAttachIdentityResolvesEnrolledCert(t *testing.T) {
	cert := makeClientCert(t, "client-app-attach")
	serial := cert.SerialNumber.Text(16)

	store := &fakeStore{identities: map[string]storage.CertIdentity{
		serial: {
			UserID:      "user-attach",
			ClientAppID: "client-app-attach",
			Serial:      serial,
			SubjectCN:   "client-app-attach",
			NotAfter:    cert.NotAfter.UTC(),
		},
	}}

	var captured Identity
	handler := AttachIdentity(store, proxy.Config{}, discardLogger())(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		id, ok := IdentityFrom(r.Context())
		if !ok {
			t.Error("IdentityFrom = (_, false); want true")
			return
		}
		captured = id
	}))

	req := newRequestWithCert(cert)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if captured.UserID != "user-attach" {
		t.Fatalf("UserID = %q, want user-attach", captured.UserID)
	}
	if captured.ClientAppID != "client-app-attach" {
		t.Fatalf("ClientAppID = %q", captured.ClientAppID)
	}
	if captured.Serial != serial {
		t.Fatalf("Serial = %q, want %q", captured.Serial, serial)
	}
}

func TestAttachIdentityPassesThroughWithoutCert(t *testing.T) {
	store := &fakeStore{}
	called := false
	handler := AttachIdentity(store, proxy.Config{}, discardLogger())(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		called = true
		if _, ok := IdentityFrom(r.Context()); ok {
			t.Error("IdentityFrom returned ok=true with no cert presented")
		}
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called {
		t.Fatal("downstream handler not invoked")
	}
}

func TestAttachIdentityPassesThroughUnknownSerial(t *testing.T) {
	cert := makeClientCert(t, "client-app-orphan")
	store := &fakeStore{identities: map[string]storage.CertIdentity{}} // no matches

	called := false
	handler := AttachIdentity(store, proxy.Config{}, discardLogger())(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		called = true
		if _, ok := IdentityFrom(r.Context()); ok {
			t.Error("IdentityFrom returned ok=true for an unknown serial")
		}
	}))

	req := newRequestWithCert(cert)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called {
		t.Fatal("downstream handler not invoked")
	}
}

func TestAttachIdentityPassesThroughOnStorageError(t *testing.T) {
	cert := makeClientCert(t, "client-app-err")
	store := &fakeStore{err: errors.New("simulated db outage")}

	called := false
	handler := AttachIdentity(store, proxy.Config{}, discardLogger())(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		called = true
		if _, ok := IdentityFrom(r.Context()); ok {
			t.Error("IdentityFrom returned ok=true when storage errored")
		}
	}))

	req := newRequestWithCert(cert)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called {
		t.Fatal("downstream handler not invoked even though storage error should pass through")
	}
}

func TestRequireIdentityRejectsWithoutIdentity(t *testing.T) {
	handler := RequireIdentity(discardLogger(), http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("guarded handler ran without identity")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/problem+json" {
		t.Fatalf("Content-Type = %q", got)
	}
}

func TestRequireIdentityPassesWithIdentity(t *testing.T) {
	called := false
	handler := RequireIdentity(discardLogger(), http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		called = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(WithIdentity(req.Context(), Identity{UserID: "u", ClientAppID: "c"}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called {
		t.Fatal("guarded handler not invoked despite attached identity")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestIdentityFromMissingReturnsFalse(t *testing.T) {
	if _, ok := IdentityFrom(context.Background()); ok {
		t.Fatal("IdentityFrom on bare context returned ok=true")
	}
}

func makeClientCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(7 * 24 * time.Hour).UTC().Truncate(time.Second),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

func newRequestWithCert(cert *x509.Certificate) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	return req
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
