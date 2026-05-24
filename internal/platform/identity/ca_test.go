package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newCAForTest(t *testing.T) (*CA, string) {
	t.Helper()
	dir := t.TempDir()
	keyStore, err := NewFileKeyStore(dir)
	if err != nil {
		t.Fatalf("NewFileKeyStore: %v", err)
	}
	ca, err := LoadOrCreate(context.Background(), keyStore, Config{Dir: dir})
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	return ca, dir
}

func TestLoadOrCreateBootstrapsCA(t *testing.T) {
	ca, dir := newCAForTest(t)

	if ca.Certificate() == nil {
		t.Fatal("Certificate() = nil")
	}
	if !ca.Certificate().IsCA {
		t.Fatal("CA certificate is not marked IsCA")
	}
	if ca.Certificate().Subject.CommonName != "Spivot Server CA" {
		t.Fatalf("subject CN = %q, want default", ca.Certificate().Subject.CommonName)
	}
	if !strings.Contains(string(ca.CertificatePEM()), "BEGIN CERTIFICATE") {
		t.Fatal("CertificatePEM does not contain BEGIN CERTIFICATE")
	}
	if len(ca.Fingerprint()) != 64 {
		t.Fatalf("fingerprint length = %d, want 64 (sha256 hex)", len(ca.Fingerprint()))
	}

	certInfo, err := os.Stat(filepath.Join(dir, caCertFile))
	if err != nil {
		t.Fatalf("stat ca cert: %v", err)
	}
	if got := certInfo.Mode().Perm(); got != 0o644 {
		t.Fatalf("cert perms = %o, want 0644", got)
	}
}

func TestLoadOrCreateReusesPersistedCA(t *testing.T) {
	dir := t.TempDir()
	keyStore, err := NewFileKeyStore(dir)
	if err != nil {
		t.Fatalf("NewFileKeyStore: %v", err)
	}
	ctx := context.Background()

	first, err := LoadOrCreate(ctx, keyStore, Config{Dir: dir})
	if err != nil {
		t.Fatalf("first LoadOrCreate: %v", err)
	}

	second, err := LoadOrCreate(ctx, keyStore, Config{Dir: dir})
	if err != nil {
		t.Fatalf("second LoadOrCreate: %v", err)
	}

	if first.Fingerprint() != second.Fingerprint() {
		t.Fatalf("CA fingerprint changed across loads: %q != %q", first.Fingerprint(), second.Fingerprint())
	}
}

func TestLoadOrCreateRejectsMismatchedKeyAndCert(t *testing.T) {
	dir := t.TempDir()
	keyStore, err := NewFileKeyStore(dir)
	if err != nil {
		t.Fatalf("NewFileKeyStore: %v", err)
	}
	ctx := context.Background()
	if _, err := LoadOrCreate(ctx, keyStore, Config{Dir: dir}); err != nil {
		t.Fatalf("initial LoadOrCreate: %v", err)
	}

	// Simulate the failure mode: the CA cert is preserved but the key file
	// is deleted, so the next LoadOrCreate generates a fresh key whose
	// public half does not match the persisted certificate.
	if err := os.Remove(filepath.Join(dir, "ca.key.pem")); err != nil {
		t.Fatalf("remove ca key: %v", err)
	}

	_, err = LoadOrCreate(ctx, keyStore, Config{Dir: dir})
	if err == nil {
		t.Fatal("LoadOrCreate(mismatched key/cert) error = nil, want error")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("LoadOrCreate(mismatched) error = %v, want match-failure message", err)
	}
}

func TestLoadOrCreateHonorsCustomSubject(t *testing.T) {
	dir := t.TempDir()
	keyStore, err := NewFileKeyStore(dir)
	if err != nil {
		t.Fatalf("NewFileKeyStore: %v", err)
	}

	ca, err := LoadOrCreate(context.Background(), keyStore, Config{
		Dir:     dir,
		Subject: pkix.Name{CommonName: "Custom CA", Organization: []string{"Spivot"}},
	})
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	if ca.Certificate().Subject.CommonName != "Custom CA" {
		t.Fatalf("subject CN = %q, want Custom CA", ca.Certificate().Subject.CommonName)
	}
	if len(ca.Certificate().Subject.Organization) == 0 || ca.Certificate().Subject.Organization[0] != "Spivot" {
		t.Fatalf("subject Organization = %v, want [Spivot]", ca.Certificate().Subject.Organization)
	}
}

func TestSignProducesValidLeafCertificate(t *testing.T) {
	ca, _ := newCAForTest(t)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "client-app-test"},
	}, leafKey)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}

	leaf, leafPEM, err := ca.Sign(context.Background(), csr, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if leaf.IsCA {
		t.Fatal("leaf cert should not be IsCA")
	}
	if leaf.Subject.CommonName != "client-app-test" {
		t.Fatalf("leaf CN = %q, want client-app-test", leaf.Subject.CommonName)
	}
	if leaf.NotAfter.Sub(leaf.NotBefore) < 7*24*time.Hour-2*time.Minute {
		t.Fatalf("leaf lifetime = %s, want approx 7d", leaf.NotAfter.Sub(leaf.NotBefore))
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate())
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("leaf verify against CA: %v", err)
	}

	if !strings.Contains(string(leafPEM), "BEGIN CERTIFICATE") {
		t.Fatal("leaf PEM missing BEGIN CERTIFICATE")
	}
	block, _ := pem.Decode(leafPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("leaf PEM did not decode to CERTIFICATE block: %+v", block)
	}
}

func TestSignRejectsInvalidInput(t *testing.T) {
	ca, _ := newCAForTest(t)

	if _, _, err := ca.Sign(context.Background(), nil, time.Hour); err == nil {
		t.Fatal("Sign(nil, ...) error = nil, want error")
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test"},
	}, leafKey)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}

	if _, _, err := ca.Sign(context.Background(), csr, 0); err == nil {
		t.Fatal("Sign(csr, 0) error = nil, want error")
	}
	if _, _, err := ca.Sign(context.Background(), csr, -time.Hour); err == nil {
		t.Fatal("Sign(csr, -1h) error = nil, want error")
	}
}

func TestSignGeneratesUniqueSerials(t *testing.T) {
	ca, _ := newCAForTest(t)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test"},
	}, leafKey)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}

	seen := make(map[string]struct{}, 8)
	for range 8 {
		leaf, _, err := ca.Sign(context.Background(), csr, time.Hour)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		key := leaf.SerialNumber.String()
		if _, dup := seen[key]; dup {
			t.Fatalf("serial %s reused", key)
		}
		seen[key] = struct{}{}
	}
}
