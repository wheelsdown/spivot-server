package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// makeClientCert builds a fresh self-signed P-256 cert for the named
// subject CN. Used by every cert-extraction test as the "client app"
// that presented itself either directly via mTLS or via proxy headers.
func makeClientCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(123456789),
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

func expectedFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func TestClientCertFromDirectTLS(t *testing.T) {
	cert := makeClientCert(t, "client-app-direct")
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}

	got := RequestInfoFrom(req, Config{}).ClientCert
	if got == nil {
		t.Fatal("ClientCert = nil, want populated from direct TLS")
	}
	if got.SubjectCN != "client-app-direct" {
		t.Fatalf("SubjectCN = %q", got.SubjectCN)
	}
	if got.Serial != cert.SerialNumber.Text(16) {
		t.Fatalf("Serial = %q, want %q", got.Serial, cert.SerialNumber.Text(16))
	}
	if got.Fingerprint != expectedFingerprint(cert) {
		t.Fatalf("Fingerprint mismatch")
	}
	if !got.NotAfter.Equal(cert.NotAfter.UTC()) {
		t.Fatalf("NotAfter = %v, want %v", got.NotAfter, cert.NotAfter.UTC())
	}
}

func TestClientCertDirectTLSIgnoresTrustConfig(t *testing.T) {
	cert := makeClientCert(t, "tls-trusts-itself")
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.RemoteAddr = "8.8.8.8:443" // untrusted internet IP
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}

	got := RequestInfoFrom(req, Config{
		TrustForwardedHeaders:  false,
		TrustClientCertHeaders: false,
	}).ClientCert

	if got == nil {
		t.Fatal("direct-mTLS extraction should always run, untrusted IP or not")
	}
	if got.SubjectCN != "tls-trusts-itself" {
		t.Fatalf("SubjectCN = %q", got.SubjectCN)
	}
}

func TestClientCertFromForwardedPEM(t *testing.T) {
	cert := makeClientCert(t, "client-app-pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	encoded := url.QueryEscape(string(pemBytes))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set(headerForwardedClientCert, encoded)

	cfg := configWithLocalhost(t, true, true)
	got := RequestInfoFrom(req, cfg).ClientCert
	if got == nil {
		t.Fatal("ClientCert = nil, want populated from forwarded PEM")
	}
	if got.SubjectCN != "client-app-pem" {
		t.Fatalf("SubjectCN = %q", got.SubjectCN)
	}
	if got.Fingerprint != expectedFingerprint(cert) {
		t.Fatalf("Fingerprint mismatch from PEM path")
	}
}

func TestClientCertFromForwardedInfoFallback(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set(headerForwardedClientCertInfo,
		`Subject="CN=client-app-info,O=Example";SerialNumber="DEADBEEF";NotAfter="2026-06-01T00:00:00Z"`)

	cfg := configWithLocalhost(t, true, true)
	got := RequestInfoFrom(req, cfg).ClientCert
	if got == nil {
		t.Fatal("ClientCert = nil, want populated from forwarded info")
	}
	if got.SubjectCN != "client-app-info" {
		t.Fatalf("SubjectCN = %q", got.SubjectCN)
	}
	if got.Serial != "deadbeef" {
		t.Fatalf("Serial = %q", got.Serial)
	}
	want, _ := time.Parse(time.RFC3339, "2026-06-01T00:00:00Z")
	if !got.NotAfter.Equal(want) {
		t.Fatalf("NotAfter = %v, want %v", got.NotAfter, want)
	}
	if got.Fingerprint != "" {
		t.Fatalf("Fingerprint = %q, want empty (info header carries no DER)", got.Fingerprint)
	}
}

func TestClientCertPEMTakesPrecedenceOverInfo(t *testing.T) {
	cert := makeClientCert(t, "client-app-prefer-pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set(headerForwardedClientCert, url.QueryEscape(string(pemBytes)))
	req.Header.Set(headerForwardedClientCertInfo, `Subject="CN=should-be-ignored"`)

	cfg := configWithLocalhost(t, true, true)
	got := RequestInfoFrom(req, cfg).ClientCert
	if got == nil || got.SubjectCN != "client-app-prefer-pem" {
		t.Fatalf("PEM path lost precedence; got = %+v", got)
	}
}

func TestClientCertHeadersIgnoredFromUntrustedPeer(t *testing.T) {
	cert := makeClientCert(t, "from-attacker")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "8.8.8.8:443" // not in trusted CIDR
	req.Header.Set(headerForwardedClientCert, url.QueryEscape(string(pemBytes)))

	cfg := configWithLocalhost(t, true, true)
	if got := RequestInfoFrom(req, cfg).ClientCert; got != nil {
		t.Fatalf("ClientCert populated from untrusted peer: %+v", got)
	}
}

func TestClientCertHeadersIgnoredWhenTrustDisabled(t *testing.T) {
	cert := makeClientCert(t, "trusted-peer-disabled-flag")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set(headerForwardedClientCert, url.QueryEscape(string(pemBytes)))

	cfg := configWithLocalhost(t, true, false) // TrustClientCertHeaders=false
	if got := RequestInfoFrom(req, cfg).ClientCert; got != nil {
		t.Fatalf("ClientCert populated despite TrustClientCertHeaders=false: %+v", got)
	}
}

func TestClientCertMalformedHeadersDegrade(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set(headerForwardedClientCert, "%%not-url-encoded%%")
	req.Header.Set(headerForwardedClientCertInfo, ";;;not=info=here;;")

	cfg := configWithLocalhost(t, true, true)
	if got := RequestInfoFrom(req, cfg).ClientCert; got != nil {
		t.Fatalf("ClientCert populated from malformed headers: %+v", got)
	}
}

func TestSubjectCommonNameExtraction(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`CN=foo,O=Example`, "foo"},
		{`O=Example,CN=foo`, "foo"},
		{`OU=Engineering, CN=spaced cn, O=Spivot`, "spaced cn"},
		{`cn=lowercase-attr`, "lowercase-attr"},
		{`O=Just-Org`, ""},
		{``, ""},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := subjectCommonName(tc.in); got != tc.want {
				t.Fatalf("subjectCommonName(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestCanonicalSerialNormalizesFormatting(t *testing.T) {
	// big.Int.Text(16)'s canonical form is the target: lowercase hex,
	// no separators, no 0x prefix, no leading zeros. canonicalSerial
	// should produce that regardless of incidental formatting Traefik
	// (or any other proxy) might add.
	canonical := "abcdef12"
	cases := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{"plain lowercase", "abcdef12", canonical, true},
		{"plain uppercase", "ABCDEF12", canonical, true},
		{"with 0x prefix", "0xabcdef12", canonical, true},
		{"with 0X prefix uppercase", "0XABCDEF12", canonical, true},
		{"with colons", "ab:cd:ef:12", canonical, true},
		{"with hyphens", "ab-cd-ef-12", canonical, true},
		{"surrounding whitespace", "  abcdef12  ", canonical, true},
		{"leading zeros dropped", "0000abcdef12", canonical, true},
		{"empty rejected", "", "", false},
		{"non-hex rejected", "not-a-hex-value-xyz", "", false},
		{"zero rejected", "0", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := canonicalSerial(tc.in)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClientCertInfoSerialMatchesPEMPath(t *testing.T) {
	// The Phase 3c identity middleware will look up cert serials in
	// issued_certificates, which stores cert.SerialNumber.Text(16).
	// Whether the cert came in via direct TLS, the forwarded PEM
	// header, or the forwarded Info header, the Serial field must
	// match that canonical form so the lookup succeeds.
	cert := makeClientCert(t, "serial-canonicalization")
	canonical := cert.SerialNumber.Text(16)

	// Info header with the serial formatted differently than the
	// canonical big.Int representation.
	uppercase := strings.ToUpper(canonical)
	header := `Subject="CN=foo";SerialNumber="0x` + uppercase + `"`

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set(headerForwardedClientCertInfo, header)

	cfg := configWithLocalhost(t, true, true)
	got := RequestInfoFrom(req, cfg).ClientCert
	if got == nil {
		t.Fatal("ClientCert = nil")
	}
	if got.Serial != canonical {
		t.Fatalf("Serial = %q, want %q (must match cert.SerialNumber.Text(16))", got.Serial, canonical)
	}
}

func TestSplitInfoFieldsRespectsQuotedSemicolons(t *testing.T) {
	header := `Subject="CN=foo;bar,O=Org";SerialNumber="ABC123";NotAfter="2026-06-01T00:00:00Z"`
	fields := splitInfoFields(header)
	if got := fields["Subject"]; got != `CN=foo;bar,O=Org` {
		t.Fatalf("Subject = %q, want CN=foo;bar,O=Org", got)
	}
	if got := fields["SerialNumber"]; got != "ABC123" {
		t.Fatalf("SerialNumber = %q", got)
	}
}

// configWithLocalhost returns a Config that trusts 127.0.0.0/8 with the
// requested combination of TrustForwardedHeaders / TrustClientCertHeaders
// flags. Used by the proxy-path tests so the trust-CIDR check accepts
// the synthetic 127.0.0.1 RemoteAddr. Fails the test if the CIDR list
// somehow refuses to parse — a regression there would mask trust-gate
// failures elsewhere in this file.
func configWithLocalhost(t *testing.T, forwarded, clientCert bool) Config {
	t.Helper()
	nets, err := ParseCIDRs([]string{"127.0.0.0/8"})
	if err != nil {
		t.Fatalf("ParseCIDRs: %v", err)
	}
	return Config{
		TrustForwardedHeaders:  forwarded,
		TrustClientCertHeaders: clientCert,
		TrustedNetworks:        nets,
	}
}
