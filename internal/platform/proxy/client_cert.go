package proxy

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Traefik (and most TLS-terminating reverse proxies) expose client
// certificate metadata via two header conventions:
//
//   - X-Forwarded-Tls-Client-Cert carries the full client certificate
//     as URL-encoded PEM. When set, the application can recompute
//     anything it needs (fingerprint, full subject, key bits) without
//     trusting the proxy's parsing.
//   - X-Forwarded-Tls-Client-Cert-Info carries selected fields as
//     semicolon-separated `Key="value"` pairs. Smaller payload; loses
//     the ability to compute a SHA-256 fingerprint or re-derive any
//     field the proxy didn't include.
//
// Either or both may be set depending on Traefik's middleware config
// (passTLSClientCert.pem and passTLSClientCert.info). This package
// honors both with PEM taking precedence when available. Direct mTLS
// (the no-proxy deployment shape) takes precedence over both.
const (
	headerForwardedClientCert     = "X-Forwarded-Tls-Client-Cert"
	headerForwardedClientCertInfo = "X-Forwarded-Tls-Client-Cert-Info"
)

// ClientCert is the subset of client-certificate metadata Spivot Server
// keys off downstream. The fields are the protocol-relevant ones: Serial
// (used by the identity middleware to look up the issuing record in
// issued_certificates), SubjectCN (informational, useful for logs and
// human-facing audit trails), NotAfter (for renewal-window decisions),
// and Fingerprint (lowercase hex SHA-256 over DER for out-of-band
// verification and CA-pinning checks).
//
// Fields may be empty when the source layer did not carry them. Serial
// is the most reliably populated; Fingerprint requires either direct
// mTLS or the URL-encoded PEM header (it cannot be computed from the
// structured info-only header).
type ClientCert struct {
	SubjectCN   string
	Serial      string
	NotAfter    time.Time
	Fingerprint string
}

// clientCertFromTLS returns the leaf client certificate when the
// request was terminated by Go's TLS stack (no reverse proxy in front)
// and the client presented at least one cert. Fingerprint, Serial,
// SubjectCN, and NotAfter are all reliably populated.
func clientCertFromTLS(r *http.Request) *ClientCert {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	leaf := r.TLS.PeerCertificates[0]
	return &ClientCert{
		SubjectCN:   leaf.Subject.CommonName,
		Serial:      leaf.SerialNumber.Text(16),
		NotAfter:    leaf.NotAfter.UTC(),
		Fingerprint: certFingerprint(leaf),
	}
}

// parseForwardedClientCertPEM decodes the URL-encoded PEM Traefik
// forwards when passTLSClientCert.pem is enabled.
//
// Traefik concatenates multiple certs (a chain) with commas. We take
// the first PEM block (the leaf) and ignore the rest; the identity
// middleware only needs the leaf's identity. Returns nil on any
// decoding or parsing failure so a misconfigured proxy degrades to
// "no cert" rather than emitting a partial ClientCert.
func parseForwardedClientCertPEM(headerValue string) *ClientCert {
	// Traefik separates chain entries with commas (not part of PEM
	// itself, since the BEGIN/END markers wrap the base64 body).
	firstPart := headerValue
	if i := strings.Index(headerValue, ","); i >= 0 {
		firstPart = headerValue[:i]
	}
	decoded, err := url.QueryUnescape(firstPart)
	if err != nil {
		return nil
	}
	block, _ := pem.Decode([]byte(decoded))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return &ClientCert{
		SubjectCN:   cert.Subject.CommonName,
		Serial:      cert.SerialNumber.Text(16),
		NotAfter:    cert.NotAfter.UTC(),
		Fingerprint: certFingerprint(cert),
	}
}

// parseForwardedClientCertInfo parses Traefik's structured cert-info
// header: a semicolon-separated list of Key="value" pairs where
// Subject and Issuer carry comma-separated RDN strings.
//
// Returns a best-effort ClientCert. Fingerprint is always empty (the
// proxy didn't send the DER). Returns nil only when the input is
// entirely empty after parsing; partially-recognized headers still
// produce a ClientCert with whatever fields could be extracted.
func parseForwardedClientCertInfo(headerValue string) *ClientCert {
	fields := splitInfoFields(headerValue)
	if len(fields) == 0 {
		return nil
	}
	out := &ClientCert{}
	for k, v := range fields {
		switch strings.ToLower(k) {
		case "subject":
			out.SubjectCN = subjectCommonName(v)
		case "serialnumber", "sn":
			if normalized, ok := canonicalSerial(v); ok {
				out.Serial = normalized
			}
		case "notafter":
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				out.NotAfter = t.UTC()
			}
		}
	}
	if out.SubjectCN == "" && out.Serial == "" && out.NotAfter.IsZero() {
		return nil
	}
	return out
}

// splitInfoFields walks the structured-info header value and returns a
// map of Key → unquoted value. Splits at top-level semicolons while
// respecting double-quoted runs (so Subject="CN=foo,O=bar" stays one
// value even though it contains commas and equals signs).
func splitInfoFields(headerValue string) map[string]string {
	out := make(map[string]string, 4)
	var (
		inQuotes bool
		token    strings.Builder
	)
	emit := func(raw string) {
		k, v, ok := strings.Cut(raw, "=")
		if !ok {
			return
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		v = strings.Trim(v, `"`)
		if k == "" || v == "" {
			return
		}
		out[k] = v
	}
	for i := 0; i < len(headerValue); i++ {
		c := headerValue[i]
		switch c {
		case '"':
			inQuotes = !inQuotes
			token.WriteByte(c)
		case ';':
			if inQuotes {
				token.WriteByte(c)
				continue
			}
			emit(token.String())
			token.Reset()
		default:
			token.WriteByte(c)
		}
	}
	if token.Len() > 0 {
		emit(token.String())
	}
	return out
}

// subjectCommonName extracts the CN component from an X.500 RDN string
// like "CN=foo,O=bar,OU=baz". Case-insensitive on the attribute name.
// Returns the empty string when no CN is present.
//
// Production X.500 strings can include escaped commas in values (per
// RFC 4514) but Traefik does not currently emit such escaping for the
// fields this server requests. A future Traefik change that does
// introduces an extraction bug rather than a security issue; the field
// is informational.
func subjectCommonName(rdnString string) string {
	for _, part := range strings.Split(rdnString, ",") {
		part = strings.TrimSpace(part)
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(k), "CN") {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// certFingerprint returns the lowercase hex SHA-256 fingerprint of a
// parsed certificate's DER bytes. Format matches what `openssl x509
// -fingerprint -sha256 -noout` would produce, without colons.
func certFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// canonicalSerial parses a hex-encoded certificate serial number that
// may carry incidental formatting and re-encodes it in the canonical
// form Spivot Server uses everywhere else (lowercase hex, no leading
// zeros, no separators, no 0x prefix — matching cert.SerialNumber.Text(16)).
//
// Accepted input variants:
//   - Plain lowercase or uppercase hex: "abcdef123" or "ABCDEF123"
//   - "0x" or "0X" prefix
//   - Hyphen or colon separators (used by some OpenSSL outputs)
//   - Surrounding whitespace
//
// The big.Int round-trip is the key: it produces the same string the
// direct-TLS and forwarded-PEM paths produce via cert.SerialNumber.Text(16),
// so the Phase 3c identity middleware can look up issued_certificates
// keyed by serial regardless of which extraction path produced the
// ClientCert. Returns ok=false for inputs that don't parse as a
// positive hex integer; the caller treats that as "no serial."
func canonicalSerial(raw string) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	trimmed = strings.TrimPrefix(trimmed, "0x")
	trimmed = strings.TrimPrefix(trimmed, "0X")
	trimmed = strings.ReplaceAll(trimmed, ":", "")
	trimmed = strings.ReplaceAll(trimmed, "-", "")
	if trimmed == "" {
		return "", false
	}
	n, ok := new(big.Int).SetString(trimmed, 16)
	if !ok || n.Sign() <= 0 {
		return "", false
	}
	return n.Text(16), true
}
