package identity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// caKeyName is the KeyStore name under which the CA private key is
// persisted. There is only ever one CA per server.
const caKeyName = "ca"

// caCertFile is the filename used for the persisted CA certificate
// inside the identity directory.
const caCertFile = "ca.crt.pem"

// caDefaultLifetime is how long a freshly-generated CA certificate is
// valid. The CA cert is self-signed and long-lived because rotating it
// requires re-issuing client app certs and updating any client-side CA
// pinning.
const caDefaultLifetime = 10 * 365 * 24 * time.Hour

// caSerialBits is the bit width of randomly-generated certificate serial
// numbers. 128 bits matches Let's Encrypt and modern PKI practice and is
// well above any reasonable collision threshold.
const caSerialBits = 128

// Config describes how the CA is bootstrapped on first use.
type Config struct {
	// Dir is the directory where the CA certificate is stored alongside
	// the KeyStore's key files. Must be set.
	Dir string
	// Subject is the X.509 subject for the CA self-signed certificate.
	// If CommonName is empty, "Spivot Server CA" is used.
	Subject pkix.Name
	// Lifetime overrides the default CA certificate lifetime. A non-positive
	// value selects the default.
	Lifetime time.Duration
}

// CA is the server-local certificate authority. CA values are safe for
// concurrent use after LoadOrCreate returns.
type CA struct {
	cert    *x509.Certificate
	certPEM []byte
	key     crypto.Signer
	dir     string
}

// LoadOrCreate returns the CA. If a CA key + cert are already persisted
// in cfg.Dir, they are loaded. Otherwise a fresh P-256 ECDSA keypair is
// generated, a self-signed CA certificate is issued, and both are
// persisted.
func LoadOrCreate(ctx context.Context, keystore KeyStore, cfg Config) (*CA, error) {
	if cfg.Dir == "" {
		return nil, errors.New("identity: ca dir must be set")
	}
	cfg.Dir = filepath.Clean(cfg.Dir)
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("identity: create ca dir %q: %w", cfg.Dir, err)
	}
	// MkdirAll ignores the perm arg when the directory already exists, so
	// tighten explicitly: the CA directory contains key material and must
	// be 0700 regardless of how an operator pre-created it.
	if err := os.Chmod(cfg.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("identity: chmod ca dir %q: %w", cfg.Dir, err)
	}

	subject := cfg.Subject
	if strings.TrimSpace(subject.CommonName) == "" {
		subject.CommonName = "Spivot Server CA"
	}
	lifetime := cfg.Lifetime
	if lifetime <= 0 {
		lifetime = caDefaultLifetime
	}

	key, err := keystore.LoadOrGenerate(ctx, caKeyName, func() (crypto.Signer, error) {
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	})
	if err != nil {
		return nil, fmt.Errorf("identity: load ca key: %w", err)
	}

	certPath := filepath.Join(cfg.Dir, caCertFile)
	certPEM, cert, loadErr := loadCertificate(certPath)
	if loadErr != nil {
		if !errors.Is(loadErr, fs.ErrNotExist) {
			return nil, loadErr
		}
		cert, certPEM, err = generateSelfSignedCA(subject, key, lifetime)
		if err != nil {
			return nil, err
		}
		if err := atomicWrite(cfg.Dir, certPath, certPEM, 0o644); err != nil {
			return nil, fmt.Errorf("identity: persist ca cert: %w", err)
		}
	} else if err := verifyCertMatchesKey(cert, key); err != nil {
		// A persisted cert that was not issued by the loaded key would
		// silently produce leaf certs that fail to validate against the
		// returned CA cert. Fail fast and let the operator decide whether
		// to restore the missing piece or wipe and re-bootstrap.
		return nil, fmt.Errorf("identity: ca state at %q is inconsistent: %w", cfg.Dir, err)
	}

	if cert == nil {
		return nil, errors.New("identity: ca certificate unavailable after bootstrap")
	}
	return &CA{cert: cert, certPEM: certPEM, key: key, dir: cfg.Dir}, nil
}

// verifyCertMatchesKey reports whether cert's public key matches the public
// half of key. Used to detect the case where the CA key and CA certificate
// have drifted (one was restored from backup without the other, or one was
// deleted and regenerated while the other was retained).
func verifyCertMatchesKey(cert *x509.Certificate, key crypto.Signer) error {
	certPub, ok := cert.PublicKey.(interface {
		Equal(crypto.PublicKey) bool
	})
	if !ok {
		return errors.New("ca certificate public key does not support equality comparison")
	}
	if !certPub.Equal(key.Public()) {
		return errors.New("ca certificate public key does not match loaded ca private key")
	}
	return nil
}

// Certificate returns the parsed CA certificate.
func (c *CA) Certificate() *x509.Certificate {
	return c.cert
}

// CertificatePEM returns the PEM-encoded CA certificate suitable for
// printing or shipping inside a client bundle.
func (c *CA) CertificatePEM() []byte {
	out := make([]byte, len(c.certPEM))
	copy(out, c.certPEM)
	return out
}

// Fingerprint returns the lowercase hex SHA-256 fingerprint of the CA
// certificate, the form most commonly used to identify a CA out of band.
func (c *CA) Fingerprint() string {
	sum := sha256.Sum256(c.cert.Raw)
	return hex.EncodeToString(sum[:])
}

// Sign issues a leaf certificate over the public key in csr, valid for
// lifetime from now. The CSR's signature is verified before signing; the
// CSR's subject is preserved. Issued certs carry a random 128-bit serial,
// digitalSignature + keyEncipherment usages, and ExtKeyUsage clientAuth.
//
// Implementations enforce protocol-level CSR policy (algorithm,
// subject/SAN constraints) before calling Sign; the CA itself is policy-
// agnostic beyond verifying the CSR signature and rejecting non-positive
// lifetimes.
func (c *CA) Sign(_ context.Context, csr *x509.CertificateRequest, lifetime time.Duration) (*x509.Certificate, []byte, error) {
	if csr == nil {
		return nil, nil, errors.New("identity: csr must not be nil")
	}
	if lifetime <= 0 {
		return nil, nil, errors.New("identity: lifetime must be positive")
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("identity: verify csr signature: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	notBefore := now.Add(-1 * time.Minute) // clock-skew tolerance for fast-clock clients
	notAfter := now.Add(lifetime)

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		DNSNames:              csr.DNSNames,
		EmailAddresses:        csr.EmailAddresses,
		IPAddresses:           csr.IPAddresses,
		URIs:                  csr.URIs,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		// KeyUsageKeyEncipherment is intentionally omitted: it applies to
		// RSA key transport and is not meaningful for ECDSA client-auth
		// certs. Some strict verifiers reject ECDSA certs that declare
		// it; digitalSignature is sufficient for mTLS client auth.
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, c.cert, csr.PublicKey, c.key)
	if err != nil {
		return nil, nil, fmt.Errorf("identity: create leaf certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("identity: parse leaf certificate: %w", err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return leaf, leafPEM, nil
}

func loadCertificate(path string) ([]byte, *x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, err
		}
		return nil, nil, fmt.Errorf("identity: read ca cert %q: %w", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("identity: ca cert %q is not a CERTIFICATE PEM block", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("identity: parse ca cert %q: %w", path, err)
	}
	return raw, cert, nil
}

func generateSelfSignedCA(subject pkix.Name, key crypto.Signer, lifetime time.Duration) (*x509.Certificate, []byte, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	notBefore := now.Add(-1 * time.Minute)
	notAfter := now.Add(lifetime)

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, nil, fmt.Errorf("identity: create ca certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("identity: parse ca certificate: %w", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return cert, encoded, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), caSerialBits)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("identity: generate serial: %w", err)
	}
	return serial, nil
}

func atomicWrite(dir, finalPath string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(finalPath)+"-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = os.Remove(tmpPath)
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		cleanup()
		return err
	}
	return nil
}
