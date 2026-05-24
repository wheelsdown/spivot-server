package identity_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/wheelsdown/spivot-server/internal/platform/identity"
)

// ExampleLoadOrCreate bootstraps a fresh CA into a temporary directory,
// prints its subject, and verifies that a second call reuses the
// persisted CA rather than generating a new one.
//
// The pattern shown here is the contract the spivot-server CLI uses
// for both `ca init` (first-time bootstrap) and `ca cert` (load and
// print) — they both call [identity.LoadOrCreate] with the same Dir,
// and the second invocation observes the persisted CA from the first.
func ExampleLoadOrCreate() {
	dir, err := os.MkdirTemp("", "identity-example-")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	keyStore, err := identity.NewFileKeyStore(dir)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	first, err := identity.LoadOrCreate(ctx, keyStore, identity.Config{
		Dir:     dir,
		Subject: pkix.Name{CommonName: "Example Spivot CA"},
	})
	if err != nil {
		log.Fatal(err)
	}

	second, err := identity.LoadOrCreate(ctx, keyStore, identity.Config{Dir: dir})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(first.Certificate().Subject.CommonName)
	fmt.Println("fingerprint stable across reloads:", first.Fingerprint() == second.Fingerprint())
	// Output:
	// Example Spivot CA
	// fingerprint stable across reloads: true
}

// ExampleCA_Sign issues a 7-day client-auth leaf certificate from a
// fresh CSR and verifies the leaf against the CA's root using the
// stdlib [x509] package. This is exactly the shape the Phase 3a
// enrollment endpoint will run on each successful enrollment.
func ExampleCA_Sign() {
	dir, err := os.MkdirTemp("", "identity-example-sign-")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	keyStore, err := identity.NewFileKeyStore(dir)
	if err != nil {
		log.Fatal(err)
	}
	ca, err := identity.LoadOrCreate(context.Background(), keyStore, identity.Config{Dir: dir})
	if err != nil {
		log.Fatal(err)
	}

	// In a real enrollment, this CSR arrives in the HTTP request body;
	// the client app generates the keypair and CSR locally. Here we
	// build one inline so the example is self-contained.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "example-client-app"},
	}, leafKey)
	if err != nil {
		log.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		log.Fatal(err)
	}

	leaf, _, err := ca.Sign(context.Background(), csr, 7*24*time.Hour)
	if err != nil {
		log.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate())
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		log.Fatal(err)
	}

	fmt.Println("leaf subject:    ", leaf.Subject.CommonName)
	fmt.Println("leaf is_ca:      ", leaf.IsCA)
	fmt.Println("leaf ext_key_use:", leaf.ExtKeyUsage[0] == x509.ExtKeyUsageClientAuth)
	// Output:
	// leaf subject:     example-client-app
	// leaf is_ca:       false
	// leaf ext_key_use: true
}

// ExampleCA_CertificatePEM shows the operator-facing artifact: the CA
// cert as a PEM block, suitable for piping to a file
// (`spivot-server ca cert > spivot-ca.crt`) and bundling with clients
// that will pin it.
func ExampleCA_CertificatePEM() {
	dir, err := os.MkdirTemp("", "identity-example-cert-")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	keyStore, err := identity.NewFileKeyStore(dir)
	if err != nil {
		log.Fatal(err)
	}
	ca, err := identity.LoadOrCreate(context.Background(), keyStore, identity.Config{Dir: dir})
	if err != nil {
		log.Fatal(err)
	}

	pem := ca.CertificatePEM()
	// PEM is ASCII; the first 27 bytes are the standard BEGIN line.
	fmt.Println(string(pem[:27]))
	// Output: -----BEGIN CERTIFICATE-----
}

// ExampleFileKeyStore_LoadOrGenerate shows the cold-start vs warm-start
// behavior of a [identity.FileKeyStore]. The first call invokes the
// supplied gen function and persists the result; the second call
// loads the persisted key and never invokes gen.
//
// This is the primitive [identity.LoadOrCreate] is built on top of —
// callers wanting their own stable identities (a server signing key,
// a federation key) use this directly with a domain-specific name.
func ExampleFileKeyStore_LoadOrGenerate() {
	dir, err := os.MkdirTemp("", "identity-example-keystore-")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	keyStore, err := identity.NewFileKeyStore(dir)
	if err != nil {
		log.Fatal(err)
	}

	calls := 0
	gen := func() (crypto.Signer, error) {
		calls++
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}

	ctx := context.Background()
	if _, err := keyStore.LoadOrGenerate(ctx, "example", gen); err != nil {
		log.Fatal(err)
	}
	if _, err := keyStore.LoadOrGenerate(ctx, "example", gen); err != nil {
		log.Fatal(err)
	}

	fmt.Println("gen invocations across two LoadOrGenerate calls:", calls)
	// Output: gen invocations across two LoadOrGenerate calls: 1
}
