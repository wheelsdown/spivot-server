// Package identity manages Spivot Server's cryptographic identities: the
// server-local certificate authority that signs short-lived client app
// certificates, and the private-key storage backing it.
//
// Spivot Server acts as its own CA. Every client app (an iOS install, an
// Android install, a CLI, a future web client) submits a CSR carrying its
// own locally-generated P-256 ECDSA public key during enrollment; the
// server signs a short-lived leaf certificate over that key. The leaf
// certificate is what authenticates the client app to subsequent HTTP
// requests via mTLS. Macaroon-based sessions (issued separately) ride on
// top of that authenticated transport.
//
// # Architecture
//
// The package has two layers with an explicit seam between them:
//
//   - [KeyStore] is the persistence boundary for private keys. The
//     production implementation [FileKeyStore] writes PKCS#8 PEM files
//     under a 0700 directory with 0600 file permissions, atomic writes,
//     and parent-directory fsync after each rename. A future
//     KMS/HSM-backed implementation can replace [FileKeyStore] without
//     touching any caller.
//   - [CA] is the operational boundary for the certificate authority.
//     [LoadOrCreate] reads or bootstraps the CA on first call; [CA.Sign]
//     produces leaf certificates from caller-supplied CSRs; [CA.Certificate]
//     and [CA.CertificatePEM] export the root for client-side pinning;
//     [CA.Fingerprint] returns the SHA-256 hex digest typically shown to
//     operators out of band.
//
// # Security Model
//
// What this package protects:
//
//   - Private-key confidentiality at rest. Keys are stored with
//     filesystem-enforced 0600 permissions in a 0700 directory. They are
//     never written to logs, never returned through API surfaces, and
//     never marshaled into JSON or other serialization paths.
//   - Atomic durable writes. Every persisted file is written to a
//     temporary file, fsync'd, renamed into place, and the parent
//     directory is fsync'd. A crash or power loss between the call and
//     return cannot leave a partially-written key or a renamed-but-lost
//     file on disk.
//   - CA state coherence. If a persisted CA certificate's public key
//     does not match the loaded CA private key (an operator restored one
//     file from backup without the other), [LoadOrCreate] fails fast
//     with a clear diagnostic rather than silently issuing leaf certs
//     that fail validation against the returned CA root.
//
// What this package does NOT protect:
//
//   - Process-memory access. A reader with arbitrary memory-read access
//     to the running spivot-server process can extract the CA private
//     key; defending against that requires HSM/TEE-backed storage, which
//     is the design driver for keeping [KeyStore] as an interface.
//   - Filesystem encryption at rest. Operators are responsible for
//     deploying the runtime data directory on an encrypted volume.
//   - TLS termination. mTLS for client connections is terminated by the
//     reverse proxy in front of spivot-server; this package only deals
//     with the keypair and CA that the enrollment endpoint will use
//     downstream.
//
// # On-disk Layout
//
// Given a configured Dir of /var/lib/spivot/identity:
//
//	/var/lib/spivot/identity/         (0700, dir)
//	/var/lib/spivot/identity/ca.key.pem   (0600, PKCS#8 PEM, CA private key)
//	/var/lib/spivot/identity/ca.crt.pem   (0644, X.509 PEM,  CA root cert)
//
// The CA certificate is non-sensitive (it's the public root, designed to
// be distributed) and is intentionally readable to other processes that
// might want to bundle it with clients.
//
// # Lifecycle
//
// [LoadOrCreate] is idempotent. The expected operational pattern:
//
//  1. Operator runs `spivot-server ca init` once on a fresh deployment.
//     A keypair and self-signed CA cert are generated and persisted.
//     The certificate's SHA-256 fingerprint is printed for out-of-band
//     verification.
//  2. Subsequent invocations of `ca init`, `ca cert`, and (later)
//     `serve` all call [LoadOrCreate] with the same directory and
//     receive the existing CA. The CA fingerprint is stable across
//     restarts.
//  3. The runtime HTTP server (added in a later phase) calls
//     [CA.Sign] once per successful client-app enrollment to issue a
//     short-lived leaf certificate. Leaf-cert lifetime is per-call
//     (the package recommends 7 days; expired clients silently renew).
//
// # Algorithm Choice
//
// P-256 ECDSA is the only key algorithm exercised today. It is the
// hardware-backed sweet spot: iOS Secure Enclave supports only P-256,
// Android Keystore supports P-256 universally, and WebAuthn ES256 is
// P-256. [FileKeyStore.save] explicitly rejects non-ECDSA keys for now
// so that no caller accidentally persists an algorithm we have not
// validated against the rest of the stack.
//
// # Concurrency
//
// After [LoadOrCreate] returns, the returned [*CA] is safe for
// concurrent use by multiple goroutines. The underlying crypto/rand
// reader is safe under concurrency, and the cert and key are not mutated
// after construction. [FileKeyStore] is similarly safe for concurrent
// reads; concurrent first-time generation of the same key is serialized
// by the file system's create-with-O_EXCL semantics inside
// [os.CreateTemp].
//
// # Future Evolution
//
// The boundaries deliberately leave room for:
//
//   - A KMS-backed [KeyStore] implementation. Sketch: a new file
//     kms_keystore.go that wraps an AWS KMS / GCP Cloud KMS / Vault
//     transit-engine client and never exposes raw key material — Sign
//     calls indirect through the KMS API.
//   - CA rotation. A future addition will accept multiple trusted CAs
//     (current + previous) so a fleet of clients can be migrated to a
//     new CA cert without simultaneous app updates.
//   - Revocation. Short-lived leaf certs make CRL/OCSP infrastructure
//     unnecessary for the common case; revocation is implemented as
//     "stop renewing." A persisted revoked_at column in the audit table
//     allows short-window emergency revocation if needed.
package identity
