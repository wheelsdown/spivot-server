// Package identity manages the Spivot Server's cryptographic identities:
// the server-local certificate authority that signs short-lived client app
// certificates, and the key storage backing it.
//
// The package keeps two concerns explicitly separate:
//
//   - KeyStore is the persistence boundary for private keys. The
//     FileKeyStore implementation writes keys to disk with strict
//     permissions; a future KMS-backed implementation can swap in without
//     changing callers.
//   - CA is the operational boundary for the certificate authority: load
//     or generate the CA keypair via the KeyStore, hold the self-signed
//     root certificate, sign incoming CSRs for client apps.
//
// Cert lifetimes are short by design. Short-lived leaf certificates
// obviate online revocation infrastructure (CRL/OCSP) and turn revocation
// into "stop renewing." Callers choose the lifetime per Sign call.
package identity
