// Package integrity verifies OpenCaravan [opencaravan.Integrity]
// envelopes against the public keys of enrolled client app
// certificates.
//
// Every signed OpenCaravan payload carries an Integrity envelope with
// {Algorithm, KeyID, Signature}. The signed bytes are the payload's
// CanonicalEncoding() (which excludes the Integrity field itself).
// This package provides:
//
//   - [Verifier]: parses the envelope, resolves KeyID to a public key
//     via an injected [KeyResolver], computes the canonical hash, and
//     runs the algorithm-specific signature check.
//   - [KeyResolver]: the narrow lookup capability the verifier needs.
//     Production wires a resolver backed by
//     [storage.Store.EnrolledCertByClientAppID]; tests inject a fake
//     that returns a known public key by id.
//
// KeyID semantics: by convention this server uses the signing client
// app's enrolled ClientAppID (a UUID), which uniquely identifies the
// signing device + key pair. A future protocol revision may switch
// to cert serial or fingerprint — see [Verifier.VerifyPayload] for
// how the verifier stays agnostic to the KeyID format.
//
// Supported algorithm: "ecdsa-p256-sha256" only. Other algorithm
// strings return [ErrUnsupportedAlgorithm] so a future protocol bump
// surfaces explicitly rather than being silently accepted.
package integrity
