package integrity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/opencaravan/opencaravan-go"
)

// AlgorithmECDSAP256SHA256 is the only [opencaravan.Integrity.Algorithm]
// value this verifier accepts. Matches the spec'd default in
// opencaravan-go and what every existing test payload uses.
const AlgorithmECDSAP256SHA256 = "ecdsa-p256-sha256"

// ErrUnsupportedAlgorithm is returned when the supplied Integrity
// envelope names an algorithm the verifier doesn't implement.
// Detected via [errors.Is].
var ErrUnsupportedAlgorithm = errors.New("integrity: unsupported algorithm")

// ErrKeyIDUnresolved is returned when the [KeyResolver] could not
// find a public key for the supplied Integrity.KeyID. Distinguishes
// "we know this key id and the signature is wrong" from "we don't
// have a record of this key id at all."
var ErrKeyIDUnresolved = errors.New("integrity: key id could not be resolved to a public key")

// ErrSignatureInvalid is returned when the resolved public key fails
// to verify the supplied signature over the canonical payload bytes.
// This is the auth-failure case the handler maps to 403.
var ErrSignatureInvalid = errors.New("integrity: signature does not verify against resolved key")

// ErrSignatureMalformed is returned when the Integrity.Signature
// field can't be base64-decoded or isn't a valid ASN.1 ECDSA
// signature. Distinct from [ErrSignatureInvalid] (which means the
// signature is well-formed but doesn't match): malformed signatures
// indicate a client serialization bug or a tampered payload, not a
// key mismatch.
var ErrSignatureMalformed = errors.New("integrity: signature is malformed")

// ErrKeyTypeMismatch is returned when the resolved public key isn't
// the type the named algorithm expects (e.g., RSA key returned for
// the ecdsa-p256-sha256 algorithm).
var ErrKeyTypeMismatch = errors.New("integrity: resolved key type does not match algorithm")

// ErrResolverTransport wraps any error returned by the [KeyResolver]
// that ISN'T [ErrKeyIDUnresolved]. Used to distinguish auth failures
// (which return 401/403) from infrastructure failures (which return
// 500 and shouldn't be confused with a malicious caller).
var ErrResolverTransport = errors.New("integrity: key resolver transport failure")

// KeyResolver looks up the public key for the supplied Integrity.KeyID.
// Production wires a resolver backed by [storage.Store]; tests
// inject a fake that returns a known *ecdsa.PublicKey by id.
//
// Implementations must return [ErrKeyIDUnresolved] when no key is
// known for the id. Any other error is wrapped as
// [ErrResolverTransport] by the verifier and surfaces as 500 to the
// handler.
type KeyResolver interface {
	ResolvePublicKey(ctx context.Context, keyID string) (any, error)
}

// KeyResolverFunc adapts a plain function to the [KeyResolver]
// interface, mirroring the http.HandlerFunc pattern.
type KeyResolverFunc func(ctx context.Context, keyID string) (any, error)

// ResolvePublicKey calls f(ctx, keyID).
func (f KeyResolverFunc) ResolvePublicKey(ctx context.Context, keyID string) (any, error) {
	return f(ctx, keyID)
}

// Verifier checks OpenCaravan Integrity envelopes against payloads.
// Construct with [NewVerifier], then call [Verifier.VerifyPayload]
// per envelope.
type Verifier struct {
	resolver KeyResolver
}

// NewVerifier returns a verifier backed by the supplied resolver.
// Panics if resolver is nil — verifying with no way to resolve keys
// is always a configuration bug.
func NewVerifier(resolver KeyResolver) *Verifier {
	if resolver == nil {
		panic("integrity: NewVerifier: resolver must not be nil")
	}
	return &Verifier{resolver: resolver}
}

// VerifyPayload checks that integrity is a valid ECDSA-P-256
// signature over canonicalPayload, produced by the key identified
// by integrity.KeyID.
//
// Error precedence:
//
//  1. integrity.Validate() fails → wrapped error (caller should 400).
//  2. integrity.Algorithm is not [AlgorithmECDSAP256SHA256] →
//     [ErrUnsupportedAlgorithm] (caller should 400).
//  3. integrity.Signature is not valid base64 or ASN.1 ECDSA →
//     [ErrSignatureMalformed] (caller should 400).
//  4. KeyResolver returns [ErrKeyIDUnresolved] →
//     [ErrKeyIDUnresolved] (caller should 401/403).
//  5. KeyResolver returns any other error → [ErrResolverTransport]
//     (caller should 500).
//  6. Resolved key isn't a P-256 ECDSA public key →
//     [ErrKeyTypeMismatch] (caller should 500 — config bug).
//  7. ECDSA verification fails → [ErrSignatureInvalid] (caller
//     should 403).
func (v *Verifier) VerifyPayload(ctx context.Context, canonicalPayload []byte, integrity opencaravan.Integrity) error {
	if err := integrity.Validate(); err != nil {
		return fmt.Errorf("integrity validate: %w", err)
	}
	if integrity.Algorithm != AlgorithmECDSAP256SHA256 {
		return fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, integrity.Algorithm)
	}
	sig, err := base64.StdEncoding.DecodeString(integrity.Signature)
	if err != nil {
		return fmt.Errorf("%w: base64 decode: %v", ErrSignatureMalformed, err)
	}
	if len(canonicalPayload) == 0 {
		return errors.New("integrity: canonical payload is empty")
	}

	pubAny, err := v.resolver.ResolvePublicKey(ctx, integrity.KeyID)
	if err != nil {
		if errors.Is(err, ErrKeyIDUnresolved) {
			return err
		}
		return fmt.Errorf("%w: %v", ErrResolverTransport, err)
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok || pub == nil {
		return fmt.Errorf("%w: got %T", ErrKeyTypeMismatch, pubAny)
	}
	if pub.Curve != elliptic.P256() {
		return fmt.Errorf("%w: curve is %s, want P-256", ErrKeyTypeMismatch, pub.Curve.Params().Name)
	}

	digest := sha256.Sum256(canonicalPayload)
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return ErrSignatureInvalid
	}
	return nil
}
