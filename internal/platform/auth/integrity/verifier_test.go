package integrity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/opencaravan/opencaravan-go"
)

// signTestPayload generates a fresh P-256 key, signs the supplied
// canonical bytes, and returns both an Integrity envelope binding
// the signature to the supplied keyID and the corresponding public
// key (so tests can wire it into the KeyResolver).
func signTestPayload(t *testing.T, keyID string, canonical []byte) (opencaravan.Integrity, *ecdsa.PublicKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	digest := sha256.Sum256(canonical)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("SignASN1: %v", err)
	}
	return opencaravan.Integrity{
		Algorithm: AlgorithmECDSAP256SHA256,
		KeyID:     keyID,
		Signature: base64.StdEncoding.EncodeToString(sig),
	}, &priv.PublicKey
}

func resolverReturning(key any, err error) KeyResolverFunc {
	return func(_ context.Context, _ string) (any, error) {
		return key, err
	}
}

func TestVerifyPayloadHappyPath(t *testing.T) {
	canonical := []byte(`{"id":"test"}`)
	envelope, pub := signTestPayload(t, "app-1", canonical)
	v := NewVerifier(resolverReturning(pub, nil))
	if err := v.VerifyPayload(context.Background(), canonical, envelope); err != nil {
		t.Fatalf("VerifyPayload: %v", err)
	}
}

func TestVerifyPayloadDetectsTamperedCanonicalBytes(t *testing.T) {
	canonical := []byte(`{"id":"original"}`)
	envelope, pub := signTestPayload(t, "app-1", canonical)
	v := NewVerifier(resolverReturning(pub, nil))

	tampered := []byte(`{"id":"tampered"}`)
	err := v.VerifyPayload(context.Background(), tampered, envelope)
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("got %v, want ErrSignatureInvalid", err)
	}
}

func TestVerifyPayloadDetectsWrongKey(t *testing.T) {
	canonical := []byte(`{"id":"x"}`)
	envelope, _ := signTestPayload(t, "app-1", canonical) // sign with key A
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey other: %v", err)
	}
	// Resolver returns the WRONG public key for the same id.
	v := NewVerifier(resolverReturning(&other.PublicKey, nil))
	verr := v.VerifyPayload(context.Background(), canonical, envelope)
	if !errors.Is(verr, ErrSignatureInvalid) {
		t.Fatalf("got %v, want ErrSignatureInvalid", verr)
	}
}

func TestVerifyPayloadUnsupportedAlgorithm(t *testing.T) {
	envelope, pub := signTestPayload(t, "app-1", []byte("data"))
	envelope.Algorithm = "rsa-pss-sha512"
	v := NewVerifier(resolverReturning(pub, nil))
	err := v.VerifyPayload(context.Background(), []byte("data"), envelope)
	if !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("got %v, want ErrUnsupportedAlgorithm", err)
	}
}

func TestVerifyPayloadKeyIDUnresolved(t *testing.T) {
	envelope, _ := signTestPayload(t, "app-1", []byte("data"))
	v := NewVerifier(resolverReturning(nil, ErrKeyIDUnresolved))
	err := v.VerifyPayload(context.Background(), []byte("data"), envelope)
	if !errors.Is(err, ErrKeyIDUnresolved) {
		t.Fatalf("got %v, want ErrKeyIDUnresolved", err)
	}
}

func TestVerifyPayloadResolverTransportError(t *testing.T) {
	envelope, _ := signTestPayload(t, "app-1", []byte("data"))
	v := NewVerifier(resolverReturning(nil, errors.New("db down")))
	err := v.VerifyPayload(context.Background(), []byte("data"), envelope)
	if !errors.Is(err, ErrResolverTransport) {
		t.Fatalf("got %v, want ErrResolverTransport", err)
	}
}

func TestVerifyPayloadKeyTypeMismatch(t *testing.T) {
	envelope, _ := signTestPayload(t, "app-1", []byte("data"))
	// Resolve to an RSA key — wrong type for ecdsa-p256-sha256.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	v := NewVerifier(resolverReturning(&rsaKey.PublicKey, nil))
	verr := v.VerifyPayload(context.Background(), []byte("data"), envelope)
	if !errors.Is(verr, ErrKeyTypeMismatch) {
		t.Fatalf("got %v, want ErrKeyTypeMismatch", verr)
	}
}

func TestVerifyPayloadKeyTypeMismatchWrongCurve(t *testing.T) {
	envelope, _ := signTestPayload(t, "app-1", []byte("data"))
	// P-384 key when verifier expects P-256.
	wrongCurve, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey P-384: %v", err)
	}
	v := NewVerifier(resolverReturning(&wrongCurve.PublicKey, nil))
	verr := v.VerifyPayload(context.Background(), []byte("data"), envelope)
	if !errors.Is(verr, ErrKeyTypeMismatch) {
		t.Fatalf("got %v, want ErrKeyTypeMismatch", verr)
	}
}

func TestVerifyPayloadMalformedSignatureBase64(t *testing.T) {
	envelope, pub := signTestPayload(t, "app-1", []byte("data"))
	envelope.Signature = "!!!not-base64!!!"
	v := NewVerifier(resolverReturning(pub, nil))
	err := v.VerifyPayload(context.Background(), []byte("data"), envelope)
	if !errors.Is(err, ErrSignatureMalformed) {
		t.Fatalf("got %v, want ErrSignatureMalformed", err)
	}
}

func TestVerifyPayloadMalformedSignatureASN1(t *testing.T) {
	// Valid base64 but the decoded bytes are not valid ASN.1
	// SEQUENCE-of-INTEGER. Without explicit ASN.1 validation this
	// would fall through to ecdsa.VerifyASN1 returning false →
	// ErrSignatureInvalid, which would be a misleading "wrong key"
	// signal for what's actually garbage bytes.
	envelope, pub := signTestPayload(t, "app-1", []byte("data"))
	envelope.Signature = base64.StdEncoding.EncodeToString([]byte("not-asn1-garbage-bytes-xxxxxxx"))
	v := NewVerifier(resolverReturning(pub, nil))
	err := v.VerifyPayload(context.Background(), []byte("data"), envelope)
	if !errors.Is(err, ErrSignatureMalformed) {
		t.Fatalf("got %v, want ErrSignatureMalformed", err)
	}
}

func TestVerifyPayloadErrorChainUnwrapsToRootCause(t *testing.T) {
	// Asserts the doc claim: wrapped errors use %w so callers can
	// errors.Is the sentinel AND errors.Unwrap to the root cause.
	envelope, pub := signTestPayload(t, "app-1", []byte("data"))
	envelope.Signature = "!!!not-base64!!!"
	v := NewVerifier(resolverReturning(pub, nil))
	err := v.VerifyPayload(context.Background(), []byte("data"), envelope)
	if !errors.Is(err, ErrSignatureMalformed) {
		t.Fatalf("missing sentinel: got %v", err)
	}
	// Unwrap to confirm the root base64.CorruptInputError is preserved.
	var corrupt base64.CorruptInputError
	if !errors.As(err, &corrupt) {
		t.Fatalf("errors.As did not find base64.CorruptInputError in chain: %v", err)
	}
}

func TestVerifyPayloadResolverTransportErrorChainUnwrapsToRootCause(t *testing.T) {
	envelope, _ := signTestPayload(t, "app-1", []byte("data"))
	root := errors.New("specific db error")
	v := NewVerifier(resolverReturning(nil, root))
	err := v.VerifyPayload(context.Background(), []byte("data"), envelope)
	if !errors.Is(err, ErrResolverTransport) {
		t.Fatalf("missing sentinel: got %v", err)
	}
	if !errors.Is(err, root) {
		t.Fatalf("errors.Is did not find root error in chain: %v", err)
	}
}

func TestVerifyPayloadEmptyCanonical(t *testing.T) {
	envelope, pub := signTestPayload(t, "app-1", []byte("data"))
	v := NewVerifier(resolverReturning(pub, nil))
	err := v.VerifyPayload(context.Background(), nil, envelope)
	if err == nil {
		t.Fatal("expected error for empty canonical payload, got nil")
	}
}

func TestVerifyPayloadInvalidIntegrityEnvelope(t *testing.T) {
	envelope := opencaravan.Integrity{Algorithm: "", KeyID: "", Signature: ""}
	v := NewVerifier(resolverReturning(nil, nil))
	err := v.VerifyPayload(context.Background(), []byte("data"), envelope)
	if err == nil {
		t.Fatal("expected validate error, got nil")
	}
}

func TestNewVerifierPanicsOnNilResolver(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic, got none")
		}
	}()
	_ = NewVerifier(nil)
}
