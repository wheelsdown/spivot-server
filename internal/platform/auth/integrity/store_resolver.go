package integrity

import (
	"context"
	"errors"
	"fmt"

	"github.com/wheelsdown/spivot-server/internal/platform/storage"
)

// EnrolledCertLookup is the narrow subset of [storage.Store] the
// production [NewStoreResolver] depends on. Satisfied by
// [*storage.Store] via duck-typing; tests can inject a fake.
type EnrolledCertLookup interface {
	EnrolledCertByClientAppID(ctx context.Context, clientAppID string) (storage.EnrolledCertRecord, error)
}

// NewStoreResolver returns a [KeyResolver] that resolves
// Integrity.KeyID as a client_app_id, loads the enrolled cert for
// that client app, and returns the cert's public key.
//
// Returns [ErrKeyIDUnresolved] when:
//
//   - the key id doesn't match any enrolled client app's id
//     ([storage.ErrCertNotEnrolled]), or
//   - the row exists but pre-dates the cert-PEM migration so the
//     public key is unrecoverable
//     ([storage.ErrEnrolledCertMissingPEM]).
//
// Other storage errors are propagated for the verifier to wrap as
// [ErrResolverTransport].
func NewStoreResolver(lookup EnrolledCertLookup) KeyResolver {
	if lookup == nil {
		panic("integrity: NewStoreResolver: lookup must not be nil")
	}
	return KeyResolverFunc(func(ctx context.Context, keyID string) (any, error) {
		rec, err := lookup.EnrolledCertByClientAppID(ctx, keyID)
		if err != nil {
			if errors.Is(err, storage.ErrCertNotEnrolled) || errors.Is(err, storage.ErrEnrolledCertMissingPEM) {
				return nil, ErrKeyIDUnresolved
			}
			return nil, fmt.Errorf("load enrolled cert: %w", err)
		}
		if rec.Certificate == nil {
			return nil, ErrKeyIDUnresolved
		}
		return rec.Certificate.PublicKey, nil
	})
}
