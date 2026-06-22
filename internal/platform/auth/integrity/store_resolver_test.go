package integrity

import (
	"context"
	"errors"
	"testing"

	"github.com/wheelsdown/spivot-server/internal/platform/storage"
)

// fakeEnrolledCertLookup implements [EnrolledCertLookup] for unit
// tests of [NewStoreResolver]. The real storage round-trip is
// covered in the storage package's TestEnrolledCertByClientAppID*
// tests; this fake exercises the resolver's error mapping.
type fakeEnrolledCertLookup struct {
	rec storage.EnrolledCertRecord
	err error
}

func (f fakeEnrolledCertLookup) EnrolledCertByClientAppID(_ context.Context, _ string) (storage.EnrolledCertRecord, error) {
	return f.rec, f.err
}

func TestStoreResolverMapsCertNotEnrolled(t *testing.T) {
	res := NewStoreResolver(fakeEnrolledCertLookup{err: storage.ErrCertNotEnrolled})
	_, err := res.ResolvePublicKey(context.Background(), "any-id")
	if !errors.Is(err, ErrKeyIDUnresolved) {
		t.Fatalf("got %v, want ErrKeyIDUnresolved", err)
	}
}

func TestStoreResolverMapsMissingPEM(t *testing.T) {
	res := NewStoreResolver(fakeEnrolledCertLookup{err: storage.ErrEnrolledCertMissingPEM})
	_, err := res.ResolvePublicKey(context.Background(), "any-id")
	if !errors.Is(err, ErrKeyIDUnresolved) {
		t.Fatalf("got %v, want ErrKeyIDUnresolved", err)
	}
}

func TestStoreResolverPropagatesTransportError(t *testing.T) {
	transient := errors.New("db transport error")
	res := NewStoreResolver(fakeEnrolledCertLookup{err: transient})
	_, err := res.ResolvePublicKey(context.Background(), "any-id")
	if errors.Is(err, ErrKeyIDUnresolved) {
		t.Fatalf("got ErrKeyIDUnresolved, expected transport propagation")
	}
	if !errors.Is(err, transient) {
		t.Fatalf("got %v, want wrapping of transient error", err)
	}
}

func TestNewStoreResolverPanicsOnNilLookup(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic, got none")
		}
	}()
	_ = NewStoreResolver(nil)
}
