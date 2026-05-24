package storage

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestIssueMacaroonRootPersistsRow(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	root, err := store.IssueMacaroonRoot(ctx)
	if err != nil {
		t.Fatalf("IssueMacaroonRoot: %v", err)
	}
	if root.ID == "" {
		t.Fatal("ID is empty")
	}
	if len(root.Key) != macaroonRootKeyLen {
		t.Fatalf("Key length = %d, want %d", len(root.Key), macaroonRootKeyLen)
	}
	if !root.Active() {
		t.Fatal("freshly-issued root reports !Active")
	}
	if root.CreatedTime.IsZero() {
		t.Fatal("CreatedTime is zero")
	}

	// Round-trip: the stored row matches what IssueMacaroonRoot
	// returned.
	got, err := store.MacaroonRootByID(ctx, root.ID)
	if err != nil {
		t.Fatalf("MacaroonRootByID: %v", err)
	}
	if got.ID != root.ID {
		t.Fatalf("ID = %q, want %q", got.ID, root.ID)
	}
	if string(got.Key) != string(root.Key) {
		t.Fatalf("Key round-trip mismatch")
	}
	if !got.Active() {
		t.Fatal("round-tripped row reports !Active")
	}
}

func TestIssueMacaroonRootGeneratesDistinctRows(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	a, err := store.IssueMacaroonRoot(ctx)
	if err != nil {
		t.Fatalf("IssueMacaroonRoot (a): %v", err)
	}
	b, err := store.IssueMacaroonRoot(ctx)
	if err != nil {
		t.Fatalf("IssueMacaroonRoot (b): %v", err)
	}
	if a.ID == b.ID {
		t.Fatal("two issues produced identical IDs")
	}
	if string(a.Key) == string(b.Key) {
		t.Fatal("two issues produced identical keys (entropy failure)")
	}
}

func TestActiveMacaroonRootEmptyTable(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.ActiveMacaroonRoot(context.Background()); !errors.Is(err, ErrNoActiveMacaroonRoot) {
		t.Fatalf("err = %v, want ErrNoActiveMacaroonRoot", err)
	}
}

func TestActiveMacaroonRootPicksNewestUnrotated(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	older, err := store.IssueMacaroonRoot(ctx)
	if err != nil {
		t.Fatalf("issue older: %v", err)
	}
	// Force a non-zero gap so the ORDER BY created_time tiebreak has
	// something to bite on regardless of clock granularity.
	if _, err := store.db.ExecContext(ctx, `
UPDATE macaroon_roots SET created_time = ? WHERE id = ?
`, formatSQLiteTime(time.Now().UTC().Add(-time.Hour)), older.ID); err != nil {
		t.Fatalf("backdate older: %v", err)
	}

	newer, err := store.IssueMacaroonRoot(ctx)
	if err != nil {
		t.Fatalf("issue newer: %v", err)
	}

	got, err := store.ActiveMacaroonRoot(ctx)
	if err != nil {
		t.Fatalf("ActiveMacaroonRoot: %v", err)
	}
	if got.ID != newer.ID {
		t.Fatalf("active = %q, want %q (the newer row)", got.ID, newer.ID)
	}
}

func TestActiveMacaroonRootSkipsRotatedRows(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	root, err := store.IssueMacaroonRoot(ctx)
	if err != nil {
		t.Fatalf("IssueMacaroonRoot: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `
UPDATE macaroon_roots SET rotated_time = ? WHERE id = ?
`, formatSQLiteTime(time.Now()), root.ID); err != nil {
		t.Fatalf("rotate row: %v", err)
	}

	if _, err := store.ActiveMacaroonRoot(ctx); !errors.Is(err, ErrNoActiveMacaroonRoot) {
		t.Fatalf("err = %v, want ErrNoActiveMacaroonRoot once only row is rotated", err)
	}

	// Rotated row is still recoverable by id so the verifier can
	// honor macaroons that were minted against it.
	got, err := store.MacaroonRootByID(ctx, root.ID)
	if err != nil {
		t.Fatalf("MacaroonRootByID after rotate: %v", err)
	}
	if got.Active() {
		t.Fatal("rotated row reports Active=true")
	}
	if got.RotatedTime == nil {
		t.Fatal("rotated row has nil RotatedTime")
	}
}

func TestMacaroonRootByIDMissing(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.MacaroonRootByID(context.Background(), "deadbeef"); !errors.Is(err, ErrMacaroonRootNotFound) {
		t.Fatalf("err = %v, want ErrMacaroonRootNotFound", err)
	}
}

func TestMacaroonRootByIDEmpty(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.MacaroonRootByID(context.Background(), ""); !errors.Is(err, ErrMacaroonRootNotFound) {
		t.Fatalf("err = %v, want ErrMacaroonRootNotFound for empty id", err)
	}
}
