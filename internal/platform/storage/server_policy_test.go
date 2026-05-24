package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureServerPolicySnapshotStoresCanonicalDocument(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{Path: filepath.Join(t.TempDir(), "spivot.db")})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	}()

	snapshot, err := store.EnsureServerPolicySnapshot(ctx, []byte(`{"registration":{"mode":"invite_only"},"version":"v1"}`))
	if err != nil {
		t.Fatalf("ensure policy snapshot: %v", err)
	}
	if snapshot.ID == "" {
		t.Fatal("snapshot ID is empty")
	}
	if !strings.HasPrefix(snapshot.PolicyHash, "sha256:") {
		t.Fatalf("policy hash = %q, want sha256 prefix", snapshot.PolicyHash)
	}
	if snapshot.DocumentJSON != `{"registration":{"mode":"invite_only"},"version":"v1"}` {
		t.Fatalf("document JSON = %q", snapshot.DocumentJSON)
	}
	if snapshot.CreatedTime == "" {
		t.Fatal("created time is empty")
	}

	got, err := store.ServerPolicySnapshot(ctx, snapshot.PolicyHash)
	if err != nil {
		t.Fatalf("get policy snapshot: %v", err)
	}
	if got != snapshot {
		t.Fatalf("snapshot mismatch:\ngot  %#v\nwant %#v", got, snapshot)
	}
}

func TestEnsureServerPolicySnapshotIsIdempotent(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{Path: filepath.Join(t.TempDir(), "spivot.db")})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	}()

	first, err := store.EnsureServerPolicySnapshot(ctx, []byte(`{"version":"v1","registration":{"mode":"invite_only"}}`))
	if err != nil {
		t.Fatalf("ensure first snapshot: %v", err)
	}
	second, err := store.EnsureServerPolicySnapshot(ctx, []byte(`{
		"registration": {"mode": "invite_only"},
		"version": "v1"
	}`))
	if err != nil {
		t.Fatalf("ensure second snapshot: %v", err)
	}
	if first.ID != second.ID {
		t.Fatalf("id = %q, want %q", second.ID, first.ID)
	}
	if first.CreatedTime != second.CreatedTime {
		t.Fatalf("created time = %q, want original %q", second.CreatedTime, first.CreatedTime)
	}
}

func TestEnsureServerPolicySnapshotRejectsInvalidJSON(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{Path: filepath.Join(t.TempDir(), "spivot.db")})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	}()

	_, err = store.EnsureServerPolicySnapshot(ctx, []byte(`{"version":"v1"} {"extra":true}`))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestServerPolicySnapshotMissing(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, Config{Path: filepath.Join(t.TempDir(), "spivot.db")})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	}()

	_, err = store.ServerPolicySnapshot(ctx, "sha256:missing")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), sql.ErrNoRows.Error()) {
		t.Fatalf("error = %v, want sql.ErrNoRows", err)
	}
}
