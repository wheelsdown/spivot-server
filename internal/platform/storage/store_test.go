package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func TestOpenAppliesMigrations(t *testing.T) {
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

	migrations, err := Migrations()
	if err != nil {
		t.Fatalf("load migrations: %v", err)
	}
	applied, err := store.AppliedMigrations(ctx)
	if err != nil {
		t.Fatalf("applied migrations: %v", err)
	}
	if len(applied) != len(migrations) {
		t.Fatalf("applied migration count = %d, want %d", len(applied), len(migrations))
	}
	for i, migration := range migrations {
		if applied[i] != migration.Version {
			t.Fatalf("applied[%d] = %d, want %d", i, applied[i], migration.Version)
		}
	}
}

func TestOpenIsIdempotent(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "spivot.db")

	store, err := Open(ctx, Config{Path: path})
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close first store: %v", err)
	}

	store, err = Open(ctx, Config{Path: path})
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close second store: %v", err)
		}
	}()

	applied, err := store.AppliedMigrations(ctx)
	if err != nil {
		t.Fatalf("applied migrations: %v", err)
	}
	if len(applied) == 0 {
		t.Fatal("no applied migrations recorded")
	}
}

func TestOpenRejectsEmptyPath(t *testing.T) {
	_, err := Open(context.Background(), Config{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestApplyMigrationsRejectsFutureDatabase(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "future.db")

	db, err := sql.Open(sqliteDriverName, path)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TEXT NOT NULL
);
INSERT INTO schema_migrations (version, name, applied_at) VALUES (999, 'future', '2026-05-24T00:00:00Z');
`); err != nil {
		t.Fatalf("seed future migration: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close raw db: %v", err)
	}

	_, err = Open(ctx, Config{Path: path})
	if err == nil {
		t.Fatal("expected future migration error")
	}
}
