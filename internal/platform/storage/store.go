package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const sqliteDriverName = "sqlite"

// Config describes the runtime SQLite database.
type Config struct {
	// Path is the filesystem path to the SQLite database.
	Path string
}

// Store owns the runtime database connection pool.
type Store struct {
	db   *sql.DB
	path string
}

// Open opens the SQLite database, configures connection behavior, and applies
// embedded schema migrations.
func Open(ctx context.Context, cfg Config) (*Store, error) {
	path := strings.TrimSpace(cfg.Path)
	if path == "" {
		return nil, errors.New("database path is required")
	}
	path = filepath.Clean(path)

	db, err := sql.Open(sqliteDriverName, path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database %q: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	store := &Store{db: db, path: path}
	if err := store.configure(ctx); err != nil {
		_ = store.Close()
		return nil, err
	}
	if err := store.ApplyMigrations(ctx); err != nil {
		_ = store.Close()
		return nil, err
	}
	return store, nil
}

// Path returns the SQLite database path.
func (s *Store) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// Ping verifies that the database is reachable.
func (s *Store) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("database is not open")
	}
	return s.db.PingContext(ctx)
}

// Close releases the database connection pool.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) configure(ctx context.Context) error {
	if err := s.Ping(ctx); err != nil {
		return fmt.Errorf("ping sqlite database %q: %w", s.path, err)
	}

	pragmas := []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA busy_timeout = 5000",
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = NORMAL",
	}
	for _, pragma := range pragmas {
		if _, err := s.db.ExecContext(ctx, pragma); err != nil {
			return fmt.Errorf("configure sqlite database %q with %q: %w", s.path, pragma, err)
		}
	}
	return nil
}

// ApplyMigrations applies all embedded schema migrations that have not already
// been recorded in the database.
func (s *Store) ApplyMigrations(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("database is not open")
	}

	migrations, err := Migrations()
	if err != nil {
		return err
	}
	if err := s.rejectFutureMigration(ctx, len(migrations)); err != nil {
		return err
	}

	for _, migration := range migrations {
		applied, err := s.migrationApplied(ctx, migration.Version)
		if err != nil {
			return fmt.Errorf("check migration %06d_%s: %w", migration.Version, migration.Name, err)
		}
		if applied {
			continue
		}
		if err := s.applyMigration(ctx, migration); err != nil {
			return err
		}
	}
	return nil
}

// AppliedMigrations returns the recorded migration versions in ascending order.
func (s *Store) AppliedMigrations(ctx context.Context) ([]int, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("database is not open")
	}

	rows, err := s.db.QueryContext(ctx, "SELECT version FROM schema_migrations ORDER BY version")
	if err != nil {
		if isMissingSchemaMigrationsTable(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("query applied migrations: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var versions []int
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("scan applied migration: %w", err)
		}
		versions = append(versions, version)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate applied migrations: %w", err)
	}
	return versions, nil
}

func (s *Store) rejectFutureMigration(ctx context.Context, currentCount int) error {
	var version int
	err := s.db.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&version)
	if err != nil {
		if isMissingSchemaMigrationsTable(err) {
			return nil
		}
		return fmt.Errorf("query latest migration: %w", err)
	}
	if version > currentCount {
		return fmt.Errorf("database migration version %d is newer than this binary supports (%d)", version, currentCount)
	}
	return nil
}

func (s *Store) migrationApplied(ctx context.Context, version int) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations WHERE version = ?", version).Scan(&count)
	if err != nil {
		if isMissingSchemaMigrationsTable(err) {
			return false, nil
		}
		return false, err
	}
	return count > 0, nil
}

func (s *Store) applyMigration(ctx context.Context, migration Migration) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration %06d_%s: %w", migration.Version, migration.Name, err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.ExecContext(ctx, migration.SQL); err != nil {
		return fmt.Errorf("apply migration %06d_%s: %w", migration.Version, migration.Name, err)
	}

	appliedAt := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
		migration.Version, migration.Name, appliedAt,
	); err != nil {
		return fmt.Errorf("record migration %06d_%s: %w", migration.Version, migration.Name, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %06d_%s: %w", migration.Version, migration.Name, err)
	}
	return nil
}

func isMissingSchemaMigrationsTable(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such table") && strings.Contains(msg, "schema_migrations")
}
