package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// macaroonRootKeyLen is the length in bytes of every HMAC root key.
// 32 bytes (256 bits) is the size macaroon.v2 uses internally for
// HMAC-SHA-256 and is large enough that key search against the
// macaroon's signature is computationally infeasible.
const macaroonRootKeyLen = 32

// MacaroonRoot is one row from macaroon_roots: the HMAC key the
// server signs (and verifies) session macaroons against, plus a
// public identifier the verifier uses to pick the right key for a
// given macaroon.
//
// Rotation is encoded by RotatedTime: a nil value marks the row as
// the active issuer. Rotated rows are retained — the verifier
// consults every row in the table so macaroons signed by a key that
// has since been rotated remain redeemable until their own
// time<expiration caveat fires.
type MacaroonRoot struct {
	// ID is the public, opaque identifier the issuer embeds in every
	// macaroon's Id field so the verifier can locate the matching key.
	// 128 bits of lowercase hex from [crypto/rand]; the value is
	// unlinkable to the key and safe to log or include in error
	// messages.
	ID string
	// Key is 32 bytes of [crypto/rand] used as the HMAC-SHA-256 root.
	// Treat as a secret; never log, never serialize to anything other
	// than the macaroon_roots row.
	Key []byte
	// CreatedTime is the wall-clock instant the row was inserted.
	CreatedTime time.Time
	// RotatedTime is nil while the row is the active issuer and
	// non-nil thereafter. Phase 4a's path only ever has one active
	// row; later phases will explicitly rotate.
	RotatedTime *time.Time
}

// Active reports whether this row is the current issuer. Equivalent
// to "RotatedTime is nil"; provided as a method so call sites read
// declaratively.
func (r MacaroonRoot) Active() bool {
	return r.RotatedTime == nil
}

// ErrNoActiveMacaroonRoot is returned by [Store.ActiveMacaroonRoot]
// when no row has a NULL rotated_time. The expected call site is
// server startup: a nil error means "issue macaroons against this
// key"; this sentinel means "no active root exists yet — call
// IssueMacaroonRoot to mint the first one." Detected via [errors.Is].
var ErrNoActiveMacaroonRoot = errors.New("storage: no active macaroon root")

// ErrMacaroonRootNotFound is returned by [Store.MacaroonRootByID] when
// the supplied id matches no row. The verifier treats this as "the
// macaroon was signed by a key this server does not (or no longer)
// know about" — equivalent to a signature mismatch. Detected via
// [errors.Is].
var ErrMacaroonRootNotFound = errors.New("storage: macaroon root not found")

// IssueMacaroonRoot mints a fresh root key, persists it as the active
// issuer, and returns the resulting row.
//
// The id and key are both generated from [crypto/rand]: 128 bits of
// id entropy (lowercase hex) and 256 bits of key entropy. The
// PRIMARY KEY on id makes any (astronomically unlikely) collision
// surface as a SQL constraint error rather than as a silent
// overwrite.
//
// Concurrent IssueMacaroonRoot calls each generate independent rows.
// The "active root" surface — [ActiveMacaroonRoot] — returns the most
// recently created unrotated row, so two concurrent issues during
// bootstrap produce two roots, one of which is then observed as
// active; both remain queryable by id for verification. Production
// callers serialize bootstrap so this path is single-writer in
// practice.
func (s *Store) IssueMacaroonRoot(ctx context.Context) (MacaroonRoot, error) {
	if s == nil || s.db == nil {
		return MacaroonRoot{}, errors.New("storage: database is not open")
	}

	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return MacaroonRoot{}, fmt.Errorf("storage: generate macaroon root id: %w", err)
	}
	id := hex.EncodeToString(idBytes)

	key := make([]byte, macaroonRootKeyLen)
	if _, err := rand.Read(key); err != nil {
		return MacaroonRoot{}, fmt.Errorf("storage: generate macaroon root key: %w", err)
	}

	now := time.Now().UTC()
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO macaroon_roots (id, key, created_time)
VALUES (?, ?, ?)
`, id, key, formatSQLiteTime(now)); err != nil {
		return MacaroonRoot{}, fmt.Errorf("storage: record macaroon root: %w", err)
	}

	return MacaroonRoot{
		ID:          id,
		Key:         key,
		CreatedTime: now,
	}, nil
}

// ActiveMacaroonRoot returns the most recently created row whose
// rotated_time is NULL, i.e. the row the issuer should sign new
// macaroons against. Returns [ErrNoActiveMacaroonRoot] when no such
// row exists.
//
// "Most recent" is the right tiebreaker if a future operator path
// ever ends up with two unrotated rows (e.g. a half-completed
// rotation): the newer key wins and the older one gracefully
// degrades to verify-only status until rotated_time is filled in.
func (s *Store) ActiveMacaroonRoot(ctx context.Context) (MacaroonRoot, error) {
	if s == nil || s.db == nil {
		return MacaroonRoot{}, errors.New("storage: database is not open")
	}
	row := s.db.QueryRowContext(ctx, `
SELECT id, key, created_time, rotated_time
FROM macaroon_roots
WHERE rotated_time IS NULL
ORDER BY created_time DESC
LIMIT 1
`)
	root, err := scanMacaroonRoot(row)
	if errors.Is(err, sql.ErrNoRows) {
		return MacaroonRoot{}, ErrNoActiveMacaroonRoot
	}
	return root, err
}

// MacaroonRootByID returns the row whose id matches, regardless of
// rotation state. The verifier uses this to look up the key a
// presented macaroon was signed against (the id lives in the
// macaroon's Id field). Returns [ErrMacaroonRootNotFound] when no
// such row exists.
func (s *Store) MacaroonRootByID(ctx context.Context, id string) (MacaroonRoot, error) {
	if s == nil || s.db == nil {
		return MacaroonRoot{}, errors.New("storage: database is not open")
	}
	if id == "" {
		return MacaroonRoot{}, ErrMacaroonRootNotFound
	}
	row := s.db.QueryRowContext(ctx, `
SELECT id, key, created_time, rotated_time
FROM macaroon_roots
WHERE id = ?
`, id)
	root, err := scanMacaroonRoot(row)
	if errors.Is(err, sql.ErrNoRows) {
		return MacaroonRoot{}, ErrMacaroonRootNotFound
	}
	return root, err
}

// scanMacaroonRoot is the shared row → struct mapper for the
// macaroon_roots table. Kept in one place so the column order /
// type coercion is consistent across every query.
func scanMacaroonRoot(row *sql.Row) (MacaroonRoot, error) {
	var (
		id          string
		key         []byte
		createdTime string
		rotatedTime sql.NullString
	)
	if err := row.Scan(&id, &key, &createdTime, &rotatedTime); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return MacaroonRoot{}, sql.ErrNoRows
		}
		return MacaroonRoot{}, fmt.Errorf("storage: load macaroon root: %w", err)
	}
	created, err := time.Parse(sqliteTimeFormat, createdTime)
	if err != nil {
		return MacaroonRoot{}, fmt.Errorf("storage: parse macaroon root created_time: %w", err)
	}
	out := MacaroonRoot{
		ID:          id,
		Key:         key,
		CreatedTime: created,
	}
	if rotatedTime.Valid {
		rotated, err := time.Parse(sqliteTimeFormat, rotatedTime.String)
		if err != nil {
			return MacaroonRoot{}, fmt.Errorf("storage: parse macaroon root rotated_time: %w", err)
		}
		out.RotatedTime = &rotated
	}
	return out, nil
}
