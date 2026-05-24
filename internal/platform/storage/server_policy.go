package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// ServerPolicySnapshot is an immutable server policy document recorded in the
// database.
type ServerPolicySnapshot struct {
	// ID is the snapshot identifier. It is currently the policy hash.
	ID string
	// PolicyHash is the SHA-256 digest of the canonical policy document.
	PolicyHash string
	// DocumentJSON is the canonical JSON policy document.
	DocumentJSON string
	// CreatedTime is the RFC3339 UTC time when this snapshot was first stored.
	CreatedTime string
}

// EnsureServerPolicySnapshot records document as an immutable server policy
// snapshot if that exact canonical document has not already been stored.
func (s *Store) EnsureServerPolicySnapshot(ctx context.Context, document []byte) (ServerPolicySnapshot, error) {
	if s == nil || s.db == nil {
		return ServerPolicySnapshot{}, errors.New("database is not open")
	}

	canonical, err := canonicalJSON(document)
	if err != nil {
		return ServerPolicySnapshot{}, err
	}
	policyHash := hashJSON(canonical)
	createdTime := time.Now().UTC().Format(time.RFC3339Nano)

	if _, err := s.db.ExecContext(ctx, `
INSERT OR IGNORE INTO server_policy_snapshots (id, policy_hash, document_json, created_at)
VALUES (?, ?, ?, ?)
`, policyHash, policyHash, string(canonical), createdTime); err != nil {
		return ServerPolicySnapshot{}, fmt.Errorf("record server policy snapshot: %w", err)
	}
	return s.ServerPolicySnapshot(ctx, policyHash)
}

// ServerPolicySnapshot returns a stored policy snapshot by hash or ID.
func (s *Store) ServerPolicySnapshot(ctx context.Context, idOrHash string) (ServerPolicySnapshot, error) {
	if s == nil || s.db == nil {
		return ServerPolicySnapshot{}, errors.New("database is not open")
	}

	var snapshot ServerPolicySnapshot
	err := s.db.QueryRowContext(ctx, `
SELECT id, policy_hash, document_json, created_at
FROM server_policy_snapshots
WHERE id = ? OR policy_hash = ?
`, idOrHash, idOrHash).Scan(
		&snapshot.ID,
		&snapshot.PolicyHash,
		&snapshot.DocumentJSON,
		&snapshot.CreatedTime,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ServerPolicySnapshot{}, fmt.Errorf("server policy snapshot %q: %w", idOrHash, sql.ErrNoRows)
		}
		return ServerPolicySnapshot{}, fmt.Errorf("query server policy snapshot %q: %w", idOrHash, err)
	}
	return snapshot, nil
}

func canonicalJSON(document []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(document))
	dec.UseNumber()

	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode server policy JSON: %w", err)
	}
	var extra any
	err := dec.Decode(&extra)
	switch {
	case errors.Is(err, io.EOF):
	case err == nil:
		return nil, errors.New("server policy JSON must contain one document")
	default:
		return nil, fmt.Errorf("decode trailing server policy JSON: %w", err)
	}

	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("canonicalize server policy JSON: %w", err)
	}
	return canonical, nil
}

func hashJSON(document []byte) string {
	sum := sha256.Sum256(document)
	return "sha256:" + hex.EncodeToString(sum[:])
}
