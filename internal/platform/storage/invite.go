package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/opencaravan/opencaravan-go"
)

// Invite is a server-side record of an invite token that has been issued.
// The plaintext token value is never persisted; only the SHA-256 hash and
// lifecycle metadata are stored.
type Invite struct {
	// TokenHash is the hex-encoded SHA-256 of the plaintext token value.
	TokenHash string
	// Scope identifies what kind of action the invite authorizes (see the
	// opencaravan.InviteScope values).
	Scope opencaravan.InviteScope
	// CreatedTime is the RFC3339 UTC time the invite was issued.
	CreatedTime time.Time
	// ExpirationTime is the RFC3339 UTC time after which redemption fails.
	ExpirationTime time.Time
	// UsedTime is set when the invite has been consumed.
	UsedTime *time.Time
	// UsedByClientAppID is the ClientApp ID that redeemed the invite,
	// populated alongside UsedTime.
	UsedByClientAppID string
}

// Active reports whether the invite is currently redeemable: not yet used
// and not yet expired as of now.
func (i Invite) Active(now time.Time) bool {
	if i.UsedTime != nil {
		return false
	}
	return now.Before(i.ExpirationTime)
}

// ErrInviteNotFound is returned when no invite matches the supplied token.
var ErrInviteNotFound = errors.New("storage: invite not found")

// ErrInviteAlreadyUsed is returned when the invite has already been
// redeemed.
var ErrInviteAlreadyUsed = errors.New("storage: invite already used")

// ErrInviteExpired is returned when the invite's ExpirationTime has passed.
var ErrInviteExpired = errors.New("storage: invite expired")

// IssueInvite generates a fresh invite token of the requested scope,
// persists its hash + metadata, and returns the plaintext token (the only
// time the caller sees it) alongside the persisted Invite record.
//
// Lifetime must be positive. The generated token follows the OpenCaravan
// invite-token convention (256 bits of entropy, unpadded base64url).
func (s *Store) IssueInvite(ctx context.Context, scope opencaravan.InviteScope, lifetime time.Duration) (opencaravan.InviteToken, Invite, error) {
	if s == nil || s.db == nil {
		return opencaravan.InviteToken{}, Invite{}, errors.New("storage: database is not open")
	}
	if !scope.Valid() {
		return opencaravan.InviteToken{}, Invite{}, fmt.Errorf("storage: invite scope %q is not a known OpenCaravan value", scope)
	}
	if lifetime <= 0 {
		return opencaravan.InviteToken{}, Invite{}, errors.New("storage: invite lifetime must be positive")
	}

	now := time.Now().UTC()
	expiration := now.Add(lifetime)
	token, err := opencaravan.NewInviteToken(expiration)
	if err != nil {
		return opencaravan.InviteToken{}, Invite{}, fmt.Errorf("storage: generate invite token: %w", err)
	}
	hash := hashInviteToken(token.Value)

	if _, err := s.db.ExecContext(ctx, `
INSERT INTO client_app_invites (token_hash, scope, created_time, expiration_time)
VALUES (?, ?, ?, ?)
`, hash, string(scope), now.Format(time.RFC3339Nano), expiration.Format(time.RFC3339Nano)); err != nil {
		return opencaravan.InviteToken{}, Invite{}, fmt.Errorf("storage: record invite: %w", err)
	}

	return token, Invite{
		TokenHash:      hash,
		Scope:          scope,
		CreatedTime:    now,
		ExpirationTime: expiration,
	}, nil
}

// LookupInvite returns the Invite associated with tokenValue. Returns
// ErrInviteNotFound if no row matches the token's hash; ErrInviteExpired
// if the invite has expired; ErrInviteAlreadyUsed if the invite has been
// redeemed.
func (s *Store) LookupInvite(ctx context.Context, tokenValue string) (Invite, error) {
	invite, err := s.lookupInviteByHash(ctx, hashInviteToken(tokenValue))
	if err != nil {
		return Invite{}, err
	}
	if invite.UsedTime != nil {
		return invite, ErrInviteAlreadyUsed
	}
	if time.Now().UTC().After(invite.ExpirationTime) {
		return invite, ErrInviteExpired
	}
	return invite, nil
}

// ConsumeInvite atomically marks the invite identified by tokenValue as
// used by clientAppID. Returns ErrInviteNotFound, ErrInviteAlreadyUsed, or
// ErrInviteExpired if the invite cannot be redeemed.
func (s *Store) ConsumeInvite(ctx context.Context, tokenValue string, clientAppID string) (Invite, error) {
	if s == nil || s.db == nil {
		return Invite{}, errors.New("storage: database is not open")
	}
	if clientAppID == "" {
		return Invite{}, errors.New("storage: client app id must be set when consuming invite")
	}

	hash := hashInviteToken(tokenValue)
	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339Nano)

	res, err := s.db.ExecContext(ctx, `
UPDATE client_app_invites
SET used_time = ?, used_by_client_app_id = ?
WHERE token_hash = ?
  AND used_time IS NULL
  AND expiration_time > ?
`, nowStr, clientAppID, hash, nowStr)
	if err != nil {
		return Invite{}, fmt.Errorf("storage: consume invite: %w", err)
	}
	updated, err := res.RowsAffected()
	if err != nil {
		return Invite{}, fmt.Errorf("storage: consume invite rows affected: %w", err)
	}
	if updated == 0 {
		invite, lookupErr := s.lookupInviteByHash(ctx, hash)
		if lookupErr != nil {
			return Invite{}, lookupErr
		}
		if invite.UsedTime != nil {
			return invite, ErrInviteAlreadyUsed
		}
		return invite, ErrInviteExpired
	}

	return s.lookupInviteByHash(ctx, hash)
}

// UnconsumedInviteCount returns the number of currently-active (unused,
// unexpired) invites with the requested scope. Used by the bootstrap
// log-emission path to decide whether a fresh server_registration invite
// is needed on first run.
func (s *Store) UnconsumedInviteCount(ctx context.Context, scope opencaravan.InviteScope) (int, error) {
	if s == nil || s.db == nil {
		return 0, errors.New("storage: database is not open")
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	var count int
	err := s.db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM client_app_invites
WHERE scope = ? AND used_time IS NULL AND expiration_time > ?
`, string(scope), now).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("storage: count unconsumed invites: %w", err)
	}
	return count, nil
}

// AccountCount returns the number of rows in the accounts table. Used by
// the bootstrap log-emission path; an empty accounts table is the signal
// that the server has never registered a user.
//
// TODO: rename to UserCount when the accounts table is migrated to align
// with the opencaravan-go vocabulary (account -> user).
func (s *Store) AccountCount(ctx context.Context) (int, error) {
	if s == nil || s.db == nil {
		return 0, errors.New("storage: database is not open")
	}
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM accounts`).Scan(&count); err != nil {
		return 0, fmt.Errorf("storage: count accounts: %w", err)
	}
	return count, nil
}

func (s *Store) lookupInviteByHash(ctx context.Context, hash string) (Invite, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT token_hash, scope, created_time, expiration_time, used_time, used_by_client_app_id
FROM client_app_invites
WHERE token_hash = ?
`, hash)

	var (
		tokenHash      string
		scope          string
		createdTime    string
		expirationTime string
		usedTime       sql.NullString
		usedBy         sql.NullString
	)
	if err := row.Scan(&tokenHash, &scope, &createdTime, &expirationTime, &usedTime, &usedBy); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Invite{}, ErrInviteNotFound
		}
		return Invite{}, fmt.Errorf("storage: load invite: %w", err)
	}

	created, err := time.Parse(time.RFC3339Nano, createdTime)
	if err != nil {
		return Invite{}, fmt.Errorf("storage: parse invite created_time: %w", err)
	}
	expiration, err := time.Parse(time.RFC3339Nano, expirationTime)
	if err != nil {
		return Invite{}, fmt.Errorf("storage: parse invite expiration_time: %w", err)
	}
	invite := Invite{
		TokenHash:      tokenHash,
		Scope:          opencaravan.InviteScope(scope),
		CreatedTime:    created,
		ExpirationTime: expiration,
	}
	if usedTime.Valid {
		used, err := time.Parse(time.RFC3339Nano, usedTime.String)
		if err != nil {
			return Invite{}, fmt.Errorf("storage: parse invite used_time: %w", err)
		}
		invite.UsedTime = &used
	}
	if usedBy.Valid {
		invite.UsedByClientAppID = usedBy.String
	}
	return invite, nil
}

func hashInviteToken(tokenValue string) string {
	sum := sha256.Sum256([]byte(tokenValue))
	return hex.EncodeToString(sum[:])
}
