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

// Invite is the server-side record of an invite token that has been issued
// against the client_app_invites table.
//
// The plaintext token value is never stored — only its SHA-256 hash, the
// scope it authorizes, and lifecycle timestamps. Callers who receive an
// Invite from [Store.IssueInvite], [Store.LookupInvite], or
// [Store.ConsumeInvite] hold a complete snapshot of the row; the type
// carries no shared state and is safe to share across goroutines.
//
// The lifecycle is linear: issued → optionally consumed (single-use) →
// eventually expired. UsedTime is non-nil exactly when the invite has
// been consumed; UsedByClientAppID names the ClientApp that consumed it.
// Expiration is purely time-based; an unconsumed but expired invite
// remains in the table until an operator prunes it.
type Invite struct {
	// TokenHash is the lowercase hex SHA-256 of the plaintext token value
	// and serves as the primary key of the underlying row. The plaintext
	// is intentionally unrecoverable from this record.
	TokenHash string
	// Scope identifies what action the invite authorizes. Values are drawn
	// from [opencaravan.InviteScope] and persisted as their wire string.
	Scope opencaravan.InviteScope
	// CreatedTime is the RFC3339 UTC time the invite was issued.
	CreatedTime time.Time
	// ExpirationTime is the RFC3339 UTC time after which redemption fails
	// with [ErrInviteExpired].
	ExpirationTime time.Time
	// UsedTime is non-nil exactly when the invite has been consumed.
	UsedTime *time.Time
	// UsedByClientAppID is the ClientApp that consumed the invite,
	// populated atomically alongside UsedTime.
	UsedByClientAppID string
}

// Active reports whether the invite is currently redeemable: not yet used
// and not yet expired as of now. Callers pass an explicit now to keep the
// check deterministic in tests.
func (i Invite) Active(now time.Time) bool {
	if i.UsedTime != nil {
		return false
	}
	return now.Before(i.ExpirationTime)
}

// sqliteTimeFormat is a fixed-width RFC3339 layout for persisting
// timestamps as TEXT in SQLite. SQLite compares TEXT lexicographically;
// time.RFC3339Nano produces variable-width fractional seconds (a
// timestamp with zero nanoseconds renders without any fractional part
// at all), which breaks string ordering against timestamps with finer
// precision. Nine fractional digits + a literal Z suffix make every
// stored value the same width, so `expiration_time > ?` comparisons
// behave correctly across the entire valid timestamp range.
const sqliteTimeFormat = "2006-01-02T15:04:05.000000000Z"

// formatSQLiteTime renders t for storage in or comparison against a
// SQLite TEXT timestamp column. Always uses UTC and a fixed-width
// nanosecond representation; see [sqliteTimeFormat].
func formatSQLiteTime(t time.Time) string {
	return t.UTC().Format(sqliteTimeFormat)
}

// ErrInviteNotFound is returned (wrapped via [fmt.Errorf] with %w where
// the call site has helpful context) when no row in client_app_invites
// matches the supplied token's hash. Callers detect this via [errors.Is].
var ErrInviteNotFound = errors.New("storage: invite not found")

// ErrInviteAlreadyUsed is returned by [Store.LookupInvite] and
// [Store.ConsumeInvite] when the row exists but its UsedTime is already
// set. Single-use is enforced at the storage layer via the conditional
// UPDATE inside ConsumeInvite, so this is the canonical "second caller
// lost the race" signal.
var ErrInviteAlreadyUsed = errors.New("storage: invite already used")

// ErrInviteExpired is returned by [Store.LookupInvite] and
// [Store.ConsumeInvite] when the row exists, is unused, but its
// ExpirationTime has passed. Expired invites are not auto-deleted.
var ErrInviteExpired = errors.New("storage: invite expired")

// IssueInvite generates a fresh invite token of the requested scope and
// persists it.
//
// The plaintext token is returned to the caller; only the SHA-256 hash
// is stored. The plaintext is the caller's single chance to display,
// log, or share the token — once IssueInvite returns, the hash is the
// only record of it. Token bytes follow the OpenCaravan convention:
// 256 bits of [crypto/rand] entropy encoded as unpadded base64url via
// [opencaravan.NewInviteToken].
//
// Concurrent IssueInvite calls are independent. Each generates its own
// random token, each produces a distinct TokenHash, and the PRIMARY KEY
// on token_hash means any (astronomically unlikely) collision surfaces
// as a SQL error rather than as a silent overwrite. Two parallel admin
// operations can each successfully issue a server_registration invite
// without coordination — this is the intended pattern.
//
// Returns an error if the store is closed, scope is not a known
// [opencaravan.InviteScope], lifetime is non-positive, or the insert
// fails.
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
`, hash, string(scope), formatSQLiteTime(now), formatSQLiteTime(expiration)); err != nil {
		return opencaravan.InviteToken{}, Invite{}, fmt.Errorf("storage: record invite: %w", err)
	}

	return token, Invite{
		TokenHash:      hash,
		Scope:          scope,
		CreatedTime:    now,
		ExpirationTime: expiration,
	}, nil
}

// LookupInvite returns the Invite whose stored hash matches tokenValue,
// without mutating any row. Used as a read-only check (for example, to
// display expiry to the caller) before [Store.ConsumeInvite] commits the
// redeem.
//
// The "redeemable" semantics ride along in the return: an active invite
// returns a nil error; an existing-but-used row returns the loaded
// Invite plus [ErrInviteAlreadyUsed]; an existing-but-expired row
// returns the loaded Invite plus [ErrInviteExpired]; an unknown token
// returns [ErrInviteNotFound] and a zero Invite.
//
// The expiration check is "now" relative to the wall clock at call
// time; an unexpired LookupInvite return does not guarantee a subsequent
// ConsumeInvite will succeed if the call straddles the expiration
// boundary. Callers that need exact atomicity rely on ConsumeInvite
// directly.
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
// used by clientAppID and returns the resulting Invite.
//
// Atomicity is provided by a single conditional UPDATE: the row is
// mutated in one SQL statement only when its used_time is still NULL and
// its expiration_time is still in the future. Two concurrent
// ConsumeInvite calls for the same token cannot both succeed; exactly
// one observes rows-affected == 1, the other observes zero and gets
// [ErrInviteAlreadyUsed]. The same guarantee holds across multiple
// processes against the same SQLite database thanks to SQLite's
// per-statement transactional semantics.
//
// Returns [ErrInviteNotFound], [ErrInviteAlreadyUsed], or
// [ErrInviteExpired] when the invite cannot be redeemed, or an error
// wrapping the underlying SQL failure for transport-level problems.
// clientAppID must be non-empty.
func (s *Store) ConsumeInvite(ctx context.Context, tokenValue string, clientAppID string) (Invite, error) {
	if s == nil || s.db == nil {
		return Invite{}, errors.New("storage: database is not open")
	}
	if clientAppID == "" {
		return Invite{}, errors.New("storage: client app id must be set when consuming invite")
	}

	hash := hashInviteToken(tokenValue)
	now := time.Now().UTC()
	nowStr := formatSQLiteTime(now)

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
// unexpired) invites with the requested scope.
//
// The returned count is a snapshot at the time of the SELECT; concurrent
// IssueInvite or ConsumeInvite operations can change the underlying
// value the instant the function returns. The bootstrap-emission path
// in cmd/spivot-server treats a zero result as "no invite has been
// issued yet" and proceeds to issue one; two parallel zero observations
// produce two harmless bootstrap invites rather than any correctness
// problem.
func (s *Store) UnconsumedInviteCount(ctx context.Context, scope opencaravan.InviteScope) (int, error) {
	if s == nil || s.db == nil {
		return 0, errors.New("storage: database is not open")
	}

	now := formatSQLiteTime(time.Now())
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

// AccountCount returns the number of rows in the accounts table.
//
// The bootstrap-emission path uses this as the "has this server ever
// registered a user?" signal: a zero count combined with zero unconsumed
// server_registration invites triggers a fresh bootstrap invite.
//
// The helper still names "accounts" because that is the table created by
// the initial migration; a later phase renames accounts → users to align
// with the opencaravan-go vocabulary, at which point this becomes
// UserCount with identical shape.
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

// lookupInviteByHash loads the persisted row keyed by hash without
// applying any "is it redeemable now?" interpretation. Shared by
// LookupInvite (which adds the time/used checks afterward) and the
// rows-affected==0 fallback in ConsumeInvite (which needs the existing
// row's state to distinguish ErrInviteAlreadyUsed from ErrInviteExpired).
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

	created, err := time.Parse(sqliteTimeFormat,createdTime)
	if err != nil {
		return Invite{}, fmt.Errorf("storage: parse invite created_time: %w", err)
	}
	expiration, err := time.Parse(sqliteTimeFormat,expirationTime)
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
		used, err := time.Parse(sqliteTimeFormat,usedTime.String)
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

// hashInviteToken returns the lowercase hex SHA-256 of tokenValue.
//
// Plain SHA-256 (not HMAC) is sufficient here because the input is a
// uniformly-random 256-bit value generated by [opencaravan.NewInviteToken]
// — preimage and collision resistance are equivalent to the underlying
// entropy, and there is no attacker-chosen-input path that an HMAC key
// would defend. No salt: the token is its own entropy source, and a
// deterministic plaintext→hash mapping is what lets ConsumeInvite
// locate the row.
func hashInviteToken(tokenValue string) string {
	sum := sha256.Sum256([]byte(tokenValue))
	return hex.EncodeToString(sum[:])
}
