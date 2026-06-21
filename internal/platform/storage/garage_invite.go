package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/opencaravan/opencaravan-go"
)

// GarageInviteRecord is the persisted shape of a garage invite.
// The plaintext token is returned only on issue; subsequent
// reads see TokenHash. Revoked invites set RevokedAt and remain
// in the table for the audit trail.
type GarageInviteRecord struct {
	ID              string
	GarageID        string
	CreatedByUserID string
	TokenHash       string
	CreatedAt       time.Time
	ExpiresAt       time.Time
	MaxRedemptions  int
	RedemptionCount int
	RevokedAt       *time.Time
}

// GarageInviteRedemptionRecord is the persisted shape of one
// successful redemption.
type GarageInviteRedemptionRecord struct {
	ID             string
	GarageInviteID string
	RedeemerUserID string
	RedeemedAt     time.Time
}

// GarageInviteIssueParams names the input to
// [Store.IssueGarageInvite].
type GarageInviteIssueParams struct {
	GarageID        string
	CreatedByUserID string
	Lifetime        time.Duration
	MaxRedemptions  int
}

// ErrGarageInviteNotFound is returned when no invite matches the
// supplied token / id.
var ErrGarageInviteNotFound = errors.New("storage: garage invite not found")

// ErrGarageInviteExpired is returned when redeem hits an invite
// past its expiration time.
var ErrGarageInviteExpired = errors.New("storage: garage invite expired")

// ErrGarageInviteRevoked is returned when redeem hits a revoked invite.
var ErrGarageInviteRevoked = errors.New("storage: garage invite revoked")

// ErrGarageInviteExhausted is returned when the invite's
// redemption_count has reached max_redemptions.
var ErrGarageInviteExhausted = errors.New("storage: garage invite has reached its redemption limit")

// ErrGarageInviteAlreadyRedeemed is returned when the same user
// tries to redeem the same invite twice.
var ErrGarageInviteAlreadyRedeemed = errors.New("storage: user has already redeemed this garage invite")

// ErrGarageOwnerAlreadyAccepted is returned by
// [Store.RedeemGarageInvite] when the redeemer is already an
// accepted owner of the target garage. Distinct from "redeem
// success" because a duplicate join shouldn't increment the
// redemption count.
var ErrGarageOwnerAlreadyAccepted = errors.New("storage: redeemer is already an accepted owner of the garage")

// IssueGarageInvite mints a fresh invite token and persists its
// metadata. The plaintext token is returned ONCE; only the SHA-256
// hash is stored. Callers must surface the token to the inviter
// immediately and never log it.
func (s *Store) IssueGarageInvite(ctx context.Context, params GarageInviteIssueParams) (opencaravan.InviteToken, GarageInviteRecord, error) {
	if s == nil || s.db == nil {
		return opencaravan.InviteToken{}, GarageInviteRecord{}, errors.New("storage: database is not open")
	}
	if params.GarageID == "" {
		return opencaravan.InviteToken{}, GarageInviteRecord{}, errors.New("storage: garage id must be set")
	}
	if params.CreatedByUserID == "" {
		return opencaravan.InviteToken{}, GarageInviteRecord{}, errors.New("storage: created_by_user_id must be set")
	}
	if params.Lifetime <= 0 {
		return opencaravan.InviteToken{}, GarageInviteRecord{}, errors.New("storage: invite lifetime must be positive")
	}
	if params.MaxRedemptions < 1 {
		return opencaravan.InviteToken{}, GarageInviteRecord{}, errors.New("storage: max_redemptions must be at least 1")
	}

	now := time.Now().UTC()
	expiration := now.Add(params.Lifetime)
	token, err := opencaravan.NewInviteToken(expiration)
	if err != nil {
		return opencaravan.InviteToken{}, GarageInviteRecord{}, fmt.Errorf("storage: mint invite token: %w", err)
	}
	hash := hashInviteToken(token.Value)
	inviteID, err := opencaravan.NewUUID()
	if err != nil {
		return opencaravan.InviteToken{}, GarageInviteRecord{}, fmt.Errorf("storage: mint invite id: %w", err)
	}

	if _, err := s.db.ExecContext(ctx, `
INSERT INTO garage_invites (
    id, garage_id, created_by_user_id, token_hash, created_at,
    expires_at, max_redemptions, redemption_count
) VALUES (?, ?, ?, ?, ?, ?, ?, 0)
`,
		string(inviteID),
		params.GarageID,
		params.CreatedByUserID,
		hash,
		formatSQLiteTime(now),
		formatSQLiteTime(expiration),
		params.MaxRedemptions,
	); err != nil {
		return opencaravan.InviteToken{}, GarageInviteRecord{}, fmt.Errorf("storage: insert garage invite: %w", err)
	}

	return token, GarageInviteRecord{
		ID:              string(inviteID),
		GarageID:        params.GarageID,
		CreatedByUserID: params.CreatedByUserID,
		TokenHash:       hash,
		CreatedAt:       now,
		ExpiresAt:       expiration,
		MaxRedemptions:  params.MaxRedemptions,
		RedemptionCount: 0,
	}, nil
}

// ListGarageInvites returns every invite for the supplied garage,
// including expired/revoked/exhausted rows so the inviter can see
// the full history. Ordered by created_at descending so the most
// recent invites appear first.
func (s *Store) ListGarageInvites(ctx context.Context, garageID string) ([]GarageInviteRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("storage: database is not open")
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, garage_id, created_by_user_id, token_hash, created_at,
       expires_at, max_redemptions, redemption_count, revoked_at
FROM garage_invites
WHERE garage_id = ?
ORDER BY created_at DESC
`, garageID)
	if err != nil {
		return nil, fmt.Errorf("storage: query garage invites: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []GarageInviteRecord
	for rows.Next() {
		rec, err := scanGarageInvite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// RevokeGarageInvite marks an invite revoked. Subsequent redeems
// return [ErrGarageInviteRevoked]. Already-completed redemptions
// remain in place; revocation prevents future ones only.
func (s *Store) RevokeGarageInvite(ctx context.Context, garageID, inviteID string) error {
	if s == nil || s.db == nil {
		return errors.New("storage: database is not open")
	}
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `
UPDATE garage_invites
SET revoked_at = ?
WHERE id = ? AND garage_id = ? AND revoked_at IS NULL
`, formatSQLiteTime(now), inviteID, garageID)
	if err != nil {
		return fmt.Errorf("storage: revoke garage invite: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("storage: read rows affected: %w", err)
	}
	if affected == 0 {
		// Either the invite doesn't exist in this garage, or it's
		// already revoked. Map to not-found — idempotent revoke
		// surfaces as success to the caller in either case.
		var exists bool
		if err := s.db.QueryRowContext(ctx,
			`SELECT 1 FROM garage_invites WHERE id = ? AND garage_id = ?`,
			inviteID, garageID).Scan(&exists); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrGarageInviteNotFound
			}
			return fmt.Errorf("storage: check garage invite existence: %w", err)
		}
		// Existed and was already revoked. Idempotent — return nil.
	}
	return nil
}

// GarageInviteRedemptionResult is what [Store.RedeemGarageInvite]
// returns when redemption succeeds. The redeemer is now an
// accepted owner of the garage; the caller can render the updated
// garage state immediately.
type GarageInviteRedemptionResult struct {
	Invite     GarageInviteRecord
	Redemption GarageInviteRedemptionRecord
}

// RedeemGarageInvite looks up the invite by its plaintext token,
// verifies it's redeemable, records the redemption, and adds the
// redeemer to garage_owners as an accepted owner. All five steps
// happen in one transaction so a partial failure leaves no
// orphans.
//
// Returns:
//
//   - [ErrGarageInviteNotFound] when the token doesn't match.
//   - [ErrGarageInviteExpired] when expires_at has passed.
//   - [ErrGarageInviteRevoked] when revoked_at is set.
//   - [ErrGarageInviteExhausted] when redemption_count == max_redemptions.
//   - [ErrGarageInviteAlreadyRedeemed] when this user redeemed before.
//   - [ErrGarageOwnerAlreadyAccepted] when the redeemer is already
//     a (non-pending) owner of the target garage.
func (s *Store) RedeemGarageInvite(ctx context.Context, tokenValue, redeemerUserID string) (GarageInviteRedemptionResult, error) {
	if s == nil || s.db == nil {
		return GarageInviteRedemptionResult{}, errors.New("storage: database is not open")
	}
	if redeemerUserID == "" {
		return GarageInviteRedemptionResult{}, errors.New("storage: redeemer_user_id must be set")
	}
	hash := hashInviteToken(tokenValue)
	now := time.Now().UTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return GarageInviteRedemptionResult{}, fmt.Errorf("storage: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	invite, err := scanGarageInvite(tx.QueryRowContext(ctx, `
SELECT id, garage_id, created_by_user_id, token_hash, created_at,
       expires_at, max_redemptions, redemption_count, revoked_at
FROM garage_invites
WHERE token_hash = ?
`, hash))
	if err != nil {
		return GarageInviteRedemptionResult{}, err
	}
	if invite.RevokedAt != nil {
		return GarageInviteRedemptionResult{}, ErrGarageInviteRevoked
	}
	if !now.Before(invite.ExpiresAt) {
		return GarageInviteRedemptionResult{}, ErrGarageInviteExpired
	}
	if invite.RedemptionCount >= invite.MaxRedemptions {
		return GarageInviteRedemptionResult{}, ErrGarageInviteExhausted
	}

	// Caller already an accepted owner? Idempotent-no-op short
	// circuit so a double-tap doesn't increment redemption_count
	// (which could exhaust the invite for legitimate redeemers).
	var existingAccepted sql.NullString
	switch err := tx.QueryRowContext(ctx, `
SELECT accepted_time FROM garage_owners
WHERE garage_id = ? AND user_id = ?
`, invite.GarageID, redeemerUserID).Scan(&existingAccepted); {
	case errors.Is(err, sql.ErrNoRows):
		// Not yet an owner — proceed to add.
	case err != nil:
		return GarageInviteRedemptionResult{}, fmt.Errorf("storage: check existing owner: %w", err)
	default:
		if existingAccepted.Valid {
			return GarageInviteRedemptionResult{}, ErrGarageOwnerAlreadyAccepted
		}
		// Owner row exists in pending state (added via a regular
		// garage revision before, never accepted). Promote to
		// accepted via this redemption. Treat as success.
	}

	redemptionID, err := opencaravan.NewUUID()
	if err != nil {
		return GarageInviteRedemptionResult{}, fmt.Errorf("storage: mint redemption id: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO garage_invite_redemptions (
    id, garage_invite_id, redeemer_user_id, redeemed_at
) VALUES (?, ?, ?, ?)
`,
		string(redemptionID),
		invite.ID,
		redeemerUserID,
		formatSQLiteTime(now),
	); err != nil {
		if isUniqueViolation(err) {
			return GarageInviteRedemptionResult{}, ErrGarageInviteAlreadyRedeemed
		}
		return GarageInviteRedemptionResult{}, fmt.Errorf("storage: insert redemption: %w", err)
	}

	// Conditional increment — atomically enforces the redemption
	// limit even under concurrent redeems. Two transactions can
	// both pass the pre-check above and both reach this UPDATE;
	// only one will pass the `redemption_count < max_redemptions`
	// clause. The loser sees RowsAffected = 0 and returns
	// ErrGarageInviteExhausted; the tx rolls back so the
	// redemption row inserted above doesn't land and no owner is
	// added. Matches the conditional-UPDATE pattern used for
	// signed-revision append head pointers.
	res, err := tx.ExecContext(ctx,
		`UPDATE garage_invites
SET redemption_count = redemption_count + 1
WHERE id = ? AND redemption_count < max_redemptions`,
		invite.ID,
	)
	if err != nil {
		return GarageInviteRedemptionResult{}, fmt.Errorf("storage: bump redemption_count: %w", err)
	}
	if affected, affErr := res.RowsAffected(); affErr != nil {
		return GarageInviteRedemptionResult{}, fmt.Errorf("storage: read rows affected: %w", affErr)
	} else if affected == 0 {
		return GarageInviteRedemptionResult{}, ErrGarageInviteExhausted
	}

	// Add (or promote) the redeemer in garage_owners as accepted.
	// added_in_revision_version points at the current head — the
	// pointer is purely informational here because invite-driven
	// adds skip the GarageOwnershipAcceptance flow entirely.
	var currentRevision int
	if err := tx.QueryRowContext(ctx,
		`SELECT current_revision_version FROM garages WHERE id = ?`, invite.GarageID).Scan(&currentRevision); err != nil {
		return GarageInviteRedemptionResult{}, fmt.Errorf("storage: load garage head: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO garage_owners (garage_id, user_id, added_time, added_in_revision_version, accepted_time)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT (garage_id, user_id) DO UPDATE SET accepted_time = excluded.accepted_time
`,
		invite.GarageID,
		redeemerUserID,
		formatSQLiteTime(now),
		currentRevision,
		formatSQLiteTime(now),
	); err != nil {
		return GarageInviteRedemptionResult{}, fmt.Errorf("storage: add/promote owner: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return GarageInviteRedemptionResult{}, fmt.Errorf("storage: commit redemption: %w", err)
	}

	invite.RedemptionCount++
	return GarageInviteRedemptionResult{
		Invite: invite,
		Redemption: GarageInviteRedemptionRecord{
			ID:             string(redemptionID),
			GarageInviteID: invite.ID,
			RedeemerUserID: redeemerUserID,
			RedeemedAt:     now,
		},
	}, nil
}

func scanGarageInvite(row rowScanner) (GarageInviteRecord, error) {
	var (
		rec       GarageInviteRecord
		createdAt string
		expiresAt string
		revokedAt sql.NullString
	)
	if err := row.Scan(&rec.ID, &rec.GarageID, &rec.CreatedByUserID,
		&rec.TokenHash, &createdAt, &expiresAt, &rec.MaxRedemptions,
		&rec.RedemptionCount, &revokedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return GarageInviteRecord{}, ErrGarageInviteNotFound
		}
		return GarageInviteRecord{}, fmt.Errorf("storage: scan garage invite: %w", err)
	}
	parsedCreated, err := time.Parse(sqliteTimeFormat, createdAt)
	if err != nil {
		return GarageInviteRecord{}, fmt.Errorf("storage: parse created_at: %w", err)
	}
	parsedExpires, err := time.Parse(sqliteTimeFormat, expiresAt)
	if err != nil {
		return GarageInviteRecord{}, fmt.Errorf("storage: parse expires_at: %w", err)
	}
	rec.CreatedAt = parsedCreated
	rec.ExpiresAt = parsedExpires
	if revokedAt.Valid {
		rt, err := time.Parse(sqliteTimeFormat, revokedAt.String)
		if err != nil {
			return GarageInviteRecord{}, fmt.Errorf("storage: parse revoked_at: %w", err)
		}
		rec.RevokedAt = &rt
	}
	return rec, nil
}
