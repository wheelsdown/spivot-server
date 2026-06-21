package storage

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestIssueGarageInviteRoundTrip(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	garageID, owner := seedGarageForVehicleTest(t, store)

	token, rec, err := store.IssueGarageInvite(ctx, GarageInviteIssueParams{
		GarageID:        garageID,
		CreatedByUserID: string(owner),
		Lifetime:        time.Hour,
		MaxRedemptions:  1,
	})
	if err != nil {
		t.Fatalf("IssueGarageInvite: %v", err)
	}
	if token.Value == "" {
		t.Fatal("token value is empty")
	}
	if rec.GarageID != garageID {
		t.Fatalf("garage_id: got %q", rec.GarageID)
	}
	if rec.MaxRedemptions != 1 {
		t.Fatalf("max_redemptions: got %d", rec.MaxRedemptions)
	}

	list, err := store.ListGarageInvites(ctx, garageID)
	if err != nil {
		t.Fatalf("ListGarageInvites: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 invite, got %d", len(list))
	}
}

func TestRedeemGarageInviteAddsOwner(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	garageID, owner := seedGarageForVehicleTest(t, store)
	redeemer := mustUUID(t)
	seedAccount(t, store, redeemer)

	token, _, err := store.IssueGarageInvite(ctx, GarageInviteIssueParams{
		GarageID:        garageID,
		CreatedByUserID: string(owner),
		Lifetime:        time.Hour,
		MaxRedemptions:  1,
	})
	if err != nil {
		t.Fatalf("IssueGarageInvite: %v", err)
	}

	result, err := store.RedeemGarageInvite(ctx, token.Value, string(redeemer))
	if err != nil {
		t.Fatalf("RedeemGarageInvite: %v", err)
	}
	if result.Invite.RedemptionCount != 1 {
		t.Fatalf("redemption_count: got %d", result.Invite.RedemptionCount)
	}
	if result.Redemption.RedeemerUserID != string(redeemer) {
		t.Fatalf("redeemer_user_id: got %q", result.Redemption.RedeemerUserID)
	}

	owners, err := store.ListGarageOwners(ctx, garageID)
	if err != nil {
		t.Fatalf("ListGarageOwners: %v", err)
	}
	foundAccepted := false
	for _, o := range owners {
		if o.UserID == string(redeemer) && o.AcceptedTime != nil {
			foundAccepted = true
		}
	}
	if !foundAccepted {
		t.Fatal("redeemer not found as accepted owner")
	}
}

func TestRedeemGarageInviteUnknownToken(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	redeemer := mustUUID(t)
	seedAccount(t, store, redeemer)
	_, err := store.RedeemGarageInvite(ctx, "not-a-real-token", string(redeemer))
	if !errors.Is(err, ErrGarageInviteNotFound) {
		t.Fatalf("got %v, want ErrGarageInviteNotFound", err)
	}
}

func TestRedeemGarageInviteExpired(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	garageID, owner := seedGarageForVehicleTest(t, store)
	redeemer := mustUUID(t)
	seedAccount(t, store, redeemer)

	// Issue with a 1-second lifetime, then directly age the row to make it expired.
	token, rec, err := store.IssueGarageInvite(ctx, GarageInviteIssueParams{
		GarageID:        garageID,
		CreatedByUserID: string(owner),
		Lifetime:        time.Second,
		MaxRedemptions:  1,
	})
	if err != nil {
		t.Fatalf("IssueGarageInvite: %v", err)
	}
	past := time.Now().Add(-time.Hour).UTC()
	if _, err := store.db.ExecContext(ctx,
		`UPDATE garage_invites SET expires_at = ? WHERE id = ?`,
		formatSQLiteTime(past), rec.ID); err != nil {
		t.Fatalf("age invite: %v", err)
	}

	_, err = store.RedeemGarageInvite(ctx, token.Value, string(redeemer))
	if !errors.Is(err, ErrGarageInviteExpired) {
		t.Fatalf("got %v, want ErrGarageInviteExpired", err)
	}
}

func TestRedeemGarageInviteRevoked(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	garageID, owner := seedGarageForVehicleTest(t, store)
	redeemer := mustUUID(t)
	seedAccount(t, store, redeemer)

	token, rec, err := store.IssueGarageInvite(ctx, GarageInviteIssueParams{
		GarageID:        garageID,
		CreatedByUserID: string(owner),
		Lifetime:        time.Hour,
		MaxRedemptions:  1,
	})
	if err != nil {
		t.Fatalf("IssueGarageInvite: %v", err)
	}
	if err := store.RevokeGarageInvite(ctx, garageID, rec.ID); err != nil {
		t.Fatalf("RevokeGarageInvite: %v", err)
	}
	_, err = store.RedeemGarageInvite(ctx, token.Value, string(redeemer))
	if !errors.Is(err, ErrGarageInviteRevoked) {
		t.Fatalf("got %v, want ErrGarageInviteRevoked", err)
	}
}

func TestRedeemGarageInviteAlreadyRedeemedByUser(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	garageID, owner := seedGarageForVehicleTest(t, store)
	redeemer := mustUUID(t)
	seedAccount(t, store, redeemer)

	token, _, err := store.IssueGarageInvite(ctx, GarageInviteIssueParams{
		GarageID:        garageID,
		CreatedByUserID: string(owner),
		Lifetime:        time.Hour,
		MaxRedemptions:  5, // allow multi-redeem so we hit "this user already redeemed" not "exhausted"
	})
	if err != nil {
		t.Fatalf("IssueGarageInvite: %v", err)
	}
	if _, err := store.RedeemGarageInvite(ctx, token.Value, string(redeemer)); err != nil {
		t.Fatalf("first redeem: %v", err)
	}
	// Second redeem by same user — already an accepted owner.
	_, err = store.RedeemGarageInvite(ctx, token.Value, string(redeemer))
	if !errors.Is(err, ErrGarageOwnerAlreadyAccepted) {
		t.Fatalf("got %v, want ErrGarageOwnerAlreadyAccepted", err)
	}
}

func TestRedeemGarageInviteExhausted(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	garageID, owner := seedGarageForVehicleTest(t, store)
	redeemerA := mustUUID(t)
	redeemerB := mustUUID(t)
	seedAccount(t, store, redeemerA)
	seedAccount(t, store, redeemerB)

	token, _, err := store.IssueGarageInvite(ctx, GarageInviteIssueParams{
		GarageID:        garageID,
		CreatedByUserID: string(owner),
		Lifetime:        time.Hour,
		MaxRedemptions:  1, // one-shot
	})
	if err != nil {
		t.Fatalf("IssueGarageInvite: %v", err)
	}
	if _, err := store.RedeemGarageInvite(ctx, token.Value, string(redeemerA)); err != nil {
		t.Fatalf("first redeem: %v", err)
	}
	_, err = store.RedeemGarageInvite(ctx, token.Value, string(redeemerB))
	if !errors.Is(err, ErrGarageInviteExhausted) {
		t.Fatalf("got %v, want ErrGarageInviteExhausted", err)
	}
}

func TestRevokeGarageInviteIdempotent(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	garageID, owner := seedGarageForVehicleTest(t, store)
	_, rec, err := store.IssueGarageInvite(ctx, GarageInviteIssueParams{
		GarageID: garageID, CreatedByUserID: string(owner),
		Lifetime: time.Hour, MaxRedemptions: 1,
	})
	if err != nil {
		t.Fatalf("IssueGarageInvite: %v", err)
	}
	if err := store.RevokeGarageInvite(ctx, garageID, rec.ID); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	// Second revoke should be idempotent (no error).
	if err := store.RevokeGarageInvite(ctx, garageID, rec.ID); err != nil {
		t.Fatalf("second revoke: %v", err)
	}
}

// TestRedeemGarageInviteConditionalIncrementBlocksOverlimit
// deterministically exercises the conditional-UPDATE branch
// in RedeemGarageInvite. Mirrors the PR #29 pattern: simulate a
// concurrent redeem winning the race by pre-incrementing
// redemption_count out-of-band, then attempt the conditional
// UPDATE clause directly. The clause `redemption_count <
// max_redemptions` must see the row at max and return 0 rows
// affected — the storage method maps that to
// ErrGarageInviteExhausted and the tx rolls back so no orphan
// redemption row lands.
func TestRedeemGarageInviteConditionalIncrementBlocksOverlimit(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	garageID, owner := seedGarageForVehicleTest(t, store)
	_, rec, err := store.IssueGarageInvite(ctx, GarageInviteIssueParams{
		GarageID:        garageID,
		CreatedByUserID: string(owner),
		Lifetime:        time.Hour,
		MaxRedemptions:  1,
	})
	if err != nil {
		t.Fatalf("IssueGarageInvite: %v", err)
	}

	// Simulate the winner having committed: bump count to max.
	if _, err := store.db.ExecContext(ctx,
		`UPDATE garage_invites SET redemption_count = max_redemptions WHERE id = ?`, rec.ID); err != nil {
		t.Fatalf("pre-bump: %v", err)
	}

	// Loser: open a manual tx, run the same conditional UPDATE the
	// storage method uses. The clause must block.
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx,
		`UPDATE garage_invites SET redemption_count = redemption_count + 1 WHERE id = ? AND redemption_count < max_redemptions`,
		rec.ID)
	if err != nil {
		t.Fatalf("conditional UPDATE: %v", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		t.Fatalf("RowsAffected: %v", err)
	}
	if affected != 0 {
		t.Fatalf("conditional UPDATE did not block over-limit redeem: got %d, want 0", affected)
	}

	_ = tx.Rollback()

	// Verify count is still at max (the loser's would-be increment didn't land).
	var count int
	if err := store.db.QueryRowContext(ctx,
		`SELECT redemption_count FROM garage_invites WHERE id = ?`, rec.ID).Scan(&count); err != nil {
		t.Fatalf("count query: %v", err)
	}
	if count != rec.MaxRedemptions {
		t.Fatalf("count drifted: got %d want %d", count, rec.MaxRedemptions)
	}
}

// TestGarageInviteCheckConstraintRejectsOverlimit ensures the DB
// CHECK in the migration catches any future code path that tries
// to push redemption_count past max_redemptions, even if the
// application-layer conditional UPDATE is bypassed or buggy.
func TestGarageInviteCheckConstraintRejectsOverlimit(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	garageID, owner := seedGarageForVehicleTest(t, store)
	_, rec, err := store.IssueGarageInvite(ctx, GarageInviteIssueParams{
		GarageID:        garageID,
		CreatedByUserID: string(owner),
		Lifetime:        time.Hour,
		MaxRedemptions:  1,
	})
	if err != nil {
		t.Fatalf("IssueGarageInvite: %v", err)
	}
	// Direct UPDATE bypassing the conditional clause — CHECK should reject.
	_, err = store.db.ExecContext(ctx,
		`UPDATE garage_invites SET redemption_count = 5 WHERE id = ?`, rec.ID)
	if err == nil {
		t.Fatal("expected CHECK violation, got nil error")
	}
}

func TestRevokeGarageInviteWrongGarageIDNotFound(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	garageA, owner := seedGarageForVehicleTest(t, store)
	garageB, _ := seedGarageForVehicleTest(t, store)
	_, rec, err := store.IssueGarageInvite(ctx, GarageInviteIssueParams{
		GarageID: garageA, CreatedByUserID: string(owner),
		Lifetime: time.Hour, MaxRedemptions: 1,
	})
	if err != nil {
		t.Fatalf("IssueGarageInvite: %v", err)
	}
	err = store.RevokeGarageInvite(ctx, garageB, rec.ID)
	if !errors.Is(err, ErrGarageInviteNotFound) {
		t.Fatalf("got %v, want ErrGarageInviteNotFound (invite is in A, not B)", err)
	}
}
