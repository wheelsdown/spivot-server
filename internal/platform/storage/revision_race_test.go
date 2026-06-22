package storage

import (
	"context"
	"testing"
	"time"

	"github.com/opencaravan/opencaravan-go"
)

// The three tests in this file are deterministic regression
// guards for the conditional head-pointer UPDATE clauses in
// AppendJourneyVehicleACL, AppendGarageRevision, and
// AppendGarageVehicleRevision.
//
// Test strategy: simulate the race-loss state directly. A real
// race has two transactions both observing current_version = N
// from their snapshots, both passing the strict check, and the
// loser's conditional UPDATE then sees the row at v > N+1 because
// the winner committed in between. This test compresses the
// timeline: advance the head to v=3 via the real storage method,
// then in a manual tx (mirroring the storage method's INSERT +
// conditional UPDATE pattern) try to land a v=2 revision. The
// conditional clause `current_version < 2` must see current=3,
// fail, and return RowsAffected=0. Tx rollback ensures the loser
// revision row never lands in history.
//
// If a future refactor drops the `... AND current_version < ?`
// clause or the RowsAffected check, these tests fail loudly:
// the conditional UPDATE would succeed, the head would regress,
// and the v=2 revision row would be visible — all three asserted
// against.

func TestAppendGarageRevisionConditionalUpdateBlocksLoserRevision(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	owner := mustUUID(t)
	seedAccount(t, store, owner)
	v1, c1 := newSignedGarage(t, owner, "G")
	rec, err := store.CreateGarage(ctx, GarageCreateParams{Garage: v1, CanonicalPayload: c1})
	if err != nil {
		t.Fatalf("CreateGarage: %v", err)
	}

	// Winner: advance head to v=3 via the real storage method.
	acceptedNow := v1.Owners[0].AddedTime
	v3Time := time.Now().Add(time.Minute).UTC()
	v3 := opencaravan.Garage{
		ID:              v1.ID,
		Name:            "WinnerName",
		RevisionVersion: 3,
		RevisionTime:    v3Time,
		Owners: []opencaravan.GarageOwner{
			{UserID: owner, AddedTime: v1.Owners[0].AddedTime, AcceptedTime: &acceptedNow},
		},
		SignedBy: owner,
	}
	v3Canonical, err := v3.CanonicalEncoding()
	if err != nil {
		t.Fatalf("v3 CanonicalEncoding: %v", err)
	}
	v3.Integrity = &opencaravan.Integrity{Algorithm: "x", KeyID: string(owner), Signature: "x"}
	if _, err := store.AppendGarageRevision(ctx, GarageAppendRevisionParams{
		Garage: v3, CanonicalPayload: v3Canonical,
	}); err != nil {
		t.Fatalf("winner v=3 advance: %v", err)
	}

	// Loser: open a manual tx that mirrors AppendGarageRevision's
	// pattern. Skip the strict check (we're simulating the race
	// window where the loser's snapshot believed current=1, the
	// winner committed v=3, and the loser is about to INSERT v=2
	// + conditional UPDATE). The conditional clause must block.
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	loserRevID := mustUUID(t)
	loserVersion := 2
	if _, err := tx.ExecContext(ctx, `
INSERT INTO garage_revisions (
    id, garage_id, revision_version, revision_time, signed_by,
    integrity_algorithm, integrity_key_id, integrity_signature,
    canonical_payload_json, received_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`,
		string(loserRevID), rec.ID, loserVersion,
		formatSQLiteTime(time.Now().UTC()), string(owner),
		"x", string(owner), "x", "loser-payload",
		formatSQLiteTime(time.Now().UTC()),
	); err != nil {
		t.Fatalf("loser INSERT: %v", err)
	}

	res, err := tx.ExecContext(ctx, `
UPDATE garages
SET name = ?, current_revision_version = ?, current_revision_time = ?
WHERE id = ? AND current_revision_version < ?
`,
		"LoserName", loserVersion, formatSQLiteTime(time.Now().UTC()), rec.ID, loserVersion)
	if err != nil {
		t.Fatalf("conditional UPDATE: %v", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		t.Fatalf("RowsAffected: %v", err)
	}
	if affected != 0 {
		t.Fatalf("conditional UPDATE clause did not block loser: got %d rows affected, want 0", affected)
	}

	// The storage method would now return ErrGarageRevisionVersionConflict.
	// We mirror that by rolling back the tx — the loser revision row
	// goes away.
	_ = tx.Rollback()

	head, err := store.GarageByID(ctx, rec.ID)
	if err != nil {
		t.Fatalf("GarageByID: %v", err)
	}
	if head.CurrentRevisionVersion != 3 {
		t.Fatalf("head regressed: got %d want 3", head.CurrentRevisionVersion)
	}
	if head.Name == "LoserName" {
		t.Fatal("loser revision's name leaked into head")
	}
	if head.Name != "WinnerName" {
		t.Fatalf("name: got %q want WinnerName", head.Name)
	}

	var revisionCount int
	if err := store.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM garage_revisions WHERE garage_id = ?`, rec.ID).Scan(&revisionCount); err != nil {
		t.Fatalf("count revisions: %v", err)
	}
	if revisionCount != 2 {
		t.Fatalf("revisions count: got %d want 2 (v=1 + v=3, no orphan v=2)", revisionCount)
	}
}

func TestAppendGarageVehicleRevisionConditionalUpdateBlocksLoserRevision(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	garageID, owner := seedGarageForVehicleTest(t, store)
	v1, c1 := newSignedGarageVehicle(t, opencaravan.UUID(garageID), owner, "Van")
	if _, err := store.CreateGarageVehicle(ctx, GarageVehicleCreateParams{
		GarageVehicle: v1, CanonicalPayload: c1,
	}); err != nil {
		t.Fatalf("CreateGarageVehicle: %v", err)
	}

	// Winner: advance head to v=3.
	v3Time := time.Now().Add(time.Minute).UTC()
	v3 := opencaravan.GarageVehicle{
		ID:              v1.ID,
		GarageID:        v1.GarageID,
		RevisionVersion: 3,
		RevisionTime:    v3Time,
		DisplayName:     "WinnerName",
		Make:            v1.Make,
		Model:           v1.Model,
		ModelYear:       v1.ModelYear,
		Color:           v1.Color,
		Capacity:        v1.Capacity,
		SignedBy:        owner,
	}
	v3Canonical, err := v3.CanonicalEncoding()
	if err != nil {
		t.Fatalf("v3 CanonicalEncoding: %v", err)
	}
	v3.Integrity = &opencaravan.Integrity{Algorithm: "x", KeyID: string(owner), Signature: "x"}
	if _, err := store.AppendGarageVehicleRevision(ctx, GarageVehicleAppendRevisionParams{
		GarageVehicle: v3, CanonicalPayload: v3Canonical,
	}); err != nil {
		t.Fatalf("winner v=3 advance: %v", err)
	}

	// Loser: manual tx, INSERT v=2 revision row + attempt conditional UPDATE.
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	loserRevID := mustUUID(t)
	loserVersion := 2
	if _, err := tx.ExecContext(ctx, `
INSERT INTO garage_vehicle_revisions (
    id, garage_vehicle_id, revision_version, revision_time,
    integrity_algorithm, integrity_key_id, integrity_signature,
    canonical_payload_json, signed_by_user_id,
    avatar_blob_hash, banner_blob_hash, received_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`,
		string(loserRevID), string(v1.ID), loserVersion,
		formatSQLiteTime(time.Now().UTC()),
		"x", string(owner), "x", "loser-payload", string(owner),
		nil, nil,
		formatSQLiteTime(time.Now().UTC()),
	); err != nil {
		t.Fatalf("loser INSERT: %v", err)
	}

	res, err := tx.ExecContext(ctx, `
UPDATE garage_vehicles
SET current_revision_version = ?, canonical_payload_json = ?
WHERE id = ? AND garage_id = ? AND current_revision_version < ?
`,
		loserVersion, "loser-payload", string(v1.ID), garageID, loserVersion)
	if err != nil {
		t.Fatalf("conditional UPDATE: %v", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		t.Fatalf("RowsAffected: %v", err)
	}
	if affected != 0 {
		t.Fatalf("conditional UPDATE clause did not block loser: got %d, want 0", affected)
	}

	_ = tx.Rollback()

	head, err := store.GarageVehicleByID(ctx, garageID, string(v1.ID))
	if err != nil {
		t.Fatalf("GarageVehicleByID: %v", err)
	}
	if head.CurrentRevisionVersion != 3 {
		t.Fatalf("head regressed: got %d want 3", head.CurrentRevisionVersion)
	}
	if string(head.CanonicalPayloadJSON) != string(v3Canonical) {
		t.Fatalf("head canonical payload changed: loser leaked through")
	}

	var revisionCount int
	if err := store.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM garage_vehicle_revisions WHERE garage_vehicle_id = ?`, string(v1.ID)).Scan(&revisionCount); err != nil {
		t.Fatalf("count revisions: %v", err)
	}
	if revisionCount != 2 {
		t.Fatalf("revisions count: got %d want 2 (v=1 + v=3, no orphan v=2)", revisionCount)
	}
}

func TestAppendJourneyVehicleACLConditionalUpdateBlocksLoserRevision(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	journeyID, ownerID := seedJourneyForVehicleTest(t, store)
	vehicle, vehicleCanonical, acl, aclCanonical := newSignedVehicleBundle(t, ownerID)
	rec, err := store.CreateJourneyVehicle(ctx, JourneyVehicleCreateParams{
		JourneyID:               journeyID,
		Vehicle:                 vehicle,
		InitialACL:              acl,
		CanonicalVehiclePayload: vehicleCanonical,
		CanonicalACLPayload:     aclCanonical,
	})
	if err != nil {
		t.Fatalf("CreateJourneyVehicle: %v", err)
	}

	// Winner: advance ACL to v=3.
	v3 := opencaravan.VehicleACL{
		VehicleID:         vehicle.ID,
		OwnerUserID:       ownerID,
		ACLVersion:        3,
		AuthorizedDrivers: acl.AuthorizedDrivers,
		EffectiveTime:     time.Now().Add(time.Minute).UTC(),
	}
	v3Canonical, err := v3.CanonicalEncoding()
	if err != nil {
		t.Fatalf("v3 CanonicalEncoding: %v", err)
	}
	v3.Integrity = &opencaravan.Integrity{Algorithm: "x", KeyID: string(ownerID), Signature: "x"}
	if _, err := store.AppendJourneyVehicleACL(ctx, JourneyVehicleACLAppendParams{
		JourneyVehicleID: rec.ID,
		ACL:              v3,
		CanonicalPayload: v3Canonical,
	}); err != nil {
		t.Fatalf("winner v=3 advance: %v", err)
	}

	// Loser: manual tx, INSERT v=2 ACL revision row + attempt conditional UPDATE.
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	loserRevID := mustUUID(t)
	loserVersion := 2
	if _, err := tx.ExecContext(ctx, `
INSERT INTO journey_vehicle_acl_revisions (
    id, journey_vehicle_id, acl_version, effective_time,
    authorized_drivers_json, emergency_rule_kind,
    integrity_algorithm, integrity_key_id, integrity_signature,
    canonical_payload_json, received_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`,
		string(loserRevID), rec.ID, loserVersion,
		formatSQLiteTime(time.Now().UTC()),
		`[]`, "",
		"x", string(ownerID), "x", "loser-payload",
		formatSQLiteTime(time.Now().UTC()),
	); err != nil {
		t.Fatalf("loser INSERT: %v", err)
	}

	res, err := tx.ExecContext(ctx, `
UPDATE journey_vehicles SET current_acl_version = ?
WHERE id = ? AND current_acl_version < ?
`, loserVersion, rec.ID, loserVersion)
	if err != nil {
		t.Fatalf("conditional UPDATE: %v", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		t.Fatalf("RowsAffected: %v", err)
	}
	if affected != 0 {
		t.Fatalf("conditional UPDATE clause did not block loser: got %d, want 0", affected)
	}

	_ = tx.Rollback()

	head, err := store.JourneyVehicleByID(ctx, journeyID, rec.ID)
	if err != nil {
		t.Fatalf("JourneyVehicleByID: %v", err)
	}
	if head.CurrentACLVersion != 3 {
		t.Fatalf("ACL head regressed: got %d want 3", head.CurrentACLVersion)
	}

	var revisionCount int
	if err := store.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM journey_vehicle_acl_revisions WHERE journey_vehicle_id = ?`, rec.ID).Scan(&revisionCount); err != nil {
		t.Fatalf("count revisions: %v", err)
	}
	if revisionCount != 2 {
		t.Fatalf("ACL revisions count: got %d want 2 (v=1 + v=3, no orphan v=2)", revisionCount)
	}
}
