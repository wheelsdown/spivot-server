package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/opencaravan/opencaravan-go"
)

// seedGarageForVehicleTest provisions a garage owned by `owner`
// (already an accepted owner at v=1). Returns garageID + ownerID
// so tests can build GarageVehicles against it without repeating
// the create boilerplate.
func seedGarageForVehicleTest(t *testing.T, store *Store) (garageID string, ownerID opencaravan.UUID) {
	t.Helper()
	owner := mustUUID(t)
	seedAccount(t, store, owner)
	garage, canonical := newSignedGarage(t, owner, "Test Garage")
	rec, err := store.CreateGarage(context.Background(), GarageCreateParams{
		Garage:           garage,
		CanonicalPayload: canonical,
	})
	if err != nil {
		t.Fatalf("CreateGarage: %v", err)
	}
	return rec.ID, owner
}

func newSignedGarageVehicle(t *testing.T, garageID opencaravan.UUID, ownerID opencaravan.UUID, displayName string) (opencaravan.GarageVehicle, []byte) {
	t.Helper()
	vehicleID := mustUUID(t)
	now := time.Now().UTC()
	gv := opencaravan.GarageVehicle{
		ID:              vehicleID,
		GarageID:        garageID,
		RevisionVersion: 1,
		RevisionTime:    now,
		DisplayName:     displayName,
		Make:            "Toyota",
		Model:           "Sienna",
		ModelYear:       2024,
		Color:           "Blueprint Blue",
		Capacity:        7,
		SignedBy:        ownerID,
	}
	canonical, err := gv.CanonicalEncoding()
	if err != nil {
		t.Fatalf("CanonicalEncoding: %v", err)
	}
	gv.Integrity = &opencaravan.Integrity{
		Algorithm: "ecdsa-p256-sha256",
		KeyID:     string(ownerID),
		Signature: "test-garage-vehicle-signature",
	}
	return gv, canonical
}

func TestCreateGarageVehicleRoundTrip(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	garageID, ownerID := seedGarageForVehicleTest(t, store)
	gv, canonical := newSignedGarageVehicle(t, opencaravan.UUID(garageID), ownerID, "Family Van")
	rec, err := store.CreateGarageVehicle(ctx, GarageVehicleCreateParams{
		GarageVehicle:    gv,
		CanonicalPayload: canonical,
	})
	if err != nil {
		t.Fatalf("CreateGarageVehicle: %v", err)
	}
	if rec.CurrentRevisionVersion != 1 {
		t.Fatalf("revision: got %d", rec.CurrentRevisionVersion)
	}
	if rec.SignedByUserID != string(ownerID) {
		t.Fatalf("signed_by_user_id: got %q want %q", rec.SignedByUserID, ownerID)
	}
	if string(rec.CanonicalPayloadJSON) != string(canonical) {
		t.Fatalf("canonical payload not persisted verbatim")
	}

	got, err := store.GarageVehicleByID(ctx, garageID, rec.ID)
	if err != nil {
		t.Fatalf("GarageVehicleByID: %v", err)
	}
	if got.CurrentRevisionVersion != 1 {
		t.Fatalf("read-back revision: got %d", got.CurrentRevisionVersion)
	}
	if string(got.CanonicalPayloadJSON) != string(canonical) {
		t.Fatalf("read-back canonical payload mismatch")
	}
}

func TestAppendGarageVehicleRevisionAdvancesHead(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	garageID, ownerID := seedGarageForVehicleTest(t, store)
	gv, canonical := newSignedGarageVehicle(t, opencaravan.UUID(garageID), ownerID, "Original Name")
	if _, err := store.CreateGarageVehicle(ctx, GarageVehicleCreateParams{
		GarageVehicle:    gv,
		CanonicalPayload: canonical,
	}); err != nil {
		t.Fatalf("CreateGarageVehicle: %v", err)
	}

	// v=2 with renamed display + bumped capacity.
	v2Time := time.Now().Add(time.Minute).UTC()
	v2 := opencaravan.GarageVehicle{
		ID:              gv.ID,
		GarageID:        gv.GarageID,
		RevisionVersion: 2,
		RevisionTime:    v2Time,
		DisplayName:     "Renamed Van",
		Make:            gv.Make,
		Model:           gv.Model,
		ModelYear:       gv.ModelYear,
		Color:           gv.Color,
		Capacity:        8,
		SignedBy:        ownerID,
	}
	v2Canonical, err := v2.CanonicalEncoding()
	if err != nil {
		t.Fatalf("v2 CanonicalEncoding: %v", err)
	}
	v2.Integrity = &opencaravan.Integrity{
		Algorithm: "ecdsa-p256-sha256",
		KeyID:     string(ownerID),
		Signature: "v2",
	}
	if _, err := store.AppendGarageVehicleRevision(ctx, GarageVehicleAppendRevisionParams{
		GarageVehicle:    v2,
		CanonicalPayload: v2Canonical,
	}); err != nil {
		t.Fatalf("AppendGarageVehicleRevision: %v", err)
	}

	got, err := store.GarageVehicleByID(ctx, garageID, string(gv.ID))
	if err != nil {
		t.Fatalf("GarageVehicleByID: %v", err)
	}
	if got.CurrentRevisionVersion != 2 {
		t.Fatalf("revision: got %d want 2", got.CurrentRevisionVersion)
	}
	if string(got.CanonicalPayloadJSON) != string(v2Canonical) {
		t.Fatalf("head canonical payload not updated to v2")
	}
}

func TestAppendGarageVehicleRevisionRejectsStaleVersion(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	garageID, ownerID := seedGarageForVehicleTest(t, store)
	gv, canonical := newSignedGarageVehicle(t, opencaravan.UUID(garageID), ownerID, "G")
	if _, err := store.CreateGarageVehicle(ctx, GarageVehicleCreateParams{
		GarageVehicle:    gv,
		CanonicalPayload: canonical,
	}); err != nil {
		t.Fatalf("CreateGarageVehicle: %v", err)
	}
	stale := gv
	stale.Integrity = nil
	staleCanonical, err := stale.CanonicalEncoding()
	if err != nil {
		t.Fatalf("re-canonical: %v", err)
	}
	stale.Integrity = &opencaravan.Integrity{
		Algorithm: "ecdsa-p256-sha256",
		KeyID:     string(ownerID),
		Signature: "x",
	}
	_, err = store.AppendGarageVehicleRevision(ctx, GarageVehicleAppendRevisionParams{
		GarageVehicle:    stale,
		CanonicalPayload: staleCanonical,
	})
	if !errors.Is(err, ErrGarageVehicleRevisionVersionConflict) {
		t.Fatalf("got %v, want ErrGarageVehicleRevisionVersionConflict", err)
	}
}

func TestGarageVehicleByIDMissingReturnsSentinel(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	garageID, _ := seedGarageForVehicleTest(t, store)
	missing := mustUUID(t)
	_, err := store.GarageVehicleByID(ctx, garageID, string(missing))
	if !errors.Is(err, ErrGarageVehicleNotFound) {
		t.Fatalf("got %v, want ErrGarageVehicleNotFound", err)
	}
}

func TestListGarageVehiclesOrdersByReceivedAt(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	garageID, ownerID := seedGarageForVehicleTest(t, store)
	ids := make([]string, 0, 3)
	for _, name := range []string{"First", "Second", "Third"} {
		gv, canonical := newSignedGarageVehicle(t, opencaravan.UUID(garageID), ownerID, name)
		if _, err := store.CreateGarageVehicle(ctx, GarageVehicleCreateParams{
			GarageVehicle:    gv,
			CanonicalPayload: canonical,
		}); err != nil {
			t.Fatalf("CreateGarageVehicle %q: %v", name, err)
		}
		ids = append(ids, string(gv.ID))
		// Sleep so received_at progresses (sqliteTimeFormat is fixed-precision nanos).
		time.Sleep(2 * time.Millisecond)
	}

	got, err := store.ListGarageVehicles(ctx, garageID)
	if err != nil {
		t.Fatalf("ListGarageVehicles: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 vehicles, got %d", len(got))
	}
	if got[0].ID != ids[0] || got[2].ID != ids[2] {
		t.Fatalf("ordering wrong: got %q ... %q", got[0].ID, got[2].ID)
	}
}

func TestAppendGarageVehicleRevisionRejectsWrongGarageID(t *testing.T) {
	// Defense in depth: the storage method must enforce
	// (id, garage_id) scoping even if a malformed payload reaches
	// it. The handler already checks GarageID, but storage
	// shouldn't trust callers.
	store := openTestStore(t)
	ctx := context.Background()

	garageA, ownerA := seedGarageForVehicleTest(t, store)
	garageB, _ := seedGarageForVehicleTest(t, store)
	gv, canonical := newSignedGarageVehicle(t, opencaravan.UUID(garageA), ownerA, "In A")
	if _, err := store.CreateGarageVehicle(ctx, GarageVehicleCreateParams{
		GarageVehicle:    gv,
		CanonicalPayload: canonical,
	}); err != nil {
		t.Fatalf("CreateGarageVehicle: %v", err)
	}

	// Attempt to append a v=2 revision claiming garage B as
	// the container. Must return not-found, not silently
	// mutate the row in garage A.
	v2Time := time.Now().Add(time.Minute).UTC()
	wrong := opencaravan.GarageVehicle{
		ID:              gv.ID,
		GarageID:        opencaravan.UUID(garageB), // wrong
		RevisionVersion: 2,
		RevisionTime:    v2Time,
		DisplayName:     "Spoofed",
		Capacity:        7,
		SignedBy:        ownerA,
	}
	wrongCanonical, err := wrong.CanonicalEncoding()
	if err != nil {
		t.Fatalf("wrong CanonicalEncoding: %v", err)
	}
	wrong.Integrity = &opencaravan.Integrity{
		Algorithm: "ecdsa-p256-sha256",
		KeyID:     string(ownerA),
		Signature: "x",
	}
	_, err = store.AppendGarageVehicleRevision(ctx, GarageVehicleAppendRevisionParams{
		GarageVehicle:    wrong,
		CanonicalPayload: wrongCanonical,
	})
	if !errors.Is(err, ErrGarageVehicleNotFound) {
		t.Fatalf("got %v, want ErrGarageVehicleNotFound (wrong garage_id should miss)", err)
	}

	// Confirm garage A's vehicle still at v=1, untouched.
	got, err := store.GarageVehicleByID(ctx, garageA, string(gv.ID))
	if err != nil {
		t.Fatalf("GarageVehicleByID: %v", err)
	}
	if got.CurrentRevisionVersion != 1 {
		t.Fatalf("vehicle in garage A mutated: revision = %d", got.CurrentRevisionVersion)
	}
	if string(got.CanonicalPayloadJSON) != string(canonical) {
		t.Fatalf("vehicle in garage A canonical payload changed")
	}
}

func TestGarageVehicleByIDScopedToGarage(t *testing.T) {
	// A vehicle from garage A should NOT be findable via garage B's
	// lookup. Defends against a caller using a vehicle id they
	// happen to know to read a vehicle from a garage they don't
	// own.
	store := openTestStore(t)
	ctx := context.Background()

	garageA, ownerA := seedGarageForVehicleTest(t, store)
	garageB, _ := seedGarageForVehicleTest(t, store)
	gv, canonical := newSignedGarageVehicle(t, opencaravan.UUID(garageA), ownerA, "In A")
	if _, err := store.CreateGarageVehicle(ctx, GarageVehicleCreateParams{
		GarageVehicle:    gv,
		CanonicalPayload: canonical,
	}); err != nil {
		t.Fatalf("CreateGarageVehicle: %v", err)
	}
	_, err := store.GarageVehicleByID(ctx, garageB, string(gv.ID))
	if !errors.Is(err, ErrGarageVehicleNotFound) {
		t.Fatalf("got %v, want ErrGarageVehicleNotFound (vehicle from A leaked through B's lookup)", err)
	}
}
