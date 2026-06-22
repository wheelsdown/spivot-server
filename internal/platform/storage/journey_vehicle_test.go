package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/opencaravan/opencaravan-go"
)

func mustUUID(t *testing.T) opencaravan.UUID {
	t.Helper()
	id, err := opencaravan.NewUUID()
	if err != nil {
		t.Fatalf("NewUUID: %v", err)
	}
	return id
}

// seedJourneyForVehicleTest writes the minimum rows the journey
// vehicle storage layer depends on: an accounts row for the owner
// and a journeys row that journey_vehicles.journey_id can reference.
func seedJourneyForVehicleTest(t *testing.T, store *Store) (journeyID string, ownerID opencaravan.UUID) {
	t.Helper()
	owner := mustUUID(t)
	hostID := string(owner)
	seedHostUser(t, store, hostID)
	journey, err := store.CreateJourney(context.Background(), validJourneyParams(hostID))
	if err != nil {
		t.Fatalf("CreateJourney: %v", err)
	}
	return journey.ID, owner
}

// newSignedVehicleBundle builds the Vehicle metadata bundle + the
// initial VehicleACL paired with it, canonicalizes both, and
// attaches placeholder Integrity envelopes. Storage-layer tests
// don't exercise cryptographic verification — that lives in the
// API tier — so a syntactically valid Integrity envelope is
// enough to satisfy Validate().
func newSignedVehicleBundle(t *testing.T, ownerID opencaravan.UUID) (vehicle opencaravan.Vehicle, vehicleCanonical []byte, acl opencaravan.VehicleACL, aclCanonical []byte) {
	t.Helper()
	vehicleID := mustUUID(t)
	authorized := mustUUID(t)
	now := time.Now().UTC()
	vehicle = opencaravan.Vehicle{
		ID:              vehicleID,
		OwnerUserID:     ownerID,
		RevisionVersion: 1,
		RevisionTime:    now,
		DisplayName:     "Riley's Subaru",
		Make:            "Subaru",
		Model:           "Outback",
		ModelYear:       2022,
		Color:           "Autumn Green",
		Capacity:        5,
	}
	var err error
	vehicleCanonical, err = vehicle.CanonicalEncoding()
	if err != nil {
		t.Fatalf("Vehicle CanonicalEncoding: %v", err)
	}
	vehicle.Integrity = &opencaravan.Integrity{
		Algorithm: "ecdsa-p256-sha256",
		KeyID:     string(ownerID),
		Signature: "test-signature-placeholder",
	}

	acl = opencaravan.VehicleACL{
		VehicleID:         vehicleID,
		OwnerUserID:       ownerID,
		ACLVersion:        1,
		AuthorizedDrivers: []opencaravan.UUID{ownerID, authorized},
		EmergencyRule: &opencaravan.VehicleEmergencyRule{
			Kind: opencaravan.VehicleEmergencyRuleAnyJourneyParticipant,
		},
		EffectiveTime: now,
	}
	aclCanonical, err = acl.CanonicalEncoding()
	if err != nil {
		t.Fatalf("VehicleACL CanonicalEncoding: %v", err)
	}
	acl.Integrity = &opencaravan.Integrity{
		Algorithm: "ecdsa-p256-sha256",
		KeyID:     string(ownerID),
		Signature: "test-acl-signature-placeholder",
	}
	return vehicle, vehicleCanonical, acl, aclCanonical
}

func TestCreateJourneyVehicleRoundTrip(t *testing.T) {
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
	if rec.ID != string(vehicle.ID) {
		t.Fatalf("id: got %q want %q", rec.ID, string(vehicle.ID))
	}
	if rec.CurrentRevisionVersion != 1 {
		t.Fatalf("current_revision_version: got %d want 1", rec.CurrentRevisionVersion)
	}
	if rec.CurrentACLVersion != 1 {
		t.Fatalf("current_acl_version: got %d want 1", rec.CurrentACLVersion)
	}
	if string(rec.CanonicalPayloadJSON) != string(vehicleCanonical) {
		t.Fatalf("canonical payload not persisted verbatim")
	}

	got, err := store.JourneyVehicleByID(ctx, journeyID, rec.ID)
	if err != nil {
		t.Fatalf("JourneyVehicleByID: %v", err)
	}
	if got.OwnerUserID != string(ownerID) {
		t.Fatalf("owner_user_id: got %q want %q", got.OwnerUserID, ownerID)
	}
	if string(got.CanonicalPayloadJSON) != string(vehicleCanonical) {
		t.Fatalf("canonical payload mismatch on read-back")
	}
}

func TestCreateJourneyVehicleDuplicateOwnerConflict(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	journeyID, ownerID := seedJourneyForVehicleTest(t, store)
	vehicle, vehicleCanonical, acl, aclCanonical := newSignedVehicleBundle(t, ownerID)
	if _, err := store.CreateJourneyVehicle(ctx, JourneyVehicleCreateParams{
		JourneyID:               journeyID,
		Vehicle:                 vehicle,
		InitialACL:              acl,
		CanonicalVehiclePayload: vehicleCanonical,
		CanonicalACLPayload:     aclCanonical,
	}); err != nil {
		t.Fatalf("first CreateJourneyVehicle: %v", err)
	}

	second, secondCanonical, secondACL, secondACLCanonical := newSignedVehicleBundle(t, ownerID)
	_, err := store.CreateJourneyVehicle(ctx, JourneyVehicleCreateParams{
		JourneyID:               journeyID,
		Vehicle:                 second,
		InitialACL:              secondACL,
		CanonicalVehiclePayload: secondCanonical,
		CanonicalACLPayload:     secondACLCanonical,
	})
	if !errors.Is(err, ErrJourneyVehicleDuplicateOwner) {
		t.Fatalf("got %v, want ErrJourneyVehicleDuplicateOwner", err)
	}
}

func TestJourneyVehicleByIDMissingReturnsSentinel(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	journeyID, _ := seedJourneyForVehicleTest(t, store)
	missing := mustUUID(t)

	_, err := store.JourneyVehicleByID(ctx, journeyID, string(missing))
	if !errors.Is(err, ErrJourneyVehicleNotFound) {
		t.Fatalf("got %v, want ErrJourneyVehicleNotFound", err)
	}
}

func TestListJourneyVehiclesOrdersByReceivedAt(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	journeyID, ownerA := seedJourneyForVehicleTest(t, store)
	ownerB := mustUUID(t)
	seedHostUser(t, store, string(ownerB))

	first, firstCanonical, firstACL, firstACLCanonical := newSignedVehicleBundle(t, ownerA)
	if _, err := store.CreateJourneyVehicle(ctx, JourneyVehicleCreateParams{
		JourneyID:               journeyID,
		Vehicle:                 first,
		InitialACL:              firstACL,
		CanonicalVehiclePayload: firstCanonical,
		CanonicalACLPayload:     firstACLCanonical,
	}); err != nil {
		t.Fatalf("first CreateJourneyVehicle: %v", err)
	}

	time.Sleep(10 * time.Millisecond)

	second, secondCanonical, secondACL, secondACLCanonical := newSignedVehicleBundle(t, ownerB)
	if _, err := store.CreateJourneyVehicle(ctx, JourneyVehicleCreateParams{
		JourneyID:               journeyID,
		Vehicle:                 second,
		InitialACL:              secondACL,
		CanonicalVehiclePayload: secondCanonical,
		CanonicalACLPayload:     secondACLCanonical,
	}); err != nil {
		t.Fatalf("second CreateJourneyVehicle: %v", err)
	}

	got, err := store.ListJourneyVehicles(ctx, journeyID)
	if err != nil {
		t.Fatalf("ListJourneyVehicles: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 vehicles, got %d", len(got))
	}
	if got[0].OwnerUserID != string(ownerA) || got[1].OwnerUserID != string(ownerB) {
		t.Fatalf("ordering wrong: got %v then %v", got[0].OwnerUserID, got[1].OwnerUserID)
	}
}

func TestAppendJourneyVehicleACLAdvancesPointer(t *testing.T) {
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

	newDriver := mustUUID(t)
	v2 := opencaravan.VehicleACL{
		VehicleID:         vehicle.ID,
		OwnerUserID:       ownerID,
		ACLVersion:        2,
		AuthorizedDrivers: []opencaravan.UUID{ownerID, newDriver},
		EmergencyRule: &opencaravan.VehicleEmergencyRule{
			Kind: opencaravan.VehicleEmergencyRuleNone,
		},
		EffectiveTime: time.Now().Add(time.Minute).UTC(),
	}
	v2Canonical, err := v2.CanonicalEncoding()
	if err != nil {
		t.Fatalf("acl CanonicalEncoding: %v", err)
	}
	v2.Integrity = &opencaravan.Integrity{
		Algorithm: "ecdsa-p256-sha256",
		KeyID:     string(ownerID),
		Signature: "test-acl-signature",
	}

	if _, err := store.AppendJourneyVehicleACL(ctx, JourneyVehicleACLAppendParams{
		JourneyVehicleID: rec.ID,
		ACL:              v2,
		CanonicalPayload: v2Canonical,
	}); err != nil {
		t.Fatalf("AppendJourneyVehicleACL: %v", err)
	}

	got, err := store.JourneyVehicleByID(ctx, journeyID, rec.ID)
	if err != nil {
		t.Fatalf("JourneyVehicleByID: %v", err)
	}
	if got.CurrentACLVersion != 2 {
		t.Fatalf("current_acl_version: got %d want 2", got.CurrentACLVersion)
	}
}

func TestAppendJourneyVehicleACLConflictOnDuplicateVersion(t *testing.T) {
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

	dup := opencaravan.VehicleACL{
		VehicleID:         vehicle.ID,
		OwnerUserID:       ownerID,
		ACLVersion:        1,
		AuthorizedDrivers: acl.AuthorizedDrivers,
		EffectiveTime:     time.Now().UTC(),
	}
	dupCanonical, err := dup.CanonicalEncoding()
	if err != nil {
		t.Fatalf("acl CanonicalEncoding: %v", err)
	}
	dup.Integrity = &opencaravan.Integrity{
		Algorithm: "ecdsa-p256-sha256",
		KeyID:     string(ownerID),
		Signature: "test-acl-signature",
	}

	_, err = store.AppendJourneyVehicleACL(ctx, JourneyVehicleACLAppendParams{
		JourneyVehicleID: rec.ID,
		ACL:              dup,
		CanonicalPayload: dupCanonical,
	})
	if !errors.Is(err, ErrJourneyVehicleACLVersionConflict) {
		t.Fatalf("got %v, want ErrJourneyVehicleACLVersionConflict", err)
	}
}

func TestAppendJourneyVehicleACLRejectsStaleVersion(t *testing.T) {
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

	// Advance to v=2.
	v2 := opencaravan.VehicleACL{
		VehicleID:         vehicle.ID,
		OwnerUserID:       ownerID,
		ACLVersion:        2,
		AuthorizedDrivers: acl.AuthorizedDrivers,
		EffectiveTime:     time.Now().Add(time.Minute).UTC(),
	}
	v2Canonical, err := v2.CanonicalEncoding()
	if err != nil {
		t.Fatalf("v2 CanonicalEncoding: %v", err)
	}
	v2.Integrity = &opencaravan.Integrity{
		Algorithm: "ecdsa-p256-sha256",
		KeyID:     string(ownerID),
		Signature: "test-v2",
	}
	if _, err := store.AppendJourneyVehicleACL(ctx, JourneyVehicleACLAppendParams{
		JourneyVehicleID: rec.ID,
		ACL:              v2,
		CanonicalPayload: v2Canonical,
	}); err != nil {
		t.Fatalf("v2 append: %v", err)
	}

	// Now attempt to insert a stale v=1. The strict-monotonic check
	// must reject this even though v=1 already exists in history.
	stale := opencaravan.VehicleACL{
		VehicleID:         vehicle.ID,
		OwnerUserID:       ownerID,
		ACLVersion:        1,
		AuthorizedDrivers: acl.AuthorizedDrivers,
		EffectiveTime:     time.Now().Add(time.Hour).UTC(),
	}
	staleCanonical, err := stale.CanonicalEncoding()
	if err != nil {
		t.Fatalf("stale CanonicalEncoding: %v", err)
	}
	stale.Integrity = &opencaravan.Integrity{
		Algorithm: "ecdsa-p256-sha256",
		KeyID:     string(ownerID),
		Signature: "test-stale",
	}
	_, err = store.AppendJourneyVehicleACL(ctx, JourneyVehicleACLAppendParams{
		JourneyVehicleID: rec.ID,
		ACL:              stale,
		CanonicalPayload: staleCanonical,
	})
	if !errors.Is(err, ErrJourneyVehicleACLVersionConflict) {
		t.Fatalf("got %v, want ErrJourneyVehicleACLVersionConflict", err)
	}

	// Vehicle pointer stayed at v=2.
	got, err := store.JourneyVehicleByID(ctx, journeyID, rec.ID)
	if err != nil {
		t.Fatalf("JourneyVehicleByID: %v", err)
	}
	if got.CurrentACLVersion != 2 {
		t.Fatalf("current_acl_version: got %d want 2", got.CurrentACLVersion)
	}
}

func TestCreateJourneyVehicleRejectsDuplicateID(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	journeyID, ownerA := seedJourneyForVehicleTest(t, store)
	ownerB := mustUUID(t)
	seedHostUser(t, store, string(ownerB))

	first, firstCanonical, firstACL, firstACLCanonical := newSignedVehicleBundle(t, ownerA)
	if _, err := store.CreateJourneyVehicle(ctx, JourneyVehicleCreateParams{
		JourneyID:               journeyID,
		Vehicle:                 first,
		InitialACL:              firstACL,
		CanonicalVehiclePayload: firstCanonical,
		CanonicalACLPayload:     firstACLCanonical,
	}); err != nil {
		t.Fatalf("first CreateJourneyVehicle: %v", err)
	}

	// Second vehicle owned by a different user, reusing the same
	// Vehicle.ID. Must surface as ErrJourneyVehicleDuplicateID
	// rather than DuplicateOwner — the conflict is on the ID,
	// not the (journey, owner) pair.
	second, _, secondACL, _ := newSignedVehicleBundle(t, ownerB)
	second.ID = first.ID
	secondACL.VehicleID = first.ID
	secondCanonical, err := second.CanonicalEncoding()
	if err != nil {
		t.Fatalf("re-canonicalize vehicle: %v", err)
	}
	secondACLCanonical, err := secondACL.CanonicalEncoding()
	if err != nil {
		t.Fatalf("re-canonicalize acl: %v", err)
	}

	_, err = store.CreateJourneyVehicle(ctx, JourneyVehicleCreateParams{
		JourneyID:               journeyID,
		Vehicle:                 second,
		InitialACL:              secondACL,
		CanonicalVehiclePayload: secondCanonical,
		CanonicalACLPayload:     secondACLCanonical,
	})
	if !errors.Is(err, ErrJourneyVehicleDuplicateID) {
		t.Fatalf("got %v, want ErrJourneyVehicleDuplicateID", err)
	}
}

func TestJourneyVehicleACLAtResolvesHistoricalRevision(t *testing.T) {
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

	v1Time := acl.EffectiveTime
	v2Time := v1Time.Add(time.Hour)

	v2NewDriver := mustUUID(t)
	v2 := opencaravan.VehicleACL{
		VehicleID:         vehicle.ID,
		OwnerUserID:       ownerID,
		ACLVersion:        2,
		AuthorizedDrivers: []opencaravan.UUID{ownerID, v2NewDriver},
		EffectiveTime:     v2Time,
	}
	v2Canonical, err := v2.CanonicalEncoding()
	if err != nil {
		t.Fatalf("v2 CanonicalEncoding: %v", err)
	}
	v2.Integrity = &opencaravan.Integrity{
		Algorithm: "ecdsa-p256-sha256",
		KeyID:     string(ownerID),
		Signature: "test-v2-signature",
	}
	if _, err := store.AppendJourneyVehicleACL(ctx, JourneyVehicleACLAppendParams{
		JourneyVehicleID: rec.ID,
		ACL:              v2,
		CanonicalPayload: v2Canonical,
	}); err != nil {
		t.Fatalf("AppendJourneyVehicleACL v2: %v", err)
	}

	// Attestation effective between v1 and v2 must resolve to v1.
	between := v1Time.Add(30 * time.Minute)
	gotV1, err := store.JourneyVehicleACLAt(ctx, rec.ID, between)
	if err != nil {
		t.Fatalf("JourneyVehicleACLAt v1: %v", err)
	}
	if gotV1.ACLVersion != 1 {
		t.Fatalf("at %s expected v1, got v%d", between, gotV1.ACLVersion)
	}

	// Attestation effective after v2 must resolve to v2.
	after := v2Time.Add(time.Minute)
	gotV2, err := store.JourneyVehicleACLAt(ctx, rec.ID, after)
	if err != nil {
		t.Fatalf("JourneyVehicleACLAt v2: %v", err)
	}
	if gotV2.ACLVersion != 2 {
		t.Fatalf("at %s expected v2, got v%d", after, gotV2.ACLVersion)
	}
}

func TestAppendJourneyVehicleRevisionAdvancesPointer(t *testing.T) {
	// New endpoint companion to AppendJourneyVehicleACL but for the
	// Vehicle metadata bundle. Confirms that publishing a v=2
	// metadata revision moves current_revision_version forward and
	// updates the canonical payload that JourneyVehicleByID returns.
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

	v2 := vehicle
	v2.RevisionVersion = 2
	v2.RevisionTime = time.Now().Add(time.Minute).UTC()
	v2.DisplayName = "Renamed Subaru"
	v2.Integrity = nil
	v2Canonical, err := v2.CanonicalEncoding()
	if err != nil {
		t.Fatalf("v2 CanonicalEncoding: %v", err)
	}
	v2.Integrity = &opencaravan.Integrity{
		Algorithm: "ecdsa-p256-sha256",
		KeyID:     string(ownerID),
		Signature: "test-v2",
	}

	if _, err := store.AppendJourneyVehicleRevision(ctx, JourneyVehicleRevisionAppendParams{
		JourneyVehicleID: rec.ID,
		Vehicle:          v2,
		CanonicalPayload: v2Canonical,
	}); err != nil {
		t.Fatalf("AppendJourneyVehicleRevision: %v", err)
	}

	got, err := store.JourneyVehicleByID(ctx, journeyID, rec.ID)
	if err != nil {
		t.Fatalf("JourneyVehicleByID: %v", err)
	}
	if got.CurrentRevisionVersion != 2 {
		t.Fatalf("current_revision_version: got %d want 2", got.CurrentRevisionVersion)
	}
	if string(got.CanonicalPayloadJSON) != string(v2Canonical) {
		t.Fatalf("head canonical payload not updated to v2")
	}
}

func TestAppendJourneyVehicleRevisionRejectsStaleVersion(t *testing.T) {
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

	stale := vehicle
	stale.Integrity = nil
	staleCanonical, err := stale.CanonicalEncoding()
	if err != nil {
		t.Fatalf("stale CanonicalEncoding: %v", err)
	}
	stale.Integrity = &opencaravan.Integrity{
		Algorithm: "ecdsa-p256-sha256",
		KeyID:     string(ownerID),
		Signature: "test-stale",
	}
	_, err = store.AppendJourneyVehicleRevision(ctx, JourneyVehicleRevisionAppendParams{
		JourneyVehicleID: rec.ID,
		Vehicle:          stale,
		CanonicalPayload: staleCanonical,
	})
	if !errors.Is(err, ErrJourneyVehicleRevisionConflict) {
		t.Fatalf("got %v, want ErrJourneyVehicleRevisionConflict", err)
	}
}
