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

func newSignedVehicle(t *testing.T, ownerID opencaravan.UUID) (opencaravan.Vehicle, []byte) {
	t.Helper()
	vehicleID := mustUUID(t)
	authorized := mustUUID(t)
	v := opencaravan.Vehicle{
		ID:                vehicleID,
		DisplayName:       "Riley's Subaru",
		Make:              "Subaru",
		Model:             "Outback",
		ModelYear:         2022,
		Color:             "Autumn Green",
		OwnerUserID:       ownerID,
		Capacity:          5,
		AuthorizedDrivers: []opencaravan.UUID{ownerID, authorized},
		ACLVersion:        1,
		EmergencyRule: &opencaravan.VehicleEmergencyRule{
			Kind: opencaravan.VehicleEmergencyRuleAnyJourneyParticipant,
		},
	}
	canonical, err := v.CanonicalEncoding()
	if err != nil {
		t.Fatalf("CanonicalEncoding: %v", err)
	}
	v.Integrity = &opencaravan.Integrity{
		Algorithm: "ecdsa-p256-sha256",
		KeyID:     string(ownerID),
		Signature: "test-signature-placeholder",
	}
	return v, canonical
}

func TestCreateJourneyVehicleRoundTrip(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	journeyID, ownerID := seedJourneyForVehicleTest(t, store)
	vehicle, canonical := newSignedVehicle(t, ownerID)

	rec, err := store.CreateJourneyVehicle(ctx, JourneyVehicleCreateParams{
		JourneyID:        journeyID,
		Vehicle:          vehicle,
		CanonicalPayload: canonical,
	})
	if err != nil {
		t.Fatalf("CreateJourneyVehicle: %v", err)
	}
	if rec.ID != string(vehicle.ID) {
		t.Fatalf("id: got %q want %q", rec.ID, string(vehicle.ID))
	}
	if rec.CurrentACLVersion != 1 {
		t.Fatalf("current_acl_version: got %d want 1", rec.CurrentACLVersion)
	}
	if rec.EmergencyRuleKind != string(opencaravan.VehicleEmergencyRuleAnyJourneyParticipant) {
		t.Fatalf("emergency_rule_kind: got %q want %q", rec.EmergencyRuleKind, opencaravan.VehicleEmergencyRuleAnyJourneyParticipant)
	}
	if string(rec.CanonicalPayload) != string(canonical) {
		t.Fatalf("canonical payload not persisted verbatim")
	}

	got, err := store.JourneyVehicleByID(ctx, journeyID, rec.ID)
	if err != nil {
		t.Fatalf("JourneyVehicleByID: %v", err)
	}
	if got.DisplayName != "Riley's Subaru" {
		t.Fatalf("DisplayName: got %q", got.DisplayName)
	}
	if got.Capacity != 5 {
		t.Fatalf("Capacity: got %d want 5", got.Capacity)
	}
	if got.ModelYear != 2022 {
		t.Fatalf("ModelYear: got %d want 2022", got.ModelYear)
	}
}

func TestCreateJourneyVehicleDuplicateOwnerConflict(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	journeyID, ownerID := seedJourneyForVehicleTest(t, store)
	vehicle, canonical := newSignedVehicle(t, ownerID)
	if _, err := store.CreateJourneyVehicle(ctx, JourneyVehicleCreateParams{
		JourneyID:        journeyID,
		Vehicle:          vehicle,
		CanonicalPayload: canonical,
	}); err != nil {
		t.Fatalf("first CreateJourneyVehicle: %v", err)
	}

	second, secondCanonical := newSignedVehicle(t, ownerID)
	_, err := store.CreateJourneyVehicle(ctx, JourneyVehicleCreateParams{
		JourneyID:        journeyID,
		Vehicle:          second,
		CanonicalPayload: secondCanonical,
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

func TestListJourneyVehiclesOrdersByCreatedAt(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	journeyID, ownerA := seedJourneyForVehicleTest(t, store)
	ownerB := mustUUID(t)
	seedHostUser(t, store, string(ownerB))

	first, firstCanonical := newSignedVehicle(t, ownerA)
	if _, err := store.CreateJourneyVehicle(ctx, JourneyVehicleCreateParams{
		JourneyID:        journeyID,
		Vehicle:          first,
		CanonicalPayload: firstCanonical,
	}); err != nil {
		t.Fatalf("first CreateJourneyVehicle: %v", err)
	}

	time.Sleep(10 * time.Millisecond)

	second, secondCanonical := newSignedVehicle(t, ownerB)
	if _, err := store.CreateJourneyVehicle(ctx, JourneyVehicleCreateParams{
		JourneyID:        journeyID,
		Vehicle:          second,
		CanonicalPayload: secondCanonical,
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
	vehicle, canonical := newSignedVehicle(t, ownerID)
	rec, err := store.CreateJourneyVehicle(ctx, JourneyVehicleCreateParams{
		JourneyID:        journeyID,
		Vehicle:          vehicle,
		CanonicalPayload: canonical,
	})
	if err != nil {
		t.Fatalf("CreateJourneyVehicle: %v", err)
	}

	newDriver := mustUUID(t)
	acl := opencaravan.VehicleACL{
		VehicleID:         vehicle.ID,
		OwnerUserID:       ownerID,
		ACLVersion:        2,
		AuthorizedDrivers: []opencaravan.UUID{ownerID, newDriver},
		EmergencyRule: &opencaravan.VehicleEmergencyRule{
			Kind: opencaravan.VehicleEmergencyRuleNone,
		},
		EffectiveTime: time.Now().Add(time.Minute).UTC(),
	}
	aclCanonical, err := acl.CanonicalEncoding()
	if err != nil {
		t.Fatalf("acl CanonicalEncoding: %v", err)
	}
	acl.Integrity = &opencaravan.Integrity{
		Algorithm: "ecdsa-p256-sha256",
		KeyID:     string(ownerID),
		Signature: "test-acl-signature",
	}

	if _, err := store.AppendJourneyVehicleACL(ctx, JourneyVehicleACLAppendParams{
		JourneyVehicleID: rec.ID,
		ACL:              acl,
		CanonicalPayload: aclCanonical,
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
	if got.EmergencyRuleKind != string(opencaravan.VehicleEmergencyRuleNone) {
		t.Fatalf("emergency_rule_kind: got %q want %q", got.EmergencyRuleKind, opencaravan.VehicleEmergencyRuleNone)
	}
}

func TestAppendJourneyVehicleACLConflictOnDuplicateVersion(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	journeyID, ownerID := seedJourneyForVehicleTest(t, store)
	vehicle, canonical := newSignedVehicle(t, ownerID)
	rec, err := store.CreateJourneyVehicle(ctx, JourneyVehicleCreateParams{
		JourneyID:        journeyID,
		Vehicle:          vehicle,
		CanonicalPayload: canonical,
	})
	if err != nil {
		t.Fatalf("CreateJourneyVehicle: %v", err)
	}

	acl := opencaravan.VehicleACL{
		VehicleID:         vehicle.ID,
		OwnerUserID:       ownerID,
		ACLVersion:        1,
		AuthorizedDrivers: vehicle.AuthorizedDrivers,
		EffectiveTime:     time.Now().UTC(),
	}
	aclCanonical, err := acl.CanonicalEncoding()
	if err != nil {
		t.Fatalf("acl CanonicalEncoding: %v", err)
	}
	acl.Integrity = &opencaravan.Integrity{
		Algorithm: "ecdsa-p256-sha256",
		KeyID:     string(ownerID),
		Signature: "test-acl-signature",
	}

	_, err = store.AppendJourneyVehicleACL(ctx, JourneyVehicleACLAppendParams{
		JourneyVehicleID: rec.ID,
		ACL:              acl,
		CanonicalPayload: aclCanonical,
	})
	if !errors.Is(err, ErrJourneyVehicleACLVersionConflict) {
		t.Fatalf("got %v, want ErrJourneyVehicleACLVersionConflict", err)
	}
}

func TestJourneyVehicleACLAtResolvesHistoricalRevision(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	journeyID, ownerID := seedJourneyForVehicleTest(t, store)
	vehicle, canonical := newSignedVehicle(t, ownerID)
	rec, err := store.CreateJourneyVehicle(ctx, JourneyVehicleCreateParams{
		JourneyID:        journeyID,
		Vehicle:          vehicle,
		CanonicalPayload: canonical,
	})
	if err != nil {
		t.Fatalf("CreateJourneyVehicle: %v", err)
	}

	v1Time := rec.CreatedAt
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
