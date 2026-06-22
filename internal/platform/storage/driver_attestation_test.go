package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/opencaravan/opencaravan-go"
)

// seedJourneyVehicleForAttestation provisions a journey with one
// uploaded Vehicle so attestations have a real journey_vehicle_id
// to target. Returns the journey id, the vehicle id, and the
// owner's UUID (which the helper makes the vehicle's
// AuthorizedDrivers root member, so attestations against the
// owner classify as authorized in tests that opt to set
// driver_user_id = owner).
func seedJourneyVehicleForAttestation(t *testing.T, store *Store) (journeyID, vehicleID string, ownerID opencaravan.UUID) {
	t.Helper()
	jID, owner := seedJourneyForVehicleTest(t, store)
	vehicle, vehicleCanonical, acl, aclCanonical := newSignedVehicleBundle(t, owner)
	rec, err := store.CreateJourneyVehicle(context.Background(), JourneyVehicleCreateParams{
		JourneyID:               jID,
		Vehicle:                 vehicle,
		InitialACL:              acl,
		CanonicalVehiclePayload: vehicleCanonical,
		CanonicalACLPayload:     aclCanonical,
	})
	if err != nil {
		t.Fatalf("CreateJourneyVehicle: %v", err)
	}
	return jID, rec.ID, owner
}

func newSignedAttestation(t *testing.T, vehicleID opencaravan.UUID, driverID opencaravan.UUID, effective time.Time, aclVersion int, priorHash *string) (opencaravan.DriverAttestation, []byte) {
	t.Helper()
	segmentID := mustUUID(t)
	a := opencaravan.DriverAttestation{
		VehicleID:            vehicleID,
		SegmentID:            segmentID,
		DriverUserID:         driverID,
		EffectiveTime:        effective,
		ACLVersionConsulted:  aclVersion,
		PriorAttestationHash: priorHash,
	}
	canonical, err := a.CanonicalEncoding()
	if err != nil {
		t.Fatalf("CanonicalEncoding: %v", err)
	}
	a.Integrity = &opencaravan.Integrity{
		Algorithm: "ecdsa-p256-sha256",
		KeyID:     string(driverID),
		Signature: "test-attestation-signature",
	}
	return a, canonical
}

func TestRecordDriverAttestationRoundTrip(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	_, vehicleID, ownerID := seedJourneyVehicleForAttestation(t, store)

	effective := time.Now().Add(time.Minute).UTC()
	attestation, canonical := newSignedAttestation(t, opencaravan.UUID(vehicleID), ownerID, effective, 1, nil)

	rec, err := store.RecordDriverAttestation(ctx, DriverAttestationRecordParams{
		Attestation:      attestation,
		JourneyVehicleID: vehicleID,
		TrustFlag:        DriverAttestationTrustAuthorized,
		CanonicalPayload: canonical,
	})
	if err != nil {
		t.Fatalf("RecordDriverAttestation: %v", err)
	}
	if rec.JourneyVehicleID != vehicleID {
		t.Fatalf("journey_vehicle_id: got %q want %q", rec.JourneyVehicleID, vehicleID)
	}
	if rec.DriverUserID != string(ownerID) {
		t.Fatalf("driver_user_id: got %q", rec.DriverUserID)
	}
	if rec.TrustFlag != DriverAttestationTrustAuthorized {
		t.Fatalf("trust_flag: got %q", rec.TrustFlag)
	}
	if rec.ACLVersionConsulted != 1 {
		t.Fatalf("acl_version_consulted: got %d", rec.ACLVersionConsulted)
	}
}

func TestRecordDriverAttestationDuplicateReturnsSentinel(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	_, vehicleID, ownerID := seedJourneyVehicleForAttestation(t, store)

	effective := time.Now().Add(time.Minute).UTC()
	a1, c1 := newSignedAttestation(t, opencaravan.UUID(vehicleID), ownerID, effective, 1, nil)
	if _, err := store.RecordDriverAttestation(ctx, DriverAttestationRecordParams{
		Attestation:      a1,
		JourneyVehicleID: vehicleID,
		TrustFlag:        DriverAttestationTrustAuthorized,
		CanonicalPayload: c1,
	}); err != nil {
		t.Fatalf("first RecordDriverAttestation: %v", err)
	}

	a2, c2 := newSignedAttestation(t, opencaravan.UUID(vehicleID), ownerID, effective, 1, nil)
	_, err := store.RecordDriverAttestation(ctx, DriverAttestationRecordParams{
		Attestation:      a2,
		JourneyVehicleID: vehicleID,
		TrustFlag:        DriverAttestationTrustAuthorized,
		CanonicalPayload: c2,
	})
	if !errors.Is(err, ErrDriverAttestationDuplicate) {
		t.Fatalf("got %v, want ErrDriverAttestationDuplicate", err)
	}

	// The original record is still retrievable via the replay key.
	existing, err := store.DriverAttestationByReplayKey(ctx, vehicleID, string(ownerID), effective)
	if err != nil {
		t.Fatalf("DriverAttestationByReplayKey: %v", err)
	}
	if existing.DriverUserID != string(ownerID) {
		t.Fatalf("replay lookup: got driver %q", existing.DriverUserID)
	}
}

func TestListDriverAttestationsOrderedByEffectiveTime(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	_, vehicleID, ownerID := seedJourneyVehicleForAttestation(t, store)

	t0 := time.Now().UTC()
	for i, delta := range []time.Duration{2 * time.Minute, 5 * time.Minute, 1 * time.Minute} {
		effective := t0.Add(delta)
		a, c := newSignedAttestation(t, opencaravan.UUID(vehicleID), ownerID, effective, 1, nil)
		if _, err := store.RecordDriverAttestation(ctx, DriverAttestationRecordParams{
			Attestation:      a,
			JourneyVehicleID: vehicleID,
			TrustFlag:        DriverAttestationTrustAuthorized,
			CanonicalPayload: c,
		}); err != nil {
			t.Fatalf("record #%d: %v", i, err)
		}
	}

	got, err := store.ListDriverAttestations(ctx, vehicleID)
	if err != nil {
		t.Fatalf("ListDriverAttestations: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(got))
	}
	for i := 1; i < len(got); i++ {
		if !got[i].EffectiveTime.After(got[i-1].EffectiveTime) {
			t.Fatalf("not sorted ascending: %v then %v", got[i-1].EffectiveTime, got[i].EffectiveTime)
		}
	}
}

func TestDriverAttestationForkSiblingsFindsMatchingPriorHash(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	_, vehicleID, ownerID := seedJourneyVehicleForAttestation(t, store)
	driver2 := mustUUID(t)
	seedHostUser(t, store, string(driver2))

	priorHash := "sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	t0 := time.Now().Add(time.Minute).UTC()
	a1, c1 := newSignedAttestation(t, opencaravan.UUID(vehicleID), ownerID, t0, 1, &priorHash)
	if _, err := store.RecordDriverAttestation(ctx, DriverAttestationRecordParams{
		Attestation:      a1,
		JourneyVehicleID: vehicleID,
		TrustFlag:        DriverAttestationTrustAuthorized,
		CanonicalPayload: c1,
	}); err != nil {
		t.Fatalf("record a1: %v", err)
	}

	// A second attestation by a different driver claiming the SAME
	// predecessor — that's a fork.
	a2, c2 := newSignedAttestation(t, opencaravan.UUID(vehicleID), driver2, t0.Add(time.Second), 1, &priorHash)
	if _, err := store.RecordDriverAttestation(ctx, DriverAttestationRecordParams{
		Attestation:      a2,
		JourneyVehicleID: vehicleID,
		TrustFlag:        DriverAttestationTrustACLViolation,
		CanonicalPayload: c2,
	}); err != nil {
		t.Fatalf("record a2: %v", err)
	}

	siblings, err := store.DriverAttestationForkSiblings(ctx, vehicleID, priorHash)
	if err != nil {
		t.Fatalf("DriverAttestationForkSiblings: %v", err)
	}
	if len(siblings) != 2 {
		t.Fatalf("expected 2 fork siblings, got %d", len(siblings))
	}
}

func TestCurrentDriverForJourneyVehicleResolvesAtTime(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	_, vehicleID, ownerID := seedJourneyVehicleForAttestation(t, store)
	driverB := mustUUID(t)
	seedHostUser(t, store, string(driverB))

	t0 := time.Now().UTC()
	// v=1 by owner at t0 + 1 min
	a1, c1 := newSignedAttestation(t, opencaravan.UUID(vehicleID), ownerID, t0.Add(time.Minute), 1, nil)
	if _, err := store.RecordDriverAttestation(ctx, DriverAttestationRecordParams{
		Attestation: a1, JourneyVehicleID: vehicleID,
		TrustFlag: DriverAttestationTrustAuthorized, CanonicalPayload: c1,
	}); err != nil {
		t.Fatalf("a1: %v", err)
	}
	// v=2 by driverB at t0 + 5 min — supersedes a1 as the current driver.
	a2, c2 := newSignedAttestation(t, opencaravan.UUID(vehicleID), driverB, t0.Add(5*time.Minute), 1, nil)
	if _, err := store.RecordDriverAttestation(ctx, DriverAttestationRecordParams{
		Attestation: a2, JourneyVehicleID: vehicleID,
		TrustFlag: DriverAttestationTrustAuthorized, CanonicalPayload: c2,
	}); err != nil {
		t.Fatalf("a2: %v", err)
	}

	// At t0 + 3 min: a1 is current.
	gotA1, err := store.CurrentDriverForJourneyVehicle(ctx, vehicleID, t0.Add(3*time.Minute))
	if err != nil {
		t.Fatalf("CurrentDriverForJourneyVehicle a1: %v", err)
	}
	if gotA1.DriverUserID != string(ownerID) {
		t.Fatalf("at t+3min: expected owner, got %q", gotA1.DriverUserID)
	}

	// At t0 + 10 min: a2 is current.
	gotA2, err := store.CurrentDriverForJourneyVehicle(ctx, vehicleID, t0.Add(10*time.Minute))
	if err != nil {
		t.Fatalf("CurrentDriverForJourneyVehicle a2: %v", err)
	}
	if gotA2.DriverUserID != string(driverB) {
		t.Fatalf("at t+10min: expected driverB, got %q", gotA2.DriverUserID)
	}
}

func TestCurrentDriverForJourneyVehicleBeforeAnyAttestation(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	_, vehicleID, ownerID := seedJourneyVehicleForAttestation(t, store)

	// Record one attestation 10 minutes from now.
	future := time.Now().Add(10 * time.Minute).UTC()
	a, c := newSignedAttestation(t, opencaravan.UUID(vehicleID), ownerID, future, 1, nil)
	if _, err := store.RecordDriverAttestation(ctx, DriverAttestationRecordParams{
		Attestation: a, JourneyVehicleID: vehicleID,
		TrustFlag: DriverAttestationTrustAuthorized, CanonicalPayload: c,
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	// Query before the attestation — nothing in effect yet.
	_, err := store.CurrentDriverForJourneyVehicle(ctx, vehicleID, time.Now().UTC())
	if !errors.Is(err, ErrDriverAttestationNotFound) {
		t.Fatalf("got %v, want ErrDriverAttestationNotFound", err)
	}
}

func TestDriverAttestationByReplayKeyMissing(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	_, vehicleID, _ := seedJourneyVehicleForAttestation(t, store)

	missing := mustUUID(t)
	_, err := store.DriverAttestationByReplayKey(ctx, vehicleID, string(missing), time.Now().UTC())
	if !errors.Is(err, ErrDriverAttestationNotFound) {
		t.Fatalf("got %v, want ErrDriverAttestationNotFound", err)
	}
}

func TestRecordDriverAttestationRejectsUnknownTrustFlag(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	_, vehicleID, ownerID := seedJourneyVehicleForAttestation(t, store)

	a, c := newSignedAttestation(t, opencaravan.UUID(vehicleID), ownerID, time.Now().UTC(), 1, nil)
	_, err := store.RecordDriverAttestation(ctx, DriverAttestationRecordParams{
		Attestation:      a,
		JourneyVehicleID: vehicleID,
		TrustFlag:        DriverAttestationTrust("nonsense"),
		CanonicalPayload: c,
	})
	if err == nil {
		t.Fatal("expected error for unknown trust flag, got nil")
	}
}
