package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/opencaravan/opencaravan-go"
)

func newSignedGarage(t *testing.T, ownerID opencaravan.UUID, name string, additionalOwners ...opencaravan.GarageOwner) (opencaravan.Garage, []byte) {
	t.Helper()
	now := time.Now().UTC()
	garageID := mustUUID(t)
	acceptedNow := now
	owners := []opencaravan.GarageOwner{
		{UserID: ownerID, AddedTime: now, AcceptedTime: &acceptedNow},
	}
	owners = append(owners, additionalOwners...)
	g := opencaravan.Garage{
		ID:              garageID,
		Name:            name,
		RevisionVersion: 1,
		RevisionTime:    now,
		Owners:          owners,
		SignedBy:        ownerID,
	}
	canonical, err := g.CanonicalEncoding()
	if err != nil {
		t.Fatalf("CanonicalEncoding: %v", err)
	}
	g.Integrity = &opencaravan.Integrity{
		Algorithm: "ecdsa-p256-sha256",
		KeyID:     string(ownerID),
		Signature: "test-garage-signature",
	}
	return g, canonical
}

// seedAccount creates an accounts row for the supplied user so FK
// references in subsequent inserts succeed. Thin wrapper over
// seedHostUser so the garage-test call sites stay terse.
func seedAccount(t *testing.T, store *Store, userID opencaravan.UUID) {
	t.Helper()
	seedHostUser(t, store, string(userID))
}

func TestCreateGarageRoundTrip(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	owner := mustUUID(t)
	seedAccount(t, store, owner)

	garage, canonical := newSignedGarage(t, owner, "Riley's Garage")
	rec, err := store.CreateGarage(ctx, GarageCreateParams{
		Garage:           garage,
		CanonicalPayload: canonical,
	})
	if err != nil {
		t.Fatalf("CreateGarage: %v", err)
	}
	if rec.ID != string(garage.ID) {
		t.Fatalf("id mismatch: got %q want %q", rec.ID, garage.ID)
	}
	if rec.Name != "Riley's Garage" {
		t.Fatalf("name: got %q", rec.Name)
	}
	if rec.CurrentRevisionVersion != 1 {
		t.Fatalf("revision version: got %d", rec.CurrentRevisionVersion)
	}

	got, err := store.GarageByID(ctx, rec.ID)
	if err != nil {
		t.Fatalf("GarageByID: %v", err)
	}
	if got.Name != "Riley's Garage" {
		t.Fatalf("get: name %q", got.Name)
	}

	owners, err := store.ListGarageOwners(ctx, rec.ID)
	if err != nil {
		t.Fatalf("ListGarageOwners: %v", err)
	}
	if len(owners) != 1 {
		t.Fatalf("expected 1 owner, got %d", len(owners))
	}
	if owners[0].AcceptedTime == nil {
		t.Fatal("creator should be accepted at create time")
	}
}

func TestAppendGarageRevisionAddsPendingOwner(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	owner := mustUUID(t)
	invitee := mustUUID(t)
	seedAccount(t, store, owner)
	seedAccount(t, store, invitee)

	garage, canonical := newSignedGarage(t, owner, "Household Garage")
	rec, err := store.CreateGarage(ctx, GarageCreateParams{
		Garage:           garage,
		CanonicalPayload: canonical,
	})
	if err != nil {
		t.Fatalf("CreateGarage: %v", err)
	}

	// v=2 adds the invitee as pending (AcceptedTime nil).
	now := time.Now().Add(time.Minute).UTC()
	acceptedNow := garage.Owners[0].AddedTime
	v2 := opencaravan.Garage{
		ID:              garage.ID,
		Name:            garage.Name,
		RevisionVersion: 2,
		RevisionTime:    now,
		Owners: []opencaravan.GarageOwner{
			{UserID: owner, AddedTime: garage.Owners[0].AddedTime, AcceptedTime: &acceptedNow},
			{UserID: invitee, AddedTime: now}, // pending
		},
		SignedBy: owner,
	}
	v2Canonical, err := v2.CanonicalEncoding()
	if err != nil {
		t.Fatalf("v2 CanonicalEncoding: %v", err)
	}
	v2.Integrity = &opencaravan.Integrity{
		Algorithm: "ecdsa-p256-sha256",
		KeyID:     string(owner),
		Signature: "test-v2-signature",
	}
	if _, err := store.AppendGarageRevision(ctx, GarageAppendRevisionParams{
		Garage:           v2,
		CanonicalPayload: v2Canonical,
	}); err != nil {
		t.Fatalf("AppendGarageRevision: %v", err)
	}

	got, err := store.GarageByID(ctx, rec.ID)
	if err != nil {
		t.Fatalf("GarageByID: %v", err)
	}
	if got.CurrentRevisionVersion != 2 {
		t.Fatalf("revision version: got %d want 2", got.CurrentRevisionVersion)
	}

	owners, err := store.ListGarageOwners(ctx, rec.ID)
	if err != nil {
		t.Fatalf("ListGarageOwners: %v", err)
	}
	if len(owners) != 2 {
		t.Fatalf("expected 2 owners, got %d", len(owners))
	}
	for _, o := range owners {
		if o.UserID == string(invitee) && o.AcceptedTime != nil {
			t.Fatal("invitee should still be pending")
		}
	}
}

func TestAppendGarageRevisionRejectsStaleVersion(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	owner := mustUUID(t)
	seedAccount(t, store, owner)
	garage, canonical := newSignedGarage(t, owner, "G")
	if _, err := store.CreateGarage(ctx, GarageCreateParams{Garage: garage, CanonicalPayload: canonical}); err != nil {
		t.Fatalf("CreateGarage: %v", err)
	}

	// Re-publish v=1.
	stale := garage
	staleCanonical, err := stale.CanonicalEncoding()
	if err != nil {
		t.Fatalf("re-canonical: %v", err)
	}
	stale.Integrity = &opencaravan.Integrity{
		Algorithm: "ecdsa-p256-sha256",
		KeyID:     string(owner),
		Signature: "x",
	}
	_, err = store.AppendGarageRevision(ctx, GarageAppendRevisionParams{
		Garage:           stale,
		CanonicalPayload: staleCanonical,
	})
	if !errors.Is(err, ErrGarageRevisionVersionConflict) {
		t.Fatalf("got %v, want ErrGarageRevisionVersionConflict", err)
	}
}

func TestAcceptGarageOwnershipMovesPendingToAccepted(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	owner := mustUUID(t)
	invitee := mustUUID(t)
	seedAccount(t, store, owner)
	seedAccount(t, store, invitee)

	garage, canonical := newSignedGarage(t, owner, "Shared")
	if _, err := store.CreateGarage(ctx, GarageCreateParams{Garage: garage, CanonicalPayload: canonical}); err != nil {
		t.Fatalf("CreateGarage: %v", err)
	}
	now := time.Now().Add(time.Minute).UTC()
	acceptedNow := garage.Owners[0].AddedTime
	v2 := opencaravan.Garage{
		ID:              garage.ID,
		Name:            garage.Name,
		RevisionVersion: 2,
		RevisionTime:    now,
		Owners: []opencaravan.GarageOwner{
			{UserID: owner, AddedTime: garage.Owners[0].AddedTime, AcceptedTime: &acceptedNow},
			{UserID: invitee, AddedTime: now},
		},
		SignedBy: owner,
	}
	v2Canonical, err := v2.CanonicalEncoding()
	if err != nil {
		t.Fatalf("v2 CanonicalEncoding: %v", err)
	}
	v2.Integrity = &opencaravan.Integrity{
		Algorithm: "ecdsa-p256-sha256",
		KeyID:     string(owner),
		Signature: "x",
	}
	if _, err := store.AppendGarageRevision(ctx, GarageAppendRevisionParams{
		Garage:           v2,
		CanonicalPayload: v2Canonical,
	}); err != nil {
		t.Fatalf("AppendGarageRevision: %v", err)
	}

	// Invitee accepts.
	acceptanceTime := time.Now().Add(2 * time.Minute).UTC()
	acceptance := opencaravan.GarageOwnershipAcceptance{
		GarageID:                garage.ID,
		RevisionVersionAccepted: 2,
		AccepterUserID:          invitee,
		AcceptedTime:            acceptanceTime,
	}
	aCanonical, err := acceptance.CanonicalEncoding()
	if err != nil {
		t.Fatalf("acceptance CanonicalEncoding: %v", err)
	}
	acceptance.Integrity = &opencaravan.Integrity{
		Algorithm: "ecdsa-p256-sha256",
		KeyID:     string(invitee),
		Signature: "accept",
	}
	if _, err := store.AcceptGarageOwnership(ctx, GarageAcceptOwnershipParams{
		Acceptance:       acceptance,
		CanonicalPayload: aCanonical,
	}); err != nil {
		t.Fatalf("AcceptGarageOwnership: %v", err)
	}

	owners, err := store.ListGarageOwners(ctx, string(garage.ID))
	if err != nil {
		t.Fatalf("ListGarageOwners: %v", err)
	}
	for _, o := range owners {
		if o.UserID == string(invitee) && o.AcceptedTime == nil {
			t.Fatal("invitee still pending after acceptance")
		}
	}
}

func TestAcceptGarageOwnershipRejectsUninvited(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	owner := mustUUID(t)
	stranger := mustUUID(t)
	seedAccount(t, store, owner)
	seedAccount(t, store, stranger)

	garage, canonical := newSignedGarage(t, owner, "Solo")
	if _, err := store.CreateGarage(ctx, GarageCreateParams{Garage: garage, CanonicalPayload: canonical}); err != nil {
		t.Fatalf("CreateGarage: %v", err)
	}

	acceptance := opencaravan.GarageOwnershipAcceptance{
		GarageID:                garage.ID,
		RevisionVersionAccepted: 1,
		AccepterUserID:          stranger,
		AcceptedTime:            time.Now().UTC(),
	}
	canonical2, err := acceptance.CanonicalEncoding()
	if err != nil {
		t.Fatalf("acceptance CanonicalEncoding: %v", err)
	}
	acceptance.Integrity = &opencaravan.Integrity{
		Algorithm: "ecdsa-p256-sha256",
		KeyID:     string(stranger),
		Signature: "x",
	}
	_, err = store.AcceptGarageOwnership(ctx, GarageAcceptOwnershipParams{
		Acceptance:       acceptance,
		CanonicalPayload: canonical2,
	})
	if !errors.Is(err, ErrGarageOwnershipNotPending) {
		t.Fatalf("got %v, want ErrGarageOwnershipNotPending", err)
	}
}

func TestListGaragesForUserIncludesPending(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	owner := mustUUID(t)
	invitee := mustUUID(t)
	seedAccount(t, store, owner)
	seedAccount(t, store, invitee)

	garage, canonical := newSignedGarage(t, owner, "Shared")
	if _, err := store.CreateGarage(ctx, GarageCreateParams{Garage: garage, CanonicalPayload: canonical}); err != nil {
		t.Fatalf("CreateGarage: %v", err)
	}
	now := time.Now().Add(time.Minute).UTC()
	acceptedNow := garage.Owners[0].AddedTime
	v2 := opencaravan.Garage{
		ID:              garage.ID,
		Name:            garage.Name,
		RevisionVersion: 2,
		RevisionTime:    now,
		Owners: []opencaravan.GarageOwner{
			{UserID: owner, AddedTime: garage.Owners[0].AddedTime, AcceptedTime: &acceptedNow},
			{UserID: invitee, AddedTime: now},
		},
		SignedBy: owner,
	}
	v2Canonical, err := v2.CanonicalEncoding()
	if err != nil {
		t.Fatalf("v2 CanonicalEncoding: %v", err)
	}
	v2.Integrity = &opencaravan.Integrity{
		Algorithm: "ecdsa-p256-sha256",
		KeyID:     string(owner),
		Signature: "x",
	}
	if _, err := store.AppendGarageRevision(ctx, GarageAppendRevisionParams{
		Garage:           v2,
		CanonicalPayload: v2Canonical,
	}); err != nil {
		t.Fatalf("AppendGarageRevision: %v", err)
	}

	// Invitee sees the garage in their list even though pending.
	got, err := store.ListGaragesForUser(ctx, string(invitee))
	if err != nil {
		t.Fatalf("ListGaragesForUser: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 garage in invitee's list, got %d", len(got))
	}
}

func TestAppendGarageRevisionRemovesAbsentOwner(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	owner := mustUUID(t)
	coOwner := mustUUID(t)
	seedAccount(t, store, owner)
	seedAccount(t, store, coOwner)

	// v=1 has both as accepted owners.
	now := time.Now().UTC()
	garageID := mustUUID(t)
	g1 := opencaravan.Garage{
		ID:              garageID,
		Name:            "Shared",
		RevisionVersion: 1,
		RevisionTime:    now,
		Owners: []opencaravan.GarageOwner{
			{UserID: owner, AddedTime: now, AcceptedTime: &now},
			{UserID: coOwner, AddedTime: now, AcceptedTime: &now},
		},
		SignedBy: owner,
	}
	c1, err := g1.CanonicalEncoding()
	if err != nil {
		t.Fatalf("v1 CanonicalEncoding: %v", err)
	}
	g1.Integrity = &opencaravan.Integrity{
		Algorithm: "ecdsa-p256-sha256",
		KeyID:     string(owner),
		Signature: "x",
	}
	if _, err := store.CreateGarage(ctx, GarageCreateParams{Garage: g1, CanonicalPayload: c1}); err != nil {
		t.Fatalf("CreateGarage: %v", err)
	}

	// v=2 removes coOwner (unilateral removal).
	v2Time := now.Add(time.Minute)
	g2 := opencaravan.Garage{
		ID:              garageID,
		Name:            "Shared",
		RevisionVersion: 2,
		RevisionTime:    v2Time,
		Owners: []opencaravan.GarageOwner{
			{UserID: owner, AddedTime: now, AcceptedTime: &now},
		},
		SignedBy: owner,
	}
	c2, err := g2.CanonicalEncoding()
	if err != nil {
		t.Fatalf("v2 CanonicalEncoding: %v", err)
	}
	g2.Integrity = &opencaravan.Integrity{
		Algorithm: "ecdsa-p256-sha256",
		KeyID:     string(owner),
		Signature: "x",
	}
	if _, err := store.AppendGarageRevision(ctx, GarageAppendRevisionParams{
		Garage:           g2,
		CanonicalPayload: c2,
	}); err != nil {
		t.Fatalf("AppendGarageRevision: %v", err)
	}

	owners, err := store.ListGarageOwners(ctx, string(garageID))
	if err != nil {
		t.Fatalf("ListGarageOwners: %v", err)
	}
	if len(owners) != 1 {
		t.Fatalf("expected 1 owner after removal, got %d", len(owners))
	}
	if owners[0].UserID != string(owner) {
		t.Fatalf("expected remaining owner to be the un-removed one, got %q", owners[0].UserID)
	}
}
