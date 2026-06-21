package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/opencaravan/opencaravan-go"
)

func newSignedGaragePayload(t *testing.T, ownerID string, name string, additionalOwners ...opencaravan.GarageOwner) opencaravan.Garage {
	t.Helper()
	garageID, err := opencaravan.NewUUID()
	if err != nil {
		t.Fatalf("NewUUID: %v", err)
	}
	now := time.Now().UTC()
	owners := []opencaravan.GarageOwner{
		{UserID: opencaravan.UUID(ownerID), AddedTime: now, AcceptedTime: &now},
	}
	owners = append(owners, additionalOwners...)
	return opencaravan.Garage{
		ID:              garageID,
		Name:            name,
		RevisionVersion: 1,
		RevisionTime:    now,
		Owners:          owners,
		SignedBy:        opencaravan.UUID(ownerID),
		Integrity: &opencaravan.Integrity{
			Algorithm: "ecdsa-p256-sha256",
			KeyID:     ownerID,
			Signature: "test-garage-signature",
		},
	}
}

func TestGarageCreateHappyPath(t *testing.T) {
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	payload := newSignedGaragePayload(t, owner.UserID, "Riley's Garage")

	rec := env.post(t, "/v1/garages", payload, owner, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp GarageResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Name != "Riley's Garage" {
		t.Fatalf("name: got %q", resp.Name)
	}
	if resp.CurrentRevisionVersion != 1 {
		t.Fatalf("revision_version: got %d", resp.CurrentRevisionVersion)
	}
	if len(resp.Owners) != 1 {
		t.Fatalf("expected 1 owner, got %d", len(resp.Owners))
	}
	if resp.Owners[0].AcceptedTime == nil {
		t.Fatal("creator should be accepted")
	}
}

func TestGarageCreateSignerMismatchRejected(t *testing.T) {
	env := newJourneyEnv(t)
	caller := env.mintIdentity(t)
	other := env.mintIdentity(t)
	// Payload claims `other` signed it, but caller is the session.
	payload := newSignedGaragePayload(t, other.UserID, "G")
	rec := env.post(t, "/v1/garages", payload, caller, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want 403; body=%s", rec.Code, rec.Body.String())
	}
}

func TestGarageCreateRequiresRevisionVersionOne(t *testing.T) {
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	payload := newSignedGaragePayload(t, owner.UserID, "G")
	payload.RevisionVersion = 2 // wrong for create
	rec := env.post(t, "/v1/garages", payload, owner, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestGarageListReturnsOwnedAndPending(t *testing.T) {
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	invitee := env.mintIdentity(t)

	payload := newSignedGaragePayload(t, owner.UserID, "Shared")
	if rec := env.post(t, "/v1/garages", payload, owner, ""); rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d", rec.Code)
	}

	// Owner publishes v=2 inviting `invitee`.
	now := time.Now().Add(time.Minute).UTC()
	acceptedNow := payload.Owners[0].AddedTime
	v2 := opencaravan.Garage{
		ID:              payload.ID,
		Name:            payload.Name,
		RevisionVersion: 2,
		RevisionTime:    now,
		Owners: []opencaravan.GarageOwner{
			{UserID: opencaravan.UUID(owner.UserID), AddedTime: payload.Owners[0].AddedTime, AcceptedTime: &acceptedNow},
			{UserID: opencaravan.UUID(invitee.UserID), AddedTime: now},
		},
		SignedBy: opencaravan.UUID(owner.UserID),
		Integrity: &opencaravan.Integrity{
			Algorithm: "ecdsa-p256-sha256",
			KeyID:     owner.UserID,
			Signature: "x",
		},
	}
	if rec := env.post(t, "/v1/garages/"+string(payload.ID)+"/revisions", v2, owner, ""); rec.Code != http.StatusCreated {
		t.Fatalf("revision: got %d body=%s", rec.Code, rec.Body.String())
	}

	// Owner sees the garage in their list.
	rec := env.get(t, "/v1/garages", owner, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("owner list: got %d", rec.Code)
	}
	var list GarageListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list.Garages) != 1 {
		t.Fatalf("owner list: expected 1 garage, got %d", len(list.Garages))
	}

	// Invitee ALSO sees the garage in their list (pending).
	inviteeRec := env.get(t, "/v1/garages", invitee, "")
	if inviteeRec.Code != http.StatusOK {
		t.Fatalf("invitee list: got %d", inviteeRec.Code)
	}
	var inviteeList GarageListResponse
	if err := json.Unmarshal(inviteeRec.Body.Bytes(), &inviteeList); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(inviteeList.Garages) != 1 {
		t.Fatalf("invitee list: expected 1 garage, got %d", len(inviteeList.Garages))
	}
}

func TestGarageGetForbidsNonOwner(t *testing.T) {
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	stranger := env.mintIdentity(t)
	payload := newSignedGaragePayload(t, owner.UserID, "Private")
	if rec := env.post(t, "/v1/garages", payload, owner, ""); rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d", rec.Code)
	}

	rec := env.get(t, "/v1/garages/"+string(payload.ID), stranger, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: got %d want 404 (non-owner sees not-found); body=%s", rec.Code, rec.Body.String())
	}
}

func TestGarageOwnershipAcceptanceFullLifecycle(t *testing.T) {
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	invitee := env.mintIdentity(t)

	payload := newSignedGaragePayload(t, owner.UserID, "Household")
	if rec := env.post(t, "/v1/garages", payload, owner, ""); rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d", rec.Code)
	}

	inviteTime := time.Now().Add(time.Minute).UTC()
	acceptedNow := payload.Owners[0].AddedTime
	v2 := opencaravan.Garage{
		ID:              payload.ID,
		Name:            payload.Name,
		RevisionVersion: 2,
		RevisionTime:    inviteTime,
		Owners: []opencaravan.GarageOwner{
			{UserID: opencaravan.UUID(owner.UserID), AddedTime: payload.Owners[0].AddedTime, AcceptedTime: &acceptedNow},
			{UserID: opencaravan.UUID(invitee.UserID), AddedTime: inviteTime},
		},
		SignedBy: opencaravan.UUID(owner.UserID),
		Integrity: &opencaravan.Integrity{
			Algorithm: "ecdsa-p256-sha256",
			KeyID:     owner.UserID,
			Signature: "x",
		},
	}
	if rec := env.post(t, "/v1/garages/"+string(payload.ID)+"/revisions", v2, owner, ""); rec.Code != http.StatusCreated {
		t.Fatalf("revision: got %d body=%s", rec.Code, rec.Body.String())
	}

	// Invitee accepts.
	acceptance := opencaravan.GarageOwnershipAcceptance{
		GarageID:                payload.ID,
		RevisionVersionAccepted: 2,
		AccepterUserID:          opencaravan.UUID(invitee.UserID),
		AcceptedTime:            time.Now().Add(2 * time.Minute).UTC(),
		Integrity: &opencaravan.Integrity{
			Algorithm: "ecdsa-p256-sha256",
			KeyID:     invitee.UserID,
			Signature: "accept",
		},
	}
	rec := env.post(t, "/v1/garages/"+string(payload.ID)+"/ownership-acceptances", acceptance, invitee, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("accept: got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp GarageOwnershipAcceptanceResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Invitee should now appear accepted in the embedded garage state.
	foundAccepted := false
	for _, o := range resp.Garage.Owners {
		if o.UserID == invitee.UserID && o.AcceptedTime != nil {
			foundAccepted = true
		}
	}
	if !foundAccepted {
		t.Fatal("invitee should be accepted after acceptance response")
	}
}

func TestGarageOwnershipAcceptanceReplayReturns200WithStoredValues(t *testing.T) {
	// Locks in the "replay returns 200 OK with the original
	// acceptance metadata" invariant from the PR description.
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	invitee := env.mintIdentity(t)

	payload := newSignedGaragePayload(t, owner.UserID, "Household")
	if rec := env.post(t, "/v1/garages", payload, owner, ""); rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d", rec.Code)
	}
	inviteTime := time.Now().Add(time.Minute).UTC()
	acceptedNow := payload.Owners[0].AddedTime
	v2 := opencaravan.Garage{
		ID:              payload.ID,
		Name:            payload.Name,
		RevisionVersion: 2,
		RevisionTime:    inviteTime,
		Owners: []opencaravan.GarageOwner{
			{UserID: opencaravan.UUID(owner.UserID), AddedTime: payload.Owners[0].AddedTime, AcceptedTime: &acceptedNow},
			{UserID: opencaravan.UUID(invitee.UserID), AddedTime: inviteTime},
		},
		SignedBy: opencaravan.UUID(owner.UserID),
		Integrity: &opencaravan.Integrity{
			Algorithm: "ecdsa-p256-sha256",
			KeyID:     owner.UserID,
			Signature: "x",
		},
	}
	if rec := env.post(t, "/v1/garages/"+string(payload.ID)+"/revisions", v2, owner, ""); rec.Code != http.StatusCreated {
		t.Fatalf("revision: got %d body=%s", rec.Code, rec.Body.String())
	}

	acceptance := opencaravan.GarageOwnershipAcceptance{
		GarageID:                payload.ID,
		RevisionVersionAccepted: 2,
		AccepterUserID:          opencaravan.UUID(invitee.UserID),
		AcceptedTime:            time.Now().Add(2 * time.Minute).UTC(),
		Integrity: &opencaravan.Integrity{
			Algorithm: "ecdsa-p256-sha256",
			KeyID:     invitee.UserID,
			Signature: "accept",
		},
	}
	first := env.post(t, "/v1/garages/"+string(payload.ID)+"/ownership-acceptances", acceptance, invitee, "")
	if first.Code != http.StatusCreated {
		t.Fatalf("first accept: got %d body=%s", first.Code, first.Body.String())
	}
	var firstResp GarageOwnershipAcceptanceResponse
	if err := json.Unmarshal(first.Body.Bytes(), &firstResp); err != nil {
		t.Fatalf("decode first: %v", err)
	}

	// Replay — same wire payload — must return 200 with stored
	// values (id, integrity, received_at all populated, matching
	// the original).
	replay := env.post(t, "/v1/garages/"+string(payload.ID)+"/ownership-acceptances", acceptance, invitee, "")
	if replay.Code != http.StatusOK {
		t.Fatalf("replay: got %d want 200; body=%s", replay.Code, replay.Body.String())
	}
	var replayResp GarageOwnershipAcceptanceResponse
	if err := json.Unmarshal(replay.Body.Bytes(), &replayResp); err != nil {
		t.Fatalf("decode replay: %v", err)
	}
	if replayResp.AcceptanceID == "" {
		t.Fatal("replay should return a populated acceptance_id, not zero")
	}
	if replayResp.AcceptanceID != firstResp.AcceptanceID {
		t.Fatalf("replay should resolve to original acceptance_id; got %q want %q",
			replayResp.AcceptanceID, firstResp.AcceptanceID)
	}
	if replayResp.Integrity.Signature == "" {
		t.Fatal("replay should return the stored Integrity envelope, not zero values")
	}
	if replayResp.ReceivedAt.IsZero() {
		t.Fatal("replay should return the stored received_at, not zero")
	}
}

func TestGarageCreateRejectsPreSeededAdditionalOwners(t *testing.T) {
	// Defense against bypassing the consent-based add flow: a
	// client cannot pre-seed extra owners (pending or accepted)
	// at create time. Co-owners come via revisions + signed
	// acceptances.
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	other := env.mintIdentity(t)
	payload := newSignedGaragePayload(t, owner.UserID, "G")
	// Pre-seed another accepted owner — must be rejected.
	otherAccepted := payload.Owners[0].AddedTime
	payload.Owners = append(payload.Owners, opencaravan.GarageOwner{
		UserID:       opencaravan.UUID(other.UserID),
		AddedTime:    payload.Owners[0].AddedTime,
		AcceptedTime: &otherAccepted,
	})
	rec := env.post(t, "/v1/garages", payload, owner, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestGarageOwnershipAcceptanceAccepterMismatchRejected(t *testing.T) {
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	invitee := env.mintIdentity(t)
	stranger := env.mintIdentity(t)

	payload := newSignedGaragePayload(t, owner.UserID, "G")
	if rec := env.post(t, "/v1/garages", payload, owner, ""); rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d", rec.Code)
	}
	now := time.Now().Add(time.Minute).UTC()
	acceptedNow := payload.Owners[0].AddedTime
	v2 := opencaravan.Garage{
		ID:              payload.ID,
		Name:            payload.Name,
		RevisionVersion: 2,
		RevisionTime:    now,
		Owners: []opencaravan.GarageOwner{
			{UserID: opencaravan.UUID(owner.UserID), AddedTime: payload.Owners[0].AddedTime, AcceptedTime: &acceptedNow},
			{UserID: opencaravan.UUID(invitee.UserID), AddedTime: now},
		},
		SignedBy: opencaravan.UUID(owner.UserID),
		Integrity: &opencaravan.Integrity{
			Algorithm: "ecdsa-p256-sha256",
			KeyID:     owner.UserID,
			Signature: "x",
		},
	}
	if rec := env.post(t, "/v1/garages/"+string(payload.ID)+"/revisions", v2, owner, ""); rec.Code != http.StatusCreated {
		t.Fatalf("revision: got %d", rec.Code)
	}

	// `stranger` tries to accept on `invitee`'s behalf — should reject 403.
	spoofed := opencaravan.GarageOwnershipAcceptance{
		GarageID:                payload.ID,
		RevisionVersionAccepted: 2,
		AccepterUserID:          opencaravan.UUID(invitee.UserID),
		AcceptedTime:            time.Now().Add(2 * time.Minute).UTC(),
		Integrity: &opencaravan.Integrity{
			Algorithm: "ecdsa-p256-sha256",
			KeyID:     stranger.UserID,
			Signature: "spoof",
		},
	}
	rec := env.post(t, "/v1/garages/"+string(payload.ID)+"/ownership-acceptances", spoofed, stranger, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want 403; body=%s", rec.Code, rec.Body.String())
	}
}

func TestGarageRevisionPendingOwnerCannotPublish(t *testing.T) {
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	invitee := env.mintIdentity(t)

	payload := newSignedGaragePayload(t, owner.UserID, "G")
	if rec := env.post(t, "/v1/garages", payload, owner, ""); rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d", rec.Code)
	}
	now := time.Now().Add(time.Minute).UTC()
	acceptedNow := payload.Owners[0].AddedTime
	v2 := opencaravan.Garage{
		ID:              payload.ID,
		Name:            payload.Name,
		RevisionVersion: 2,
		RevisionTime:    now,
		Owners: []opencaravan.GarageOwner{
			{UserID: opencaravan.UUID(owner.UserID), AddedTime: payload.Owners[0].AddedTime, AcceptedTime: &acceptedNow},
			{UserID: opencaravan.UUID(invitee.UserID), AddedTime: now},
		},
		SignedBy: opencaravan.UUID(owner.UserID),
		Integrity: &opencaravan.Integrity{
			Algorithm: "ecdsa-p256-sha256",
			KeyID:     owner.UserID,
			Signature: "x",
		},
	}
	if rec := env.post(t, "/v1/garages/"+string(payload.ID)+"/revisions", v2, owner, ""); rec.Code != http.StatusCreated {
		t.Fatalf("revision: got %d", rec.Code)
	}

	// Invitee (pending) tries to publish a v=3 revision. Should reject 403.
	v3Time := time.Now().Add(2 * time.Minute).UTC()
	v3 := opencaravan.Garage{
		ID:              payload.ID,
		Name:            "Renamed By Invitee",
		RevisionVersion: 3,
		RevisionTime:    v3Time,
		Owners:          v2.Owners,
		SignedBy:        opencaravan.UUID(invitee.UserID),
		Integrity: &opencaravan.Integrity{
			Algorithm: "ecdsa-p256-sha256",
			KeyID:     invitee.UserID,
			Signature: "x",
		},
	}
	rec := env.post(t, "/v1/garages/"+string(payload.ID)+"/revisions", v3, invitee, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want 403 (pending invitee cannot publish); body=%s", rec.Code, rec.Body.String())
	}
}
