package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/opencaravan/opencaravan-go"

	"github.com/wheelsdown/spivot-server/internal/server/middleware"
)

// createGarageFor is a test helper: create a garage owned solely
// by `owner` and return its id.
func createGarageFor(t *testing.T, env *journeyEnv, owner middleware.Identity, name string) opencaravan.UUID {
	t.Helper()
	payload := env.newSignedGaragePayload(t, owner, name)
	if rec := env.post(t, "/v1/garages", payload, owner, ""); rec.Code != http.StatusCreated {
		t.Fatalf("create garage: got %d, body=%s", rec.Code, rec.Body.String())
	}
	return payload.ID
}

func (e *journeyEnv) newSignedGarageVehiclePayload(t *testing.T, garageID opencaravan.UUID, signer middleware.Identity, displayName string) opencaravan.GarageVehicle {
	t.Helper()
	vehicleID, err := opencaravan.NewUUID()
	if err != nil {
		t.Fatalf("NewUUID: %v", err)
	}
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
		SignedBy:        opencaravan.UUID(signer.UserID),
	}
	e.signGarageVehicle(t, signer, &gv)
	return gv
}

func TestGarageVehicleCreateHappyPath(t *testing.T) {
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	garageID := createGarageFor(t, env, owner, "Household")
	payload := env.newSignedGarageVehiclePayload(t, garageID, owner, "Family Van")

	rec := env.post(t, "/v1/garages/"+string(garageID)+"/vehicles", payload, owner, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp GarageVehicleResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.DisplayName != "Family Van" {
		t.Fatalf("display_name: got %q", resp.DisplayName)
	}
	if resp.Capacity != 7 {
		t.Fatalf("capacity: got %d", resp.Capacity)
	}
}

func TestGarageVehicleCreateNonOwnerRejected(t *testing.T) {
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	stranger := env.mintIdentity(t)
	garageID := createGarageFor(t, env, owner, "Private")
	payload := env.newSignedGarageVehiclePayload(t, garageID, stranger, "Stranger's Car")

	rec := env.post(t, "/v1/garages/"+string(garageID)+"/vehicles", payload, stranger, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: got %d want 404 (non-owner); body=%s", rec.Code, rec.Body.String())
	}
}

func TestGarageVehicleCreatePendingInviteeRejected(t *testing.T) {
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	invitee := env.mintIdentity(t)
	garageID := createGarageFor(t, env, owner, "Shared")

	// Invite invitee via v=2.
	inviteTime := time.Now().Add(time.Minute).UTC()
	acceptedNow := time.Now().Add(-time.Minute).UTC()
	v2 := opencaravan.Garage{
		ID:              garageID,
		Name:            "Shared",
		RevisionVersion: 2,
		RevisionTime:    inviteTime,
		Owners: []opencaravan.GarageOwner{
			{UserID: opencaravan.UUID(owner.UserID), AddedTime: acceptedNow, AcceptedTime: &acceptedNow},
			{UserID: opencaravan.UUID(invitee.UserID), AddedTime: inviteTime},
		},
		SignedBy: opencaravan.UUID(owner.UserID),
	}
	env.signGarage(t, owner, &v2)
	if rec := env.post(t, "/v1/garages/"+string(garageID)+"/revisions", v2, owner, ""); rec.Code != http.StatusCreated {
		t.Fatalf("revision: got %d body=%s", rec.Code, rec.Body.String())
	}

	// Pending invitee tries to add a vehicle — must 403.
	payload := env.newSignedGarageVehiclePayload(t, garageID, invitee, "Invitee's Car")
	rec := env.post(t, "/v1/garages/"+string(garageID)+"/vehicles", payload, invitee, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want 403 (pending); body=%s", rec.Code, rec.Body.String())
	}
}

func TestGarageVehicleCreateSignerMismatchRejected(t *testing.T) {
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	other := env.mintIdentity(t)
	garageID := createGarageFor(t, env, owner, "G")
	// Payload claims `other` signed it; caller is owner. Even
	// though owner has authority, the payload's signed_by must
	// match the session.
	payload := env.newSignedGarageVehiclePayload(t, garageID, other, "Spoofed")
	rec := env.post(t, "/v1/garages/"+string(garageID)+"/vehicles", payload, owner, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want 403; body=%s", rec.Code, rec.Body.String())
	}
}

func TestGarageVehicleListAndGetRoundTrip(t *testing.T) {
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	garageID := createGarageFor(t, env, owner, "G")
	payload := env.newSignedGarageVehiclePayload(t, garageID, owner, "Van")
	if rec := env.post(t, "/v1/garages/"+string(garageID)+"/vehicles", payload, owner, ""); rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d", rec.Code)
	}

	listRec := env.get(t, "/v1/garages/"+string(garageID)+"/vehicles", owner, "")
	if listRec.Code != http.StatusOK {
		t.Fatalf("list: got %d", listRec.Code)
	}
	var list GarageVehicleListResponse
	if err := json.Unmarshal(listRec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list.Vehicles) != 1 {
		t.Fatalf("expected 1 vehicle, got %d", len(list.Vehicles))
	}

	getRec := env.get(t, "/v1/garages/"+string(garageID)+"/vehicles/"+string(payload.ID), owner, "")
	if getRec.Code != http.StatusOK {
		t.Fatalf("get: got %d", getRec.Code)
	}
	var got GarageVehicleResponse
	if err := json.Unmarshal(getRec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if got.DisplayName != "Van" {
		t.Fatalf("display_name: got %q", got.DisplayName)
	}
}

func TestGarageVehicleListPendingInviteeCanRead(t *testing.T) {
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	invitee := env.mintIdentity(t)
	garageID := createGarageFor(t, env, owner, "Shared")
	if rec := env.post(t, "/v1/garages/"+string(garageID)+"/vehicles",
		env.newSignedGarageVehiclePayload(t, garageID, owner, "Existing"), owner, ""); rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d", rec.Code)
	}

	// Invite invitee at v=2 — pending.
	inviteTime := time.Now().Add(time.Minute).UTC()
	acceptedNow := time.Now().Add(-time.Minute).UTC()
	v2 := opencaravan.Garage{
		ID:              garageID,
		Name:            "Shared",
		RevisionVersion: 2,
		RevisionTime:    inviteTime,
		Owners: []opencaravan.GarageOwner{
			{UserID: opencaravan.UUID(owner.UserID), AddedTime: acceptedNow, AcceptedTime: &acceptedNow},
			{UserID: opencaravan.UUID(invitee.UserID), AddedTime: inviteTime},
		},
		SignedBy: opencaravan.UUID(owner.UserID),
	}
	env.signGarage(t, owner, &v2)
	if rec := env.post(t, "/v1/garages/"+string(garageID)+"/revisions", v2, owner, ""); rec.Code != http.StatusCreated {
		t.Fatalf("revision: got %d", rec.Code)
	}

	// Pending invitee can READ the vehicle list — to preview what
	// they're being invited into — even though they can't mutate.
	rec := env.get(t, "/v1/garages/"+string(garageID)+"/vehicles", invitee, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200 (pending invitee can read); body=%s", rec.Code, rec.Body.String())
	}
	var list GarageVehicleListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list.Vehicles) != 1 {
		t.Fatalf("expected 1 vehicle visible to pending invitee, got %d", len(list.Vehicles))
	}
}

func TestGarageVehicleRevisionAppendUpdatesHead(t *testing.T) {
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	garageID := createGarageFor(t, env, owner, "G")
	payload := env.newSignedGarageVehiclePayload(t, garageID, owner, "Original")
	if rec := env.post(t, "/v1/garages/"+string(garageID)+"/vehicles", payload, owner, ""); rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d", rec.Code)
	}

	v2Time := time.Now().Add(time.Minute).UTC()
	v2 := opencaravan.GarageVehicle{
		ID:              payload.ID,
		GarageID:        garageID,
		RevisionVersion: 2,
		RevisionTime:    v2Time,
		DisplayName:     "Renamed",
		Make:            payload.Make,
		Model:           payload.Model,
		ModelYear:       payload.ModelYear,
		Color:           payload.Color,
		Capacity:        9,
		SignedBy:        opencaravan.UUID(owner.UserID),
	}
	env.signGarageVehicle(t, owner, &v2)
	rec := env.post(t, "/v1/garages/"+string(garageID)+"/vehicles/"+string(payload.ID)+"/revisions", v2, owner, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("revision: got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp GarageVehicleResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.CurrentRevisionVersion != 2 {
		t.Fatalf("revision: got %d want 2", resp.CurrentRevisionVersion)
	}
	if resp.DisplayName != "Renamed" {
		t.Fatalf("display_name: got %q", resp.DisplayName)
	}
	if resp.Capacity != 9 {
		t.Fatalf("capacity: got %d", resp.Capacity)
	}
}

func TestGarageVehicleRevisionStaleVersionConflict(t *testing.T) {
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	garageID := createGarageFor(t, env, owner, "G")
	payload := env.newSignedGarageVehiclePayload(t, garageID, owner, "V")
	if rec := env.post(t, "/v1/garages/"+string(garageID)+"/vehicles", payload, owner, ""); rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d", rec.Code)
	}
	// Resubmit v=1 — must conflict.
	rec := env.post(t, "/v1/garages/"+string(garageID)+"/vehicles/"+string(payload.ID)+"/revisions", payload, owner, "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("status: got %d want 409; body=%s", rec.Code, rec.Body.String())
	}
}

func TestGarageVehicleCreateRejectsTamperedSignature(t *testing.T) {
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	garageID := createGarageFor(t, env, owner, "Household")
	payload := env.newSignedGarageVehiclePayload(t, garageID, owner, "Original Name")
	// Sign then tamper.
	payload.DisplayName = "Tampered Name"

	rec := env.post(t, "/v1/garages/"+string(garageID)+"/vehicles", payload, owner, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want 403; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "signature_invalid") {
		t.Fatalf("expected signature_invalid; body=%s", rec.Body.String())
	}
}
