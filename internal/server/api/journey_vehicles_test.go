package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/opencaravan/opencaravan-go"
)

// newSignedVehiclePayload builds a Vehicle the handler will accept:
// owned by ownerID, signed (Integrity envelope present), capacity
// and ACL version filled. Signature bytes are placeholder — Phase 2
// does not verify them; the test harness exercises the structural
// + identity path that Phase 2 actually enforces.
func newSignedVehiclePayload(t *testing.T, ownerID string) opencaravan.Vehicle {
	t.Helper()
	vehicleID, err := opencaravan.NewUUID()
	if err != nil {
		t.Fatalf("NewUUID vehicle: %v", err)
	}
	authorized, err := opencaravan.NewUUID()
	if err != nil {
		t.Fatalf("NewUUID authorized: %v", err)
	}
	return opencaravan.Vehicle{
		ID:                vehicleID,
		DisplayName:       "Riley's Subaru",
		Make:              "Subaru",
		Model:             "Outback",
		ModelYear:         2022,
		Color:             "Autumn Green",
		OwnerUserID:       opencaravan.UUID(ownerID),
		Capacity:          5,
		AuthorizedDrivers: []opencaravan.UUID{opencaravan.UUID(ownerID), authorized},
		ACLVersion:        1,
		EmergencyRule: &opencaravan.VehicleEmergencyRule{
			Kind: opencaravan.VehicleEmergencyRuleAnyJourneyParticipant,
		},
		Integrity: &opencaravan.Integrity{
			Algorithm: "ecdsa-p256-sha256",
			KeyID:     ownerID,
			Signature: "test-signature-placeholder",
		},
	}
}

func TestJourneyVehicleCreateHappyPath(t *testing.T) {
	env := newJourneyEnv(t)
	id := env.mintIdentity(t)
	journey := env.mustCreateJourney(t, id, "Pacific Coast Drive")
	jid, err := opencaravan.ParseUUID(journey.ID)
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}
	mac := env.issueSessionMacaroon(t, id, jid, opencaravan.SessionActionJourneyWrite)

	payload := newSignedVehiclePayload(t, id.UserID)
	rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles", payload, id, mac)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp JourneyVehicleResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.ID != string(payload.ID) {
		t.Fatalf("id: got %q want %q", resp.ID, payload.ID)
	}
	if resp.CurrentACLVersion != 1 {
		t.Fatalf("current_acl_version: got %d want 1", resp.CurrentACLVersion)
	}
	if resp.Capacity != 5 {
		t.Fatalf("capacity: got %d want 5", resp.Capacity)
	}
	if resp.EmergencyRule == nil || resp.EmergencyRule.Kind != opencaravan.VehicleEmergencyRuleAnyJourneyParticipant {
		t.Fatalf("emergency_rule: got %+v", resp.EmergencyRule)
	}
}

func TestJourneyVehicleCreateOwnerMismatchRejected(t *testing.T) {
	env := newJourneyEnv(t)
	caller := env.mintIdentity(t)
	other := env.mintIdentity(t)
	journey := env.mustCreateJourney(t, caller, "Pacific Coast Drive")
	jid, err := opencaravan.ParseUUID(journey.ID)
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}
	mac := env.issueSessionMacaroon(t, caller, jid, opencaravan.SessionActionJourneyWrite)

	// Payload attributes vehicle to other.UserID, but caller is the session.
	payload := newSignedVehiclePayload(t, other.UserID)
	rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles", payload, caller, mac)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want 403; body=%s", rec.Code, rec.Body.String())
	}
}

func TestJourneyVehicleCreateRequiresWriteAction(t *testing.T) {
	env := newJourneyEnv(t)
	id := env.mintIdentity(t)
	journey := env.mustCreateJourney(t, id, "Pacific Coast Drive")
	jid, err := opencaravan.ParseUUID(journey.ID)
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}
	// journey.read instead of journey.write — middleware must reject.
	mac := env.issueSessionMacaroon(t, id, jid, opencaravan.SessionActionJourneyRead)
	payload := newSignedVehiclePayload(t, id.UserID)
	rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles", payload, id, mac)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d want 401; body=%s", rec.Code, rec.Body.String())
	}
}

func TestJourneyVehicleCreateRejectsMissingIntegrity(t *testing.T) {
	env := newJourneyEnv(t)
	id := env.mintIdentity(t)
	journey := env.mustCreateJourney(t, id, "Pacific Coast Drive")
	jid, err := opencaravan.ParseUUID(journey.ID)
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}
	mac := env.issueSessionMacaroon(t, id, jid, opencaravan.SessionActionJourneyWrite)
	payload := newSignedVehiclePayload(t, id.UserID)
	payload.Integrity = nil

	rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles", payload, id, mac)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestJourneyVehicleCreateDuplicateOwnerConflict(t *testing.T) {
	env := newJourneyEnv(t)
	id := env.mintIdentity(t)
	journey := env.mustCreateJourney(t, id, "Pacific Coast Drive")
	jid, err := opencaravan.ParseUUID(journey.ID)
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}
	mac := env.issueSessionMacaroon(t, id, jid, opencaravan.SessionActionJourneyWrite)

	first := newSignedVehiclePayload(t, id.UserID)
	if rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles", first, id, mac); rec.Code != http.StatusCreated {
		t.Fatalf("first create: got %d, body=%s", rec.Code, rec.Body.String())
	}

	second := newSignedVehiclePayload(t, id.UserID)
	rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles", second, id, mac)
	if rec.Code != http.StatusConflict {
		t.Fatalf("second create: got %d want 409; body=%s", rec.Code, rec.Body.String())
	}
}

func TestJourneyVehicleGetAndListRoundTrip(t *testing.T) {
	env := newJourneyEnv(t)
	id := env.mintIdentity(t)
	journey := env.mustCreateJourney(t, id, "Pacific Coast Drive")
	jid, err := opencaravan.ParseUUID(journey.ID)
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}
	writeMac := env.issueSessionMacaroon(t, id, jid, opencaravan.SessionActionJourneyWrite)
	readMac := env.issueSessionMacaroon(t, id, jid, opencaravan.SessionActionJourneyRead)

	payload := newSignedVehiclePayload(t, id.UserID)
	if rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles", payload, id, writeMac); rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d, body=%s", rec.Code, rec.Body.String())
	}

	rec := env.get(t, "/v1/journeys/"+journey.ID+"/vehicles/"+string(payload.ID), id, readMac)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: got %d want 200; body=%s", rec.Code, rec.Body.String())
	}
	var got JourneyVehicleResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if got.DisplayName != "Riley's Subaru" {
		t.Fatalf("display_name: got %q", got.DisplayName)
	}

	listRec := env.get(t, "/v1/journeys/"+journey.ID+"/vehicles", id, readMac)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list: got %d; body=%s", listRec.Code, listRec.Body.String())
	}
	var list JourneyVehicleListResponse
	if err := json.Unmarshal(listRec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list.Vehicles) != 1 {
		t.Fatalf("expected 1 vehicle, got %d", len(list.Vehicles))
	}
}

func TestJourneyVehicleGetMissingReturns404(t *testing.T) {
	env := newJourneyEnv(t)
	id := env.mintIdentity(t)
	journey := env.mustCreateJourney(t, id, "Pacific Coast Drive")
	jid, err := opencaravan.ParseUUID(journey.ID)
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}
	mac := env.issueSessionMacaroon(t, id, jid, opencaravan.SessionActionJourneyRead)
	missing, err := opencaravan.NewUUID()
	if err != nil {
		t.Fatalf("NewUUID: %v", err)
	}

	rec := env.get(t, "/v1/journeys/"+journey.ID+"/vehicles/"+string(missing), id, mac)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: got %d want 404; body=%s", rec.Code, rec.Body.String())
	}
}

func TestJourneyVehicleACLAppendHappyPath(t *testing.T) {
	env := newJourneyEnv(t)
	id := env.mintIdentity(t)
	journey := env.mustCreateJourney(t, id, "Pacific Coast Drive")
	jid, err := opencaravan.ParseUUID(journey.ID)
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}
	writeMac := env.issueSessionMacaroon(t, id, jid, opencaravan.SessionActionJourneyWrite)

	payload := newSignedVehiclePayload(t, id.UserID)
	if rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles", payload, id, writeMac); rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d, body=%s", rec.Code, rec.Body.String())
	}

	newDriver, err := opencaravan.NewUUID()
	if err != nil {
		t.Fatalf("NewUUID: %v", err)
	}
	acl := opencaravan.VehicleACL{
		VehicleID:         payload.ID,
		OwnerUserID:       opencaravan.UUID(id.UserID),
		ACLVersion:        2,
		AuthorizedDrivers: []opencaravan.UUID{opencaravan.UUID(id.UserID), newDriver},
		EmergencyRule: &opencaravan.VehicleEmergencyRule{
			Kind: opencaravan.VehicleEmergencyRuleNone,
		},
		EffectiveTime: time.Now().Add(time.Minute).UTC(),
		Integrity: &opencaravan.Integrity{
			Algorithm: "ecdsa-p256-sha256",
			KeyID:     id.UserID,
			Signature: "test-acl-signature",
		},
	}
	rec := env.post(t,
		"/v1/journeys/"+journey.ID+"/vehicles/"+string(payload.ID)+"/acl-revisions",
		acl, id, writeMac)
	if rec.Code != http.StatusCreated {
		t.Fatalf("acl status: got %d want 201; body=%s", rec.Code, rec.Body.String())
	}
	var aclResp JourneyVehicleACLRevisionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &aclResp); err != nil {
		t.Fatalf("decode acl: %v", err)
	}
	if aclResp.ACLVersion != 2 {
		t.Fatalf("acl version: got %d want 2", aclResp.ACLVersion)
	}
	if aclResp.EmergencyRule == nil || aclResp.EmergencyRule.Kind != opencaravan.VehicleEmergencyRuleNone {
		t.Fatalf("emergency_rule: got %+v want none", aclResp.EmergencyRule)
	}

	// The vehicle GET reflects the advanced ACL version.
	readMac := env.issueSessionMacaroon(t, id, jid, opencaravan.SessionActionJourneyRead)
	getRec := env.get(t, "/v1/journeys/"+journey.ID+"/vehicles/"+string(payload.ID), id, readMac)
	if getRec.Code != http.StatusOK {
		t.Fatalf("get: got %d", getRec.Code)
	}
	var got JourneyVehicleResponse
	if err := json.Unmarshal(getRec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if got.CurrentACLVersion != 2 {
		t.Fatalf("current_acl_version: got %d want 2", got.CurrentACLVersion)
	}
}

func TestJourneyVehicleACLAppendVehicleIDMismatchRejected(t *testing.T) {
	env := newJourneyEnv(t)
	id := env.mintIdentity(t)
	journey := env.mustCreateJourney(t, id, "Pacific Coast Drive")
	jid, err := opencaravan.ParseUUID(journey.ID)
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}
	writeMac := env.issueSessionMacaroon(t, id, jid, opencaravan.SessionActionJourneyWrite)

	payload := newSignedVehiclePayload(t, id.UserID)
	if rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles", payload, id, writeMac); rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d", rec.Code)
	}

	otherID, err := opencaravan.NewUUID()
	if err != nil {
		t.Fatalf("NewUUID: %v", err)
	}
	acl := opencaravan.VehicleACL{
		VehicleID:         otherID, // wrong — must equal payload.ID
		OwnerUserID:       opencaravan.UUID(id.UserID),
		ACLVersion:        2,
		AuthorizedDrivers: payload.AuthorizedDrivers,
		EffectiveTime:     time.Now().UTC(),
		Integrity: &opencaravan.Integrity{
			Algorithm: "ecdsa-p256-sha256",
			KeyID:     id.UserID,
			Signature: "x",
		},
	}
	rec := env.post(t,
		"/v1/journeys/"+journey.ID+"/vehicles/"+string(payload.ID)+"/acl-revisions",
		acl, id, writeMac)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestJourneyVehicleACLAppendRejectedForNonOwner(t *testing.T) {
	// Defense in depth: any journey.write holder must NOT be
	// allowed to append an ACL to another participant's vehicle,
	// even if they spoof acl.owner_user_id to themselves. The
	// handler must verify against the stored vehicle owner.
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	other := env.mintIdentity(t)
	journey := env.mustCreateJourney(t, owner, "Pacific Coast Drive")
	jid, err := opencaravan.ParseUUID(journey.ID)
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}

	// Owner uploads the vehicle.
	ownerMac := env.issueSessionMacaroon(t, owner, jid, opencaravan.SessionActionJourneyWrite)
	payload := newSignedVehiclePayload(t, owner.UserID)
	if rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles", payload, owner, ownerMac); rec.Code != http.StatusCreated {
		t.Fatalf("owner create: got %d, body=%s", rec.Code, rec.Body.String())
	}

	// "Other" caller acquires a journey.write session and tries to
	// append an ACL to the vehicle, claiming themselves as owner.
	// The handler must reject with 403 because the stored owner is
	// `owner`, not `other`.
	otherMac := env.issueSessionMacaroon(t, other, jid, opencaravan.SessionActionJourneyWrite)
	spoofed := opencaravan.VehicleACL{
		VehicleID:         payload.ID,
		OwnerUserID:       opencaravan.UUID(other.UserID),
		ACLVersion:        2,
		AuthorizedDrivers: payload.AuthorizedDrivers,
		EffectiveTime:     time.Now().Add(time.Minute).UTC(),
		Integrity: &opencaravan.Integrity{
			Algorithm: "ecdsa-p256-sha256",
			KeyID:     other.UserID,
			Signature: "spoofed-signature",
		},
	}
	rec := env.post(t,
		"/v1/journeys/"+journey.ID+"/vehicles/"+string(payload.ID)+"/acl-revisions",
		spoofed, other, otherMac)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want 403; body=%s", rec.Code, rec.Body.String())
	}
}

func TestJourneyVehicleCreate503WithoutVehicleStore(t *testing.T) {
	// Defense-in-depth: a deployment that wires MacaroonVerifier
	// but forgets VehicleStore returns 503 instead of silently
	// 404-ing or panicking. We can't easily reuse newJourneyEnv
	// here (it always wires VehicleStore); construct a focused
	// server fixture instead.
	t.Helper()
	env := newJourneyEnv(t)
	env.server.cfg.VehicleStore = nil

	id := env.mintIdentity(t)
	journey := env.mustCreateJourney(t, id, "Pacific Coast Drive")
	jid, err := opencaravan.ParseUUID(journey.ID)
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}
	mac := env.issueSessionMacaroon(t, id, jid, opencaravan.SessionActionJourneyWrite)
	payload := newSignedVehiclePayload(t, id.UserID)

	rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles", payload, id, mac)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d want 503; body=%s", rec.Code, rec.Body.String())
	}
}
