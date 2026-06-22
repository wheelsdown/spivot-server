package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/opencaravan/opencaravan-go"

	"github.com/wheelsdown/spivot-server/internal/server/middleware"
)

// newSignedVehicleBundle builds a Vehicle metadata bundle + its
// paired initial VehicleACL, both owned by the supplied identity
// and both freshly signed with that identity's enrolled signing
// key (set up by [journeyEnv.mintIdentity]).
//
// Vehicle is metadata-only in the 0.2-draft wire types — the
// authorization data (AuthorizedDrivers, EmergencyRule) lives on
// the paired VehicleACL bundle. Callers that want to vary
// emergency rule semantics for a test mutate the returned acl
// and re-sign via signVehicleACL.
//
// For tests that want a vehicle owned by user A but submitted by
// user B (e.g., session-owner mismatch test), pass A's identity
// here and post via B's identity; the helper signs both bundles
// as A regardless.
func (e *journeyEnv) newSignedVehicleBundle(t *testing.T, owner middleware.Identity) (opencaravan.Vehicle, opencaravan.VehicleACL) {
	t.Helper()
	vehicleID, err := opencaravan.NewUUID()
	if err != nil {
		t.Fatalf("NewUUID vehicle: %v", err)
	}
	authorized, err := opencaravan.NewUUID()
	if err != nil {
		t.Fatalf("NewUUID authorized: %v", err)
	}
	now := time.Now().UTC()
	v := opencaravan.Vehicle{
		ID:              vehicleID,
		OwnerUserID:     opencaravan.UUID(owner.UserID),
		RevisionVersion: 1,
		RevisionTime:    now,
		DisplayName:     "Riley's Subaru",
		Make:            "Subaru",
		Model:           "Outback",
		ModelYear:       2022,
		Color:           "Autumn Green",
		Capacity:        5,
	}
	e.signVehicle(t, owner, &v)

	acl := opencaravan.VehicleACL{
		VehicleID:         vehicleID,
		OwnerUserID:       opencaravan.UUID(owner.UserID),
		ACLVersion:        1,
		AuthorizedDrivers: []opencaravan.UUID{opencaravan.UUID(owner.UserID), authorized},
		EmergencyRule: &opencaravan.VehicleEmergencyRule{
			Kind: opencaravan.VehicleEmergencyRuleAnyJourneyParticipant,
		},
		EffectiveTime: now,
	}
	e.signVehicleACL(t, owner, &acl)
	return v, acl
}

// vehicleCreateRequest is a convenience wrapper around the create
// request shape so tests don't repeat the struct literal.
func vehicleCreateRequest(v opencaravan.Vehicle, acl opencaravan.VehicleACL) JourneyVehicleCreateRequest {
	return JourneyVehicleCreateRequest{Vehicle: v, InitialACL: acl}
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

	vehicle, acl := env.newSignedVehicleBundle(t, id)
	rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles", vehicleCreateRequest(vehicle, acl), id, mac)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp JourneyVehicleResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.ID != string(vehicle.ID) {
		t.Fatalf("id: got %q want %q", resp.ID, vehicle.ID)
	}
	if resp.CurrentRevisionVersion != 1 {
		t.Fatalf("current_revision_version: got %d want 1", resp.CurrentRevisionVersion)
	}
	if resp.CurrentACLVersion != 1 {
		t.Fatalf("current_acl_version: got %d want 1", resp.CurrentACLVersion)
	}
	if resp.Vehicle.DisplayName != "Riley's Subaru" {
		t.Fatalf("display_name: got %q", resp.Vehicle.DisplayName)
	}
	if resp.Vehicle.Capacity != 5 {
		t.Fatalf("capacity: got %d want 5", resp.Vehicle.Capacity)
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

	// Bundle attributes vehicle to other.UserID, but caller is the session.
	vehicle, acl := env.newSignedVehicleBundle(t, other)
	rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles", vehicleCreateRequest(vehicle, acl), caller, mac)
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
	vehicle, acl := env.newSignedVehicleBundle(t, id)
	rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles", vehicleCreateRequest(vehicle, acl), id, mac)
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
	vehicle, acl := env.newSignedVehicleBundle(t, id)
	vehicle.Integrity = nil

	rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles", vehicleCreateRequest(vehicle, acl), id, mac)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestJourneyVehicleCreateRejectsMissingACLIntegrity(t *testing.T) {
	env := newJourneyEnv(t)
	id := env.mintIdentity(t)
	journey := env.mustCreateJourney(t, id, "Pacific Coast Drive")
	jid, err := opencaravan.ParseUUID(journey.ID)
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}
	mac := env.issueSessionMacaroon(t, id, jid, opencaravan.SessionActionJourneyWrite)
	vehicle, acl := env.newSignedVehicleBundle(t, id)
	acl.Integrity = nil

	rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles", vehicleCreateRequest(vehicle, acl), id, mac)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestJourneyVehicleCreateRejectsACLVehicleIDMismatch(t *testing.T) {
	env := newJourneyEnv(t)
	id := env.mintIdentity(t)
	journey := env.mustCreateJourney(t, id, "Pacific Coast Drive")
	jid, err := opencaravan.ParseUUID(journey.ID)
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}
	mac := env.issueSessionMacaroon(t, id, jid, opencaravan.SessionActionJourneyWrite)
	vehicle, acl := env.newSignedVehicleBundle(t, id)
	wrong, err := opencaravan.NewUUID()
	if err != nil {
		t.Fatalf("NewUUID: %v", err)
	}
	acl.VehicleID = wrong
	env.signVehicleACL(t, id, &acl)

	rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles", vehicleCreateRequest(vehicle, acl), id, mac)
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

	firstV, firstA := env.newSignedVehicleBundle(t, id)
	if rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles", vehicleCreateRequest(firstV, firstA), id, mac); rec.Code != http.StatusCreated {
		t.Fatalf("first create: got %d, body=%s", rec.Code, rec.Body.String())
	}

	secondV, secondA := env.newSignedVehicleBundle(t, id)
	rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles", vehicleCreateRequest(secondV, secondA), id, mac)
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

	vehicle, acl := env.newSignedVehicleBundle(t, id)
	if rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles", vehicleCreateRequest(vehicle, acl), id, writeMac); rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d, body=%s", rec.Code, rec.Body.String())
	}

	rec := env.get(t, "/v1/journeys/"+journey.ID+"/vehicles/"+string(vehicle.ID), id, readMac)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: got %d want 200; body=%s", rec.Code, rec.Body.String())
	}
	var got JourneyVehicleResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if got.Vehicle.DisplayName != "Riley's Subaru" {
		t.Fatalf("display_name: got %q", got.Vehicle.DisplayName)
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

	vehicle, acl := env.newSignedVehicleBundle(t, id)
	if rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles", vehicleCreateRequest(vehicle, acl), id, writeMac); rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d, body=%s", rec.Code, rec.Body.String())
	}

	newDriver, err := opencaravan.NewUUID()
	if err != nil {
		t.Fatalf("NewUUID: %v", err)
	}
	v2 := opencaravan.VehicleACL{
		VehicleID:         vehicle.ID,
		OwnerUserID:       opencaravan.UUID(id.UserID),
		ACLVersion:        2,
		AuthorizedDrivers: []opencaravan.UUID{opencaravan.UUID(id.UserID), newDriver},
		EmergencyRule: &opencaravan.VehicleEmergencyRule{
			Kind: opencaravan.VehicleEmergencyRuleNone,
		},
		EffectiveTime: time.Now().Add(time.Minute).UTC(),
	}
	env.signVehicleACL(t, id, &v2)
	rec := env.post(t,
		"/v1/journeys/"+journey.ID+"/vehicles/"+string(vehicle.ID)+"/acl-revisions",
		v2, id, writeMac)
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
	getRec := env.get(t, "/v1/journeys/"+journey.ID+"/vehicles/"+string(vehicle.ID), id, readMac)
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

func TestJourneyVehicleACLAppendFrozenAfterOwnerDeparts(t *testing.T) {
	// Locked-in decision: a Vehicle becomes immutable when its
	// recorded owner is no longer a journey participant. The
	// vehicle remains in the journey (existing attestations still
	// validate) but the owner cannot publish a new ACL revision.
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	journey := env.mustCreateJourney(t, owner, "Pacific Coast Drive")
	jid, err := opencaravan.ParseUUID(journey.ID)
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}
	writeMac := env.issueSessionMacaroon(t, owner, jid, opencaravan.SessionActionJourneyWrite)

	vehicle, acl := env.newSignedVehicleBundle(t, owner)
	if rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles", vehicleCreateRequest(vehicle, acl), owner, writeMac); rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d body=%s", rec.Code, rec.Body.String())
	}

	// Simulate owner-departure by deleting the owner's
	// journey_participants row. The macaroon caveat path still
	// admits the request (the macaroon was minted while owner was
	// a participant), so the handler-side freeze is what should
	// reject the ACL append.
	if _, err := env.store.DB().ExecContext(context.Background(),
		`DELETE FROM journey_participants WHERE journey_id = ? AND account_id = ?`,
		journey.ID, owner.UserID); err != nil {
		t.Fatalf("simulate owner departure: %v", err)
	}

	v2 := opencaravan.VehicleACL{
		VehicleID:         vehicle.ID,
		OwnerUserID:       opencaravan.UUID(owner.UserID),
		ACLVersion:        2,
		AuthorizedDrivers: []opencaravan.UUID{opencaravan.UUID(owner.UserID)},
		EmergencyRule: &opencaravan.VehicleEmergencyRule{
			Kind: opencaravan.VehicleEmergencyRuleNone,
		},
		EffectiveTime: time.Now().Add(time.Minute).UTC(),
	}
	env.signVehicleACL(t, owner, &v2)
	rec := env.post(t,
		"/v1/journeys/"+journey.ID+"/vehicles/"+string(vehicle.ID)+"/acl-revisions",
		v2, owner, writeMac)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want 403; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "owner_not_a_participant") {
		t.Fatalf("body missing owner_not_a_participant code: %s", rec.Body.String())
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

	vehicle, acl := env.newSignedVehicleBundle(t, id)
	if rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles", vehicleCreateRequest(vehicle, acl), id, writeMac); rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d", rec.Code)
	}

	otherID, err := opencaravan.NewUUID()
	if err != nil {
		t.Fatalf("NewUUID: %v", err)
	}
	v2 := opencaravan.VehicleACL{
		VehicleID:         otherID, // wrong — must equal vehicle.ID
		OwnerUserID:       opencaravan.UUID(id.UserID),
		ACLVersion:        2,
		AuthorizedDrivers: acl.AuthorizedDrivers,
		EffectiveTime:     time.Now().UTC(),
	}
	env.signVehicleACL(t, id, &v2)
	rec := env.post(t,
		"/v1/journeys/"+journey.ID+"/vehicles/"+string(vehicle.ID)+"/acl-revisions",
		v2, id, writeMac)
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
	vehicle, acl := env.newSignedVehicleBundle(t, owner)
	if rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles", vehicleCreateRequest(vehicle, acl), owner, ownerMac); rec.Code != http.StatusCreated {
		t.Fatalf("owner create: got %d, body=%s", rec.Code, rec.Body.String())
	}

	// "Other" caller acquires a journey.write session and tries to
	// append an ACL to the vehicle, claiming themselves as owner.
	// The handler must reject with 403 because the stored owner is
	// `owner`, not `other`.
	otherMac := env.issueSessionMacaroon(t, other, jid, opencaravan.SessionActionJourneyWrite)
	spoofed := opencaravan.VehicleACL{
		VehicleID:         vehicle.ID,
		OwnerUserID:       opencaravan.UUID(other.UserID),
		ACLVersion:        2,
		AuthorizedDrivers: acl.AuthorizedDrivers,
		EffectiveTime:     time.Now().Add(time.Minute).UTC(),
	}
	env.signVehicleACL(t, other, &spoofed)
	rec := env.post(t,
		"/v1/journeys/"+journey.ID+"/vehicles/"+string(vehicle.ID)+"/acl-revisions",
		spoofed, other, otherMac)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want 403; body=%s", rec.Code, rec.Body.String())
	}
}

func TestJourneyVehicleCreateRejectsTamperedSignature(t *testing.T) {
	// Sign the bundle, then mutate a payload field — the
	// signature no longer covers the post-mutation canonical
	// bytes, so the verifier must reject with 403.
	env := newJourneyEnv(t)
	id := env.mintIdentity(t)
	journey := env.mustCreateJourney(t, id, "Pacific Coast Drive")
	jid, err := opencaravan.ParseUUID(journey.ID)
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}
	mac := env.issueSessionMacaroon(t, id, jid, opencaravan.SessionActionJourneyWrite)

	vehicle, acl := env.newSignedVehicleBundle(t, id)
	// Tamper: change the display name without re-signing.
	vehicle.DisplayName = "Tampered Vehicle Name"

	rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles", vehicleCreateRequest(vehicle, acl), id, mac)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want 403 (tampered signature); body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "signature_invalid") {
		t.Fatalf("expected signature_invalid problem code; body=%s", rec.Body.String())
	}
}

func TestJourneyVehicleCreateRejectsUnknownKeyID(t *testing.T) {
	// Sign with a valid key but set Integrity.KeyID to a UUID
	// that isn't enrolled — the cert lookup must fail with 403.
	env := newJourneyEnv(t)
	id := env.mintIdentity(t)
	journey := env.mustCreateJourney(t, id, "Pacific Coast Drive")
	jid, err := opencaravan.ParseUUID(journey.ID)
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}
	mac := env.issueSessionMacaroon(t, id, jid, opencaravan.SessionActionJourneyWrite)

	vehicle, acl := env.newSignedVehicleBundle(t, id)
	bogus, err := opencaravan.NewUUID()
	if err != nil {
		t.Fatalf("NewUUID: %v", err)
	}
	vehicle.Integrity.KeyID = string(bogus)

	rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles", vehicleCreateRequest(vehicle, acl), id, mac)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want 403 (unknown key id); body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "signer_not_enrolled") {
		t.Fatalf("expected signer_not_enrolled problem code; body=%s", rec.Body.String())
	}
}

func TestJourneyVehicleCreateRejectsSignerOwnerMismatch(t *testing.T) {
	// Two enrolled identities A and B. Build a vehicle whose
	// OwnerUserID claims A, but sign it with B's key (i.e.,
	// Integrity.KeyID = B's client_app_id). The session-vs-owner
	// check is satisfied (A's session, A's owner), but the
	// cert-vs-owner cross-check must fire and reject because the
	// signer cert belongs to B, not A.
	env := newJourneyEnv(t)
	a := env.mintIdentity(t)
	b := env.mintIdentity(t)
	journey := env.mustCreateJourney(t, a, "Pacific Coast Drive")
	jid, err := opencaravan.ParseUUID(journey.ID)
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}
	mac := env.issueSessionMacaroon(t, a, jid, opencaravan.SessionActionJourneyWrite)

	// Build the vehicle with owner=A as usual, then re-sign with
	// B's key. signVehicle preserves OwnerUserID, only replaces
	// Integrity — so the result is a perfectly valid signature
	// by B over a payload owned by A. The cert-vs-owner check
	// must catch this even though the signature itself verifies.
	vehicle, acl := env.newSignedVehicleBundle(t, a)
	env.signVehicle(t, b, &vehicle)

	rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles", vehicleCreateRequest(vehicle, acl), a, mac)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want 403 (signer/owner mismatch); body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "signer_owner_mismatch") {
		t.Fatalf("expected signer_owner_mismatch problem code; body=%s", rec.Body.String())
	}
}

func TestJourneyVehicleACLAppendRejectsTamperedSignature(t *testing.T) {
	env := newJourneyEnv(t)
	id := env.mintIdentity(t)
	journey := env.mustCreateJourney(t, id, "Pacific Coast Drive")
	jid, err := opencaravan.ParseUUID(journey.ID)
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}
	writeMac := env.issueSessionMacaroon(t, id, jid, opencaravan.SessionActionJourneyWrite)

	vehicle, acl := env.newSignedVehicleBundle(t, id)
	if rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles", vehicleCreateRequest(vehicle, acl), id, writeMac); rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d", rec.Code)
	}

	newDriver, err := opencaravan.NewUUID()
	if err != nil {
		t.Fatalf("NewUUID: %v", err)
	}
	v2 := opencaravan.VehicleACL{
		VehicleID:         vehicle.ID,
		OwnerUserID:       opencaravan.UUID(id.UserID),
		ACLVersion:        2,
		AuthorizedDrivers: []opencaravan.UUID{opencaravan.UUID(id.UserID), newDriver},
		EffectiveTime:     time.Now().Add(time.Minute).UTC(),
	}
	env.signVehicleACL(t, id, &v2)
	// Tamper: bump ACL version without re-signing.
	v2.ACLVersion = 99

	rec := env.post(t,
		"/v1/journeys/"+journey.ID+"/vehicles/"+string(vehicle.ID)+"/acl-revisions",
		v2, id, writeMac)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want 403; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "signature_invalid") {
		t.Fatalf("expected signature_invalid problem code; body=%s", rec.Body.String())
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
	vehicle, acl := env.newSignedVehicleBundle(t, id)

	rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles", vehicleCreateRequest(vehicle, acl), id, mac)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d want 503; body=%s", rec.Code, rec.Body.String())
	}
}

func TestJourneyVehicleRevisionAppendHappyPath(t *testing.T) {
	// New endpoint: POST /v1/journeys/{id}/vehicles/{vid}/revisions
	// accepts a new signed Vehicle metadata bundle (no ACL change)
	// and advances current_revision_version. The GET handler must
	// then surface the new bundle.
	env := newJourneyEnv(t)
	id := env.mintIdentity(t)
	journey := env.mustCreateJourney(t, id, "Pacific Coast Drive")
	jid, err := opencaravan.ParseUUID(journey.ID)
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}
	writeMac := env.issueSessionMacaroon(t, id, jid, opencaravan.SessionActionJourneyWrite)

	vehicle, acl := env.newSignedVehicleBundle(t, id)
	if rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles", vehicleCreateRequest(vehicle, acl), id, writeMac); rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d body=%s", rec.Code, rec.Body.String())
	}

	v2 := vehicle
	v2.RevisionVersion = 2
	v2.RevisionTime = time.Now().Add(time.Minute).UTC()
	v2.DisplayName = "Riley's Renamed Subaru"
	env.signVehicle(t, id, &v2)

	rec := env.post(t,
		"/v1/journeys/"+journey.ID+"/vehicles/"+string(vehicle.ID)+"/revisions",
		v2, id, writeMac)
	if rec.Code != http.StatusCreated {
		t.Fatalf("revision status: got %d want 201; body=%s", rec.Code, rec.Body.String())
	}
	var revResp JourneyVehicleRevisionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &revResp); err != nil {
		t.Fatalf("decode revision: %v", err)
	}
	if revResp.RevisionVersion != 2 {
		t.Fatalf("revision_version: got %d want 2", revResp.RevisionVersion)
	}

	// GET reflects the new revision in canonical_payload-decoded form.
	readMac := env.issueSessionMacaroon(t, id, jid, opencaravan.SessionActionJourneyRead)
	getRec := env.get(t, "/v1/journeys/"+journey.ID+"/vehicles/"+string(vehicle.ID), id, readMac)
	if getRec.Code != http.StatusOK {
		t.Fatalf("get: got %d", getRec.Code)
	}
	var got JourneyVehicleResponse
	if err := json.Unmarshal(getRec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if got.CurrentRevisionVersion != 2 {
		t.Fatalf("current_revision_version: got %d want 2", got.CurrentRevisionVersion)
	}
	if got.Vehicle.DisplayName != "Riley's Renamed Subaru" {
		t.Fatalf("display_name: got %q", got.Vehicle.DisplayName)
	}
}

func TestJourneyVehicleRevisionAppendStaleVersionConflict(t *testing.T) {
	env := newJourneyEnv(t)
	id := env.mintIdentity(t)
	journey := env.mustCreateJourney(t, id, "Pacific Coast Drive")
	jid, err := opencaravan.ParseUUID(journey.ID)
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}
	writeMac := env.issueSessionMacaroon(t, id, jid, opencaravan.SessionActionJourneyWrite)

	vehicle, acl := env.newSignedVehicleBundle(t, id)
	if rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles", vehicleCreateRequest(vehicle, acl), id, writeMac); rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d", rec.Code)
	}
	// Re-post v=1 — must 409.
	rec := env.post(t,
		"/v1/journeys/"+journey.ID+"/vehicles/"+string(vehicle.ID)+"/revisions",
		vehicle, id, writeMac)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status: got %d want 409; body=%s", rec.Code, rec.Body.String())
	}
}

func TestJourneyVehicleRevisionAppendFrozenAfterOwnerDeparts(t *testing.T) {
	// The owner-departure freeze applies symmetrically to
	// metadata revisions and ACL revisions: a departed owner
	// can't bump a photo any more than they can rotate drivers.
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	journey := env.mustCreateJourney(t, owner, "Pacific Coast Drive")
	jid, err := opencaravan.ParseUUID(journey.ID)
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}
	writeMac := env.issueSessionMacaroon(t, owner, jid, opencaravan.SessionActionJourneyWrite)

	vehicle, acl := env.newSignedVehicleBundle(t, owner)
	if rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles", vehicleCreateRequest(vehicle, acl), owner, writeMac); rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d", rec.Code)
	}
	if _, err := env.store.DB().ExecContext(context.Background(),
		`DELETE FROM journey_participants WHERE journey_id = ? AND account_id = ?`,
		journey.ID, owner.UserID); err != nil {
		t.Fatalf("simulate owner departure: %v", err)
	}

	v2 := vehicle
	v2.RevisionVersion = 2
	v2.RevisionTime = time.Now().Add(time.Minute).UTC()
	v2.DisplayName = "After departure"
	env.signVehicle(t, owner, &v2)
	rec := env.post(t,
		"/v1/journeys/"+journey.ID+"/vehicles/"+string(vehicle.ID)+"/revisions",
		v2, owner, writeMac)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want 403; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "owner_not_a_participant") {
		t.Fatalf("body missing owner_not_a_participant: %s", rec.Body.String())
	}
}
