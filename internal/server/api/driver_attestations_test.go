package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/opencaravan/opencaravan-go"

	"github.com/wheelsdown/spivot-server/internal/platform/storage"
	"github.com/wheelsdown/spivot-server/internal/server/middleware"
)

// uploadVehicleFor uploads a journey vehicle owned by `owner`
// with the supplied emergency rule (nil keeps the default rule
// from newSignedVehiclePayload) and returns the vehicle's id.
// Helper for the attestation handler tests so the per-test
// boilerplate stays focused on the attestation flow itself.
func uploadVehicleFor(t *testing.T, env *journeyEnv, owner middleware.Identity, journey JourneyResponse, emergency *opencaravan.VehicleEmergencyRule) opencaravan.UUID {
	t.Helper()
	jid, err := opencaravan.ParseUUID(journey.ID)
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}
	mac := env.issueSessionMacaroon(t, owner, jid, opencaravan.SessionActionJourneyWrite)
	payload := env.newSignedVehiclePayload(t, owner)
	payload.EmergencyRule = emergency
	// Re-sign after the EmergencyRule mutation since the signature
	// produced by newSignedVehiclePayload covers the default rule.
	env.signVehicle(t, owner, &payload)
	rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles", payload, owner, mac)
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload vehicle: got %d, body=%s", rec.Code, rec.Body.String())
	}
	return payload.ID
}

// newSignedAttestationPayload builds a DriverAttestation owned
// by `driver` (DriverUserID set + signed with that identity's
// enrolled key).
//
// For tests that need the SIGNER and CLAIMED driver to differ
// (driver-mismatch tests like
// TestDriverAttestationRecordRejectsSignerDriverMismatch), build
// the payload with the claimed driver passed here, then call
// env.signDriverAttestation(t, otherIdentity, &payload) to
// re-sign with a different identity's key. The re-sign preserves
// DriverUserID while replacing Integrity, so the signature stays
// cryptographically valid (over the unchanged canonical bytes)
// and the cert-vs-driver cross-check at the handler is what
// fires. Mutating DriverUserID after signing would invalidate
// the signature and short-circuit to ErrSignatureInvalid before
// the cross-check can run — useless for testing the cross-check.
func (e *journeyEnv) newSignedAttestationPayload(t *testing.T, vehicleID opencaravan.UUID, driver middleware.Identity, effective time.Time, aclVersion int, priorHash *string) opencaravan.DriverAttestation {
	t.Helper()
	segmentID, err := opencaravan.NewUUID()
	if err != nil {
		t.Fatalf("NewUUID segment: %v", err)
	}
	a := opencaravan.DriverAttestation{
		VehicleID:            vehicleID,
		SegmentID:            segmentID,
		DriverUserID:         opencaravan.UUID(driver.UserID),
		EffectiveTime:        effective,
		ACLVersionConsulted:  aclVersion,
		PriorAttestationHash: priorHash,
	}
	e.signDriverAttestation(t, driver, &a)
	return a
}

// joinJourneyAsParticipant inserts a journey_participants row in
// "joined" state for `user`. Required by the emergency-fallback
// path: the trust resolver checks the driver is a current
// participant before classifying as emergency_fallback.
func joinJourneyAsParticipant(t *testing.T, env *journeyEnv, user middleware.Identity, journey JourneyResponse) {
	t.Helper()
	participantUUID, err := opencaravan.NewUUID()
	if err != nil {
		t.Fatalf("NewUUID participant: %v", err)
	}
	// Match the storage layer's fixed-width sqliteTimeFormat so the
	// subsequent lookup doesn't trip on variable-precision nanos.
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z")
	if _, err := env.store.DB().ExecContext(context.Background(), `
INSERT INTO journey_participants (
    id, journey_id, account_id, display_name, role, state, sharing_state,
    policy_hash, joined_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
`,
		string(participantUUID),
		journey.ID,
		user.UserID,
		"",
		"driver",
		"joined",
		"off",
		"test-policy-hash",
		now,
	); err != nil {
		t.Fatalf("insert participant: %v", err)
	}
}

func TestDriverAttestationRecordAuthorizedHappyPath(t *testing.T) {
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	journey := env.mustCreateJourney(t, owner, "Pacific Coast Drive")
	jid, err := opencaravan.ParseUUID(journey.ID)
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}
	vehicleID := uploadVehicleFor(t, env, owner, journey, &opencaravan.VehicleEmergencyRule{
		Kind: opencaravan.VehicleEmergencyRuleAnyJourneyParticipant,
	})

	// Owner is implicitly authorized — they should always classify
	// as authorized regardless of ACL contents.
	writeMac := env.issueSessionMacaroon(t, owner, jid, opencaravan.SessionActionJourneyWrite)
	attestation := env.newSignedAttestationPayload(t, vehicleID, owner,
		time.Now().Add(time.Minute).UTC(), 1, nil)
	rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles/"+string(vehicleID)+"/driver-attestations",
		attestation, owner, writeMac)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp DriverAttestationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.TrustFlag != storage.DriverAttestationTrustAuthorized {
		t.Fatalf("trust_flag: got %q want authorized", resp.TrustFlag)
	}
	if resp.ACLVersionConsulted != 1 {
		t.Fatalf("acl_version_consulted: got %d", resp.ACLVersionConsulted)
	}
}

func TestDriverAttestationRecordEmergencyFallbackPath(t *testing.T) {
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	other := env.mintIdentity(t)
	journey := env.mustCreateJourney(t, owner, "Pacific Coast Drive")
	jid, err := opencaravan.ParseUUID(journey.ID)
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}
	// Vehicle with emergency rule = any_journey_participant. Other
	// is NOT in AuthorizedDrivers (vehicle was just uploaded with
	// owner + a fresh UUID as the authorized members).
	vehicleID := uploadVehicleFor(t, env, owner, journey, &opencaravan.VehicleEmergencyRule{
		Kind: opencaravan.VehicleEmergencyRuleAnyJourneyParticipant,
	})
	// Other is a journey participant — the emergency fallback
	// requires the driver be a current participant.
	joinJourneyAsParticipant(t, env, other, journey)

	writeMac := env.issueSessionMacaroon(t, other, jid, opencaravan.SessionActionJourneyWrite)
	attestation := env.newSignedAttestationPayload(t, vehicleID, other,
		time.Now().Add(time.Minute).UTC(), 1, nil)
	rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles/"+string(vehicleID)+"/driver-attestations",
		attestation, other, writeMac)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp DriverAttestationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.TrustFlag != storage.DriverAttestationTrustEmergencyFallback {
		t.Fatalf("trust_flag: got %q want emergency_fallback", resp.TrustFlag)
	}
}

func TestDriverAttestationRecordACLViolationPath(t *testing.T) {
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	other := env.mintIdentity(t)
	journey := env.mustCreateJourney(t, owner, "Pacific Coast Drive")
	jid, err := opencaravan.ParseUUID(journey.ID)
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}
	// Emergency rule = none → no fallback. Other is not in ACL.
	// Don't seed as a participant — even joining wouldn't matter
	// when emergency_rule is none; this verifies the no-fallback
	// path explicitly.
	vehicleID := uploadVehicleFor(t, env, owner, journey, &opencaravan.VehicleEmergencyRule{
		Kind: opencaravan.VehicleEmergencyRuleNone,
	})

	writeMac := env.issueSessionMacaroon(t, other, jid, opencaravan.SessionActionJourneyWrite)
	attestation := env.newSignedAttestationPayload(t, vehicleID, other,
		time.Now().Add(time.Minute).UTC(), 1, nil)
	rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles/"+string(vehicleID)+"/driver-attestations",
		attestation, other, writeMac)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp DriverAttestationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.TrustFlag != storage.DriverAttestationTrustACLViolation {
		t.Fatalf("trust_flag: got %q want acl_violation", resp.TrustFlag)
	}
}

func TestDriverAttestationRecordReplayReturns200(t *testing.T) {
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	journey := env.mustCreateJourney(t, owner, "Pacific Coast Drive")
	jid, err := opencaravan.ParseUUID(journey.ID)
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}
	vehicleID := uploadVehicleFor(t, env, owner, journey, nil)

	writeMac := env.issueSessionMacaroon(t, owner, jid, opencaravan.SessionActionJourneyWrite)
	effective := time.Now().Add(time.Minute).UTC()
	first := env.newSignedAttestationPayload(t, vehicleID, owner, effective, 1, nil)
	if rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles/"+string(vehicleID)+"/driver-attestations",
		first, owner, writeMac); rec.Code != http.StatusCreated {
		t.Fatalf("first: got %d", rec.Code)
	}

	// Replay with the same effective_time (gossip retry) — must
	// return 200 OK with the existing record.
	second := env.newSignedAttestationPayload(t, vehicleID, owner, effective, 1, nil)
	rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles/"+string(vehicleID)+"/driver-attestations",
		second, owner, writeMac)
	if rec.Code != http.StatusOK {
		t.Fatalf("replay status: got %d want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestDriverAttestationRecordReplayPreservesOriginalTrust(t *testing.T) {
	// Locks in the "replay returns the original trust_flag" invariant
	// from the PR description: an ACL revision published between the
	// original record and a gossip replay must NOT retroactively
	// reclassify the existing row. This also exercises the new
	// short-circuit ordering — the handler now checks the replay
	// key BEFORE running the classifier, so even if the classifier
	// would now produce a different outcome (or fail transiently),
	// the response reflects the state at original record time.
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	other := env.mintIdentity(t)
	journey := env.mustCreateJourney(t, owner, "Pacific Coast Drive")
	jid, err := opencaravan.ParseUUID(journey.ID)
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}
	// Emergency rule = none, so other classifies as acl_violation on first submit.
	vehicleID := uploadVehicleFor(t, env, owner, journey, &opencaravan.VehicleEmergencyRule{
		Kind: opencaravan.VehicleEmergencyRuleNone,
	})
	otherMac := env.issueSessionMacaroon(t, other, jid, opencaravan.SessionActionJourneyWrite)

	effective := time.Now().Add(time.Minute).UTC()
	first := env.newSignedAttestationPayload(t, vehicleID, other, effective, 1, nil)
	if rec := env.post(t,
		"/v1/journeys/"+journey.ID+"/vehicles/"+string(vehicleID)+"/driver-attestations",
		first, other, otherMac); rec.Code != http.StatusCreated {
		t.Fatalf("first: got %d body=%s", rec.Code, rec.Body.String())
	}

	// Owner publishes a new VehicleACL revision that adds `other`
	// to AuthorizedDrivers. A fresh classification would now
	// produce "authorized" instead of "acl_violation".
	ownerWriteMac := env.issueSessionMacaroon(t, owner, jid, opencaravan.SessionActionJourneyWrite)
	acl := opencaravan.VehicleACL{
		VehicleID:         vehicleID,
		OwnerUserID:       opencaravan.UUID(owner.UserID),
		ACLVersion:        2,
		AuthorizedDrivers: []opencaravan.UUID{opencaravan.UUID(owner.UserID), opencaravan.UUID(other.UserID)},
		EffectiveTime:     time.Now().Add(2 * time.Minute).UTC(),
	}
	env.signVehicleACL(t, owner, &acl)
	if rec := env.post(t,
		"/v1/journeys/"+journey.ID+"/vehicles/"+string(vehicleID)+"/acl-revisions",
		acl, owner, ownerWriteMac); rec.Code != http.StatusCreated {
		t.Fatalf("acl revision: got %d body=%s", rec.Code, rec.Body.String())
	}

	// Replay the original attestation — must return the original
	// "acl_violation" classification, NOT a freshly-recomputed
	// "authorized".
	replay := env.newSignedAttestationPayload(t, vehicleID, other, effective, 1, nil)
	rec := env.post(t,
		"/v1/journeys/"+journey.ID+"/vehicles/"+string(vehicleID)+"/driver-attestations",
		replay, other, otherMac)
	if rec.Code != http.StatusOK {
		t.Fatalf("replay status: got %d want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp DriverAttestationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.TrustFlag != storage.DriverAttestationTrustACLViolation {
		t.Fatalf("trust_flag: got %q want acl_violation (replay must preserve original)", resp.TrustFlag)
	}
}

func TestDriverAttestationRecordDriverMismatchRejected(t *testing.T) {
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	other := env.mintIdentity(t)
	journey := env.mustCreateJourney(t, owner, "Pacific Coast Drive")
	jid, err := opencaravan.ParseUUID(journey.ID)
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}
	vehicleID := uploadVehicleFor(t, env, owner, journey, nil)

	// Caller is `other` but they claim to BE the owner. Must reject 403.
	otherMac := env.issueSessionMacaroon(t, other, jid, opencaravan.SessionActionJourneyWrite)
	spoofed := env.newSignedAttestationPayload(t, vehicleID, owner,
		time.Now().Add(time.Minute).UTC(), 1, nil)
	rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles/"+string(vehicleID)+"/driver-attestations",
		spoofed, other, otherMac)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want 403; body=%s", rec.Code, rec.Body.String())
	}
}

func TestDriverAttestationRecordVehicleIDMismatchRejected(t *testing.T) {
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	journey := env.mustCreateJourney(t, owner, "Pacific Coast Drive")
	jid, err := opencaravan.ParseUUID(journey.ID)
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}
	vehicleID := uploadVehicleFor(t, env, owner, journey, nil)

	writeMac := env.issueSessionMacaroon(t, owner, jid, opencaravan.SessionActionJourneyWrite)
	wrongID, err := opencaravan.NewUUID()
	if err != nil {
		t.Fatalf("NewUUID: %v", err)
	}
	bad := env.newSignedAttestationPayload(t, wrongID, owner,
		time.Now().Add(time.Minute).UTC(), 1, nil)
	rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles/"+string(vehicleID)+"/driver-attestations",
		bad, owner, writeMac)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestDriverAttestationRecordMissingIntegrityRejected(t *testing.T) {
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	journey := env.mustCreateJourney(t, owner, "Pacific Coast Drive")
	jid, err := opencaravan.ParseUUID(journey.ID)
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}
	vehicleID := uploadVehicleFor(t, env, owner, journey, nil)

	writeMac := env.issueSessionMacaroon(t, owner, jid, opencaravan.SessionActionJourneyWrite)
	bad := env.newSignedAttestationPayload(t, vehicleID, owner,
		time.Now().Add(time.Minute).UTC(), 1, nil)
	bad.Integrity = nil
	rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles/"+string(vehicleID)+"/driver-attestations",
		bad, owner, writeMac)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestDriverAttestationRecordNoACLAtEffectiveTimeRejected(t *testing.T) {
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	journey := env.mustCreateJourney(t, owner, "Pacific Coast Drive")
	jid, err := opencaravan.ParseUUID(journey.ID)
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}
	vehicleID := uploadVehicleFor(t, env, owner, journey, nil)

	// effective_time before the vehicle's initial ACL effective
	// time. The resolver has nothing to validate against and the
	// handler must reject with 400.
	writeMac := env.issueSessionMacaroon(t, owner, jid, opencaravan.SessionActionJourneyWrite)
	tooEarly := time.Now().Add(-365 * 24 * time.Hour).UTC()
	bad := env.newSignedAttestationPayload(t, vehicleID, owner, tooEarly, 1, nil)
	rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles/"+string(vehicleID)+"/driver-attestations",
		bad, owner, writeMac)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestDriverAttestationListReturnsRecorded(t *testing.T) {
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	journey := env.mustCreateJourney(t, owner, "Pacific Coast Drive")
	jid, err := opencaravan.ParseUUID(journey.ID)
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}
	vehicleID := uploadVehicleFor(t, env, owner, journey, nil)

	writeMac := env.issueSessionMacaroon(t, owner, jid, opencaravan.SessionActionJourneyWrite)
	attestation := env.newSignedAttestationPayload(t, vehicleID, owner,
		time.Now().Add(time.Minute).UTC(), 1, nil)
	if rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles/"+string(vehicleID)+"/driver-attestations",
		attestation, owner, writeMac); rec.Code != http.StatusCreated {
		t.Fatalf("record: got %d", rec.Code)
	}

	readMac := env.issueSessionMacaroon(t, owner, jid, opencaravan.SessionActionJourneyRead)
	rec := env.get(t, "/v1/journeys/"+journey.ID+"/vehicles/"+string(vehicleID)+"/driver-attestations",
		owner, readMac)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status: got %d want 200; body=%s", rec.Code, rec.Body.String())
	}
	var list DriverAttestationListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list.Attestations) != 1 {
		t.Fatalf("expected 1 attestation, got %d", len(list.Attestations))
	}
}

func TestDriverAttestationRecordRejectsTamperedSignature(t *testing.T) {
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	journey := env.mustCreateJourney(t, owner, "Pacific Coast Drive")
	jid, err := opencaravan.ParseUUID(journey.ID)
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}
	vehicleID := uploadVehicleFor(t, env, owner, journey, &opencaravan.VehicleEmergencyRule{
		Kind: opencaravan.VehicleEmergencyRuleAnyJourneyParticipant,
	})

	writeMac := env.issueSessionMacaroon(t, owner, jid, opencaravan.SessionActionJourneyWrite)
	attestation := env.newSignedAttestationPayload(t, vehicleID, owner,
		time.Now().Add(time.Minute).UTC(), 1, nil)
	// Tamper: change ACL version after signing.
	attestation.ACLVersionConsulted = 999

	rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles/"+string(vehicleID)+"/driver-attestations",
		attestation, owner, writeMac)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want 403; body=%s", rec.Code, rec.Body.String())
	}
}

func TestDriverAttestationRecordRejectsSignerDriverMismatch(t *testing.T) {
	// driver = A, but signed by B's key. The cert-vs-driver
	// cross-check must fire even though the signature itself is
	// cryptographically valid (signed properly by B's key).
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	other := env.mintIdentity(t)
	journey := env.mustCreateJourney(t, owner, "Pacific Coast Drive")
	jid, err := opencaravan.ParseUUID(journey.ID)
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}
	vehicleID := uploadVehicleFor(t, env, owner, journey, &opencaravan.VehicleEmergencyRule{
		Kind: opencaravan.VehicleEmergencyRuleAnyJourneyParticipant,
	})
	joinJourneyAsParticipant(t, env, other, journey)

	// Build the attestation claiming `other` is the driver, then
	// re-sign with `owner`'s key. signDriverAttestation preserves
	// DriverUserID; only Integrity is replaced.
	otherMac := env.issueSessionMacaroon(t, other, jid, opencaravan.SessionActionJourneyWrite)
	attestation := env.newSignedAttestationPayload(t, vehicleID, other,
		time.Now().Add(time.Minute).UTC(), 1, nil)
	env.signDriverAttestation(t, owner, &attestation)

	rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles/"+string(vehicleID)+"/driver-attestations",
		attestation, other, otherMac)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want 403; body=%s", rec.Code, rec.Body.String())
	}
}

func TestDriverAttestationForkSiblingsExposedOnRecord(t *testing.T) {
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	other := env.mintIdentity(t)
	journey := env.mustCreateJourney(t, owner, "Pacific Coast Drive")
	jid, err := opencaravan.ParseUUID(journey.ID)
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}
	vehicleID := uploadVehicleFor(t, env, owner, journey, &opencaravan.VehicleEmergencyRule{
		Kind: opencaravan.VehicleEmergencyRuleAnyJourneyParticipant,
	})
	joinJourneyAsParticipant(t, env, other, journey)

	priorHash := "sha256:" + "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

	// Owner records first attestation chaining to the predecessor.
	ownerMac := env.issueSessionMacaroon(t, owner, jid, opencaravan.SessionActionJourneyWrite)
	first := env.newSignedAttestationPayload(t, vehicleID, owner,
		time.Now().Add(time.Minute).UTC(), 1, &priorHash)
	if rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles/"+string(vehicleID)+"/driver-attestations",
		first, owner, ownerMac); rec.Code != http.StatusCreated {
		t.Fatalf("first: got %d body=%s", rec.Code, rec.Body.String())
	}

	// Other claims the SAME predecessor — that's a fork.
	otherMac := env.issueSessionMacaroon(t, other, jid, opencaravan.SessionActionJourneyWrite)
	second := env.newSignedAttestationPayload(t, vehicleID, other,
		time.Now().Add(2*time.Minute).UTC(), 1, &priorHash)
	rec := env.post(t, "/v1/journeys/"+journey.ID+"/vehicles/"+string(vehicleID)+"/driver-attestations",
		second, other, otherMac)
	if rec.Code != http.StatusCreated {
		t.Fatalf("second: got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp DriverAttestationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.ForkSiblings) != 2 {
		t.Fatalf("expected 2 fork siblings, got %d", len(resp.ForkSiblings))
	}
}
