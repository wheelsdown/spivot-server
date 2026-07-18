package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/opencaravan/opencaravan-go"

	"github.com/wheelsdown/spivot-server/internal/platform/storage"
	"github.com/wheelsdown/spivot-server/internal/server/middleware"
)

// JourneyVehicleCreateRequest is the wire shape for POST
// /v1/journeys/{id}/vehicles. With the OpenCaravan 0.2-draft
// transition the journey-scoped Vehicle is metadata-only and the
// AuthorizedDrivers / EmergencyRule fields live on a separate
// VehicleACL bundle, so a participant joining a journey must
// publish BOTH signed bundles atomically: the Vehicle (metadata
// v=1) and the InitialACL (authorization v=1). The server stores
// the canonical bytes of each verbatim and verifies both
// signatures before accepting the create.
type JourneyVehicleCreateRequest struct {
	// Vehicle is the signed metadata bundle (v=1) describing the
	// vehicle. Its owner_user_id must match the session user and
	// its integrity signature must verify against the owner's
	// enrolled signing key.
	Vehicle opencaravan.Vehicle `json:"vehicle"`
	// InitialACL is the signed authorization bundle (v=1) naming
	// the vehicle's authorized drivers. Signed by the same owner
	// under the same rules as Vehicle; the pair is accepted or
	// rejected atomically.
	InitialACL opencaravan.VehicleACL `json:"initial_acl"`
}

// JourneyVehicleResponse is the wire shape the journey-vehicle
// handlers return. Includes the head-pointer projection
// (id/journey/owner/version pointers) AND the latest Vehicle
// metadata bundle decoded from canonical_payload_json so clients
// don't need a separate revision fetch to render the display
// name, photos, capacity, etc. The bundle is exposed verbatim —
// no per-field projection — so clients see whatever the protocol
// version supports.
//
// Kept as a server type (not an alias for [opencaravan.Vehicle])
// so the protocol type can evolve independently from the
// server's public API surface.
type JourneyVehicleResponse struct {
	// ID is the vehicle's identifier as claimed by the signed
	// bundle, scoped to the journey.
	ID string `json:"id" openapi:"format=uuid,readOnly"`
	// JourneyID is the journey this vehicle was uploaded against.
	JourneyID string `json:"journey_id" openapi:"format=uuid,readOnly"`
	// OwnerUserID is the user who signed (and therefore owns) the
	// vehicle's bundles.
	OwnerUserID string `json:"owner_user_id" openapi:"format=uuid,readOnly"`
	// CurrentRevisionVersion is the head pointer of the vehicle's
	// metadata revision chain (monotonically increasing).
	CurrentRevisionVersion int `json:"current_revision_version" openapi:"readOnly"`
	// CurrentACLVersion is the head pointer of the vehicle's ACL
	// revision chain (monotonically increasing).
	CurrentACLVersion int `json:"current_acl_version" openapi:"readOnly"`
	// Vehicle is the latest signed metadata bundle, decoded from
	// the stored canonical bytes verbatim.
	Vehicle opencaravan.Vehicle `json:"vehicle" openapi:"readOnly"`
	// ReceivedAt is when the server accepted the vehicle's
	// original create.
	ReceivedAt time.Time `json:"received_at" openapi:"readOnly"`
}

// JourneyVehicleListResponse is the envelope returned by
// `GET /v1/journeys/{id}/vehicles`. The envelope shape lets future
// phases add pagination metadata or filter cursors without changing
// the field name "vehicles" that clients already index against.
type JourneyVehicleListResponse struct {
	// Vehicles is every vehicle uploaded against the journey,
	// oldest first.
	Vehicles []JourneyVehicleResponse `json:"vehicles"`
}

// JourneyVehicleACLRevisionResponse is what the ACL append handler
// returns: the revision metadata the client needs to confirm the
// version landed and to render an "ACL changed at $time" entry in a
// vehicle history view.
type JourneyVehicleACLRevisionResponse struct {
	// ID is the server-assigned identifier of the stored ACL
	// revision row.
	ID string `json:"id" openapi:"format=uuid,readOnly"`
	// JourneyVehicleID is the vehicle this ACL revision belongs to.
	JourneyVehicleID string `json:"journey_vehicle_id" openapi:"format=uuid,readOnly"`
	// ACLVersion is the revision's version as claimed by the
	// signed bundle. It advanced the head pointer, so it is now
	// the vehicle's current_acl_version.
	ACLVersion int `json:"acl_version" openapi:"readOnly"`
	// EffectiveTime is when the ACL takes effect, per the signed
	// bundle. Trust evaluation consults the ACL in effect at an
	// attestation's effective time, not the newest one.
	EffectiveTime time.Time `json:"effective_time" openapi:"readOnly"`
	// EmergencyRule is the bundle's non-ACL-driver fallback
	// policy. Omitted when the bundle carries none (equivalent to
	// "none": no fallback, non-ACL drivers record as violations).
	EmergencyRule *opencaravan.VehicleEmergencyRule `json:"emergency_rule,omitempty" openapi:"readOnly"`
	// Integrity is the owner's signature envelope over the
	// bundle's canonical bytes, echoed as verified and stored.
	Integrity opencaravan.Integrity `json:"integrity" openapi:"readOnly"`
	// ReceivedAt is when the server accepted this revision.
	ReceivedAt time.Time `json:"received_at" openapi:"readOnly"`
}

// JourneyVehicleRevisionResponse is what the metadata revision
// append handler returns: the revision metadata plus the decoded
// Vehicle bundle that's now current. Symmetric with
// [JourneyVehicleACLRevisionResponse] but for the metadata side.
type JourneyVehicleRevisionResponse struct {
	// ID is the server-assigned identifier of the stored metadata
	// revision row.
	ID string `json:"id" openapi:"format=uuid,readOnly"`
	// JourneyVehicleID is the vehicle this revision belongs to.
	JourneyVehicleID string `json:"journey_vehicle_id" openapi:"format=uuid,readOnly"`
	// RevisionVersion is the revision's version as claimed by the
	// signed bundle. It advanced the head pointer, so it is now
	// the vehicle's current_revision_version.
	RevisionVersion int `json:"revision_version" openapi:"readOnly"`
	// RevisionTime is the bundle's self-declared revision
	// timestamp.
	RevisionTime time.Time `json:"revision_time" openapi:"readOnly"`
	// Vehicle is the decoded metadata bundle that is now current.
	Vehicle opencaravan.Vehicle `json:"vehicle" openapi:"readOnly"`
	// ReceivedAt is when the server accepted this revision.
	ReceivedAt time.Time `json:"received_at" openapi:"readOnly"`
}

// handleJourneyVehicleCreate implements POST /v1/journeys/{id}/vehicles.
//
// Wrapped by [middleware.RequireSession] with a journey.write
// constraint: the caller's macaroon must carry journey={id} +
// action=journey.write caveats. The handler accepts a
// [JourneyVehicleCreateRequest] (Vehicle + InitialACL) and
// enforces, for BOTH bundles:
//
//  1. payload.owner_user_id == session.user_id (defense in depth
//     so a journey.write holder can't attribute a vehicle to
//     another user).
//  2. The signing client app's enrolled cert (resolved via
//     Integrity.KeyID) belongs to the claimed owner.
//  3. The Integrity envelope's ecdsa-p256-sha256 signature
//     verifies against the resolved cert's public key over the
//     canonical bytes.
//
// Canonical bytes are stored verbatim so a later signature
// re-verification doesn't depend on reproducing the original
// encoder behavior.
//
// Failures map to:
//
//   - 503 when VehicleStore or IntegrityVerifier is not wired.
//   - 400 for malformed JSON, failed structural validation, or
//     mismatched IDs between Vehicle and InitialACL.
//   - 403 when an owner-vs-session mismatch is detected, the
//     signing client app's enrolled cert doesn't belong to the
//     claimed owner, or either signature doesn't verify.
//   - 409 when the (journey_id, owner_user_id) pair already has
//     a vehicle.
//   - 500 for unexpected storage failures (logged, not exposed).
func (s *Server) handleJourneyVehicleCreate(w http.ResponseWriter, r *http.Request) {
	if s.cfg.VehicleStore == nil {
		writeProblem(w, s.logger, http.StatusServiceUnavailable, "vehicles_unavailable",
			"This server is not configured to manage journey vehicles.")
		return
	}
	id, ok := middleware.IdentityFrom(r.Context())
	if !ok {
		s.logger.Error("vehicles: handler reached without context identity")
		writeProblem(w, s.logger, http.StatusUnauthorized, "unauthenticated",
			"This endpoint requires an enrolled client app identity.")
		return
	}
	journeyID := r.PathValue("id")

	var body JourneyVehicleCreateRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_request",
			fmt.Sprintf("Could not decode vehicle create request body: %s", err))
		return
	}
	vehicle := body.Vehicle
	acl := body.InitialACL

	if err := vehicle.Validate(); err != nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_vehicle",
			fmt.Sprintf("Vehicle failed structural validation: %s", err))
		return
	}
	if vehicle.Integrity == nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_vehicle",
			"Vehicle.integrity envelope is required on the wire.")
		return
	}
	if err := acl.Validate(); err != nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_acl",
			fmt.Sprintf("initial_acl failed structural validation: %s", err))
		return
	}
	if acl.Integrity == nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_acl",
			"initial_acl.integrity envelope is required on the wire.")
		return
	}
	if acl.VehicleID != vehicle.ID {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_acl",
			"initial_acl.vehicle_id must equal vehicle.id.")
		return
	}
	if acl.OwnerUserID != vehicle.OwnerUserID {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_acl",
			"initial_acl.owner_user_id must equal vehicle.owner_user_id.")
		return
	}
	// The create endpoint mints the genesis revisions of both
	// chains. Subsequent metadata revisions go through the
	// /revisions endpoint; subsequent ACL revisions go through
	// /acl-revisions. Reject any non-genesis version here so a
	// client that mistakenly POSTs a later revision to the
	// create endpoint gets a clear error instead of silently
	// creating a chain with no v=1.
	if vehicle.RevisionVersion != 1 {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_vehicle",
			"vehicle.revision_version must be 1 on create; POST subsequent revisions to /revisions.")
		return
	}
	if acl.ACLVersion != 1 {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_acl",
			"initial_acl.acl_version must be 1 on create; POST subsequent ACL revisions to /acl-revisions.")
		return
	}
	if string(vehicle.OwnerUserID) != id.UserID {
		s.logger.Warn("vehicles: owner mismatch",
			"session_user_id", id.UserID,
			"payload_owner_user_id", vehicle.OwnerUserID,
			"journey_id", journeyID,
		)
		writeProblem(w, s.logger, http.StatusForbidden, "owner_mismatch",
			"vehicle.owner_user_id must match the session caller.")
		return
	}

	vehicleCanonical, err := vehicle.CanonicalEncoding()
	if err != nil {
		s.logger.Error("vehicles: vehicle canonical encode failed", "error", err)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not compute canonical vehicle bytes.")
		return
	}
	aclCanonical, err := acl.CanonicalEncoding()
	if err != nil {
		s.logger.Error("vehicles: acl canonical encode failed", "error", err)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not compute canonical initial_acl bytes.")
		return
	}

	// Cryptographic verification: confirm the signing client app's
	// enrolled cert belongs to the claimed owner AND that the
	// signature verifies against the cert's public key over the
	// canonical bytes — separately for the Vehicle and the
	// InitialACL. The verifier resolves each half's KeyID
	// independently; the two halves MAY be signed by different
	// client apps as long as both apps are enrolled to the same
	// owner user. This is intentional — an owner with multiple
	// devices (phone + tablet) often signs different payloads
	// from different apps, and forcing both halves through one
	// app would harm offline-first workflows.
	if !verifySignedPayload(w, r, s.logger, s.cfg.IntegrityVerifier, s.cfg.VehicleStore,
		vehicleCanonical, *vehicle.Integrity, string(vehicle.OwnerUserID), "vehicles") {
		return
	}
	if !verifySignedPayload(w, r, s.logger, s.cfg.IntegrityVerifier, s.cfg.VehicleStore,
		aclCanonical, *acl.Integrity, string(acl.OwnerUserID), "vehicles-acl") {
		return
	}

	rec, err := s.cfg.VehicleStore.CreateJourneyVehicle(r.Context(), storage.JourneyVehicleCreateParams{
		JourneyID:               journeyID,
		Vehicle:                 vehicle,
		InitialACL:              acl,
		CanonicalVehiclePayload: vehicleCanonical,
		CanonicalACLPayload:     aclCanonical,
	})
	switch {
	case errors.Is(err, storage.ErrJourneyVehicleDuplicateOwner):
		writeProblem(w, s.logger, http.StatusConflict, "vehicle_already_exists",
			"This user already has a vehicle uploaded for this journey.")
		return
	case errors.Is(err, storage.ErrJourneyVehicleDuplicateID):
		writeProblem(w, s.logger, http.StatusConflict, "vehicle_id_in_use",
			"The supplied Vehicle.id is already in use; mint a fresh UUID.")
		return
	case err != nil:
		s.logger.Error("vehicles: create failed", "error", err, "journey_id", journeyID, "user_id", id.UserID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not create journey vehicle.")
		return
	}

	s.logger.Info("journey vehicle created",
		"journey_id", rec.JourneyID,
		"vehicle_id", rec.ID,
		"owner_user_id", rec.OwnerUserID,
	)
	resp, err := journeyVehicleResponseFromRecord(rec)
	if err != nil {
		s.logger.Error("vehicles: response build failed", "error", err)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not assemble journey vehicle response.")
		return
	}
	writeJSONStatus(w, http.StatusCreated, resp, s.logger)
}

// handleJourneyVehicleList implements GET /v1/journeys/{id}/vehicles.
//
// Wrapped by [middleware.RequireSession] with a journey.read
// constraint. Every session caller permitted to read the journey
// sees the full vehicle list — no per-vehicle ACL gating at this
// layer because the journey-write authority is what controls
// vehicle visibility in v0.1.
func (s *Server) handleJourneyVehicleList(w http.ResponseWriter, r *http.Request) {
	if s.cfg.VehicleStore == nil {
		writeProblem(w, s.logger, http.StatusServiceUnavailable, "vehicles_unavailable",
			"This server is not configured to manage journey vehicles.")
		return
	}
	journeyID := r.PathValue("id")
	records, err := s.cfg.VehicleStore.ListJourneyVehicles(r.Context(), journeyID)
	if err != nil {
		s.logger.Error("vehicles: list failed", "error", err, "journey_id", journeyID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not list journey vehicles.")
		return
	}
	out := make([]JourneyVehicleResponse, 0, len(records))
	for _, rec := range records {
		resp, err := journeyVehicleResponseFromRecord(rec)
		if err != nil {
			s.logger.Error("vehicles: list decode failed", "error", err, "vehicle_id", rec.ID)
			writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
				"Could not decode stored vehicle bundle.")
			return
		}
		out = append(out, resp)
	}
	writeJSON(w, JourneyVehicleListResponse{Vehicles: out}, s.logger)
}

// handleJourneyVehicleGet implements GET /v1/journeys/{id}/vehicles/{vid}.
func (s *Server) handleJourneyVehicleGet(w http.ResponseWriter, r *http.Request) {
	if s.cfg.VehicleStore == nil {
		writeProblem(w, s.logger, http.StatusServiceUnavailable, "vehicles_unavailable",
			"This server is not configured to manage journey vehicles.")
		return
	}
	journeyID := r.PathValue("id")
	vehicleID := r.PathValue("vid")
	rec, err := s.cfg.VehicleStore.JourneyVehicleByID(r.Context(), journeyID, vehicleID)
	switch {
	case errors.Is(err, storage.ErrJourneyVehicleNotFound):
		writeProblem(w, s.logger, http.StatusNotFound, "vehicle_not_found",
			"No vehicle exists at this journey and id.")
		return
	case err != nil:
		s.logger.Error("vehicles: get failed", "error", err, "journey_id", journeyID, "vehicle_id", vehicleID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not load journey vehicle.")
		return
	}
	resp, err := journeyVehicleResponseFromRecord(rec)
	if err != nil {
		s.logger.Error("vehicles: get decode failed", "error", err, "vehicle_id", rec.ID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not decode stored vehicle bundle.")
		return
	}
	writeJSON(w, resp, s.logger)
}

// handleJourneyVehicleACLAppend implements
// POST /v1/journeys/{id}/vehicles/{vid}/acl-revisions.
//
// The caller is the vehicle's owner publishing a new VehicleACL
// revision. The handler enforces the same "owner must match
// session" defense as the create handler, plus the
// owner-departure freeze (vehicle is immutable when its recorded
// owner is no longer a journey participant) and the storage
// layer's monotonic-version invariant.
//
// Failures map to:
//
//   - 503 when VehicleStore is not wired.
//   - 400 for malformed JSON or failed ACL validation.
//   - 403 when the supplied ACL's owner_user_id != session user
//     or the owner is no longer a journey participant.
//   - 404 when the vehicle does not exist at the supplied id.
//   - 409 when the supplied ACL version is not strictly greater
//     than (or distinct from) the existing version on file.
func (s *Server) handleJourneyVehicleACLAppend(w http.ResponseWriter, r *http.Request) {
	if s.cfg.VehicleStore == nil {
		writeProblem(w, s.logger, http.StatusServiceUnavailable, "vehicles_unavailable",
			"This server is not configured to manage journey vehicles.")
		return
	}
	id, ok := middleware.IdentityFrom(r.Context())
	if !ok {
		s.logger.Error("vehicles: acl handler reached without context identity")
		writeProblem(w, s.logger, http.StatusUnauthorized, "unauthenticated",
			"This endpoint requires an enrolled client app identity.")
		return
	}
	journeyID := r.PathValue("id")
	vehicleID := r.PathValue("vid")

	if err := s.authorizeJourneyVehicleOwner(w, r, id.UserID, journeyID, vehicleID, "acl"); err != nil {
		return
	}

	var acl opencaravan.VehicleACL
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&acl); err != nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_request",
			fmt.Sprintf("Could not decode VehicleACL request body: %s", err))
		return
	}
	if err := acl.Validate(); err != nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_acl",
			fmt.Sprintf("VehicleACL failed structural validation: %s", err))
		return
	}
	if acl.Integrity == nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_acl",
			"VehicleACL.integrity envelope is required on the wire.")
		return
	}
	if string(acl.VehicleID) != vehicleID {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_acl",
			"VehicleACL.vehicle_id must match the path vehicle id.")
		return
	}
	if string(acl.OwnerUserID) != id.UserID {
		writeProblem(w, s.logger, http.StatusForbidden, "owner_mismatch",
			"VehicleACL.owner_user_id must match the session caller.")
		return
	}
	canonical, err := acl.CanonicalEncoding()
	if err != nil {
		s.logger.Error("vehicles: acl canonical encode failed", "error", err)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not compute canonical ACL bytes.")
		return
	}

	if !verifySignedPayload(w, r, s.logger, s.cfg.IntegrityVerifier, s.cfg.VehicleStore,
		canonical, *acl.Integrity, string(acl.OwnerUserID), "vehicles-acl") {
		return
	}

	rev, err := s.cfg.VehicleStore.AppendJourneyVehicleACL(r.Context(), storage.JourneyVehicleACLAppendParams{
		JourneyVehicleID: vehicleID,
		ACL:              acl,
		CanonicalPayload: canonical,
	})
	switch {
	case errors.Is(err, storage.ErrJourneyVehicleACLVersionConflict):
		writeProblem(w, s.logger, http.StatusConflict, "acl_version_conflict",
			"VehicleACL.acl_version must be strictly greater than the vehicle's current ACL version.")
		return
	case errors.Is(err, storage.ErrJourneyVehicleNotFound):
		writeProblem(w, s.logger, http.StatusNotFound, "vehicle_not_found",
			"No vehicle exists at this journey and id.")
		return
	case err != nil:
		s.logger.Error("vehicles: acl append failed", "error", err, "journey_id", journeyID, "vehicle_id", vehicleID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not record VehicleACL revision.")
		return
	}

	s.logger.Info("vehicle acl revision recorded",
		"journey_id", journeyID,
		"vehicle_id", vehicleID,
		"acl_version", rev.ACLVersion,
	)
	writeJSONStatus(w, http.StatusCreated, JourneyVehicleACLRevisionResponse{
		ID:               rev.ID,
		JourneyVehicleID: rev.JourneyVehicleID,
		ACLVersion:       rev.ACLVersion,
		EffectiveTime:    rev.EffectiveTime.UTC(),
		EmergencyRule:    decodeEmergencyRule(rev.EmergencyRuleKind),
		Integrity:        rev.Integrity,
		ReceivedAt:       rev.ReceivedAt.UTC(),
	}, s.logger)
}

// handleJourneyVehicleRevisionAppend implements
// POST /v1/journeys/{id}/vehicles/{vid}/revisions.
//
// Symmetric with handleJourneyVehicleACLAppend but for the
// Vehicle metadata bundle. Same authority chain: caller must own
// the recorded vehicle and must still be a journey participant
// (owner-departure freeze applies to metadata edits as well as
// ACL edits — a departed owner can't bump a photo any more than
// they can rotate drivers).
func (s *Server) handleJourneyVehicleRevisionAppend(w http.ResponseWriter, r *http.Request) {
	if s.cfg.VehicleStore == nil {
		writeProblem(w, s.logger, http.StatusServiceUnavailable, "vehicles_unavailable",
			"This server is not configured to manage journey vehicles.")
		return
	}
	id, ok := middleware.IdentityFrom(r.Context())
	if !ok {
		s.logger.Error("vehicles: revision handler reached without context identity")
		writeProblem(w, s.logger, http.StatusUnauthorized, "unauthenticated",
			"This endpoint requires an enrolled client app identity.")
		return
	}
	journeyID := r.PathValue("id")
	vehicleID := r.PathValue("vid")

	if err := s.authorizeJourneyVehicleOwner(w, r, id.UserID, journeyID, vehicleID, "revision"); err != nil {
		return
	}

	var vehicle opencaravan.Vehicle
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&vehicle); err != nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_request",
			fmt.Sprintf("Could not decode vehicle request body: %s", err))
		return
	}
	if err := vehicle.Validate(); err != nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_vehicle",
			fmt.Sprintf("Vehicle failed structural validation: %s", err))
		return
	}
	if vehicle.Integrity == nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_vehicle",
			"Vehicle.integrity envelope is required on the wire.")
		return
	}
	if string(vehicle.ID) != vehicleID {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_vehicle",
			"Vehicle.id must match the path vehicle id.")
		return
	}
	if string(vehicle.OwnerUserID) != id.UserID {
		writeProblem(w, s.logger, http.StatusForbidden, "owner_mismatch",
			"Vehicle.owner_user_id must match the session caller.")
		return
	}

	canonical, err := vehicle.CanonicalEncoding()
	if err != nil {
		s.logger.Error("vehicles: revision canonical encode failed", "error", err)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not compute canonical vehicle bytes.")
		return
	}

	if !verifySignedPayload(w, r, s.logger, s.cfg.IntegrityVerifier, s.cfg.VehicleStore,
		canonical, *vehicle.Integrity, string(vehicle.OwnerUserID), "vehicles-revision") {
		return
	}

	rev, err := s.cfg.VehicleStore.AppendJourneyVehicleRevision(r.Context(), storage.JourneyVehicleRevisionAppendParams{
		JourneyVehicleID: vehicleID,
		Vehicle:          vehicle,
		CanonicalPayload: canonical,
	})
	switch {
	case errors.Is(err, storage.ErrJourneyVehicleRevisionConflict):
		writeProblem(w, s.logger, http.StatusConflict, "revision_version_conflict",
			"Vehicle.revision_version must be strictly greater than the vehicle's current revision version.")
		return
	case errors.Is(err, storage.ErrJourneyVehicleNotFound):
		writeProblem(w, s.logger, http.StatusNotFound, "vehicle_not_found",
			"No vehicle exists at this journey and id.")
		return
	case err != nil:
		s.logger.Error("vehicles: revision append failed", "error", err, "journey_id", journeyID, "vehicle_id", vehicleID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not record vehicle revision.")
		return
	}

	s.logger.Info("vehicle revision recorded",
		"journey_id", journeyID,
		"vehicle_id", vehicleID,
		"revision_version", rev.RevisionVersion,
	)
	writeJSONStatus(w, http.StatusCreated, JourneyVehicleRevisionResponse{
		ID:               rev.ID,
		JourneyVehicleID: rev.JourneyVehicleID,
		RevisionVersion:  rev.RevisionVersion,
		RevisionTime:     rev.RevisionTime.UTC(),
		Vehicle:          vehicle,
		ReceivedAt:       rev.ReceivedAt.UTC(),
	}, s.logger)
}

// authorizeJourneyVehicleOwner shares the four-step
// authorization preamble between the ACL append and metadata
// revision append handlers:
//
//  1. Load the stored vehicle (404 if missing).
//  2. Confirm the session caller is the recorded owner (403
//     otherwise — defense in depth against a journey.write
//     holder trying to mutate someone else's vehicle).
//  3. Confirm JourneyStore is wired so we can verify journey
//     participation (503 otherwise).
//  4. Confirm the recorded owner is still a journey participant
//     (403 owner_not_a_participant otherwise — the
//     owner-departure freeze).
//
// On any failure the helper writes a Problem to w and returns a
// non-nil error so the caller halts. On success it returns nil
// and the caller proceeds. Neither caller needs the loaded
// record (the append paths take their state from the inbound
// request body), so the helper does not return it; the "where"
// argument tags log lines so the two callers don't collide.
func (s *Server) authorizeJourneyVehicleOwner(w http.ResponseWriter, r *http.Request, sessionUserID, journeyID, vehicleID, where string) error {
	stored, err := s.cfg.VehicleStore.JourneyVehicleByID(r.Context(), journeyID, vehicleID)
	if err != nil {
		if errors.Is(err, storage.ErrJourneyVehicleNotFound) {
			writeProblem(w, s.logger, http.StatusNotFound, "vehicle_not_found",
				"No vehicle exists at this journey and id.")
			return err
		}
		s.logger.Error("vehicles: "+where+" precheck failed", "error", err, "journey_id", journeyID, "vehicle_id", vehicleID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not look up journey vehicle.")
		return err
	}
	if stored.OwnerUserID != sessionUserID {
		s.logger.Warn("vehicles: "+where+" by non-owner rejected",
			"session_user_id", sessionUserID,
			"stored_owner_user_id", stored.OwnerUserID,
			"journey_id", journeyID,
			"vehicle_id", vehicleID,
		)
		writeProblem(w, s.logger, http.StatusForbidden, "owner_mismatch",
			"Only the vehicle's recorded owner may publish new revisions.")
		return errors.New("owner mismatch")
	}
	// Owner-departure freeze: per the protocol's locked-in
	// decision ([opencaravan-go/docs/vehicles.md], "Edit Rights
	// After Owner Departs"), a Vehicle becomes immutable when its
	// recorded owner is no longer a journey participant. The
	// vehicle remains in the journey — driver attestations
	// against the existing ACL still validate — but the owner
	// cannot publish a new revision after leaving. If they
	// rejoin the journey, the freeze lifts.
	if s.cfg.JourneyStore == nil {
		writeProblem(w, s.logger, http.StatusServiceUnavailable, "journey_unavailable",
			"This server is not configured to verify journey participation.")
		return errors.New("journey store not wired")
	}
	if _, err := s.cfg.JourneyStore.JourneyParticipantByUserAndJourney(r.Context(), stored.OwnerUserID, journeyID); err != nil {
		if errors.Is(err, storage.ErrJourneyParticipantNotFound) {
			s.logger.Info("vehicles: "+where+" append blocked — owner not a journey participant",
				"journey_id", journeyID,
				"vehicle_id", vehicleID,
				"owner_user_id", stored.OwnerUserID,
			)
			writeProblem(w, s.logger, http.StatusForbidden, "owner_not_a_participant",
				"The vehicle's owner is no longer a journey participant; the vehicle is frozen.")
			return err
		}
		s.logger.Error("vehicles: "+where+" owner-participant lookup failed", "error", err,
			"journey_id", journeyID, "owner_user_id", stored.OwnerUserID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not verify journey participation.")
		return err
	}
	return nil
}

// journeyVehicleResponseFromRecord decodes the persisted
// canonical bundle bytes into an [opencaravan.Vehicle] for the
// response and assembles the wrapper response shape. The bundle
// bytes are owner-signed and stored verbatim, so decoding here is
// pure deserialization — no re-canonicalization or signature
// re-verification.
func journeyVehicleResponseFromRecord(rec storage.JourneyVehicleRecord) (JourneyVehicleResponse, error) {
	var vehicle opencaravan.Vehicle
	if err := json.Unmarshal(rec.CanonicalPayloadJSON, &vehicle); err != nil {
		return JourneyVehicleResponse{}, fmt.Errorf("decode vehicle canonical payload: %w", err)
	}
	vehicle.Integrity = &opencaravan.Integrity{
		Algorithm: rec.Integrity.Algorithm,
		KeyID:     rec.Integrity.KeyID,
		Signature: rec.Integrity.Signature,
	}
	return JourneyVehicleResponse{
		ID:                     rec.ID,
		JourneyID:              rec.JourneyID,
		OwnerUserID:            rec.OwnerUserID,
		CurrentRevisionVersion: rec.CurrentRevisionVersion,
		CurrentACLVersion:      rec.CurrentACLVersion,
		Vehicle:                vehicle,
		ReceivedAt:             rec.ReceivedAt.UTC(),
	}, nil
}

// decodeEmergencyRule reconstructs an [opencaravan.VehicleEmergencyRule]
// from the kind string the storage layer denormalized off the ACL
// canonical payload. Returns nil when no rule was set.
func decodeEmergencyRule(kind string) *opencaravan.VehicleEmergencyRule {
	if kind == "" {
		return nil
	}
	return &opencaravan.VehicleEmergencyRule{Kind: opencaravan.VehicleEmergencyRuleKind(kind)}
}
