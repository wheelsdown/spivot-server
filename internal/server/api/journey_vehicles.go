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

// JourneyVehicleResponse is the wire shape the journey-vehicle
// handlers return. A deliberate subset of [opencaravan.Vehicle]: the
// fields a client needs to render a vehicle in a list or detail view
// plus the ACL pointer the client uses to know which VehicleACL
// revision to look up. The raw signed payload bytes are excluded
// from the JSON response by default — clients that need to
// reverify a signature can request a separate endpoint in a future
// phase.
//
// Kept as a server type (not an alias for [opencaravan.Vehicle]) so
// the protocol type can evolve independently from the server's
// public API surface.
type JourneyVehicleResponse struct {
	ID                string                            `json:"id"`
	JourneyID         string                            `json:"journey_id"`
	OwnerUserID       string                            `json:"owner_user_id"`
	DisplayName       string                            `json:"display_name"`
	Make              string                            `json:"make,omitempty"`
	Model             string                            `json:"model,omitempty"`
	ModelYear         int                               `json:"model_year,omitempty"`
	Color             string                            `json:"color,omitempty"`
	Capacity          int                               `json:"capacity"`
	AvatarImage       *opencaravan.ImageResourceRef     `json:"avatar_image,omitempty"`
	BannerImage       *opencaravan.ImageResourceRef     `json:"banner_image,omitempty"`
	CurrentACLVersion int                               `json:"current_acl_version"`
	EmergencyRule     *opencaravan.VehicleEmergencyRule `json:"emergency_rule,omitempty"`
	Integrity         opencaravan.Integrity             `json:"integrity"`
	CreatedAt         time.Time                         `json:"created_at"`
}

// JourneyVehicleListResponse is the envelope returned by
// `GET /v1/journeys/{id}/vehicles`. The envelope shape lets future
// phases add pagination metadata or filter cursors without changing
// the field name "vehicles" that clients already index against.
type JourneyVehicleListResponse struct {
	Vehicles []JourneyVehicleResponse `json:"vehicles"`
}

// JourneyVehicleACLRevisionResponse is what the ACL append handler
// returns: the revision metadata the client needs to confirm the
// version landed and to render an "ACL changed at $time" entry in a
// vehicle history view.
type JourneyVehicleACLRevisionResponse struct {
	ID               string                            `json:"id"`
	JourneyVehicleID string                            `json:"journey_vehicle_id"`
	ACLVersion       int                               `json:"acl_version"`
	EffectiveTime    time.Time                         `json:"effective_time"`
	EmergencyRule    *opencaravan.VehicleEmergencyRule `json:"emergency_rule,omitempty"`
	Integrity        opencaravan.Integrity             `json:"integrity"`
	ReceivedAt       time.Time                         `json:"received_at"`
}

// handleJourneyVehicleCreate implements POST /v1/journeys/{id}/vehicles.
//
// Wrapped by [middleware.RequireSession] with a journey.write
// constraint: the caller's macaroon must carry journey={id} +
// action=journey.write caveats. The handler additionally enforces
// "the owner_user_id in the payload must match the session
// identity" — defense in depth so a holder of a journey.write
// session cannot attribute a vehicle to another user.
//
// Signature cryptographic verification is deferred to the
// driver-attestation phase; this handler trusts the structural
// envelope plus the session-identity match. The canonical bytes
// the owner signed are recomputed and stored so a future
// verification pass can re-check the signature without trusting
// the wire body's whitespace.
//
// Failures map to:
//
//   - 503 when VehicleStore is not wired.
//   - 400 for malformed JSON or failed structural validation.
//   - 403 when payload.owner_user_id != session.user_id.
//   - 409 when the (journey_id, owner_user_id) pair already has a
//     vehicle.
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

	canonical, err := vehicle.CanonicalEncoding()
	if err != nil {
		s.logger.Error("vehicles: canonical encode failed", "error", err)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not compute canonical vehicle bytes.")
		return
	}

	rec, err := s.cfg.VehicleStore.CreateJourneyVehicle(r.Context(), storage.JourneyVehicleCreateParams{
		JourneyID:        journeyID,
		Vehicle:          vehicle,
		CanonicalPayload: canonical,
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
	writeJSONStatus(w, http.StatusCreated, journeyVehicleResponseFrom(rec, vehicle.AvatarImage, vehicle.BannerImage, vehicle.EmergencyRule), s.logger)
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
		avatar, banner := decodeImageRefs(rec)
		emergency := decodeEmergencyRule(rec.EmergencyRuleKind)
		out = append(out, journeyVehicleResponseFrom(rec, avatar, banner, emergency))
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
	avatar, banner := decodeImageRefs(rec)
	emergency := decodeEmergencyRule(rec.EmergencyRuleKind)
	writeJSON(w, journeyVehicleResponseFrom(rec, avatar, banner, emergency), s.logger)
}

// handleJourneyVehicleACLAppend implements
// POST /v1/journeys/{id}/vehicles/{vid}/acl-revisions.
//
// The caller is the vehicle's owner publishing a new VehicleACL
// revision. The handler enforces the same "owner must match
// session" defense as the create handler, plus the storage layer's
// monotonic-version invariant.
//
// Failures map to:
//
//   - 503 when VehicleStore is not wired.
//   - 400 for malformed JSON or failed ACL validation.
//   - 403 when the supplied ACL's owner_user_id != session user.
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

	// Load the stored vehicle so we can confirm the session caller is
	// the recorded owner. Without this check, any holder of a
	// journey.write session could append an ACL to another
	// participant's vehicle by setting payload.owner_user_id to
	// themselves — breaking the "owner-signed" invariant that
	// DriverAttestation relies on.
	stored, err := s.cfg.VehicleStore.JourneyVehicleByID(r.Context(), journeyID, vehicleID)
	if err != nil {
		if errors.Is(err, storage.ErrJourneyVehicleNotFound) {
			writeProblem(w, s.logger, http.StatusNotFound, "vehicle_not_found",
				"No vehicle exists at this journey and id.")
			return
		}
		s.logger.Error("vehicles: acl precheck failed", "error", err, "journey_id", journeyID, "vehicle_id", vehicleID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not look up journey vehicle.")
		return
	}
	if stored.OwnerUserID != id.UserID {
		s.logger.Warn("vehicles: acl append by non-owner rejected",
			"session_user_id", id.UserID,
			"stored_owner_user_id", stored.OwnerUserID,
			"journey_id", journeyID,
			"vehicle_id", vehicleID,
		)
		writeProblem(w, s.logger, http.StatusForbidden, "owner_mismatch",
			"Only the vehicle's recorded owner may publish ACL revisions.")
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

func journeyVehicleResponseFrom(rec storage.JourneyVehicleRecord, avatar, banner *opencaravan.ImageResourceRef, emergency *opencaravan.VehicleEmergencyRule) JourneyVehicleResponse {
	return JourneyVehicleResponse{
		ID:                rec.ID,
		JourneyID:         rec.JourneyID,
		OwnerUserID:       rec.OwnerUserID,
		DisplayName:       rec.DisplayName,
		Make:              rec.Make,
		Model:             rec.Model,
		ModelYear:         rec.ModelYear,
		Color:             rec.Color,
		Capacity:          rec.Capacity,
		AvatarImage:       avatar,
		BannerImage:       banner,
		CurrentACLVersion: rec.CurrentACLVersion,
		EmergencyRule:     emergency,
		Integrity:         rec.Integrity,
		CreatedAt:         rec.CreatedAt.UTC(),
	}
}

func decodeImageRefs(rec storage.JourneyVehicleRecord) (*opencaravan.ImageResourceRef, *opencaravan.ImageResourceRef) {
	return decodeImageRef(rec.AvatarImageRefJSON), decodeImageRef(rec.BannerImageRefJSON)
}

func decodeImageRef(raw string) *opencaravan.ImageResourceRef {
	if raw == "" {
		return nil
	}
	var ref opencaravan.ImageResourceRef
	if err := json.Unmarshal([]byte(raw), &ref); err != nil {
		return nil
	}
	return &ref
}

func decodeEmergencyRule(kind string) *opencaravan.VehicleEmergencyRule {
	if kind == "" {
		return nil
	}
	return &opencaravan.VehicleEmergencyRule{Kind: opencaravan.VehicleEmergencyRuleKind(kind)}
}
