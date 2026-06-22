package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/opencaravan/opencaravan-go"

	"github.com/wheelsdown/spivot-server/internal/platform/storage"
	"github.com/wheelsdown/spivot-server/internal/server/middleware"
)

// GarageVehicleResponse is the wire shape the garage vehicle
// handlers return. Includes the head-pointer projection plus the
// latest GarageVehicle bundle decoded from canonical_payload_json
// so clients see whatever fields the protocol version supports
// without per-attribute projection on the server side.
type GarageVehicleResponse struct {
	ID                     string                    `json:"id"`
	GarageID               string                    `json:"garage_id"`
	CurrentRevisionVersion int                       `json:"current_revision_version"`
	GarageVehicle          opencaravan.GarageVehicle `json:"garage_vehicle"`
	ReceivedAt             time.Time                 `json:"received_at"`
}

// GarageVehicleListResponse is the envelope for GET
// /v1/garages/{id}/vehicles. Envelope shape so future phases can
// add filter metadata.
type GarageVehicleListResponse struct {
	Vehicles []GarageVehicleResponse `json:"vehicles"`
}

// handleGarageVehicleCreate implements
// POST /v1/garages/{id}/vehicles.
//
// Authority: caller must be an *accepted* owner of the containing
// garage (pending invitees cannot mutate the garage's vehicle
// library). The payload's signed_by must equal the session caller
// and the payload's garage_id must equal the path garage id.
func (s *Server) handleGarageVehicleCreate(w http.ResponseWriter, r *http.Request) {
	if s.cfg.GarageStore == nil {
		writeProblem(w, s.logger, http.StatusServiceUnavailable, "garages_unavailable",
			"This server is not configured to manage garages.")
		return
	}
	id, ok := middleware.IdentityFrom(r.Context())
	if !ok {
		s.logger.Error("garage-vehicles: handler reached without context identity")
		writeProblem(w, s.logger, http.StatusUnauthorized, "unauthenticated",
			"This endpoint requires an enrolled client app identity.")
		return
	}
	garageID := r.PathValue("id")
	if err := s.requireAcceptedGarageOwner(r.Context(), id.UserID, garageID); err != nil {
		s.writeGarageOwnerError(w, err, garageID, id.UserID, "vehicle create authority check")
		return
	}

	var gv opencaravan.GarageVehicle
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&gv); err != nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_request",
			fmt.Sprintf("Could not decode GarageVehicle request body: %s", err))
		return
	}
	if err := gv.Validate(); err != nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_garage_vehicle",
			fmt.Sprintf("GarageVehicle failed structural validation: %s", err))
		return
	}
	if gv.Integrity == nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_garage_vehicle",
			"GarageVehicle.integrity envelope is required on the wire.")
		return
	}
	if gv.RevisionVersion != 1 {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_garage_vehicle",
			"POST /v1/garages/{id}/vehicles requires revision_version = 1.")
		return
	}
	if string(gv.GarageID) != garageID {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_garage_vehicle",
			"GarageVehicle.garage_id must match the path garage id.")
		return
	}
	if string(gv.SignedBy) != id.UserID {
		writeProblem(w, s.logger, http.StatusForbidden, "signer_mismatch",
			"GarageVehicle.signed_by must match the session caller.")
		return
	}

	canonical, err := gv.CanonicalEncoding()
	if err != nil {
		s.logger.Error("garage-vehicles: canonical encode failed", "error", err)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not compute canonical garage vehicle bytes.")
		return
	}
	if !verifySignedPayload(w, r, s.logger, s.cfg.IntegrityVerifier, s.cfg.GarageStore,
		canonical, *gv.Integrity, string(gv.SignedBy), "garage-vehicles") {
		return
	}
	rec, err := s.cfg.GarageStore.CreateGarageVehicle(r.Context(), storage.GarageVehicleCreateParams{
		GarageVehicle:    gv,
		CanonicalPayload: canonical,
	})
	if err != nil {
		s.logger.Error("garage-vehicles: create failed", "error", err, "garage_id", garageID, "vehicle_id", gv.ID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not create garage vehicle.")
		return
	}
	s.logger.Info("garage vehicle created",
		"garage_id", garageID,
		"vehicle_id", rec.ID,
		"signed_by", gv.SignedBy,
	)
	resp, err := garageVehicleResponseFromRecord(rec)
	if err != nil {
		s.logger.Error("garage-vehicles: response build failed", "error", err)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not assemble garage vehicle response.")
		return
	}
	writeJSONStatus(w, http.StatusCreated, resp, s.logger)
}

// handleGarageVehicleList implements
// GET /v1/garages/{id}/vehicles. Caller must be an owner of the
// garage (accepted OR pending — pending invitees can preview the
// car library they're being invited into).
func (s *Server) handleGarageVehicleList(w http.ResponseWriter, r *http.Request) {
	if s.cfg.GarageStore == nil {
		writeProblem(w, s.logger, http.StatusServiceUnavailable, "garages_unavailable",
			"This server is not configured to manage garages.")
		return
	}
	id, ok := middleware.IdentityFrom(r.Context())
	if !ok {
		writeProblem(w, s.logger, http.StatusUnauthorized, "unauthenticated",
			"This endpoint requires an enrolled client app identity.")
		return
	}
	garageID := r.PathValue("id")
	if _, err := s.cfg.GarageStore.GarageOwnerByUserAndGarage(r.Context(), id.UserID, garageID); err != nil {
		if errors.Is(err, storage.ErrGarageNotFound) {
			writeProblem(w, s.logger, http.StatusNotFound, "garage_not_found",
				"No garage exists at this id (or you are not an owner).")
			return
		}
		s.logger.Error("garage-vehicles: owner check failed", "error", err, "garage_id", garageID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not authorize garage access.")
		return
	}

	records, err := s.cfg.GarageStore.ListGarageVehicles(r.Context(), garageID)
	if err != nil {
		s.logger.Error("garage-vehicles: list failed", "error", err, "garage_id", garageID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not list garage vehicles.")
		return
	}
	out := make([]GarageVehicleResponse, 0, len(records))
	for _, rec := range records {
		resp, err := garageVehicleResponseFromRecord(rec)
		if err != nil {
			s.logger.Error("garage-vehicles: list decode failed", "error", err, "vehicle_id", rec.ID)
			writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
				"Could not decode stored garage vehicle bundle.")
			return
		}
		out = append(out, resp)
	}
	writeJSON(w, GarageVehicleListResponse{Vehicles: out}, s.logger)
}

// handleGarageVehicleGet implements
// GET /v1/garages/{id}/vehicles/{vid}.
func (s *Server) handleGarageVehicleGet(w http.ResponseWriter, r *http.Request) {
	if s.cfg.GarageStore == nil {
		writeProblem(w, s.logger, http.StatusServiceUnavailable, "garages_unavailable",
			"This server is not configured to manage garages.")
		return
	}
	id, ok := middleware.IdentityFrom(r.Context())
	if !ok {
		writeProblem(w, s.logger, http.StatusUnauthorized, "unauthenticated",
			"This endpoint requires an enrolled client app identity.")
		return
	}
	garageID := r.PathValue("id")
	vehicleID := r.PathValue("vid")
	if _, err := s.cfg.GarageStore.GarageOwnerByUserAndGarage(r.Context(), id.UserID, garageID); err != nil {
		if errors.Is(err, storage.ErrGarageNotFound) {
			writeProblem(w, s.logger, http.StatusNotFound, "garage_not_found",
				"No garage exists at this id (or you are not an owner).")
			return
		}
		s.logger.Error("garage-vehicles: get owner check failed", "error", err)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not authorize garage access.")
		return
	}
	rec, err := s.cfg.GarageStore.GarageVehicleByID(r.Context(), garageID, vehicleID)
	if err != nil {
		if errors.Is(err, storage.ErrGarageVehicleNotFound) {
			writeProblem(w, s.logger, http.StatusNotFound, "garage_vehicle_not_found",
				"No garage vehicle exists at this garage and id.")
			return
		}
		s.logger.Error("garage-vehicles: load failed", "error", err, "garage_id", garageID, "vehicle_id", vehicleID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not load garage vehicle.")
		return
	}
	resp, err := garageVehicleResponseFromRecord(rec)
	if err != nil {
		s.logger.Error("garage-vehicles: get decode failed", "error", err, "vehicle_id", rec.ID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not decode stored garage vehicle bundle.")
		return
	}
	writeJSON(w, resp, s.logger)
}

// handleGarageVehicleRevisionAppend implements
// POST /v1/garages/{id}/vehicles/{vid}/revisions. Authority same
// as create: accepted owner only, signed_by == session caller.
func (s *Server) handleGarageVehicleRevisionAppend(w http.ResponseWriter, r *http.Request) {
	if s.cfg.GarageStore == nil {
		writeProblem(w, s.logger, http.StatusServiceUnavailable, "garages_unavailable",
			"This server is not configured to manage garages.")
		return
	}
	id, ok := middleware.IdentityFrom(r.Context())
	if !ok {
		writeProblem(w, s.logger, http.StatusUnauthorized, "unauthenticated",
			"This endpoint requires an enrolled client app identity.")
		return
	}
	garageID := r.PathValue("id")
	vehicleID := r.PathValue("vid")
	if err := s.requireAcceptedGarageOwner(r.Context(), id.UserID, garageID); err != nil {
		s.writeGarageOwnerError(w, err, garageID, id.UserID, "vehicle revision authority check")
		return
	}

	// Confirm the vehicle exists in this garage before parsing
	// further so a wrong path id returns 404 distinctly from a
	// malformed payload returning 400.
	if _, err := s.cfg.GarageStore.GarageVehicleByID(r.Context(), garageID, vehicleID); err != nil {
		if errors.Is(err, storage.ErrGarageVehicleNotFound) {
			writeProblem(w, s.logger, http.StatusNotFound, "garage_vehicle_not_found",
				"No garage vehicle exists at this garage and id.")
			return
		}
		s.logger.Error("garage-vehicles: revision precheck failed", "error", err)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not look up garage vehicle.")
		return
	}

	var gv opencaravan.GarageVehicle
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&gv); err != nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_request",
			fmt.Sprintf("Could not decode GarageVehicle request body: %s", err))
		return
	}
	if err := gv.Validate(); err != nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_garage_vehicle",
			fmt.Sprintf("GarageVehicle failed structural validation: %s", err))
		return
	}
	if gv.Integrity == nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_garage_vehicle",
			"GarageVehicle.integrity envelope is required on the wire.")
		return
	}
	if string(gv.ID) != vehicleID {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_garage_vehicle",
			"GarageVehicle.id must match the path vehicle id.")
		return
	}
	if string(gv.GarageID) != garageID {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_garage_vehicle",
			"GarageVehicle.garage_id must match the path garage id.")
		return
	}
	if string(gv.SignedBy) != id.UserID {
		writeProblem(w, s.logger, http.StatusForbidden, "signer_mismatch",
			"GarageVehicle.signed_by must match the session caller.")
		return
	}

	canonical, err := gv.CanonicalEncoding()
	if err != nil {
		s.logger.Error("garage-vehicles: revision canonical encode failed", "error", err)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not compute canonical garage vehicle bytes.")
		return
	}

	if !verifySignedPayload(w, r, s.logger, s.cfg.IntegrityVerifier, s.cfg.GarageStore,
		canonical, *gv.Integrity, string(gv.SignedBy), "garage-vehicles-revision") {
		return
	}

	if _, err := s.cfg.GarageStore.AppendGarageVehicleRevision(r.Context(), storage.GarageVehicleAppendRevisionParams{
		GarageVehicle:    gv,
		CanonicalPayload: canonical,
	}); err != nil {
		switch {
		case errors.Is(err, storage.ErrGarageVehicleNotFound):
			writeProblem(w, s.logger, http.StatusNotFound, "garage_vehicle_not_found",
				"No garage vehicle exists at this id.")
			return
		case errors.Is(err, storage.ErrGarageVehicleRevisionVersionConflict):
			writeProblem(w, s.logger, http.StatusConflict, "revision_version_conflict",
				"GarageVehicle.revision_version must be strictly greater than the current revision.")
			return
		}
		s.logger.Error("garage-vehicles: revision append failed", "error", err, "vehicle_id", vehicleID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not record garage vehicle revision.")
		return
	}

	updated, err := s.cfg.GarageStore.GarageVehicleByID(r.Context(), garageID, vehicleID)
	if err != nil {
		s.logger.Error("garage-vehicles: reload after revision failed", "error", err)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Revision recorded but garage vehicle could not be reloaded.")
		return
	}
	resp, err := garageVehicleResponseFromRecord(updated)
	if err != nil {
		s.logger.Error("garage-vehicles: revision decode failed", "error", err, "vehicle_id", updated.ID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not decode stored garage vehicle bundle.")
		return
	}
	s.logger.Info("garage vehicle revision recorded",
		"garage_id", garageID,
		"vehicle_id", vehicleID,
		"revision_version", gv.RevisionVersion,
	)
	writeJSONStatus(w, http.StatusCreated, resp, s.logger)
}

// requireAcceptedGarageOwner looks up the caller's owner row and
// returns an error mapped by [Server.writeGarageOwnerError]:
//
//   - [storage.ErrGarageNotFound] — caller is not an owner; handler
//     should 404 (existence isn't leaked).
//   - errGaragePendingInvitee — caller is invited but pending;
//     handler should 403 with "accept invitation first."
//   - other — unexpected storage failure; handler should 500.
//   - nil — caller is an accepted owner; proceed.
func (s *Server) requireAcceptedGarageOwner(ctx context.Context, userID, garageID string) error {
	owner, err := s.cfg.GarageStore.GarageOwnerByUserAndGarage(ctx, userID, garageID)
	if err != nil {
		return err
	}
	if owner.AcceptedTime == nil {
		return errGaragePendingInvitee
	}
	return nil
}

func (s *Server) writeGarageOwnerError(w http.ResponseWriter, err error, garageID, userID, where string) {
	switch {
	case errors.Is(err, storage.ErrGarageNotFound):
		writeProblem(w, s.logger, http.StatusNotFound, "garage_not_found",
			"No garage exists at this id (or you are not an owner).")
	case errors.Is(err, errGaragePendingInvitee):
		writeProblem(w, s.logger, http.StatusForbidden, "not_accepted_owner",
			"Only accepted owners may mutate garage vehicles; accept the invitation first.")
	default:
		s.logger.Error("garage-vehicles: owner check failed",
			"error", err, "garage_id", garageID, "user_id", userID, "where", where)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not authorize garage vehicle mutation.")
	}
}

// errGaragePendingInvitee marks the "caller is invited but
// pending" case so the handler can map it to 403 without an
// extra storage trip.
var errGaragePendingInvitee = errors.New("api: caller is a pending garage invitee, not an accepted owner")

// garageVehicleResponseFromRecord decodes the persisted canonical
// bundle bytes into an [opencaravan.GarageVehicle] for the
// response and assembles the wrapper response shape. The bundle
// bytes are signed and stored verbatim, so decoding here is pure
// deserialization — no re-canonicalization or signature
// re-verification.
func garageVehicleResponseFromRecord(rec storage.GarageVehicleRecord) (GarageVehicleResponse, error) {
	var gv opencaravan.GarageVehicle
	if err := json.Unmarshal(rec.CanonicalPayloadJSON, &gv); err != nil {
		return GarageVehicleResponse{}, fmt.Errorf("decode garage vehicle canonical payload: %w", err)
	}
	gv.Integrity = &opencaravan.Integrity{
		Algorithm: rec.Integrity.Algorithm,
		KeyID:     rec.Integrity.KeyID,
		Signature: rec.Integrity.Signature,
	}
	return GarageVehicleResponse{
		ID:                     rec.ID,
		GarageID:               rec.GarageID,
		CurrentRevisionVersion: rec.CurrentRevisionVersion,
		GarageVehicle:          gv,
		ReceivedAt:             rec.ReceivedAt.UTC(),
	}, nil
}
