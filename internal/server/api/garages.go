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

// GarageResponse is the wire shape the garage handlers return.
// Owners is the materialized current owner list (accepted +
// pending); clients render pending invitations with reduced
// affordance until acceptance.
type GarageResponse struct {
	ID                     string                `json:"id"`
	Name                   string                `json:"name"`
	CurrentRevisionVersion int                   `json:"current_revision_version"`
	CurrentRevisionTime    time.Time             `json:"current_revision_time"`
	CreatedAt              time.Time             `json:"created_at"`
	Owners                 []GarageOwnerResponse `json:"owners"`
}

// GarageOwnerResponse is the wire shape of one materialized
// owner row. AcceptedTime is nil while the invitation is pending.
type GarageOwnerResponse struct {
	UserID       string     `json:"user_id"`
	AddedTime    time.Time  `json:"added_time"`
	AcceptedTime *time.Time `json:"accepted_time,omitempty"`
}

// GarageListResponse is the envelope for GET /v1/garages.
type GarageListResponse struct {
	Garages []GarageResponse `json:"garages"`
}

// GarageRevisionAppendResponse is what the revision POST returns —
// the revision metadata plus the new garage head state so the
// client doesn't need to follow up with a GET.
type GarageRevisionAppendResponse struct {
	RevisionID      string                `json:"revision_id"`
	GarageID        string                `json:"garage_id"`
	RevisionVersion int                   `json:"revision_version"`
	RevisionTime    time.Time             `json:"revision_time"`
	Integrity       opencaravan.Integrity `json:"integrity"`
	ReceivedAt      time.Time             `json:"received_at"`
	Garage          GarageResponse        `json:"garage"`
}

// GarageOwnershipAcceptanceResponse is what the acceptance POST
// returns — the recorded acceptance metadata plus the updated
// garage state.
type GarageOwnershipAcceptanceResponse struct {
	AcceptanceID            string                `json:"acceptance_id"`
	GarageID                string                `json:"garage_id"`
	RevisionVersionAccepted int                   `json:"revision_version_accepted"`
	AcceptedTime            time.Time             `json:"accepted_time"`
	Integrity               opencaravan.Integrity `json:"integrity"`
	ReceivedAt              time.Time             `json:"received_at"`
	Garage                  GarageResponse        `json:"garage"`
}

// handleGarageCreate implements POST /v1/garages.
//
// Wrapped by [middleware.RequireIdentity]. The handler additionally
// enforces:
//
//   - The garage.signed_by must equal the session identity (only
//     the signing owner can submit their own garage).
//   - The garage must have revision_version = 1 (this is a create,
//     not a revision append).
//   - The garage must list the caller as an accepted owner (a
//     create that omits the creator as accepted is structurally
//     wrong; opencaravan-go's Validate enforces this, but we
//     repeat the rationale here for the 400 message).
func (s *Server) handleGarageCreate(w http.ResponseWriter, r *http.Request) {
	if s.cfg.GarageStore == nil {
		writeProblem(w, s.logger, http.StatusServiceUnavailable, "garages_unavailable",
			"This server is not configured to manage garages.")
		return
	}
	id, ok := middleware.IdentityFrom(r.Context())
	if !ok {
		s.logger.Error("garages: handler reached without context identity")
		writeProblem(w, s.logger, http.StatusUnauthorized, "unauthenticated",
			"This endpoint requires an enrolled client app identity.")
		return
	}

	var garage opencaravan.Garage
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&garage); err != nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_request",
			fmt.Sprintf("Could not decode Garage request body: %s", err))
		return
	}
	if err := garage.Validate(); err != nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_garage",
			fmt.Sprintf("Garage failed structural validation: %s", err))
		return
	}
	if garage.Integrity == nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_garage",
			"Garage.integrity envelope is required on the wire.")
		return
	}
	if garage.RevisionVersion != 1 {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_garage",
			"POST /v1/garages requires revision_version = 1; use POST /v1/garages/{id}/revisions for subsequent revisions.")
		return
	}
	if string(garage.SignedBy) != id.UserID {
		writeProblem(w, s.logger, http.StatusForbidden, "signer_mismatch",
			"Garage.signed_by must match the session caller.")
		return
	}

	canonical, err := garage.CanonicalEncoding()
	if err != nil {
		s.logger.Error("garages: canonical encode failed", "error", err)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not compute canonical garage bytes.")
		return
	}

	rec, err := s.cfg.GarageStore.CreateGarage(r.Context(), storage.GarageCreateParams{
		Garage:           garage,
		CanonicalPayload: canonical,
	})
	if err != nil {
		s.logger.Error("garages: create failed", "error", err, "garage_id", garage.ID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not create garage.")
		return
	}

	s.logger.Info("garage created",
		"garage_id", rec.ID,
		"signed_by", garage.SignedBy,
	)
	resp, err := s.assembleGarageResponse(r.Context(), rec)
	if err != nil {
		s.logger.Error("garages: assemble response failed", "error", err, "garage_id", rec.ID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Garage was created but could not be loaded for the response.")
		return
	}
	writeJSONStatus(w, http.StatusCreated, resp, s.logger)
}

// handleGarageList implements GET /v1/garages.
//
// Returns every garage where the caller is an owner — accepted or
// pending — so the iOS app can render "my garages" alongside
// invitations awaiting acceptance.
func (s *Server) handleGarageList(w http.ResponseWriter, r *http.Request) {
	if s.cfg.GarageStore == nil {
		writeProblem(w, s.logger, http.StatusServiceUnavailable, "garages_unavailable",
			"This server is not configured to manage garages.")
		return
	}
	id, ok := middleware.IdentityFrom(r.Context())
	if !ok {
		s.logger.Error("garages: list handler reached without context identity")
		writeProblem(w, s.logger, http.StatusUnauthorized, "unauthenticated",
			"This endpoint requires an enrolled client app identity.")
		return
	}
	garages, err := s.cfg.GarageStore.ListGaragesForUser(r.Context(), id.UserID)
	if err != nil {
		s.logger.Error("garages: list failed", "error", err, "user_id", id.UserID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not list garages.")
		return
	}
	out := make([]GarageResponse, 0, len(garages))
	for _, g := range garages {
		resp, err := s.assembleGarageResponse(r.Context(), g)
		if err != nil {
			s.logger.Error("garages: assemble list entry failed", "error", err, "garage_id", g.ID)
			writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
				"Could not load owners for one of the garages.")
			return
		}
		out = append(out, resp)
	}
	writeJSON(w, GarageListResponse{Garages: out}, s.logger)
}

// handleGarageGet implements GET /v1/garages/{id}. The caller must
// be an owner of the garage (accepted OR pending — pending owners
// can see what they're being invited to).
func (s *Server) handleGarageGet(w http.ResponseWriter, r *http.Request) {
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
			// Either the garage doesn't exist or the caller is not
			// an owner — return 404 either way so the existence of
			// other-people's garages isn't leaked via 403 vs 404.
			writeProblem(w, s.logger, http.StatusNotFound, "garage_not_found",
				"No garage exists at this id (or you are not an owner).")
			return
		}
		s.logger.Error("garages: owner check failed", "error", err, "garage_id", garageID, "user_id", id.UserID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not authorize garage access.")
		return
	}

	rec, err := s.cfg.GarageStore.GarageByID(r.Context(), garageID)
	if err != nil {
		if errors.Is(err, storage.ErrGarageNotFound) {
			writeProblem(w, s.logger, http.StatusNotFound, "garage_not_found",
				"No garage exists at this id.")
			return
		}
		s.logger.Error("garages: load failed", "error", err, "garage_id", garageID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not load garage.")
		return
	}
	resp, err := s.assembleGarageResponse(r.Context(), rec)
	if err != nil {
		s.logger.Error("garages: assemble response failed", "error", err, "garage_id", rec.ID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not load garage owners.")
		return
	}
	writeJSON(w, resp, s.logger)
}

// handleGarageRevisionAppend implements
// POST /v1/garages/{id}/revisions. Authority: caller must be an
// accepted owner. The garage.signed_by must equal the session
// caller (mirroring the owner-signed invariant).
func (s *Server) handleGarageRevisionAppend(w http.ResponseWriter, r *http.Request) {
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

	owner, err := s.cfg.GarageStore.GarageOwnerByUserAndGarage(r.Context(), id.UserID, garageID)
	if err != nil {
		if errors.Is(err, storage.ErrGarageNotFound) {
			writeProblem(w, s.logger, http.StatusNotFound, "garage_not_found",
				"No garage exists at this id (or you are not an owner).")
			return
		}
		s.logger.Error("garages: owner check failed", "error", err, "garage_id", garageID, "user_id", id.UserID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not authorize revision append.")
		return
	}
	if owner.AcceptedTime == nil {
		writeProblem(w, s.logger, http.StatusForbidden, "not_accepted_owner",
			"Only accepted owners may publish garage revisions; accept the invitation first.")
		return
	}

	var garage opencaravan.Garage
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&garage); err != nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_request",
			fmt.Sprintf("Could not decode Garage request body: %s", err))
		return
	}
	if err := garage.Validate(); err != nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_garage",
			fmt.Sprintf("Garage failed structural validation: %s", err))
		return
	}
	if garage.Integrity == nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_garage",
			"Garage.integrity envelope is required on the wire.")
		return
	}
	if string(garage.ID) != garageID {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_garage",
			"Garage.id must match the path garage id.")
		return
	}
	if string(garage.SignedBy) != id.UserID {
		writeProblem(w, s.logger, http.StatusForbidden, "signer_mismatch",
			"Garage.signed_by must match the session caller.")
		return
	}

	canonical, err := garage.CanonicalEncoding()
	if err != nil {
		s.logger.Error("garages: canonical encode failed", "error", err)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not compute canonical garage bytes.")
		return
	}

	rev, err := s.cfg.GarageStore.AppendGarageRevision(r.Context(), storage.GarageAppendRevisionParams{
		Garage:           garage,
		CanonicalPayload: canonical,
	})
	switch {
	case errors.Is(err, storage.ErrGarageNotFound):
		writeProblem(w, s.logger, http.StatusNotFound, "garage_not_found",
			"No garage exists at this id.")
		return
	case errors.Is(err, storage.ErrGarageRevisionVersionConflict):
		writeProblem(w, s.logger, http.StatusConflict, "revision_version_conflict",
			"Garage.revision_version must be strictly greater than the current revision.")
		return
	case err != nil:
		s.logger.Error("garages: append revision failed", "error", err, "garage_id", garageID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not record garage revision.")
		return
	}

	updated, err := s.cfg.GarageStore.GarageByID(r.Context(), garageID)
	if err != nil {
		s.logger.Error("garages: reload after revision failed", "error", err, "garage_id", garageID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Revision recorded but garage could not be reloaded.")
		return
	}
	garageResp, err := s.assembleGarageResponse(r.Context(), updated)
	if err != nil {
		s.logger.Error("garages: assemble revision response failed", "error", err)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Revision recorded but response could not be assembled.")
		return
	}

	s.logger.Info("garage revision recorded",
		"garage_id", garageID,
		"revision_version", rev.RevisionVersion,
		"signed_by", rev.SignedBy,
	)
	writeJSONStatus(w, http.StatusCreated, GarageRevisionAppendResponse{
		RevisionID:      rev.ID,
		GarageID:        rev.GarageID,
		RevisionVersion: rev.RevisionVersion,
		RevisionTime:    rev.RevisionTime.UTC(),
		Integrity:       rev.Integrity,
		ReceivedAt:      rev.ReceivedAt.UTC(),
		Garage:          garageResp,
	}, s.logger)
}

// handleGarageOwnershipAccept implements
// POST /v1/garages/{id}/ownership-acceptances. The caller must be
// the pending invitee — defense-in-depth so the wire-level signed
// acceptance cannot be submitted by another user on the invitee's
// behalf.
func (s *Server) handleGarageOwnershipAccept(w http.ResponseWriter, r *http.Request) {
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

	var acceptance opencaravan.GarageOwnershipAcceptance
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&acceptance); err != nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_request",
			fmt.Sprintf("Could not decode GarageOwnershipAcceptance request body: %s", err))
		return
	}
	if err := acceptance.Validate(); err != nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_acceptance",
			fmt.Sprintf("GarageOwnershipAcceptance failed structural validation: %s", err))
		return
	}
	if acceptance.Integrity == nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_acceptance",
			"GarageOwnershipAcceptance.integrity envelope is required on the wire.")
		return
	}
	if string(acceptance.GarageID) != garageID {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_acceptance",
			"GarageOwnershipAcceptance.garage_id must match the path garage id.")
		return
	}
	if string(acceptance.AccepterUserID) != id.UserID {
		writeProblem(w, s.logger, http.StatusForbidden, "accepter_mismatch",
			"GarageOwnershipAcceptance.accepter_user_id must match the session caller.")
		return
	}

	canonical, err := acceptance.CanonicalEncoding()
	if err != nil {
		s.logger.Error("garages: acceptance canonical encode failed", "error", err)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not compute canonical acceptance bytes.")
		return
	}

	rec, err := s.cfg.GarageStore.AcceptGarageOwnership(r.Context(), storage.GarageAcceptOwnershipParams{
		Acceptance:       acceptance,
		CanonicalPayload: canonical,
	})
	switch {
	case errors.Is(err, storage.ErrGarageOwnershipNotPending):
		writeProblem(w, s.logger, http.StatusNotFound, "no_pending_invitation",
			"No pending garage ownership invitation exists for this user.")
		return
	case errors.Is(err, storage.ErrGarageOwnershipAlreadyAccepted):
		// Idempotent replay — the acceptance is already on file.
		// Surface 200 with the garage state so the client knows
		// they're already an owner.
		updated, loadErr := s.cfg.GarageStore.GarageByID(r.Context(), garageID)
		if loadErr != nil {
			s.logger.Error("garages: reload after replay accept failed", "error", loadErr)
			writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
				"Already accepted but garage could not be reloaded.")
			return
		}
		garageResp, assembleErr := s.assembleGarageResponse(r.Context(), updated)
		if assembleErr != nil {
			s.logger.Error("garages: assemble replay response failed", "error", assembleErr)
			writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
				"Already accepted but response could not be assembled.")
			return
		}
		writeJSONStatus(w, http.StatusOK, GarageOwnershipAcceptanceResponse{
			GarageID:                garageID,
			RevisionVersionAccepted: acceptance.RevisionVersionAccepted,
			AcceptedTime:            acceptance.AcceptedTime.UTC(),
			Garage:                  garageResp,
		}, s.logger)
		return
	case err != nil:
		s.logger.Error("garages: accept failed", "error", err, "garage_id", garageID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not record garage ownership acceptance.")
		return
	}

	updated, err := s.cfg.GarageStore.GarageByID(r.Context(), garageID)
	if err != nil {
		s.logger.Error("garages: reload after accept failed", "error", err, "garage_id", garageID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Acceptance recorded but garage could not be reloaded.")
		return
	}
	garageResp, err := s.assembleGarageResponse(r.Context(), updated)
	if err != nil {
		s.logger.Error("garages: assemble accept response failed", "error", err)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Acceptance recorded but response could not be assembled.")
		return
	}

	s.logger.Info("garage ownership accepted",
		"garage_id", garageID,
		"accepter_user_id", rec.AccepterUserID,
		"revision_version_accepted", rec.RevisionVersionAccepted,
	)
	writeJSONStatus(w, http.StatusCreated, GarageOwnershipAcceptanceResponse{
		AcceptanceID:            rec.ID,
		GarageID:                rec.GarageID,
		RevisionVersionAccepted: rec.RevisionVersionAccepted,
		AcceptedTime:            rec.AcceptedTime.UTC(),
		Integrity:               rec.Integrity,
		ReceivedAt:              rec.ReceivedAt.UTC(),
		Garage:                  garageResp,
	}, s.logger)
}

func (s *Server) assembleGarageResponse(ctx context.Context, rec storage.GarageRecord) (GarageResponse, error) {
	owners, err := s.cfg.GarageStore.ListGarageOwners(ctx, rec.ID)
	if err != nil {
		return GarageResponse{}, err
	}
	out := GarageResponse{
		ID:                     rec.ID,
		Name:                   rec.Name,
		CurrentRevisionVersion: rec.CurrentRevisionVersion,
		CurrentRevisionTime:    rec.CurrentRevisionTime.UTC(),
		CreatedAt:              rec.CreatedAt.UTC(),
	}
	for _, o := range owners {
		entry := GarageOwnerResponse{
			UserID:    o.UserID,
			AddedTime: o.AddedTime.UTC(),
		}
		if o.AcceptedTime != nil {
			t := o.AcceptedTime.UTC()
			entry.AcceptedTime = &t
		}
		out.Owners = append(out.Owners, entry)
	}
	return out, nil
}
