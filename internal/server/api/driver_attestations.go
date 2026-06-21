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

// DriverAttestationResponse is the wire shape the
// driver-attestation handlers return. A deliberate subset of
// [opencaravan.DriverAttestation] augmented with the
// server-computed trust_flag and fork-detection metadata.
type DriverAttestationResponse struct {
	ID                   string                         `json:"id"`
	JourneyVehicleID     string                         `json:"journey_vehicle_id"`
	SegmentID            string                         `json:"segment_id"`
	DriverUserID         string                         `json:"driver_user_id"`
	EffectiveTime        time.Time                      `json:"effective_time"`
	ACLVersionConsulted  int                            `json:"acl_version_consulted"`
	PriorAttestationHash *string                        `json:"prior_attestation_hash,omitempty"`
	TrustFlag            storage.DriverAttestationTrust `json:"trust_flag"`
	Integrity            opencaravan.Integrity          `json:"integrity"`
	ReceivedAt           time.Time                      `json:"received_at"`
	// ForkSiblings names other attestations that share this
	// attestation's prior_attestation_hash. Populated only on the
	// POST response so the submitting client can immediately see
	// when their handoff conflicts with a peer's; the list
	// includes the just-recorded record so a single-element list
	// means "you're the only claimant on this predecessor."
	ForkSiblings []DriverAttestationForkSibling `json:"fork_siblings,omitempty"`
}

// DriverAttestationForkSibling is a compact descriptor of a fork
// sibling: enough to identify who else claimed the same
// predecessor and when, without exposing the full payload.
type DriverAttestationForkSibling struct {
	ID            string                         `json:"id"`
	DriverUserID  string                         `json:"driver_user_id"`
	EffectiveTime time.Time                      `json:"effective_time"`
	TrustFlag     storage.DriverAttestationTrust `json:"trust_flag"`
}

// DriverAttestationListResponse is the envelope returned by the
// GET handler. Envelope shape so future phases can add pagination
// or filter metadata without breaking clients indexing on
// "attestations".
type DriverAttestationListResponse struct {
	Attestations []DriverAttestationResponse `json:"attestations"`
}

// handleDriverAttestationRecord implements
// POST /v1/journeys/{id}/vehicles/{vid}/driver-attestations.
//
// Wrapped by [middleware.RequireSession] with a journey.write
// constraint. The handler additionally enforces:
//
//   - attestation.driver_user_id == session.user_id (defense in
//     depth — only the driver themselves can submit their own
//     handoff record, mirroring the owner-signed invariant on
//     VehicleACL).
//   - attestation.vehicle_id == path vehicle id.
//   - integrity envelope present.
//
// Trust is evaluated server-side via the ACL-at-time resolver and
// recorded with the persisted row. A duplicate-replay (same
// vehicle, driver, effective_time tuple) returns the existing
// record with 200 OK rather than 409 — gossiped replays from
// peers are the normal case, not a fault.
//
// Failures map to:
//
//   - 503 when DriverAttestationStore / VehicleStore not wired.
//   - 400 for malformed JSON, validation failure, or path id
//     mismatch.
//   - 403 when attestation.driver_user_id != session user.
//   - 404 when the vehicle does not exist at the journey + id pair.
//   - 500 for unexpected storage / classification failures.
func (s *Server) handleDriverAttestationRecord(w http.ResponseWriter, r *http.Request) {
	if s.cfg.DriverAttestationStore == nil || s.cfg.VehicleStore == nil {
		writeProblem(w, s.logger, http.StatusServiceUnavailable, "attestations_unavailable",
			"This server is not configured to record driver attestations.")
		return
	}
	if s.cfg.JourneyStore == nil {
		// The trust evaluator's emergency-fallback path needs to
		// look up journey participants. Without a JourneyStore we
		// cannot complete that path; rather than mis-classify, we
		// surface the misconfiguration explicitly.
		writeProblem(w, s.logger, http.StatusServiceUnavailable, "attestations_unavailable",
			"This server is not configured to evaluate driver attestation trust.")
		return
	}
	id, ok := middleware.IdentityFrom(r.Context())
	if !ok {
		s.logger.Error("attestations: handler reached without context identity")
		writeProblem(w, s.logger, http.StatusUnauthorized, "unauthenticated",
			"This endpoint requires an enrolled client app identity.")
		return
	}
	journeyID := r.PathValue("id")
	vehicleID := r.PathValue("vid")

	stored, err := s.cfg.VehicleStore.JourneyVehicleByID(r.Context(), journeyID, vehicleID)
	if err != nil {
		if errors.Is(err, storage.ErrJourneyVehicleNotFound) {
			writeProblem(w, s.logger, http.StatusNotFound, "vehicle_not_found",
				"No vehicle exists at this journey and id.")
			return
		}
		s.logger.Error("attestations: vehicle lookup failed", "error", err, "journey_id", journeyID, "vehicle_id", vehicleID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not look up journey vehicle.")
		return
	}

	var attestation opencaravan.DriverAttestation
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&attestation); err != nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_request",
			fmt.Sprintf("Could not decode DriverAttestation request body: %s", err))
		return
	}
	if err := attestation.Validate(); err != nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_attestation",
			fmt.Sprintf("DriverAttestation failed structural validation: %s", err))
		return
	}
	if attestation.Integrity == nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_attestation",
			"DriverAttestation.integrity envelope is required on the wire.")
		return
	}
	if string(attestation.VehicleID) != vehicleID {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_attestation",
			"DriverAttestation.vehicle_id must match the path vehicle id.")
		return
	}
	if string(attestation.DriverUserID) != id.UserID {
		s.logger.Warn("attestations: driver mismatch",
			"session_user_id", id.UserID,
			"payload_driver_user_id", attestation.DriverUserID,
			"vehicle_id", vehicleID,
		)
		writeProblem(w, s.logger, http.StatusForbidden, "driver_mismatch",
			"DriverAttestation.driver_user_id must match the session caller.")
		return
	}

	canonical, err := attestation.CanonicalEncoding()
	if err != nil {
		s.logger.Error("attestations: canonical encode failed", "error", err)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not compute canonical attestation bytes.")
		return
	}

	resolver := &driverAttestationTrustResolver{
		store:              s.cfg.VehicleStore,
		journeyParticipant: s.cfg.JourneyStore,
	}
	trust, err := resolver.classify(r.Context(), journeyID, stored.OwnerUserID, attestation)
	if err != nil {
		if errors.Is(err, storage.ErrJourneyVehicleNotFound) {
			// No ACL revision exists at or before EffectiveTime —
			// structurally impossible for a legitimate driver to
			// have consulted an ACL that did not yet exist.
			writeProblem(w, s.logger, http.StatusBadRequest, "no_acl_at_effective_time",
				"No VehicleACL revision exists at or before the attestation's effective_time.")
			return
		}
		s.logger.Error("attestations: classify failed", "error", err, "vehicle_id", vehicleID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not classify attestation trust.")
		return
	}

	rec, err := s.cfg.DriverAttestationStore.RecordDriverAttestation(r.Context(), storage.DriverAttestationRecordParams{
		Attestation:      attestation,
		JourneyVehicleID: vehicleID,
		TrustFlag:        trust,
		CanonicalPayload: canonical,
	})
	status := http.StatusCreated
	switch {
	case errors.Is(err, storage.ErrDriverAttestationDuplicate):
		// Idempotent replay — fetch the existing record so the
		// client sees the canonical trust_flag from the original
		// classification rather than the freshly-computed one
		// (which could differ if the ACL evolved between the
		// original upload and this retry).
		existing, lookupErr := s.cfg.DriverAttestationStore.DriverAttestationByReplayKey(
			r.Context(), vehicleID, id.UserID, attestation.EffectiveTime)
		if lookupErr != nil {
			s.logger.Error("attestations: replay lookup failed", "error", lookupErr,
				"vehicle_id", vehicleID, "driver_user_id", id.UserID)
			writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
				"Could not load existing attestation after replay conflict.")
			return
		}
		rec = existing
		status = http.StatusOK
	case err != nil:
		s.logger.Error("attestations: record failed", "error", err, "vehicle_id", vehicleID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not record driver attestation.")
		return
	default:
		s.logger.Info("driver attestation recorded",
			"journey_id", journeyID,
			"vehicle_id", vehicleID,
			"driver_user_id", rec.DriverUserID,
			"acl_version_consulted", rec.ACLVersionConsulted,
			"trust_flag", rec.TrustFlag,
		)
	}

	// Surface fork siblings when the attestation chains to a
	// predecessor. The just-recorded row is included, so a
	// single-element list means "no fork yet"; ≥ 2 elements
	// indicate concurrent claims on the same predecessor that
	// peers can use to disambiguate.
	var siblings []DriverAttestationForkSibling
	if rec.PriorAttestationHash != nil {
		rows, sibErr := s.cfg.DriverAttestationStore.DriverAttestationForkSiblings(
			r.Context(), vehicleID, *rec.PriorAttestationHash)
		if sibErr != nil {
			s.logger.Warn("attestations: fork sibling lookup failed", "error", sibErr,
				"vehicle_id", vehicleID, "prior_hash", *rec.PriorAttestationHash)
			// Non-fatal — return the record without sibling info
			// rather than fail the whole request.
		} else {
			for _, row := range rows {
				siblings = append(siblings, DriverAttestationForkSibling{
					ID:            row.ID,
					DriverUserID:  row.DriverUserID,
					EffectiveTime: row.EffectiveTime.UTC(),
					TrustFlag:     row.TrustFlag,
				})
			}
			if len(siblings) > 1 {
				s.logger.Warn("driver attestation fork detected",
					"journey_id", journeyID,
					"vehicle_id", vehicleID,
					"prior_hash", *rec.PriorAttestationHash,
					"sibling_count", len(siblings),
				)
			}
		}
	}

	writeJSONStatus(w, status, driverAttestationResponseFrom(rec, siblings), s.logger)
}

// handleDriverAttestationList implements
// GET /v1/journeys/{id}/vehicles/{vid}/driver-attestations.
//
// Returns every recorded attestation for the vehicle, ordered by
// effective_time ascending. Low-trust rows are included; clients
// filter by trust_flag when "show only authorized drivers" is
// desired.
func (s *Server) handleDriverAttestationList(w http.ResponseWriter, r *http.Request) {
	if s.cfg.DriverAttestationStore == nil || s.cfg.VehicleStore == nil {
		writeProblem(w, s.logger, http.StatusServiceUnavailable, "attestations_unavailable",
			"This server is not configured to record driver attestations.")
		return
	}
	journeyID := r.PathValue("id")
	vehicleID := r.PathValue("vid")
	if _, err := s.cfg.VehicleStore.JourneyVehicleByID(r.Context(), journeyID, vehicleID); err != nil {
		if errors.Is(err, storage.ErrJourneyVehicleNotFound) {
			writeProblem(w, s.logger, http.StatusNotFound, "vehicle_not_found",
				"No vehicle exists at this journey and id.")
			return
		}
		s.logger.Error("attestations: vehicle precheck failed", "error", err,
			"journey_id", journeyID, "vehicle_id", vehicleID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not look up journey vehicle.")
		return
	}

	records, err := s.cfg.DriverAttestationStore.ListDriverAttestations(r.Context(), vehicleID)
	if err != nil {
		s.logger.Error("attestations: list failed", "error", err, "vehicle_id", vehicleID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not list driver attestations.")
		return
	}
	out := make([]DriverAttestationResponse, 0, len(records))
	for _, rec := range records {
		out = append(out, driverAttestationResponseFrom(rec, nil))
	}
	writeJSON(w, DriverAttestationListResponse{Attestations: out}, s.logger)
}

func driverAttestationResponseFrom(rec storage.DriverAttestationRecord, siblings []DriverAttestationForkSibling) DriverAttestationResponse {
	return DriverAttestationResponse{
		ID:                   rec.ID,
		JourneyVehicleID:     rec.JourneyVehicleID,
		SegmentID:            rec.SegmentID,
		DriverUserID:         rec.DriverUserID,
		EffectiveTime:        rec.EffectiveTime.UTC(),
		ACLVersionConsulted:  rec.ACLVersionConsulted,
		PriorAttestationHash: rec.PriorAttestationHash,
		TrustFlag:            rec.TrustFlag,
		Integrity:            rec.Integrity,
		ReceivedAt:           rec.ReceivedAt.UTC(),
		ForkSiblings:         siblings,
	}
}
