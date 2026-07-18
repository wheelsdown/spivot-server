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

// DriverAttestationResponse is the wire shape the
// driver-attestation handlers return. A deliberate subset of
// [opencaravan.DriverAttestation] augmented with the
// server-computed trust_flag and fork-detection metadata.
type DriverAttestationResponse struct {
	// ID is the server-assigned identifier of the stored
	// attestation row.
	ID string `json:"id" openapi:"format=uuid,readOnly"`
	// JourneyVehicleID is the vehicle whose wheel the driver
	// attested to taking.
	JourneyVehicleID string `json:"journey_vehicle_id" openapi:"format=uuid,readOnly"`
	// SegmentID is the journey segment the attestation applies to,
	// per the signed payload. Opaque at this layer: the server does
	// not yet verify the segment exists.
	SegmentID string `json:"segment_id" openapi:"format=uuid,readOnly"`
	// DriverUserID is the user who signed the attestation —
	// drivers attest to their own handoffs, so this always matches
	// the submitting session's user.
	DriverUserID string `json:"driver_user_id" openapi:"format=uuid,readOnly"`
	// EffectiveTime is when the driver took the wheel, per the
	// signed payload. The (vehicle, driver, effective_time) tuple
	// is the replay key: a gossiped duplicate returns the existing
	// record with 200 instead of 409.
	EffectiveTime time.Time `json:"effective_time" openapi:"readOnly"`
	// ACLVersionConsulted is the ACL revision the server's trust
	// evaluator consulted — the one in effect at EffectiveTime,
	// not necessarily the newest.
	ACLVersionConsulted int `json:"acl_version_consulted" openapi:"readOnly"`
	// PriorAttestationHash is the canonical hash
	// ("sha256:<64 lowercase hex>") of the predecessor attestation
	// in the handoff chain. Omitted on a chain root (the vehicle's
	// first driver).
	PriorAttestationHash *string `json:"prior_attestation_hash,omitempty" openapi:"readOnly"`
	// TrustFlag is the server-evaluated trust outcome: the driver
	// was in the consulted ACL (authorized), permitted only by the
	// vehicle's emergency fallback rule (emergency_fallback), or
	// neither — retained as evidence but untrusted (acl_violation).
	TrustFlag storage.DriverAttestationTrust `json:"trust_flag" openapi:"enum=authorized|emergency_fallback|acl_violation,readOnly"`
	// Integrity is the driver's signature envelope over the
	// attestation's canonical bytes.
	Integrity opencaravan.Integrity `json:"integrity" openapi:"readOnly"`
	// ReceivedAt is when the server recorded the attestation.
	ReceivedAt time.Time `json:"received_at" openapi:"readOnly"`
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
	// ID is the sibling attestation's server-assigned identifier.
	ID string `json:"id" openapi:"format=uuid,readOnly"`
	// DriverUserID is the user the sibling attestation names as
	// driver.
	DriverUserID string `json:"driver_user_id" openapi:"format=uuid,readOnly"`
	// EffectiveTime is when the sibling claims its driver took the
	// wheel.
	EffectiveTime time.Time `json:"effective_time" openapi:"readOnly"`
	// TrustFlag is the sibling's server-evaluated trust outcome.
	TrustFlag storage.DriverAttestationTrust `json:"trust_flag" openapi:"enum=authorized|emergency_fallback|acl_violation,readOnly"`
}

// DriverAttestationListResponse is the envelope returned by the
// GET handler. Envelope shape so future phases can add pagination
// or filter metadata without breaking clients indexing on
// "attestations".
type DriverAttestationListResponse struct {
	// Attestations is every recorded attestation for the vehicle,
	// ordered by effective_time ascending. Low-trust rows are
	// included; filter on trust_flag to show only authorized
	// drivers.
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

	// Short-circuit on replay BEFORE classification: a gossiped
	// retry of an already-stored attestation must return the
	// original record even if classify would now fail transiently
	// (DB hiccup, ACL JSON decode error, journey-participant
	// lookup error). Returning the original record also preserves
	// the original trust_flag — if the ACL evolved between the
	// first submission and this replay, the response reflects the
	// state at the time of original classification, not the freshly
	// recomputed one.
	rec, status, err := s.replayExistingAttestation(r.Context(), vehicleID, id.UserID, attestation.EffectiveTime)
	switch {
	case err != nil:
		s.logger.Error("attestations: replay key lookup failed", "error", err,
			"vehicle_id", vehicleID, "driver_user_id", id.UserID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not check for an existing attestation.")
		return
	case status == http.StatusOK:
		// Existing record returned. Fall through to fork-sibling
		// surfacing — useful for the replay client to see any
		// siblings that have appeared since the original submission.
	default:
		// No replay match — classify and insert fresh.
		canonical, encErr := attestation.CanonicalEncoding()
		if encErr != nil {
			s.logger.Error("attestations: canonical encode failed", "error", encErr)
			writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
				"Could not compute canonical attestation bytes.")
			return
		}
		// Cryptographic signature check happens BEFORE classify so
		// a tampered or wrong-key attestation is rejected without
		// burning the cost of resolving the ACL-at-time. The
		// signer must be the driver (KeyID's cert.user_id ==
		// attestation.driver_user_id).
		if !verifySignedPayload(w, r, s.logger, s.cfg.IntegrityVerifier, s.cfg.VehicleStore,
			canonical, *attestation.Integrity, string(attestation.DriverUserID), "attestations") {
			return
		}
		resolver := &driverAttestationTrustResolver{
			store:              s.cfg.VehicleStore,
			journeyParticipant: s.cfg.JourneyStore,
		}
		trust, classifyErr := resolver.classify(r.Context(), journeyID, stored.OwnerUserID, attestation)
		if classifyErr != nil {
			if errors.Is(classifyErr, storage.ErrJourneyVehicleNotFound) {
				// No ACL revision exists at or before EffectiveTime —
				// structurally impossible for a legitimate driver to
				// have consulted an ACL that did not yet exist.
				writeProblem(w, s.logger, http.StatusBadRequest, "no_acl_at_effective_time",
					"No VehicleACL revision exists at or before the attestation's effective_time.")
				return
			}
			s.logger.Error("attestations: classify failed", "error", classifyErr, "vehicle_id", vehicleID)
			writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
				"Could not classify attestation trust.")
			return
		}
		inserted, recordErr := s.cfg.DriverAttestationStore.RecordDriverAttestation(r.Context(), storage.DriverAttestationRecordParams{
			Attestation:      attestation,
			JourneyVehicleID: vehicleID,
			TrustFlag:        trust,
			CanonicalPayload: canonical,
		})
		switch {
		case errors.Is(recordErr, storage.ErrDriverAttestationDuplicate):
			// Concurrent submission won the race; fetch the
			// committed record. The pre-check above is best-effort,
			// not a lock — a peer submission between our check and
			// our insert can still produce a UNIQUE collision.
			existing, lookupErr := s.cfg.DriverAttestationStore.DriverAttestationByReplayKey(
				r.Context(), vehicleID, id.UserID, attestation.EffectiveTime)
			if lookupErr != nil {
				s.logger.Error("attestations: post-insert replay lookup failed", "error", lookupErr,
					"vehicle_id", vehicleID, "driver_user_id", id.UserID)
				writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
					"Could not load existing attestation after replay conflict.")
				return
			}
			rec = existing
			status = http.StatusOK
		case recordErr != nil:
			s.logger.Error("attestations: record failed", "error", recordErr, "vehicle_id", vehicleID)
			writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
				"Could not record driver attestation.")
			return
		default:
			rec = inserted
			status = http.StatusCreated
			s.logger.Info("driver attestation recorded",
				"journey_id", journeyID,
				"vehicle_id", vehicleID,
				"driver_user_id", rec.DriverUserID,
				"acl_version_consulted", rec.ACLVersionConsulted,
				"trust_flag", rec.TrustFlag,
			)
		}
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

// replayExistingAttestation looks up a previously-recorded
// attestation by replay key. Returns:
//
//   - rec, http.StatusOK, nil — the record exists; caller should
//     return it with 200 (and skip classify+insert).
//   - empty rec, 0, nil — no replay match; caller should classify
//     and insert fresh.
//   - empty rec, 0, err — unexpected lookup failure (NOT
//     ErrDriverAttestationNotFound).
func (s *Server) replayExistingAttestation(ctx context.Context, journeyVehicleID, driverUserID string, effectiveTime time.Time) (storage.DriverAttestationRecord, int, error) {
	existing, err := s.cfg.DriverAttestationStore.DriverAttestationByReplayKey(ctx, journeyVehicleID, driverUserID, effectiveTime)
	switch {
	case errors.Is(err, storage.ErrDriverAttestationNotFound):
		return storage.DriverAttestationRecord{}, 0, nil
	case err != nil:
		return storage.DriverAttestationRecord{}, 0, err
	}
	return existing, http.StatusOK, nil
}

// CurrentDriverResponse is what the current-driver endpoint
// returns. Carries the attestation the server picked as "in
// effect at the queried time" plus any fork siblings that share
// the picked attestation's prior_attestation_hash — so clients
// can render "right now you're being attributed to driver X, but
// also driver Y has a competing claim on the same predecessor."
//
// AsOf echoes the resolved query timestamp so the response is
// auditable when the caller didn't supply one (server used
// time.Now()).
type CurrentDriverResponse struct {
	// AsOf is the resolved query timestamp the answer is relative
	// to: the ?at value when supplied, otherwise the server's
	// current time.
	AsOf time.Time `json:"as_of" openapi:"readOnly"`
	// Attestation is the driver attestation in effect at AsOf —
	// the highest effective_time at or before it, ties broken by
	// most recently received.
	Attestation DriverAttestationResponse `json:"attestation"`
	// ForkSiblings names competing attestations sharing the picked
	// attestation's prior_attestation_hash, so clients can surface
	// a conflicting handoff claim. Omitted when there is no fork.
	ForkSiblings []DriverAttestationForkSibling `json:"fork_siblings,omitempty"`
}

// handleCurrentDriver implements
// GET /v1/journeys/{id}/vehicles/{vid}/current-driver[?at=<rfc3339>].
//
// Returns the driver attestation in effect at the supplied time
// (defaults to time.Now() when ?at is omitted). The attestation
// is the one with the highest effective_time <= the queried
// time; ties broken by received_at descending.
//
// Failures map to:
//
//   - 503 when storage interfaces aren't wired.
//   - 400 when the ?at query value isn't valid RFC3339.
//   - 404 when the vehicle doesn't exist OR no attestation is on
//     file for it at or before the queried time (i.e., no driver
//     has yet attested to taking the wheel).
//   - 500 for unexpected storage failures.
func (s *Server) handleCurrentDriver(w http.ResponseWriter, r *http.Request) {
	if s.cfg.DriverAttestationStore == nil || s.cfg.VehicleStore == nil {
		writeProblem(w, s.logger, http.StatusServiceUnavailable, "attestations_unavailable",
			"This server is not configured to record driver attestations.")
		return
	}
	journeyID := r.PathValue("id")
	vehicleID := r.PathValue("vid")

	at := time.Now().UTC()
	if raw := r.URL.Query().Get("at"); raw != "" {
		parsed, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			writeProblem(w, s.logger, http.StatusBadRequest, "invalid_request",
				fmt.Sprintf("?at must be a valid RFC3339 timestamp: %s", err))
			return
		}
		at = parsed.UTC()
	}

	if _, err := s.cfg.VehicleStore.JourneyVehicleByID(r.Context(), journeyID, vehicleID); err != nil {
		if errors.Is(err, storage.ErrJourneyVehicleNotFound) {
			writeProblem(w, s.logger, http.StatusNotFound, "vehicle_not_found",
				"No vehicle exists at this journey and id.")
			return
		}
		s.logger.Error("current-driver: vehicle precheck failed", "error", err,
			"journey_id", journeyID, "vehicle_id", vehicleID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not look up journey vehicle.")
		return
	}

	rec, err := s.cfg.DriverAttestationStore.CurrentDriverForJourneyVehicle(r.Context(), vehicleID, at)
	if err != nil {
		if errors.Is(err, storage.ErrDriverAttestationNotFound) {
			writeProblem(w, s.logger, http.StatusNotFound, "no_driver_attested",
				"No driver has attested to taking this vehicle at or before the queried time.")
			return
		}
		s.logger.Error("current-driver: load failed", "error", err,
			"vehicle_id", vehicleID, "at", at)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not load current driver.")
		return
	}

	var siblings []DriverAttestationForkSibling
	if rec.PriorAttestationHash != nil {
		rows, sibErr := s.cfg.DriverAttestationStore.DriverAttestationForkSiblings(
			r.Context(), vehicleID, *rec.PriorAttestationHash)
		if sibErr != nil {
			s.logger.Warn("current-driver: fork sibling lookup failed", "error", sibErr,
				"vehicle_id", vehicleID, "prior_hash", *rec.PriorAttestationHash)
		} else {
			for _, row := range rows {
				// DriverAttestationForkSiblings includes the
				// selected attestation by design (the POST
				// response surfaces "every claimant on this
				// predecessor, including me"). For the
				// current-driver response, ForkSiblings is the
				// "OTHER competing claims" set — exclude the
				// selected record so clients don't see it twice.
				if row.ID == rec.ID {
					continue
				}
				siblings = append(siblings, DriverAttestationForkSibling{
					ID:            row.ID,
					DriverUserID:  row.DriverUserID,
					EffectiveTime: row.EffectiveTime.UTC(),
					TrustFlag:     row.TrustFlag,
				})
			}
		}
	}

	writeJSON(w, CurrentDriverResponse{
		AsOf:         at,
		Attestation:  driverAttestationResponseFrom(rec, nil),
		ForkSiblings: siblings,
	}, s.logger)
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
