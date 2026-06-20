package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/opencaravan/opencaravan-go"

	"github.com/wheelsdown/spivot-server/internal/platform/storage"
	"github.com/wheelsdown/spivot-server/internal/server/middleware"
)

// maxTelemetryBodyBytes caps the request body size the telemetry
// handler will accept. Picked larger than a realistic batch
// (~hundreds of samples at ~200 bytes each) but small enough that
// a misbehaving client cannot DOS the server with a single
// request.
const maxTelemetryBodyBytes = 1 << 20 // 1 MiB

// TelemetryBatchRequest is the wire shape POST
// /v1/journeys/{id}/telemetry accepts. Phase 5 stores the
// envelope (client_batch_id + sample_count + payload digest)
// without expanding individual samples; future phases will
// promote Samples into per-row position_samples inserts.
type TelemetryBatchRequest struct {
	ClientBatchID string                       `json:"client_batch_id"`
	Samples       []opencaravan.PositionSample `json:"samples"`
}

// TelemetryBatchResponse is the ack the handler returns. Carries
// the server-side batch id (so the client can correlate retries
// across logs) and the count of samples the server acknowledged
// receiving.
type TelemetryBatchResponse struct {
	BatchID       string    `json:"batch_id"`
	ReceivedCount int       `json:"received_count"`
	ReceivedTime  time.Time `json:"received_time"`
}

// handleJourneyTelemetry implements POST
// /v1/journeys/{id}/telemetry.
//
// Wrapped by [middleware.RequireSession] with
// [middleware.SessionActionJourneyFromPath] at the mux: the
// caller's macaroon must carry journey={id} +
// action=telemetry.write caveats, and user= / client_app=
// caveats matching the context identity.
//
// The handler resolves the caller's [storage.JourneyParticipant]
// for this journey: a 403 fires when the macaroon's user= caveat
// matches the context identity (so the macaroon is for THIS
// caller) but the caller is not actually a participant in the
// journey (so they cannot post telemetry to it). This is the
// extra "membership" check beyond what the macaroon's caveats
// alone can express.
//
// Failures map to:
//
//   - 503 when JourneyStore is not wired.
//   - 401 when no [middleware.Session] is on context (defense in
//     depth; RequireSession handles the normal case).
//   - 400 for malformed JSON, missing client_batch_id, per-sample
//     validation failure, or body too large.
//   - 403 when the caller is not a joined participant in this
//     journey.
//   - 404 when no journey matches the id (rare — the macaroon's
//     journey caveat already gated this, but a stale macaroon
//     against a since-deleted journey would land here).
//   - 409 when the (device_id, client_batch_id) tuple is a
//     duplicate (idempotency retry was already accepted).
//   - 500 for unexpected storage failures.
func (s *Server) handleJourneyTelemetry(w http.ResponseWriter, r *http.Request) {
	if s.cfg.JourneyStore == nil {
		writeProblem(w, s.logger, http.StatusServiceUnavailable, "journey_unavailable",
			"This server is not configured to manage journeys.")
		return
	}
	id, ok := middleware.IdentityFrom(r.Context())
	if !ok {
		s.logger.Error("telemetry: handler reached without context identity; middleware chain bug")
		writeProblem(w, s.logger, http.StatusUnauthorized, "unauthenticated",
			"This endpoint requires a client certificate that resolves to an enrolled client app.")
		return
	}
	if _, ok := middleware.SessionFrom(r.Context()); !ok {
		s.logger.Error("telemetry: handler reached without context session; middleware chain bug")
		writeProblem(w, s.logger, http.StatusUnauthorized, "no_session",
			"This endpoint requires a session macaroon.")
		return
	}

	journeyID := r.PathValue("id")

	// Confirm the journey exists (and is not logically deleted —
	// JourneyByID filters on deleted_at IS NULL) BEFORE the
	// participant lookup and BEFORE reading the body. Without this
	// check, an unknown or deleted-journey id would land in the
	// participant lookup, miss, and surface as 403 not_a_participant
	// — which conflates "this journey doesn't exist" with "you're
	// not in this journey" and obscures the real reason from the
	// caller. Returning 404 here also short-circuits body-reading
	// cost for a guaranteed-rejection request.
	if _, err := s.cfg.JourneyStore.JourneyByID(r.Context(), journeyID); err != nil {
		if errors.Is(err, storage.ErrJourneyNotFound) {
			writeProblem(w, s.logger, http.StatusNotFound, "journey_not_found",
				"No journey exists at this id.")
			return
		}
		s.logger.Error("telemetry: journey lookup failed", "error", err, "journey_id", journeyID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not verify journey existence.")
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxTelemetryBodyBytes))
	if err != nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_request",
			fmt.Sprintf("Could not read telemetry body: %s", err))
		return
	}
	var req TelemetryBatchRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_request",
			fmt.Sprintf("Could not decode telemetry body: %s", err))
		return
	}
	if req.ClientBatchID == "" {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_request",
			"client_batch_id must be set")
		return
	}
	for i, sample := range req.Samples {
		if err := sample.Validate(); err != nil {
			writeProblem(w, s.logger, http.StatusBadRequest, "invalid_request",
				fmt.Sprintf("samples[%d] did not validate: %s", i, err))
			return
		}
		if string(sample.JourneyID) != journeyID {
			writeProblem(w, s.logger, http.StatusBadRequest, "invalid_request",
				fmt.Sprintf("samples[%d].journey_id does not match request path", i))
			return
		}
	}

	// Resolve the caller's participant in this journey. The
	// macaroon's journey= caveat already passed
	// CheckConstraints, so we know the macaroon is for THIS
	// journey. The remaining question is whether the macaroon's
	// user (== context identity user) actually belongs to the
	// journey as a joined participant.
	participant, err := s.cfg.JourneyStore.JourneyParticipantByUserAndJourney(r.Context(), id.UserID, journeyID)
	switch {
	case errors.Is(err, storage.ErrJourneyParticipantNotFound):
		writeProblem(w, s.logger, http.StatusForbidden, "not_a_participant",
			"The calling user is not a joined participant in this journey.")
		return
	case err != nil:
		s.logger.Error("telemetry: participant lookup failed",
			"error", err, "user_id", id.UserID, "journey_id", journeyID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not resolve participant membership.")
		return
	}

	digest := sha256.Sum256(body)
	batch, err := s.cfg.JourneyStore.RecordTelemetryBatch(r.Context(), storage.TelemetryBatchParams{
		JourneyID:     journeyID,
		ParticipantID: participant.ID,
		ClientBatchID: req.ClientBatchID,
		SampleCount:   len(req.Samples),
		PayloadDigest: "sha256:" + hex.EncodeToString(digest[:]),
	})
	switch {
	case errors.Is(err, storage.ErrTelemetryBatchDuplicate):
		writeProblem(w, s.logger, http.StatusConflict, "duplicate_batch",
			"A batch with this client_batch_id has already been recorded.")
		return
	case err != nil:
		s.logger.Error("telemetry: record batch failed", "error", err)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not record telemetry batch.")
		return
	}

	s.logger.Info("telemetry batch recorded",
		"batch_id", batch.ID,
		"journey_id", batch.JourneyID,
		"participant_id", batch.ParticipantID,
		"client_batch_id", batch.ClientBatchID,
		"sample_count", batch.SampleCount,
	)
	writeJSONStatus(w, http.StatusAccepted, TelemetryBatchResponse{
		BatchID:       batch.ID,
		ReceivedCount: batch.SampleCount,
		ReceivedTime:  batch.ReceivedAt.UTC(),
	}, s.logger)
}
