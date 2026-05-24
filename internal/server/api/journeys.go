package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/wheelsdown/spivot-server/internal/platform/storage"
	"github.com/wheelsdown/spivot-server/internal/server/middleware"
)

// JourneyCreateRequest is the minimal wire shape Phase 5 accepts
// for journey creation. Future phases will extend this toward the
// full [opencaravan.Journey] envelope as policy snapshots,
// avatars, and feature flags become first-class.
type JourneyCreateRequest struct {
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
}

// JourneyResponse is what the Phase 5 GET and POST handlers
// return. A deliberate subset of [opencaravan.Journey]: enough
// for a client to see the journey identity, state, and timestamps,
// without committing the server to fields it does not yet
// populate meaningfully (origin server URL, deletion policy,
// banner image, etc.). The shape is a server type — not aliased
// to opencaravan.Journey — so the protocol type can evolve
// independently.
type JourneyResponse struct {
	ID           string    `json:"id"`
	Title        string    `json:"title"`
	Description  string    `json:"description,omitempty"`
	HostUserID   string    `json:"host_user_id"`
	State        string    `json:"state"`
	Visibility   string    `json:"visibility"`
	CreationTime time.Time `json:"creation_time"`
}

// handleJourneyCreate implements POST /v1/journeys.
//
// Wrapped by [middleware.RequireIdentity] at the mux: the caller
// must already have an enrolled mTLS identity. No session
// macaroon needed (the caller is creating a journey, not
// operating against an existing one).
//
// The handler creates a new journey with the caller as the host
// participant. Phase 5 keeps the input minimal (title +
// description); future phases will expose the richer
// [opencaravan.Journey] envelope.
//
// Failures map to:
//
//   - 401 when no [middleware.Identity] is on the context
//     (defense in depth; RequireIdentity handles the normal case).
//   - 400 for malformed JSON or missing/blank title.
//   - 503 when the JourneyStore dependency is not wired.
//   - 500 for unexpected storage failures (logged but not exposed).
func (s *Server) handleJourneyCreate(w http.ResponseWriter, r *http.Request) {
	if s.cfg.JourneyStore == nil {
		s.logger.Warn("journey: handler unavailable; JourneyStore not wired")
		writeProblem(w, s.logger, http.StatusServiceUnavailable, "journey_unavailable",
			"This server is not configured to manage journeys.")
		return
	}
	id, ok := middleware.IdentityFrom(r.Context())
	if !ok {
		s.logger.Error("journey: handler reached without context identity; middleware chain bug")
		writeProblem(w, s.logger, http.StatusUnauthorized, "unauthenticated",
			"This endpoint requires a client certificate that resolves to an enrolled client app.")
		return
	}

	var req JourneyCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_request",
			fmt.Sprintf("Could not decode journey request body: %s", err))
		return
	}
	title := strings.TrimSpace(req.Title)
	if title == "" {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_request",
			"journey title must be set and non-blank")
		return
	}

	journey, err := s.cfg.JourneyStore.CreateJourney(r.Context(), storage.JourneyCreateParams{
		Title:       title,
		Description: strings.TrimSpace(req.Description),
		HostUserID:  id.UserID,
		PolicyHash:  s.cfg.PolicySnapshot.Hash,
		PolicyJSON:  string(s.cfg.PolicySnapshot.Document),
	})
	if err != nil {
		s.logger.Error("journey: create failed", "error", err, "user_id", id.UserID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not create journey.")
		return
	}

	s.logger.Info("journey created",
		"journey_id", journey.ID,
		"host_user_id", journey.HostUserID,
		"title", journey.Title,
	)
	writeJSONStatus(w, http.StatusCreated, journeyResponseFrom(journey), s.logger)
}

// handleJourneyGet implements GET /v1/journeys/{id}.
//
// Wrapped by [middleware.RequireSession] with a
// [middleware.SessionActionJourneyFromPath] constraint at the
// mux: the caller's macaroon must carry journey={id} +
// action=journey.read caveats, and user= / client_app= caveats
// matching the context identity.
//
// Failures map to:
//
//   - 503 when JourneyStore is not wired.
//   - 404 when no journey matches the id.
//   - 500 for unexpected storage failures.
func (s *Server) handleJourneyGet(w http.ResponseWriter, r *http.Request) {
	if s.cfg.JourneyStore == nil {
		writeProblem(w, s.logger, http.StatusServiceUnavailable, "journey_unavailable",
			"This server is not configured to manage journeys.")
		return
	}
	journeyID := r.PathValue("id")
	journey, err := s.cfg.JourneyStore.JourneyByID(r.Context(), journeyID)
	switch {
	case errors.Is(err, storage.ErrJourneyNotFound):
		writeProblem(w, s.logger, http.StatusNotFound, "journey_not_found",
			"No journey exists at this id.")
		return
	case err != nil:
		s.logger.Error("journey: load failed", "error", err, "journey_id", journeyID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not load journey.")
		return
	}
	writeJSON(w, journeyResponseFrom(journey), s.logger)
}

// journeyResponseFrom projects the storage Journey onto the
// server's response shape. Kept in one place so the GET and
// POST responses stay consistent.
func journeyResponseFrom(j storage.Journey) JourneyResponse {
	return JourneyResponse{
		ID:           j.ID,
		Title:        j.Title,
		Description:  j.Description,
		HostUserID:   j.HostUserID,
		State:        j.State,
		Visibility:   j.Visibility,
		CreationTime: j.CreatedAt.UTC(),
	}
}
