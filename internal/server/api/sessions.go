package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/opencaravan/opencaravan-go"
	"github.com/wheelsdown/spivot-server/internal/platform/auth/macaroon"
	"github.com/wheelsdown/spivot-server/internal/server/middleware"
)

// defaultSessionLifetime is the macaroon lifetime applied when a
// [opencaravan.SessionRequest] omits a positive LifetimeSeconds
// hint. Picked short enough that a stolen macaroon's blast radius
// is bounded but long enough to cover a normal drive segment
// without a renewal round-trip.
const defaultSessionLifetime = 15 * time.Minute

// maxSessionLifetime is the upper bound the server applies to the
// LifetimeSeconds hint a [opencaravan.SessionRequest] supplies.
// Clamping (rather than rejecting) means a client that requests
// longer than the server allows still gets a working macaroon,
// just for the server-side maximum. The Validate contract on
// SessionResponse documents this as a server-side decision.
const maxSessionLifetime = 60 * time.Minute

// handleSessionCreate implements POST /v1/sessions.
//
// The handler is the first consumer of [middleware.RequireIdentity];
// the route is registered already wrapped, so by the time control
// reaches this function the request carries a valid [middleware.
// Identity] in its context (RequireIdentity 401s otherwise).
//
// Flow:
//
//  1. Pull the resolved [middleware.Identity] from the request
//     context. The wrapping RequireIdentity guard guarantees
//     IdentityFrom returns ok=true; the explicit !ok branch below
//     is a defense-in-depth response if the middleware chain
//     becomes misconfigured.
//  2. Decode and protocol-validate the [opencaravan.SessionRequest].
//  3. Enforce v0's single-action constraint: each macaroon
//     authorizes exactly one action (see the Phase 4a IssueSession
//     doc for the rationale). A SessionRequest carrying multiple
//     actions is rejected with 422 today; a future protocol
//     extension can replace this with multi-macaroon issuance.
//  4. Clamp the LifetimeSeconds hint against
//     [maxSessionLifetime]; default to [defaultSessionLifetime]
//     when the hint is non-positive.
//  5. Issue a macaroon via [macaroon.Issuer.IssueSession]. The
//     issuer composes the canonical caveat set (user= +
//     client_app= + optional journey= + action= + time<expiration)
//     and returns the binary serialization.
//  6. Base64url-encode the binary serialization into
//     [opencaravan.SessionResponse.Macaroon] (the unpadded variant
//     that protocol Validate requires).
//
// Permission model: v0 is permissive. Any enrolled ClientApp can
// request any [opencaravan.SessionAction] against any journey it
// names. There is no "this user belongs to this journey" check
// today — the issue #10 design notes (and the in-flight permission
// model open question) record this as a deliberate v0.0.1 choice.
// Phase 5 (the first journey-bearing endpoint) is where membership
// gating will start to bite, and Phase 4c's session middleware
// already validates that a presented macaroon names the journey
// the request is operating on.
//
// Failures map to:
//
//   - 401 when no [middleware.Identity] is on the context (defense
//     in depth; RequireIdentity handles the normal case).
//   - 400 for malformed JSON or protocol validation failures.
//   - 422 when the request asks for more than one action
//     (v0 single-action limit) or names a journey-scoped action
//     without a JourneyID.
//   - 503 when the [macaroon.Issuer] dependency is not wired
//     (deployment misconfiguration).
//   - 500 for unexpected issuance failures, logged but not
//     exposed to the caller.
func (s *Server) handleSessionCreate(w http.ResponseWriter, r *http.Request) {
	if s.cfg.MacaroonIssuer == nil {
		s.logger.Warn("session: handler unavailable; MacaroonIssuer not wired")
		writeProblem(w, s.logger, http.StatusServiceUnavailable, "session_unavailable",
			"This server is not configured to issue session macaroons.")
		return
	}

	id, ok := middleware.IdentityFrom(r.Context())
	if !ok {
		// RequireIdentity guards this route at the mux. Reaching
		// this branch would mean a future refactor removed the
		// guard; treat it as a deployment-level bug and 401 so
		// clients don't see incorrect responses.
		s.logger.Error("session: handler reached without context identity; middleware chain bug")
		writeProblem(w, s.logger, http.StatusUnauthorized, "unauthenticated",
			"This endpoint requires a client certificate that resolves to an enrolled client app.")
		return
	}

	var req opencaravan.SessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_request",
			fmt.Sprintf("Could not decode session request body: %s", err))
		return
	}
	if err := req.Validate(); err != nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_request",
			fmt.Sprintf("Session request did not validate: %s", err))
		return
	}

	if len(req.Actions) != 1 {
		// One action= caveat per macaroon (see macaroon package
		// docs for the protocol-level rationale). Multi-action
		// sessions would require either issuing multiple macaroons
		// (the SessionResponse shape carries one) or extending the
		// protocol with a disjunctive action predicate. Reject
		// fail-closed for v0 so clients see an explicit limit
		// rather than silently lossy behavior.
		writeProblem(w, s.logger, http.StatusUnprocessableEntity, "single_action_required",
			fmt.Sprintf("v0 issues one macaroon per action; received %d actions in request.", len(req.Actions)))
		return
	}
	action := req.Actions[0]

	journeyID := opencaravan.UUID("")
	if req.JourneyID != nil {
		journeyID = *req.JourneyID
	}

	now := time.Now().UTC()
	lifetime := normalizeSessionLifetime(req.LifetimeSeconds)
	expiration := now.Add(lifetime)

	userUUID, err := opencaravan.ParseUUID(id.UserID)
	if err != nil {
		// The identity middleware loaded this UserID from the
		// issued_certificates row whose enrollment path minted it
		// via opencaravan.NewUUID — it must round-trip cleanly.
		// If it does not, the row is corrupt; surface as 500 and
		// log loud.
		s.logger.Error("session: context identity user id is not a valid UUID",
			"user_id", id.UserID, "error", err)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not interpret the caller's user id.")
		return
	}
	appUUID, err := opencaravan.ParseUUID(id.ClientAppID)
	if err != nil {
		s.logger.Error("session: context identity client app id is not a valid UUID",
			"client_app_id", id.ClientAppID, "error", err)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not interpret the caller's client app id.")
		return
	}

	params := macaroon.SessionParams{
		UserID:      userUUID,
		ClientAppID: appUUID,
		JourneyID:   journeyID,
		Action:      action,
		Expiration:  expiration,
		Now:         now,
	}
	_, serialized, err := s.cfg.MacaroonIssuer.IssueSession(params)
	if err != nil {
		if isSessionParamsValidationError(err) {
			// macaroon.SessionParams.validate surfaces all of:
			// invalid UUIDs (already caught above), unknown action,
			// journey-scoped action without a JourneyID, and
			// expiration in the past. The first two are already
			// validated at the protocol layer (req.Validate); the
			// third is the one that legitimately fires here, and
			// it's a 422 for the client to fix.
			writeProblem(w, s.logger, http.StatusUnprocessableEntity, "invalid_session_params",
				err.Error())
			return
		}
		s.logger.Error("session: issuance failed", "error", err)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not issue the session macaroon.")
		return
	}

	encoded := base64.RawURLEncoding.EncodeToString(serialized)
	resp := opencaravan.NewSessionResponse(encoded, expiration)
	s.logger.Info("session issued",
		"user_id", id.UserID,
		"client_app_id", id.ClientAppID,
		"journey_id", string(journeyID),
		"action", string(action),
		"expiration_time", expiration.Format(time.RFC3339),
		"lifetime_seconds", int(lifetime.Seconds()),
	)
	writeJSONStatus(w, http.StatusCreated, resp, s.logger)
}

// normalizeSessionLifetime clamps the client-supplied hint to the
// server's policy window. Returns [defaultSessionLifetime] when
// requested is non-positive (the wire format permits zero), and
// [maxSessionLifetime] when requested exceeds it. Otherwise
// returns the requested duration unchanged.
func normalizeSessionLifetime(requestedSeconds int) time.Duration {
	if requestedSeconds <= 0 {
		return defaultSessionLifetime
	}
	requested := time.Duration(requestedSeconds) * time.Second
	if requested > maxSessionLifetime {
		return maxSessionLifetime
	}
	return requested
}

// isSessionParamsValidationError reports whether err looks like a
// validation failure from [macaroon.SessionParams.validate].
// macaroon's validate returns plain errors created via errors.New
// / fmt.Errorf without a wrapping sentinel, so we string-match on
// the "macaroon:" prefix the package uses. Phase 4c can promote
// this to a proper exported sentinel once the same kind of mapping
// is needed in the session-validation middleware.
func isSessionParamsValidationError(err error) bool {
	if err == nil {
		return false
	}
	// errors.Is for the umbrella ErrVerifyFailed handles verifier
	// failures elsewhere; the issuer's validate path doesn't have
	// an equivalent sentinel yet. Until it does, prefix-match.
	return strings.HasPrefix(err.Error(), "macaroon: ")
}
