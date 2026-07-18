package api

import (
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

// defaultClientAppInviteLifetime is the validity window when the caller
// omits expires_in_seconds. 24h matches the first-run bootstrap and the
// CLI invite default, so API-minted invites behave identically.
const defaultClientAppInviteLifetime = 24 * time.Hour

// maxClientAppInviteLifetime caps a single invite's lifetime. Tighter
// than the 30-day garage-invite cap because a server_registration invite
// mints a brand-new identity (a higher-value capability than adding a
// garage co-owner), so an unredeemed one should not linger as long.
const maxClientAppInviteLifetime = 7 * 24 * time.Hour

// maxClientAppInviteLifetimeSeconds is the cap expressed in seconds so
// the request value can be bounds-checked BEFORE it is multiplied by
// time.Second. time.Duration is int64 nanoseconds; an unchecked
// multiply of a large expires_in_seconds would overflow and wrap to a
// negative/short duration, sliding past a post-multiply cap check.
// Comparing in seconds-space first makes the subsequent multiply
// provably overflow-free (604800 * 1e9 is well within int64).
const maxClientAppInviteLifetimeSeconds = int(maxClientAppInviteLifetime / time.Second)

// maxOutstandingClientAppInvites bounds how many unconsumed, unexpired
// server_registration invites one user may hold at once. This is the
// only enforced abuse control on the endpoint: it caps the blast radius
// of a single compromised enrolled credential being used as an
// account-minting faucet. A slot frees as soon as one of the user's
// outstanding invites is consumed or expires.
const maxOutstandingClientAppInvites = 10

// ClientAppInviteCreateRequest is the optional POST body. An empty body
// (or no Content-Length) is valid and selects the defaults.
type ClientAppInviteCreateRequest struct {
	// ExpiresInSeconds is the requested invite lifetime. Zero or
	// omitted selects the 24-hour default; values above the 7-day
	// cap (604800) or below zero are rejected with a 400.
	ExpiresInSeconds int `json:"expires_in_seconds,omitempty" openapi:"example=86400"`
}

// ClientAppInviteResponse is the wire shape for an issued invite.
//
// Token is populated ONLY on the create response — never on the list
// path, since the plaintext is stored only as a SHA-256 hash and is
// unrecoverable afterward. There is deliberately NO id or token_hash
// field: token_hash is the secret redemption key and must never leave
// the server, and exposing no public row handle is also what lets
// revocation be cleanly deferred (there is nothing to revoke by).
type ClientAppInviteResponse struct {
	// Scope is the invite's redemption scope. Always
	// "server_registration" — the only scope the enrollment
	// endpoint redeems, and the only one this endpoint mints.
	Scope string `json:"scope" openapi:"readOnly"`
	// CreatedByUserID is the user id of the enrolled account that
	// minted the invite.
	CreatedByUserID string `json:"created_by_user_id" openapi:"format=uuid,readOnly"`
	// Token is the plaintext invite token the invitee presents to
	// POST /v1/client-apps/enroll. Present only on the create
	// response: the server stores a SHA-256 hash, so the plaintext
	// is unrecoverable afterward and never appears on the list
	// path.
	Token string `json:"token,omitempty" openapi:"readOnly"`
	// CreatedAt is when the invite was minted.
	CreatedAt time.Time `json:"created_at" openapi:"readOnly"`
	// ExpiresAt is when the invite stops being redeemable.
	ExpiresAt time.Time `json:"expires_at" openapi:"readOnly"`
	// UsedAt is when the invite was redeemed by an enrollment.
	// Omitted while the invite is still outstanding.
	UsedAt *time.Time `json:"used_at,omitempty" openapi:"readOnly"`
}

// ClientAppInviteListResponse is the envelope for the list endpoint.
type ClientAppInviteListResponse struct {
	// Invites is every invite the caller has minted, newest first,
	// including used and expired rows. Token is never present here.
	Invites []ClientAppInviteResponse `json:"invites"`
}

// handleClientAppInviteCreate implements POST /v1/client-apps/invites.
//
// Wrapped by [middleware.RequireIdentity] at the mux: any enrolled
// client app may mint a server_registration invite. The scope is
// hard-coded — the caller cannot request a different scope, because
// only server_registration invites are redeemable by the enrollment
// endpoint and exposing scope selection would mint dead tokens.
//
// Failures map to:
//
//   - 503 when InviteIssuerStore is not wired.
//   - 401 when no identity is on context (defense in depth;
//     RequireIdentity handles the normal case).
//   - 403 invite_minting_disabled when InviteMintPolicy is "denied".
//   - 403 admin_only when InviteMintPolicy is "admin-only" and the
//     caller is not the founding administrator.
//   - 400 for malformed JSON, an unknown field, a negative
//     expires_in_seconds, or one exceeding the 7-day cap.
//   - 429 when the caller already holds the maximum number of
//     outstanding (unconsumed, unexpired) invites.
//   - 500 for unexpected storage failures.
func (s *Server) handleClientAppInviteCreate(w http.ResponseWriter, r *http.Request) {
	if s.cfg.InviteIssuerStore == nil {
		writeProblem(w, s.logger, http.StatusServiceUnavailable, "invites_unavailable",
			"This server is not configured to issue registration invites.")
		return
	}
	id, ok := middleware.IdentityFrom(r.Context())
	if !ok {
		writeProblem(w, s.logger, http.StatusUnauthorized, "unauthenticated",
			"This endpoint requires an enrolled client app identity.")
		return
	}

	// Server-level mint policy gate. Runs upstream of (and independent
	// from) the per-user outstanding cap, which still applies in
	// admin-only / any-user. The empty policy is treated as any-user so
	// a Config that never set it keeps the open default; production
	// resolves + validates the value at startup.
	switch s.cfg.InviteMintPolicy {
	case InviteMintDenied:
		writeProblem(w, s.logger, http.StatusForbidden, "invite_minting_disabled",
			"This server does not permit minting registration invites via the API.")
		return
	case InviteMintAdminOnly:
		isAdmin, err := s.cfg.InviteIssuerStore.IsFoundingAdmin(r.Context(), id.UserID)
		if err != nil {
			s.logger.Error("client-app-invites: admin check failed", "error", err, "user_id", id.UserID)
			writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
				"Could not verify administrator status.")
			return
		}
		if !isAdmin {
			writeProblem(w, s.logger, http.StatusForbidden, "admin_only",
				"Only the founding administrator may mint registration invites on this server.")
			return
		}
	case InviteMintAnyUser, "":
		// Any enrolled user may mint; the per-user cap still applies.
	default:
		// Unrecognized policy value. parseServeConfig validates at
		// startup so this is unreachable in production, but a
		// constructor or test that sets an invalid value must NOT
		// fall through to allow minting — fail closed.
		s.logger.Error("client-app-invites: unrecognized invite mint policy", "policy", string(s.cfg.InviteMintPolicy))
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"The server's invite mint policy is misconfigured.")
		return
	}

	// Decode whenever ContentLength != 0 — covers explicit-length AND
	// chunked transfers (ContentLength == -1). An empty body / EOF is
	// treated as "no params" so callers can POST with no body and get
	// the defaults; only a malformed body is a 400. Mirrors
	// handleGarageInviteCreate.
	var req ClientAppInviteCreateRequest
	if r.ContentLength != 0 {
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			writeProblem(w, s.logger, http.StatusBadRequest, "invalid_request",
				fmt.Sprintf("Could not decode request body: %s", err))
			return
		}
	}

	// Bounds-check in seconds-space before converting to a
	// time.Duration — see maxClientAppInviteLifetimeSeconds for why the
	// cap check must precede the multiply.
	lifetime := defaultClientAppInviteLifetime
	switch {
	case req.ExpiresInSeconds < 0:
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_request",
			"expires_in_seconds must not be negative.")
		return
	case req.ExpiresInSeconds > maxClientAppInviteLifetimeSeconds:
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_request",
			fmt.Sprintf("expires_in_seconds must be at most %d.", maxClientAppInviteLifetimeSeconds))
		return
	case req.ExpiresInSeconds > 0:
		lifetime = time.Duration(req.ExpiresInSeconds) * time.Second
	}

	token, invite, err := s.cfg.InviteIssuerStore.IssueInviteBy(r.Context(),
		opencaravan.InviteScopeServerRegistration, lifetime, id.UserID, maxOutstandingClientAppInvites)
	switch {
	case errors.Is(err, storage.ErrInviteOutstandingLimit):
		writeProblem(w, s.logger, http.StatusTooManyRequests, "invite_limit_reached",
			fmt.Sprintf("You already hold the maximum of %d outstanding registration invites; wait for one to be used or to expire.", maxOutstandingClientAppInvites))
		return
	case err != nil:
		s.logger.Error("client-app-invites: issue failed", "error", err, "created_by_user_id", id.UserID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not issue registration invite.")
		return
	}

	// One log line, never the token.
	s.logger.Info("server_registration invite created",
		"created_by_user_id", id.UserID,
		"expires_at", invite.ExpirationTime.UTC().Format(time.RFC3339),
	)
	writeJSONStatus(w, http.StatusCreated, ClientAppInviteResponse{
		Scope:           string(invite.Scope),
		CreatedByUserID: id.UserID,
		Token:           token.Value,
		CreatedAt:       invite.CreatedTime.UTC(),
		ExpiresAt:       invite.ExpirationTime.UTC(),
	}, s.logger)
}

// handleClientAppInviteList implements GET /v1/client-apps/invites.
//
// Returns every invite the calling user has minted (including used and
// expired rows for audit), newest first. The plaintext token is never
// populated on this path. Wrapped by [middleware.RequireIdentity].
func (s *Server) handleClientAppInviteList(w http.ResponseWriter, r *http.Request) {
	if s.cfg.InviteIssuerStore == nil {
		writeProblem(w, s.logger, http.StatusServiceUnavailable, "invites_unavailable",
			"This server is not configured to issue registration invites.")
		return
	}
	id, ok := middleware.IdentityFrom(r.Context())
	if !ok {
		writeProblem(w, s.logger, http.StatusUnauthorized, "unauthenticated",
			"This endpoint requires an enrolled client app identity.")
		return
	}

	records, err := s.cfg.InviteIssuerStore.InvitesCreatedBy(r.Context(), id.UserID)
	if err != nil {
		s.logger.Error("client-app-invites: list failed", "error", err, "created_by_user_id", id.UserID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not list registration invites.")
		return
	}

	out := make([]ClientAppInviteResponse, 0, len(records))
	for _, rec := range records {
		resp := ClientAppInviteResponse{
			Scope:           string(rec.Scope),
			CreatedByUserID: rec.CreatedByUserID,
			CreatedAt:       rec.CreatedTime.UTC(),
			ExpiresAt:       rec.ExpirationTime.UTC(),
		}
		if rec.UsedTime != nil {
			used := rec.UsedTime.UTC()
			resp.UsedAt = &used
		}
		out = append(out, resp)
	}
	writeJSON(w, ClientAppInviteListResponse{Invites: out}, s.logger)
}
