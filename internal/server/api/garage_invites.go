package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/wheelsdown/spivot-server/internal/platform/storage"
	"github.com/wheelsdown/spivot-server/internal/server/middleware"
)

// Default invite lifetime when the caller omits expires_in_seconds.
// 7 days is the spec'd household-sharing window: long enough for
// "send my partner a link, they get to it that evening" but short
// enough that an unredeemed link doesn't linger as an
// authorization vector indefinitely.
const defaultGarageInviteLifetime = 7 * 24 * time.Hour

// maxGarageInviteLifetime caps the per-invite lifetime. Anything
// longer should be a fresh invite, not a single long-lived one.
const maxGarageInviteLifetime = 30 * 24 * time.Hour

// GarageInviteCreateRequest is the POST body for issuing an invite.
// All fields are optional and have sensible defaults.
type GarageInviteCreateRequest struct {
	ExpiresInSeconds int `json:"expires_in_seconds,omitempty"`
	MaxRedemptions   int `json:"max_redemptions,omitempty"`
}

// GarageInviteResponse is the wire shape for a garage invite.
// Token is populated ONLY on the create response — never on list
// or any subsequent read, since the plaintext is stored only as a
// SHA-256 hash.
type GarageInviteResponse struct {
	ID              string     `json:"id"`
	GarageID        string     `json:"garage_id"`
	CreatedByUserID string     `json:"created_by_user_id"`
	Token           string     `json:"token,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	ExpiresAt       time.Time  `json:"expires_at"`
	MaxRedemptions  int        `json:"max_redemptions"`
	RedemptionCount int        `json:"redemption_count"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
}

// GarageInviteListResponse is the envelope for the list endpoint.
type GarageInviteListResponse struct {
	Invites []GarageInviteResponse `json:"invites"`
}

// GarageInviteRedeemResponse is what the redeem handler returns:
// the redemption metadata plus the updated garage state so the
// client can render "you're in" without a follow-up GET.
type GarageInviteRedeemResponse struct {
	RedemptionID   string         `json:"redemption_id"`
	GarageInviteID string         `json:"garage_invite_id"`
	RedeemedAt     time.Time      `json:"redeemed_at"`
	Garage         GarageResponse `json:"garage"`
}

// handleGarageInviteCreate implements POST /v1/garages/{id}/invites.
// Caller must be an accepted owner of the garage. The response
// contains the plaintext token — shown to the inviter once and
// never retrievable from the server.
func (s *Server) handleGarageInviteCreate(w http.ResponseWriter, r *http.Request) {
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
	if err := s.requireAcceptedGarageOwner(r.Context(), id.UserID, garageID); err != nil {
		s.writeGarageOwnerError(w, err, garageID, id.UserID, "invite create authority check")
		return
	}

	// Decode whenever ContentLength != 0 — covers explicit-length
	// requests AND chunked transfers (ContentLength == -1). An
	// empty body / EOF is treated as "no params" so callers can
	// POST with no body and get the defaults; only a malformed
	// body returns 400.
	var req GarageInviteCreateRequest
	if r.ContentLength != 0 {
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			writeProblem(w, s.logger, http.StatusBadRequest, "invalid_request",
				fmt.Sprintf("Could not decode request body: %s", err))
			return
		}
	}
	lifetime := defaultGarageInviteLifetime
	if req.ExpiresInSeconds > 0 {
		lifetime = time.Duration(req.ExpiresInSeconds) * time.Second
		if lifetime > maxGarageInviteLifetime {
			writeProblem(w, s.logger, http.StatusBadRequest, "invalid_request",
				fmt.Sprintf("expires_in_seconds must be at most %d.", int(maxGarageInviteLifetime.Seconds())))
			return
		}
	}
	maxRedemptions := 1
	if req.MaxRedemptions > 0 {
		maxRedemptions = req.MaxRedemptions
	}

	token, rec, err := s.cfg.GarageStore.IssueGarageInvite(r.Context(), storage.GarageInviteIssueParams{
		GarageID:        garageID,
		CreatedByUserID: id.UserID,
		Lifetime:        lifetime,
		MaxRedemptions:  maxRedemptions,
	})
	if err != nil {
		s.logger.Error("garage-invites: create failed", "error", err, "garage_id", garageID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not create garage invite.")
		return
	}
	s.logger.Info("garage invite created",
		"garage_id", garageID,
		"invite_id", rec.ID,
		"created_by_user_id", id.UserID,
		"max_redemptions", rec.MaxRedemptions,
	)
	writeJSONStatus(w, http.StatusCreated, garageInviteResponseFrom(rec, token.Value), s.logger)
}

// handleGarageInviteList implements GET /v1/garages/{id}/invites.
// Caller must be an accepted owner. Returns every invite (including
// expired/revoked/exhausted) so the inviter can review history.
// Token field is NEVER populated on this path.
func (s *Server) handleGarageInviteList(w http.ResponseWriter, r *http.Request) {
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
	if err := s.requireAcceptedGarageOwner(r.Context(), id.UserID, garageID); err != nil {
		s.writeGarageOwnerError(w, err, garageID, id.UserID, "invite list authority check")
		return
	}
	records, err := s.cfg.GarageStore.ListGarageInvites(r.Context(), garageID)
	if err != nil {
		s.logger.Error("garage-invites: list failed", "error", err, "garage_id", garageID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not list garage invites.")
		return
	}
	out := make([]GarageInviteResponse, 0, len(records))
	for _, rec := range records {
		out = append(out, garageInviteResponseFrom(rec, ""))
	}
	writeJSON(w, GarageInviteListResponse{Invites: out}, s.logger)
}

// handleGarageInviteRevoke implements
// POST /v1/garages/{id}/invites/{inviteId}/revoke.
func (s *Server) handleGarageInviteRevoke(w http.ResponseWriter, r *http.Request) {
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
	inviteID := r.PathValue("inviteId")
	if err := s.requireAcceptedGarageOwner(r.Context(), id.UserID, garageID); err != nil {
		s.writeGarageOwnerError(w, err, garageID, id.UserID, "invite revoke authority check")
		return
	}
	if err := s.cfg.GarageStore.RevokeGarageInvite(r.Context(), garageID, inviteID); err != nil {
		if errors.Is(err, storage.ErrGarageInviteNotFound) {
			writeProblem(w, s.logger, http.StatusNotFound, "garage_invite_not_found",
				"No garage invite exists at this garage and id.")
			return
		}
		s.logger.Error("garage-invites: revoke failed", "error", err, "invite_id", inviteID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not revoke garage invite.")
		return
	}
	s.logger.Info("garage invite revoked",
		"garage_id", garageID,
		"invite_id", inviteID,
		"revoked_by_user_id", id.UserID,
	)
	w.WriteHeader(http.StatusNoContent)
}

// GarageInviteRedeemRequest is the POST body for the redeem
// endpoint. Token is in the body (not the URL path) so it doesn't
// leak into access logs, proxy logs, or browser history.
type GarageInviteRedeemRequest struct {
	Token string `json:"token"`
}

// handleGarageInviteRedeem implements
// POST /v1/garage-invites/redeem. Any authenticated user can
// redeem if they hold the token. The token in the body IS the
// proof of authority — the holder gets added as an owner of the
// inviter's garage.
func (s *Server) handleGarageInviteRedeem(w http.ResponseWriter, r *http.Request) {
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
	var req GarageInviteRedeemRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_request",
			fmt.Sprintf("Could not decode redeem request body: %s", err))
		return
	}
	token := req.Token
	if token == "" {
		writeProblem(w, s.logger, http.StatusBadRequest, "invalid_request",
			"token must be supplied in the request body.")
		return
	}

	result, err := s.cfg.GarageStore.RedeemGarageInvite(r.Context(), token, id.UserID)
	switch {
	case errors.Is(err, storage.ErrGarageInviteNotFound):
		writeProblem(w, s.logger, http.StatusNotFound, "garage_invite_not_found",
			"No garage invite matches this token (or it has been removed).")
		return
	case errors.Is(err, storage.ErrGarageInviteExpired):
		writeProblem(w, s.logger, http.StatusGone, "garage_invite_expired",
			"This garage invite has expired; ask for a new one.")
		return
	case errors.Is(err, storage.ErrGarageInviteRevoked):
		writeProblem(w, s.logger, http.StatusGone, "garage_invite_revoked",
			"This garage invite has been revoked; ask for a new one.")
		return
	case errors.Is(err, storage.ErrGarageInviteExhausted):
		writeProblem(w, s.logger, http.StatusGone, "garage_invite_exhausted",
			"This garage invite has reached its redemption limit; ask for a new one.")
		return
	case errors.Is(err, storage.ErrGarageOwnerAlreadyAccepted):
		writeProblem(w, s.logger, http.StatusConflict, "already_an_owner",
			"You are already an accepted owner of this garage.")
		return
	case errors.Is(err, storage.ErrGarageInviteAlreadyRedeemed):
		writeProblem(w, s.logger, http.StatusConflict, "already_redeemed",
			"You have already redeemed this invite.")
		return
	case err != nil:
		s.logger.Error("garage-invites: redeem failed", "error", err, "user_id", id.UserID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Could not redeem garage invite.")
		return
	}

	garageRec, err := s.cfg.GarageStore.GarageByID(r.Context(), result.Invite.GarageID)
	if err != nil {
		s.logger.Error("garage-invites: reload after redeem failed", "error", err, "garage_id", result.Invite.GarageID)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Redemption recorded but garage could not be reloaded.")
		return
	}
	garageResp, err := s.assembleGarageResponse(r.Context(), garageRec)
	if err != nil {
		s.logger.Error("garage-invites: assemble response failed", "error", err)
		writeProblem(w, s.logger, http.StatusInternalServerError, "internal_error",
			"Redemption recorded but response could not be assembled.")
		return
	}
	s.logger.Info("garage invite redeemed",
		"garage_id", result.Invite.GarageID,
		"invite_id", result.Invite.ID,
		"redeemer_user_id", id.UserID,
	)
	writeJSONStatus(w, http.StatusCreated, GarageInviteRedeemResponse{
		RedemptionID:   result.Redemption.ID,
		GarageInviteID: result.Redemption.GarageInviteID,
		RedeemedAt:     result.Redemption.RedeemedAt.UTC(),
		Garage:         garageResp,
	}, s.logger)
}

func garageInviteResponseFrom(rec storage.GarageInviteRecord, plaintextToken string) GarageInviteResponse {
	out := GarageInviteResponse{
		ID:              rec.ID,
		GarageID:        rec.GarageID,
		CreatedByUserID: rec.CreatedByUserID,
		Token:           plaintextToken,
		CreatedAt:       rec.CreatedAt.UTC(),
		ExpiresAt:       rec.ExpiresAt.UTC(),
		MaxRedemptions:  rec.MaxRedemptions,
		RedemptionCount: rec.RedemptionCount,
	}
	if rec.RevokedAt != nil {
		t := rec.RevokedAt.UTC()
		out.RevokedAt = &t
	}
	return out
}
