package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/opencaravan/opencaravan-go"
)

func TestClientAppInviteCreateHappyPath(t *testing.T) {
	env := newJourneyEnv(t)
	caller := env.mintIdentity(t)

	rec := env.post(t, "/v1/client-apps/invites", ClientAppInviteCreateRequest{}, caller, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp ClientAppInviteResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Token == "" {
		t.Fatal("create response missing token")
	}
	if resp.Scope != string(opencaravan.InviteScopeServerRegistration) {
		t.Fatalf("scope: got %q want server_registration", resp.Scope)
	}
	if resp.CreatedByUserID != caller.UserID {
		t.Fatalf("created_by_user_id: got %q want %q", resp.CreatedByUserID, caller.UserID)
	}
	if resp.ExpiresAt.Before(resp.CreatedAt) {
		t.Fatal("expires_at precedes created_at")
	}
}

// TestClientAppInviteCreateProducesRedeemableInvite proves the minted
// token is a real, active, server_registration-scoped invite that the
// enrollment path will accept: a LookupInvite against the plaintext the
// API returned resolves to an unused, unexpired row of the right scope.
// (The full enroll->cert machinery is exercised in enrollment_test.go;
// this asserts the API handler produced a genuinely consumable token.)
func TestClientAppInviteCreateProducesRedeemableInvite(t *testing.T) {
	env := newJourneyEnv(t)
	inviter := env.mintIdentity(t)

	createRec := env.post(t, "/v1/client-apps/invites", ClientAppInviteCreateRequest{}, inviter, "")
	if createRec.Code != http.StatusCreated {
		t.Fatalf("mint: got %d body=%s", createRec.Code, createRec.Body.String())
	}
	var minted ClientAppInviteResponse
	if err := json.Unmarshal(createRec.Body.Bytes(), &minted); err != nil {
		t.Fatalf("decode mint: %v", err)
	}

	got, err := env.store.LookupInvite(context.Background(), minted.Token)
	if err != nil {
		t.Fatalf("LookupInvite on minted token: %v (token must be redeemable)", err)
	}
	if got.Scope != opencaravan.InviteScopeServerRegistration {
		t.Fatalf("minted invite scope: got %q want server_registration", got.Scope)
	}
	if got.UsedTime != nil {
		t.Fatal("freshly minted invite already marked used")
	}
	if got.CreatedByUserID != inviter.UserID {
		t.Fatalf("minted invite created_by: got %q want %q", got.CreatedByUserID, inviter.UserID)
	}
}

func TestClientAppInviteCreateRejectsNegativeLifetime(t *testing.T) {
	env := newJourneyEnv(t)
	caller := env.mintIdentity(t)
	rec := env.post(t, "/v1/client-apps/invites",
		ClientAppInviteCreateRequest{ExpiresInSeconds: -1}, caller, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestClientAppInviteCreateRejectsOverlongLifetime(t *testing.T) {
	env := newJourneyEnv(t)
	caller := env.mintIdentity(t)
	// 8 days > the 7-day cap.
	rec := env.post(t, "/v1/client-apps/invites",
		ClientAppInviteCreateRequest{ExpiresInSeconds: 8 * 24 * 60 * 60}, caller, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestClientAppInviteCreateEnforcesOutstandingCap(t *testing.T) {
	env := newJourneyEnv(t)
	caller := env.mintIdentity(t)

	// Mint up to the cap; all should succeed.
	for i := 0; i < maxOutstandingClientAppInvites; i++ {
		rec := env.post(t, "/v1/client-apps/invites", ClientAppInviteCreateRequest{}, caller, "")
		if rec.Code != http.StatusCreated {
			t.Fatalf("mint #%d: got %d body=%s", i, rec.Code, rec.Body.String())
		}
	}
	// The next one trips the cap with 429.
	rec := env.post(t, "/v1/client-apps/invites", ClientAppInviteCreateRequest{}, caller, "")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over cap: got %d want 429; body=%s", rec.Code, rec.Body.String())
	}
}

func TestClientAppInviteListReturnsOwnInvitesWithoutToken(t *testing.T) {
	env := newJourneyEnv(t)
	caller := env.mintIdentity(t)
	other := env.mintIdentity(t)

	// caller mints two; other mints one.
	for i := 0; i < 2; i++ {
		if rec := env.post(t, "/v1/client-apps/invites", ClientAppInviteCreateRequest{}, caller, ""); rec.Code != http.StatusCreated {
			t.Fatalf("caller mint #%d: %d", i, rec.Code)
		}
	}
	if rec := env.post(t, "/v1/client-apps/invites", ClientAppInviteCreateRequest{}, other, ""); rec.Code != http.StatusCreated {
		t.Fatalf("other mint: %d", rec.Code)
	}

	listRec := env.get(t, "/v1/client-apps/invites", caller, "")
	if listRec.Code != http.StatusOK {
		t.Fatalf("list: got %d body=%s", listRec.Code, listRec.Body.String())
	}
	var resp ClientAppInviteListResponse
	if err := json.Unmarshal(listRec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(resp.Invites) != 2 {
		t.Fatalf("expected 2 invites for caller, got %d (other user's invite must not leak)", len(resp.Invites))
	}
	for _, inv := range resp.Invites {
		if inv.Token != "" {
			t.Fatal("list response leaked a plaintext token")
		}
		if inv.CreatedByUserID != caller.UserID {
			t.Fatalf("list leaked an invite created by %q", inv.CreatedByUserID)
		}
	}
}

func TestClientAppInviteCreate503WhenStoreMissing(t *testing.T) {
	// A server with no InviteIssuerStore wired responds 503 rather than
	// panicking — the explicit-misconfiguration convention.
	env := newJourneyEnv(t)
	caller := env.mintIdentity(t)
	env.server.cfg.InviteIssuerStore = nil

	rec := env.post(t, "/v1/client-apps/invites", ClientAppInviteCreateRequest{}, caller, "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d want 503; body=%s", rec.Code, rec.Body.String())
	}
}
