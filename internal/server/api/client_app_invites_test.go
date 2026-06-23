package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
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

func TestClientAppInviteCreateRejectsOverflowingLifetime(t *testing.T) {
	// A seconds value so large that seconds * time.Second would overflow
	// int64 and wrap to a negative/short duration. The handler must
	// reject it deterministically with 400 (caught in seconds-space
	// before the multiply), never produce a 500 or a wrapped expiry.
	env := newJourneyEnv(t)
	caller := env.mintIdentity(t)
	rec := env.post(t, "/v1/client-apps/invites",
		ClientAppInviteCreateRequest{ExpiresInSeconds: 1 << 62}, caller, "")
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

func TestClientAppInviteCreateDeniedPolicyForbidsEveryone(t *testing.T) {
	env := newJourneyEnv(t)
	caller := env.mintIdentity(t)
	env.server.cfg.InviteMintPolicy = InviteMintDenied

	rec := env.post(t, "/v1/client-apps/invites", ClientAppInviteCreateRequest{}, caller, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want 403; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "invite_minting_disabled") {
		t.Fatalf("body missing invite_minting_disabled code: %s", rec.Body.String())
	}
}

func TestClientAppInviteCreateAdminOnlyAllowsFoundingAdmin(t *testing.T) {
	env := newJourneyEnv(t)
	// First-minted identity is the earliest account; confirm via the
	// store rather than assuming, so a same-nanosecond created_at tie
	// can't flip the test.
	a := env.mintIdentity(t)
	b := env.mintIdentity(t)
	env.server.cfg.InviteMintPolicy = InviteMintAdminOnly

	adminID, err := env.store.FoundingAdminUserID(context.Background())
	if err != nil {
		t.Fatalf("FoundingAdminUserID: %v", err)
	}
	admin, nonAdmin := a, b
	if adminID == b.UserID {
		admin, nonAdmin = b, a
	}

	if rec := env.post(t, "/v1/client-apps/invites", ClientAppInviteCreateRequest{}, admin, ""); rec.Code != http.StatusCreated {
		t.Fatalf("admin mint: got %d want 201; body=%s", rec.Code, rec.Body.String())
	}
	rec := env.post(t, "/v1/client-apps/invites", ClientAppInviteCreateRequest{}, nonAdmin, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin mint: got %d want 403; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "admin_only") {
		t.Fatalf("body missing admin_only code: %s", rec.Body.String())
	}
}

func TestClientAppInviteCreateAnyUserAllowsNonAdmin(t *testing.T) {
	env := newJourneyEnv(t)
	_ = env.mintIdentity(t) // founding admin (someone else)
	caller := env.mintIdentity(t)
	env.server.cfg.InviteMintPolicy = InviteMintAnyUser

	rec := env.post(t, "/v1/client-apps/invites", ClientAppInviteCreateRequest{}, caller, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("any-user mint by non-admin: got %d want 201; body=%s", rec.Code, rec.Body.String())
	}
}

func TestClientAppInviteCreateUnknownPolicyFailsClosed(t *testing.T) {
	// Defense in depth: an unrecognized policy value (only reachable
	// if some non-parseServeConfig path sets it) must fail closed with
	// 500, never fall through to allow minting.
	env := newJourneyEnv(t)
	caller := env.mintIdentity(t)
	env.server.cfg.InviteMintPolicy = InviteMintPolicy("everyone-go-wild")

	rec := env.post(t, "/v1/client-apps/invites", ClientAppInviteCreateRequest{}, caller, "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d want 500; body=%s", rec.Code, rec.Body.String())
	}
	// And nothing was minted.
	listRec := env.get(t, "/v1/client-apps/invites", caller, "")
	var resp ClientAppInviteListResponse
	if err := json.Unmarshal(listRec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(resp.Invites) != 0 {
		t.Fatalf("unknown policy minted %d invites; must fail closed", len(resp.Invites))
	}
}

func TestClientAppInviteListNotGatedByPolicy(t *testing.T) {
	// The list endpoint is read-only audit of the caller's own invites;
	// admin-only gates minting, not listing.
	env := newJourneyEnv(t)
	_ = env.mintIdentity(t) // founding admin
	caller := env.mintIdentity(t)
	env.server.cfg.InviteMintPolicy = InviteMintAdminOnly

	rec := env.get(t, "/v1/client-apps/invites", caller, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("non-admin list under admin-only: got %d want 200; body=%s", rec.Code, rec.Body.String())
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
