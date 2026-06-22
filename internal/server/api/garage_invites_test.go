package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/wheelsdown/spivot-server/internal/server/middleware"
)

func TestGarageInviteCreateAndRedeemFullFlow(t *testing.T) {
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	redeemer := env.mintIdentity(t)
	garageID := createGarageFor(t, env, owner, "Household")

	createRec := env.post(t, "/v1/garages/"+string(garageID)+"/invites",
		GarageInviteCreateRequest{}, owner, "")
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create: got %d body=%s", createRec.Code, createRec.Body.String())
	}
	var createResp GarageInviteResponse
	if err := json.Unmarshal(createRec.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if createResp.Token == "" {
		t.Fatal("create response missing token")
	}

	// Redeem from the other identity.
	redeemRec := env.post(t, "/v1/garage-invites/redeem",
		GarageInviteRedeemRequest{Token: createResp.Token}, redeemer, "")
	if redeemRec.Code != http.StatusCreated {
		t.Fatalf("redeem: got %d body=%s", redeemRec.Code, redeemRec.Body.String())
	}
	var redeemResp GarageInviteRedeemResponse
	if err := json.Unmarshal(redeemRec.Body.Bytes(), &redeemResp); err != nil {
		t.Fatalf("decode redeem: %v", err)
	}

	// Redeemer should now appear as an accepted owner of the garage.
	foundAccepted := false
	for _, o := range redeemResp.Garage.Owners {
		if o.UserID == redeemer.UserID && o.AcceptedTime != nil {
			foundAccepted = true
		}
	}
	if !foundAccepted {
		t.Fatal("redeemer not present as accepted owner in redeem response")
	}

	// Both users should now see the garage in their lists.
	for _, who := range []struct {
		name string
		id   middleware.Identity
	}{
		{"owner", owner},
		{"redeemer", redeemer},
	} {
		listRec := env.get(t, "/v1/garages", who.id, "")
		if listRec.Code != http.StatusOK {
			t.Fatalf("%s list: got %d", who.name, listRec.Code)
		}
		var list GarageListResponse
		if err := json.Unmarshal(listRec.Body.Bytes(), &list); err != nil {
			t.Fatalf("%s decode: %v", who.name, err)
		}
		if len(list.Garages) != 1 {
			t.Fatalf("%s: expected 1 garage in list, got %d", who.name, len(list.Garages))
		}
	}
}

func TestGarageInviteCreateRequiresAcceptedOwner(t *testing.T) {
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	stranger := env.mintIdentity(t)
	garageID := createGarageFor(t, env, owner, "G")

	rec := env.post(t, "/v1/garages/"+string(garageID)+"/invites",
		GarageInviteCreateRequest{}, stranger, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: got %d want 404 (non-owner sees not-found); body=%s", rec.Code, rec.Body.String())
	}
}

func TestGarageInviteRedeemUnknownToken(t *testing.T) {
	env := newJourneyEnv(t)
	caller := env.mintIdentity(t)
	rec := env.post(t, "/v1/garage-invites/redeem",
		GarageInviteRedeemRequest{Token: "garbage-not-a-token"}, caller, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: got %d want 404; body=%s", rec.Code, rec.Body.String())
	}
}

func TestGarageInviteRedeemMissingTokenInBody(t *testing.T) {
	env := newJourneyEnv(t)
	caller := env.mintIdentity(t)
	rec := env.post(t, "/v1/garage-invites/redeem",
		GarageInviteRedeemRequest{Token: ""}, caller, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestGarageInviteRevokeBlocksRedeem(t *testing.T) {
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	redeemer := env.mintIdentity(t)
	garageID := createGarageFor(t, env, owner, "G")

	createRec := env.post(t, "/v1/garages/"+string(garageID)+"/invites",
		GarageInviteCreateRequest{}, owner, "")
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create: got %d", createRec.Code)
	}
	var created GarageInviteResponse
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Owner revokes before anyone redeems.
	revRec := env.post(t,
		"/v1/garages/"+string(garageID)+"/invites/"+created.ID+"/revoke",
		nil, owner, "")
	if revRec.Code != http.StatusNoContent {
		t.Fatalf("revoke: got %d body=%s", revRec.Code, revRec.Body.String())
	}

	// Redeem must now fail with 410 Gone.
	redeemRec := env.post(t, "/v1/garage-invites/redeem",
		GarageInviteRedeemRequest{Token: created.Token}, redeemer, "")
	if redeemRec.Code != http.StatusGone {
		t.Fatalf("redeem after revoke: got %d want 410; body=%s", redeemRec.Code, redeemRec.Body.String())
	}
}

func TestGarageInviteListHidesTokens(t *testing.T) {
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	garageID := createGarageFor(t, env, owner, "G")
	if rec := env.post(t, "/v1/garages/"+string(garageID)+"/invites",
		GarageInviteCreateRequest{}, owner, ""); rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d", rec.Code)
	}
	listRec := env.get(t, "/v1/garages/"+string(garageID)+"/invites", owner, "")
	if listRec.Code != http.StatusOK {
		t.Fatalf("list: got %d", listRec.Code)
	}
	var list GarageInviteListResponse
	if err := json.Unmarshal(listRec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list.Invites) != 1 {
		t.Fatalf("expected 1 invite, got %d", len(list.Invites))
	}
	if list.Invites[0].Token != "" {
		t.Fatalf("list response should NOT include plaintext token; got %q", list.Invites[0].Token)
	}
}

func TestGarageInviteRedeemTwiceBySameUser(t *testing.T) {
	env := newJourneyEnv(t)
	owner := env.mintIdentity(t)
	redeemer := env.mintIdentity(t)
	garageID := createGarageFor(t, env, owner, "G")

	createRec := env.post(t, "/v1/garages/"+string(garageID)+"/invites",
		GarageInviteCreateRequest{MaxRedemptions: 5}, owner, "")
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create: got %d", createRec.Code)
	}
	var created GarageInviteResponse
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if rec := env.post(t, "/v1/garage-invites/redeem",
		GarageInviteRedeemRequest{Token: created.Token}, redeemer, ""); rec.Code != http.StatusCreated {
		t.Fatalf("first redeem: got %d", rec.Code)
	}
	rec := env.post(t, "/v1/garage-invites/redeem",
		GarageInviteRedeemRequest{Token: created.Token}, redeemer, "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("second redeem: got %d want 409; body=%s", rec.Code, rec.Body.String())
	}
}
