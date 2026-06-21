package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/opencaravan/opencaravan-go"

	"github.com/wheelsdown/spivot-server/internal/platform/auth/macaroon"
	"github.com/wheelsdown/spivot-server/internal/platform/storage"
	"github.com/wheelsdown/spivot-server/internal/server/middleware"
)

// journeyEnv bundles a fully-wired test server (real storage,
// real issuer/verifier) with handles for the test to mint
// identities, sessions, and journeys against. Phase 5 tests
// drive end-to-end stack composition, so the fixture stands up
// the whole pipeline rather than mocking parts.
type journeyEnv struct {
	server   *Server
	store    *storage.Store
	issuer   *macaroon.Issuer
	verifier *macaroon.Verifier
}

func newJourneyEnv(t *testing.T) *journeyEnv {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	store, err := storage.Open(ctx, storage.Config{Path: filepath.Join(dir, "spivot.db")})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	})

	rootID := "journey-test-root"
	rootKey := make([]byte, macaroon.RootKeyLen)
	if _, err := rand.Read(rootKey); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	issuer, err := macaroon.NewIssuer(rootID, rootKey)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	verifier, err := macaroon.NewVerifier(func(_ context.Context, id string) ([]byte, error) {
		if id != rootID {
			return nil, macaroon.ErrUnknownRoot
		}
		return rootKey, nil
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	server := NewServer(Config{
		Address:                "127.0.0.1",
		Port:                   8080,
		Store:                  store,
		IdentityStore:          store,
		JourneyStore:           store,
		VehicleStore:           store,
		DriverAttestationStore: store,
		MacaroonIssuer:         issuer,
		MacaroonVerifier:       verifier,
		PolicySnapshot: ServerPolicySnapshot{
			ID:          "policy-1",
			Hash:        "test-policy-hash",
			CreatedTime: time.Now().UTC().Format(time.RFC3339Nano),
			Document:    json.RawMessage(`{"version":"v0"}`),
		},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return &journeyEnv{
		server:   server,
		store:    store,
		issuer:   issuer,
		verifier: verifier,
	}
}

// mintIdentity inserts an accounts row + returns a
// middleware.Identity the tests can attach to a request to
// simulate a successful Phase 3c attach pass. Real production
// requests have AttachIdentity resolving an mTLS cert; tests
// short-circuit that with WithIdentity.
func (e *journeyEnv) mintIdentity(t *testing.T) middleware.Identity {
	t.Helper()
	userUUID, err := opencaravan.NewUUID()
	if err != nil {
		t.Fatalf("NewUUID user: %v", err)
	}
	appUUID, err := opencaravan.NewUUID()
	if err != nil {
		t.Fatalf("NewUUID app: %v", err)
	}
	if _, err := e.store.DB().ExecContext(context.Background(), `
INSERT INTO accounts (id, open_caravan_id, display_name, created_at)
VALUES (?, ?, ?, ?)
`, string(userUUID), string(userUUID), "", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("seed account: %v", err)
	}
	return middleware.Identity{
		UserID:      string(userUUID),
		ClientAppID: string(appUUID),
		Serial:      "deadbeef",
		SubjectCN:   "test-client",
		NotAfter:    time.Now().Add(7 * 24 * time.Hour),
	}
}

// issueSessionMacaroon mints a session macaroon for the supplied
// identity, journey, and action. Encoded as the base64url string
// callers put on Authorization: Macaroon.
func (e *journeyEnv) issueSessionMacaroon(t *testing.T, id middleware.Identity, journeyID opencaravan.UUID, action opencaravan.SessionAction) string {
	t.Helper()
	_, serialized, err := e.issuer.IssueSession(macaroon.SessionParams{
		UserID:      opencaravan.UUID(id.UserID),
		ClientAppID: opencaravan.UUID(id.ClientAppID),
		JourneyID:   journeyID,
		Action:      action,
		Expiration:  time.Now().Add(time.Hour),
		Now:         time.Now(),
	})
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(serialized)
}

func (e *journeyEnv) post(t *testing.T, path string, body any, id middleware.Identity, macaroonHeader string) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if id.UserID != "" {
		req = req.WithContext(middleware.WithIdentity(req.Context(), id))
	}
	if macaroonHeader != "" {
		req.Header.Set("Authorization", "Macaroon "+macaroonHeader)
	}
	rec := httptest.NewRecorder()
	e.server.Handler().ServeHTTP(rec, req)
	return rec
}

func (e *journeyEnv) get(t *testing.T, path string, id middleware.Identity, macaroonHeader string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if id.UserID != "" {
		req = req.WithContext(middleware.WithIdentity(req.Context(), id))
	}
	if macaroonHeader != "" {
		req.Header.Set("Authorization", "Macaroon "+macaroonHeader)
	}
	rec := httptest.NewRecorder()
	e.server.Handler().ServeHTTP(rec, req)
	return rec
}

// mustCreateJourney creates a journey with the supplied title and
// fails the test if the create response is not 201 or the
// response body does not decode. Downstream tests use this to
// surface "create failed" loud rather than silently propagating
// a zero-id JourneyResponse into the GET / telemetry flow.
func (e *journeyEnv) mustCreateJourney(t *testing.T, id middleware.Identity, title string) JourneyResponse {
	t.Helper()
	rec := e.post(t, "/v1/journeys", JourneyCreateRequest{Title: title}, id, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("create journey: status %d, want 201; body = %s", rec.Code, rec.Body.String())
	}
	var created JourneyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("create journey: decode response: %v", err)
	}
	return created
}

func TestJourneyCreateHappyPath(t *testing.T) {
	env := newJourneyEnv(t)
	id := env.mintIdentity(t)

	rec := env.post(t, "/v1/journeys", JourneyCreateRequest{
		Title:       "Pacific Coast Drive",
		Description: "Half-day along Highway 1",
	}, id, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", rec.Code, rec.Body.String())
	}
	var got JourneyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ID == "" {
		t.Fatal("ID is empty")
	}
	if got.Title != "Pacific Coast Drive" {
		t.Fatalf("Title = %q", got.Title)
	}
	if got.HostUserID != id.UserID {
		t.Fatalf("HostUserID = %q, want %q", got.HostUserID, id.UserID)
	}
	if got.State != "planned" {
		t.Fatalf("State = %q", got.State)
	}
	if got.Visibility != "private" {
		t.Fatalf("Visibility = %q", got.Visibility)
	}
}

func TestJourneyCreateRequiresIdentity(t *testing.T) {
	env := newJourneyEnv(t)
	rec := env.post(t, "/v1/journeys", JourneyCreateRequest{Title: "x"}, middleware.Identity{}, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestJourneyCreateRejectsBlankTitle(t *testing.T) {
	env := newJourneyEnv(t)
	id := env.mintIdentity(t)
	rec := env.post(t, "/v1/journeys", JourneyCreateRequest{Title: "   "}, id, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestJourneyCreateRejectsMalformedJSON(t *testing.T) {
	env := newJourneyEnv(t)
	id := env.mintIdentity(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/journeys", strings.NewReader("not-json"))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.WithIdentity(req.Context(), id))
	rec := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestJourneyCreateReachableWithoutMacaroonVerifier(t *testing.T) {
	// POST /v1/journeys is identity-only; deployments that
	// intentionally omit the session stack (no MacaroonVerifier
	// wired) must still be able to create journeys. Earlier the
	// route was conditionally registered behind MacaroonVerifier
	// != nil, which made the endpoint 404 in identity-only
	// deployments.
	env := newJourneyEnv(t)
	env.server.cfg.MacaroonVerifier = nil
	id := env.mintIdentity(t)
	rec := env.post(t, "/v1/journeys", JourneyCreateRequest{Title: "identity-only"}, id, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (route must register without verifier); body = %s", rec.Code, rec.Body.String())
	}
}

func TestJourneyGetHappyPath(t *testing.T) {
	env := newJourneyEnv(t)
	id := env.mintIdentity(t)

	// Create a journey first.
	created := env.mustCreateJourney(t, id, "Test")

	// Mint a journey.read session macaroon scoped to that journey.
	mac := env.issueSessionMacaroon(t, id, opencaravan.UUID(created.ID), opencaravan.SessionActionJourneyRead)

	rec := env.get(t, "/v1/journeys/"+created.ID, id, mac)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	var got JourneyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ID != created.ID {
		t.Fatalf("ID = %q, want %q", got.ID, created.ID)
	}
}

func TestJourneyGetRequiresSession(t *testing.T) {
	env := newJourneyEnv(t)
	rec := env.get(t, "/v1/journeys/some-id", middleware.Identity{}, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestJourneyGetRejectsWrongJourneyMacaroon(t *testing.T) {
	// The macaroon's journey= caveat scopes to journey A, but the
	// request targets journey B. CheckConstraints must reject —
	// this is the per-request constraint check that closes the
	// loop on session middleware.
	env := newJourneyEnv(t)
	id := env.mintIdentity(t)
	created := env.mustCreateJourney(t, id, "A")

	// Mint macaroon scoped to a DIFFERENT journey id.
	otherJourney, _ := opencaravan.NewUUID()
	mac := env.issueSessionMacaroon(t, id, otherJourney, opencaravan.SessionActionJourneyRead)

	rec := env.get(t, "/v1/journeys/"+created.ID, id, mac)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (journey caveat mismatch)", rec.Code)
	}
}

func TestJourneyGetRejectsWrongActionMacaroon(t *testing.T) {
	// Macaroon authorizes telemetry.write but the route requires
	// journey.read.
	env := newJourneyEnv(t)
	id := env.mintIdentity(t)
	created := env.mustCreateJourney(t, id, "A")

	mac := env.issueSessionMacaroon(t, id, opencaravan.UUID(created.ID), opencaravan.SessionActionTelemetryWrite)

	rec := env.get(t, "/v1/journeys/"+created.ID, id, mac)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (action caveat mismatch)", rec.Code)
	}
}

func TestJourneyGetNotFound(t *testing.T) {
	env := newJourneyEnv(t)
	id := env.mintIdentity(t)
	bogus, _ := opencaravan.NewUUID()
	mac := env.issueSessionMacaroon(t, id, bogus, opencaravan.SessionActionJourneyRead)
	rec := env.get(t, "/v1/journeys/"+string(bogus), id, mac)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestTelemetryHappyPath(t *testing.T) {
	env := newJourneyEnv(t)
	id := env.mintIdentity(t)
	created := env.mustCreateJourney(t, id, "Telemetry test")

	mac := env.issueSessionMacaroon(t, id, opencaravan.UUID(created.ID), opencaravan.SessionActionTelemetryWrite)

	segmentUUID, _ := opencaravan.NewUUID()
	segmentVehicleUUID, _ := opencaravan.NewUUID()
	participantUUID, _ := opencaravan.NewUUID()
	body := TelemetryBatchRequest{
		ClientBatchID: "batch-1",
		Samples: []opencaravan.PositionSample{{
			JourneyID:            opencaravan.UUID(created.ID),
			SegmentID:            segmentUUID,
			SegmentVehicleID:     segmentVehicleUUID,
			JourneyParticipantID: participantUUID,
			ClientAppID:          opencaravan.UUID(id.ClientAppID),
			ClientSequence:       1,
			CaptureTime:          time.Now().UTC(),
			LatitudeE7:           377749000,
			LongitudeE7:          -1224194000,
		}},
	}
	rec := env.post(t, "/v1/journeys/"+created.ID+"/telemetry", body, id, mac)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body = %s", rec.Code, rec.Body.String())
	}
	var got TelemetryBatchResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.BatchID == "" {
		t.Fatal("BatchID is empty")
	}
	if got.ReceivedCount != 1 {
		t.Fatalf("ReceivedCount = %d, want 1", got.ReceivedCount)
	}
}

func TestTelemetryRejectsCallerNotInJourney(t *testing.T) {
	env := newJourneyEnv(t)
	// Host creates the journey.
	host := env.mintIdentity(t)
	created := env.mustCreateJourney(t, host, "Membership test")

	// A DIFFERENT user (also enrolled) presents a macaroon claiming
	// the same journey + telemetry.write. The macaroon's caveats
	// will pass (server is permissive at issuance time per Phase 4b),
	// but the membership lookup in the telemetry handler must
	// reject 403.
	intruder := env.mintIdentity(t)
	mac := env.issueSessionMacaroon(t, intruder, opencaravan.UUID(created.ID), opencaravan.SessionActionTelemetryWrite)

	body := TelemetryBatchRequest{ClientBatchID: "batch-x", Samples: nil}
	rec := env.post(t, "/v1/journeys/"+created.ID+"/telemetry", body, intruder, mac)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (not_a_participant); body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not_a_participant") {
		t.Fatalf("body missing not_a_participant: %s", rec.Body.String())
	}
}

func TestTelemetryRejectsMismatchedSampleJourney(t *testing.T) {
	env := newJourneyEnv(t)
	id := env.mintIdentity(t)
	created := env.mustCreateJourney(t, id, "Sample mismatch")
	mac := env.issueSessionMacaroon(t, id, opencaravan.UUID(created.ID), opencaravan.SessionActionTelemetryWrite)

	// A sample whose journey_id doesn't match the path — the
	// caller could be trying to smuggle data into the wrong
	// journey via a valid telemetry macaroon for another.
	wrongJourney, _ := opencaravan.NewUUID()
	body := TelemetryBatchRequest{
		ClientBatchID: "batch-x",
		Samples: []opencaravan.PositionSample{{
			JourneyID:            wrongJourney,
			SegmentID:            wrongJourney,
			SegmentVehicleID:     wrongJourney,
			JourneyParticipantID: wrongJourney,
			ClientAppID:          opencaravan.UUID(id.ClientAppID),
			ClientSequence:       1,
			CaptureTime:          time.Now().UTC(),
			LatitudeE7:           0,
			LongitudeE7:          0,
		}},
	}
	rec := env.post(t, "/v1/journeys/"+created.ID+"/telemetry", body, id, mac)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (sample journey mismatch)", rec.Code)
	}
}

func TestTelemetryRequiresTelemetryAction(t *testing.T) {
	// Caller has a journey.read macaroon but tries to post
	// telemetry. RequireSession must reject (action caveat
	// mismatch).
	env := newJourneyEnv(t)
	id := env.mintIdentity(t)
	created := env.mustCreateJourney(t, id, "Action test")
	mac := env.issueSessionMacaroon(t, id, opencaravan.UUID(created.ID), opencaravan.SessionActionJourneyRead)

	body := TelemetryBatchRequest{ClientBatchID: "batch-x"}
	rec := env.post(t, "/v1/journeys/"+created.ID+"/telemetry", body, id, mac)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (action caveat mismatch)", rec.Code)
	}
}

func TestTelemetryRejectsMissingClientBatchID(t *testing.T) {
	env := newJourneyEnv(t)
	id := env.mintIdentity(t)
	created := env.mustCreateJourney(t, id, "Batch id test")
	mac := env.issueSessionMacaroon(t, id, opencaravan.UUID(created.ID), opencaravan.SessionActionTelemetryWrite)

	body := TelemetryBatchRequest{}
	rec := env.post(t, "/v1/journeys/"+created.ID+"/telemetry", body, id, mac)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (missing client_batch_id)", rec.Code)
	}
}

func TestTelemetryUnknownJourneyReturns404NotForbidden(t *testing.T) {
	// A macaroon scoped to a journey id that doesn't exist on this
	// server must surface as 404 journey_not_found, not 403
	// not_a_participant. Without the explicit JourneyByID gate at
	// the top of the handler, the participant lookup would miss
	// (no journey, no participants) and 403 would conflate
	// "journey doesn't exist" with "you're not in it" — making the
	// caller's debugging much harder.
	env := newJourneyEnv(t)
	id := env.mintIdentity(t)
	bogus, _ := opencaravan.NewUUID()
	mac := env.issueSessionMacaroon(t, id, bogus, opencaravan.SessionActionTelemetryWrite)
	rec := env.post(t, "/v1/journeys/"+string(bogus)+"/telemetry",
		TelemetryBatchRequest{ClientBatchID: "x"}, id, mac)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "journey_not_found") {
		t.Fatalf("body missing journey_not_found: %s", rec.Body.String())
	}
}

func TestTelemetryDeletedJourneyReturns404(t *testing.T) {
	// Companion to TestTelemetryUnknownJourneyReturns404NotForbidden:
	// a journey that exists but has deleted_at set must look
	// indistinguishable from "doesn't exist" — JourneyByID filters
	// deleted_at IS NULL — so telemetry against it gets 404, not
	// some other status that would leak the existence of deleted
	// rows.
	env := newJourneyEnv(t)
	id := env.mintIdentity(t)
	created := env.mustCreateJourney(t, id, "Soft-deleted journey")
	// Soft-delete the journey directly; v0 doesn't expose a
	// delete handler yet.
	if _, err := env.store.DB().ExecContext(context.Background(),
		`UPDATE journeys SET deleted_at = ? WHERE id = ?`,
		time.Now().UTC().Format(time.RFC3339Nano), created.ID); err != nil {
		t.Fatalf("soft-delete: %v", err)
	}
	mac := env.issueSessionMacaroon(t, id, opencaravan.UUID(created.ID), opencaravan.SessionActionTelemetryWrite)
	rec := env.post(t, "/v1/journeys/"+created.ID+"/telemetry",
		TelemetryBatchRequest{ClientBatchID: "x"}, id, mac)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for soft-deleted journey; body = %s", rec.Code, rec.Body.String())
	}
}

func TestEndToEndStackCompose(t *testing.T) {
	// The headline integration proof: a single test that walks
	// the complete auth stack end-to-end.
	//
	// 1. enrolled identity (simulated via WithIdentity)
	// 2. POST /v1/journeys with identity → 201
	// 3. issue a journey.read macaroon
	// 4. GET /v1/journeys/{id} with macaroon → 200
	// 5. issue a telemetry.write macaroon
	// 6. POST /v1/journeys/{id}/telemetry with macaroon → 202
	//
	// If any layer breaks, this test fails at the corresponding
	// step.
	env := newJourneyEnv(t)
	id := env.mintIdentity(t)

	// Step 2: POST /v1/journeys (mustCreateJourney asserts 201 + decode)
	created := env.mustCreateJourney(t, id, "End-to-end proof")

	readMac := env.issueSessionMacaroon(t, id, opencaravan.UUID(created.ID), opencaravan.SessionActionJourneyRead)
	getRec := env.get(t, "/v1/journeys/"+created.ID, id, readMac)
	if getRec.Code != http.StatusOK {
		t.Fatalf("step 4 (GET /v1/journeys/{id}): status %d body %s", getRec.Code, getRec.Body.String())
	}

	writeMac := env.issueSessionMacaroon(t, id, opencaravan.UUID(created.ID), opencaravan.SessionActionTelemetryWrite)
	segUUID, _ := opencaravan.NewUUID()
	telRec := env.post(t, "/v1/journeys/"+created.ID+"/telemetry", TelemetryBatchRequest{
		ClientBatchID: "e2e-batch",
		Samples: []opencaravan.PositionSample{{
			JourneyID:            opencaravan.UUID(created.ID),
			SegmentID:            segUUID,
			SegmentVehicleID:     segUUID,
			JourneyParticipantID: segUUID,
			ClientAppID:          opencaravan.UUID(id.ClientAppID),
			ClientSequence:       1,
			CaptureTime:          time.Now().UTC(),
			LatitudeE7:           377749000,
			LongitudeE7:          -1224194000,
		}},
	}, id, writeMac)
	if telRec.Code != http.StatusAccepted {
		t.Fatalf("step 6 (POST telemetry): status %d body %s", telRec.Code, telRec.Body.String())
	}
}
