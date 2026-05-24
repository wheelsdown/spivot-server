package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/opencaravan/opencaravan-go"
	macaroonv2 "gopkg.in/macaroon.v2"

	"github.com/wheelsdown/spivot-server/internal/platform/auth/macaroon"
	"github.com/wheelsdown/spivot-server/internal/platform/storage"
	"github.com/wheelsdown/spivot-server/internal/server/middleware"
)

// sessionsEnv bundles the dependencies a sessions handler test
// drives. A typical test acquires one via newSessionsEnv, builds
// a SessionRequest (helpers below), and calls env.do which
// attaches a synthetic identity to the request before handing it
// to the server.
type sessionsEnv struct {
	server  *Server
	store   *storage.Store
	issuer  *macaroon.Issuer
	rootKey []byte
	rootID  string
}

func newSessionsEnv(t *testing.T) *sessionsEnv {
	t.Helper()
	return newSessionsEnvWith(t, true)
}

func newSessionsEnvWith(t *testing.T, withIssuer bool) *sessionsEnv {
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

	rootID := "sessions-test-root"
	rootKey := make([]byte, macaroon.RootKeyLen)
	if _, err := rand.Read(rootKey); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	cfg := Config{
		Address:       "127.0.0.1",
		Port:          8080,
		Store:         store,
		IdentityStore: store,
	}
	var issuer *macaroon.Issuer
	if withIssuer {
		issuer, err = macaroon.NewIssuer(rootID, rootKey)
		if err != nil {
			t.Fatalf("NewIssuer: %v", err)
		}
		cfg.MacaroonIssuer = issuer
	}

	server := NewServer(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return &sessionsEnv{
		server:  server,
		store:   store,
		issuer:  issuer,
		rootKey: rootKey,
		rootID:  rootID,
	}
}

// do drives a SessionRequest through the handler with id attached
// to the context. Pass a zero-value id (UserID empty) to simulate
// the unauthenticated path through RequireIdentity.
func (e *sessionsEnv) do(t *testing.T, req opencaravan.SessionRequest, id middleware.Identity) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/sessions", bytes.NewReader(raw))
	httpReq.Header.Set("Content-Type", "application/json")
	if id.UserID != "" {
		httpReq = httpReq.WithContext(middleware.WithIdentity(httpReq.Context(), id))
	}
	rec := httptest.NewRecorder()
	e.server.Handler().ServeHTTP(rec, httpReq)
	return rec
}

func mintUUID(t *testing.T) opencaravan.UUID {
	t.Helper()
	u, err := opencaravan.NewUUID()
	if err != nil {
		t.Fatalf("NewUUID: %v", err)
	}
	return u
}

func testIdentity(t *testing.T) middleware.Identity {
	t.Helper()
	return middleware.Identity{
		UserID:      string(mintUUID(t)),
		ClientAppID: string(mintUUID(t)),
		Serial:      "deadbeef",
		SubjectCN:   "test-client",
		NotAfter:    time.Now().Add(7 * 24 * time.Hour),
	}
}

func TestSessionCreateHappyPath(t *testing.T) {
	env := newSessionsEnv(t)
	id := testIdentity(t)
	journey := mintUUID(t)

	req := opencaravan.NewSessionRequest([]opencaravan.SessionAction{opencaravan.SessionActionJourneyRead}, 300)
	req.JourneyID = &journey
	resp := env.do(t, req, id)

	if resp.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", resp.Code, resp.Body.String())
	}

	var got opencaravan.SessionResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("response.Validate: %v", err)
	}

	// Decode the macaroon and confirm the canonical caveat set is
	// what came back.
	bin, err := base64.RawURLEncoding.DecodeString(got.Macaroon)
	if err != nil {
		t.Fatalf("base64 decode macaroon: %v", err)
	}
	var m macaroonv2.Macaroon
	if err := m.UnmarshalBinary(bin); err != nil {
		t.Fatalf("unmarshal macaroon: %v", err)
	}
	if got, want := string(m.Id()), env.rootID; got != want {
		t.Fatalf("macaroon root id = %q, want %q", got, want)
	}
	if got, want := m.Location(), macaroon.Location; got != want {
		t.Fatalf("macaroon location = %q, want %q", got, want)
	}
	wantCaveats := []string{
		opencaravan.CaveatUser(opencaravan.UUID(id.UserID)),
		opencaravan.CaveatClientApp(opencaravan.UUID(id.ClientAppID)),
		opencaravan.CaveatJourney(journey),
		opencaravan.CaveatAction(opencaravan.SessionActionJourneyRead),
		// CaveatTimeBefore is checked separately by parsing the
		// remaining caveat so the test isn't fragile to clock
		// truncation; just assert there are exactly 5 caveats and
		// the first 4 match.
	}
	caveats := m.Caveats()
	if len(caveats) != 5 {
		t.Fatalf("caveat count = %d, want 5", len(caveats))
	}
	for i := range wantCaveats {
		if got, want := string(caveats[i].Id), wantCaveats[i]; got != want {
			t.Fatalf("caveat[%d] = %q, want %q", i, got, want)
		}
	}
	if !strings.HasPrefix(string(caveats[4].Id), "time<") {
		t.Fatalf("caveat[4] = %q, want time<... predicate", string(caveats[4].Id))
	}
	if got.ExpirationTime.IsZero() {
		t.Fatal("ExpirationTime is zero")
	}
}

func TestSessionCreateRequiresIdentity(t *testing.T) {
	env := newSessionsEnv(t)
	journey := mintUUID(t)
	req := opencaravan.NewSessionRequest([]opencaravan.SessionAction{opencaravan.SessionActionJourneyRead}, 300)
	req.JourneyID = &journey

	resp := env.do(t, req, middleware.Identity{}) // no UserID → no attach
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body = %s", resp.Code, resp.Body.String())
	}
	if got := resp.Header().Get("Content-Type"); got != "application/problem+json" {
		t.Fatalf("Content-Type = %q, want application/problem+json", got)
	}
}

func TestSessionCreateRejectsMultiActionRequest(t *testing.T) {
	env := newSessionsEnv(t)
	journey := mintUUID(t)
	req := opencaravan.NewSessionRequest([]opencaravan.SessionAction{
		opencaravan.SessionActionJourneyRead,
		opencaravan.SessionActionTelemetryWrite,
	}, 300)
	req.JourneyID = &journey

	resp := env.do(t, req, testIdentity(t))
	if resp.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body = %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "single_action_required") {
		t.Fatalf("body missing single_action_required code: %s", resp.Body.String())
	}
}

func TestSessionCreateRejectsJourneyActionWithoutJourney(t *testing.T) {
	env := newSessionsEnv(t)
	req := opencaravan.NewSessionRequest([]opencaravan.SessionAction{opencaravan.SessionActionJourneyRead}, 300)
	// JourneyID omitted

	resp := env.do(t, req, testIdentity(t))
	if resp.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body = %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "requires a journey id") {
		t.Fatalf("body missing journey-required message: %s", resp.Body.String())
	}
}

func TestSessionCreateAcceptsNonJourneyAction(t *testing.T) {
	env := newSessionsEnv(t)
	req := opencaravan.NewSessionRequest([]opencaravan.SessionAction{opencaravan.SessionActionInviteCreate}, 300)

	resp := env.do(t, req, testIdentity(t))
	if resp.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", resp.Code, resp.Body.String())
	}
}

func TestSessionCreateRejectsUnknownAction(t *testing.T) {
	env := newSessionsEnv(t)
	req := opencaravan.NewSessionRequest([]opencaravan.SessionAction{opencaravan.SessionAction("ransom.demand")}, 300)

	resp := env.do(t, req, testIdentity(t))
	// req.Validate (the protocol layer) catches unknown action
	// before the handler reaches macaroon issuance.
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", resp.Code, resp.Body.String())
	}
}

func TestSessionCreateRejectsMalformedJSON(t *testing.T) {
	env := newSessionsEnv(t)
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/sessions", strings.NewReader("not-json"))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq = httpReq.WithContext(middleware.WithIdentity(httpReq.Context(), testIdentity(t)))
	rec := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rec, httpReq)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}
}

func TestSessionCreateReturns503WhenIssuerMissing(t *testing.T) {
	env := newSessionsEnvWith(t, false)
	journey := mintUUID(t)
	req := opencaravan.NewSessionRequest([]opencaravan.SessionAction{opencaravan.SessionActionJourneyRead}, 300)
	req.JourneyID = &journey

	resp := env.do(t, req, testIdentity(t))
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body = %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "session_unavailable") {
		t.Fatalf("body missing session_unavailable code: %s", resp.Body.String())
	}
}

func TestSessionCreateClampsLifetimeToMax(t *testing.T) {
	env := newSessionsEnv(t)
	journey := mintUUID(t)
	// 10 hours; far above maxSessionLifetime (1 hour).
	req := opencaravan.NewSessionRequest([]opencaravan.SessionAction{opencaravan.SessionActionJourneyRead}, 10*3600)
	req.JourneyID = &journey

	before := time.Now()
	resp := env.do(t, req, testIdentity(t))
	if resp.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", resp.Code, resp.Body.String())
	}
	var got opencaravan.SessionResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	// Expiration should be within (now + maxSessionLifetime) ± a
	// generous test slack to absorb wall-clock drift.
	want := before.Add(maxSessionLifetime)
	if delta := got.ExpirationTime.Sub(want); delta < -time.Second || delta > 10*time.Second {
		t.Fatalf("expiration = %s, expected near %s (delta %s)", got.ExpirationTime, want, delta)
	}
}

func TestSessionCreateDefaultsLifetimeWhenZero(t *testing.T) {
	env := newSessionsEnv(t)
	journey := mintUUID(t)
	req := opencaravan.NewSessionRequest([]opencaravan.SessionAction{opencaravan.SessionActionJourneyRead}, 0)
	req.JourneyID = &journey

	before := time.Now()
	resp := env.do(t, req, testIdentity(t))
	if resp.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", resp.Code, resp.Body.String())
	}
	var got opencaravan.SessionResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	want := before.Add(defaultSessionLifetime)
	if delta := got.ExpirationTime.Sub(want); delta < -time.Second || delta > 10*time.Second {
		t.Fatalf("expiration = %s, expected near %s (delta %s)", got.ExpirationTime, want, delta)
	}
}

func TestSessionCreateMacaroonVerifiesEndToEnd(t *testing.T) {
	env := newSessionsEnv(t)
	id := testIdentity(t)
	journey := mintUUID(t)
	req := opencaravan.NewSessionRequest([]opencaravan.SessionAction{opencaravan.SessionActionJourneyRead}, 300)
	req.JourneyID = &journey

	resp := env.do(t, req, id)
	if resp.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", resp.Code, resp.Body.String())
	}
	var got opencaravan.SessionResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	bin, err := base64.RawURLEncoding.DecodeString(got.Macaroon)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}

	verifier, err := macaroon.NewVerifier(func(_ context.Context, id string) ([]byte, error) {
		if id != env.rootID {
			return nil, macaroon.ErrUnknownRoot
		}
		return env.rootKey, nil
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	verified, err := verifier.Verify(context.Background(), bin, macaroon.Constraints{
		JourneyID:   journey,
		Action:      opencaravan.SessionActionJourneyRead,
		UserID:      opencaravan.UUID(id.UserID),
		ClientAppID: opencaravan.UUID(id.ClientAppID),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.RootID != env.rootID {
		t.Fatalf("verified RootID = %q, want %q", verified.RootID, env.rootID)
	}
}

func TestNormalizeSessionLifetime(t *testing.T) {
	tests := []struct {
		name string
		in   int
		want time.Duration
	}{
		{"zero defaults", 0, defaultSessionLifetime},
		{"negative defaults", -1, defaultSessionLifetime},
		{"in-range pass-through", 600, 10 * time.Minute},
		{"clamped to max", int(maxSessionLifetime/time.Second) + 9999, maxSessionLifetime},
		{"exactly max", int(maxSessionLifetime / time.Second), maxSessionLifetime},
		// MaxInt would overflow time.Duration when multiplied by
		// time.Second (1e9 ns); the seconds-first clamp must
		// short-circuit before the multiplication happens.
		{"max int does not overflow", math.MaxInt, maxSessionLifetime},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeSessionLifetime(tc.in); got != tc.want {
				t.Fatalf("normalizeSessionLifetime(%d) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}
