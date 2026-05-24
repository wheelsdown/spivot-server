package middleware

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/opencaravan/opencaravan-go"
	macaroonv2 "gopkg.in/macaroon.v2"

	"github.com/wheelsdown/spivot-server/internal/platform/auth/macaroon"
)

const (
	testRootID  = "session-test-root"
	testUser    = opencaravan.UUID("11111111-1111-4111-8111-111111111111")
	testApp     = opencaravan.UUID("22222222-2222-4222-8222-222222222222")
	testJourney = opencaravan.UUID("33333333-3333-4333-8333-333333333333")
)

// sessionFixture bundles an issuer/verifier pair with a fresh
// random root key so every test gets an isolated signing key.
type sessionFixture struct {
	issuer   *macaroon.Issuer
	verifier *macaroon.Verifier
	rootKey  []byte
}

func newSessionFixture(t *testing.T) *sessionFixture {
	t.Helper()
	key := make([]byte, macaroon.RootKeyLen)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	issuer, err := macaroon.NewIssuer(testRootID, key)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	verifier, err := macaroon.NewVerifier(func(_ context.Context, id string) ([]byte, error) {
		if id != testRootID {
			return nil, macaroon.ErrUnknownRoot
		}
		return key, nil
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return &sessionFixture{issuer: issuer, verifier: verifier, rootKey: key}
}

// issueAndEncode mints a session macaroon for the supplied params
// and returns its unpadded-base64url encoding.
func (f *sessionFixture) issueAndEncode(t *testing.T, params macaroon.SessionParams) string {
	t.Helper()
	_, serialized, err := f.issuer.IssueSession(params)
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(serialized)
}

func standardParams(now time.Time) macaroon.SessionParams {
	return macaroon.SessionParams{
		UserID:      testUser,
		ClientAppID: testApp,
		JourneyID:   testJourney,
		Action:      opencaravan.SessionActionJourneyRead,
		Expiration:  now.Add(time.Hour),
		Now:         now,
	}
}

func TestAttachSessionAttachesVerifiedSession(t *testing.T) {
	fix := newSessionFixture(t)
	encoded := fix.issueAndEncode(t, standardParams(time.Now()))

	var captured Session
	handler := AttachSession(fix.verifier, discardLogger())(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		s, ok := SessionFrom(r.Context())
		if !ok {
			t.Error("SessionFrom returned ok=false")
			return
		}
		captured = s
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/journeys/x", nil)
	req.Header.Set("Authorization", "Macaroon "+encoded)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if captured.RootID != testRootID {
		t.Fatalf("RootID = %q, want %q", captured.RootID, testRootID)
	}
	if captured.UserID != testUser {
		t.Fatalf("UserID = %q, want %q", captured.UserID, testUser)
	}
	if captured.ClientAppID != testApp {
		t.Fatalf("ClientAppID = %q", captured.ClientAppID)
	}
	if captured.JourneyID != testJourney {
		t.Fatalf("JourneyID = %q", captured.JourneyID)
	}
	if captured.Action != opencaravan.SessionActionJourneyRead {
		t.Fatalf("Action = %q", captured.Action)
	}
	if captured.Expiration.IsZero() {
		t.Fatal("Expiration is zero")
	}
	// The raw caveats must be exposed for RequireSession to drive
	// CheckConstraints against the full list.
	if len(captured.Verified.Caveats) == 0 {
		t.Fatal("Verified.Caveats is empty")
	}
}

func TestAttachSessionSilentOnNoHeader(t *testing.T) {
	fix := newSessionFixture(t)
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	called := false
	handler := AttachSession(fix.verifier, logger)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		called = true
		if _, ok := SessionFrom(r.Context()); ok {
			t.Error("SessionFrom ok=true with no header")
		}
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if !called {
		t.Fatal("downstream handler not invoked")
	}
	if buf.Len() != 0 {
		t.Fatalf("expected silent pass-through with no header, got log: %s", buf.String())
	}
}

func TestAttachSessionWarnsOnMalformedHeader(t *testing.T) {
	fix := newSessionFixture(t)
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	handler := AttachSession(fix.verifier, logger)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if _, ok := SessionFrom(r.Context()); ok {
			t.Error("SessionFrom ok=true with malformed header")
		}
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Macaroon !!!not-base64!!!")
	handler.ServeHTTP(httptest.NewRecorder(), req)
	if !strings.Contains(buf.String(), "rejected Authorization header") {
		t.Fatalf("expected WARN log for malformed header, got: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "level=WARN") {
		t.Fatalf("expected WARN level, got: %s", buf.String())
	}
}

func TestAttachSessionPassesThroughWrongScheme(t *testing.T) {
	fix := newSessionFixture(t)
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	handler := AttachSession(fix.verifier, logger)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if _, ok := SessionFrom(r.Context()); ok {
			t.Error("SessionFrom ok=true with Bearer header")
		}
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	handler.ServeHTTP(httptest.NewRecorder(), req)
	if !strings.Contains(buf.String(), "not Macaroon") {
		t.Fatalf("expected log mentioning non-Macaroon scheme, got: %s", buf.String())
	}
}

func TestAttachSessionAcceptsCaseInsensitiveScheme(t *testing.T) {
	fix := newSessionFixture(t)
	encoded := fix.issueAndEncode(t, standardParams(time.Now()))

	called := false
	handler := AttachSession(fix.verifier, discardLogger())(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		called = true
		if _, ok := SessionFrom(r.Context()); !ok {
			t.Error("SessionFrom ok=false with lowercase scheme")
		}
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "macaroon "+encoded)
	handler.ServeHTTP(httptest.NewRecorder(), req)
	if !called {
		t.Fatal("handler not invoked")
	}
}

func TestAttachSessionWarnsOnBadSignature(t *testing.T) {
	fix := newSessionFixture(t)
	// Issue with a different key the verifier won't know.
	otherKey := make([]byte, macaroon.RootKeyLen)
	if _, err := rand.Read(otherKey); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	otherIssuer, err := macaroon.NewIssuer(testRootID, otherKey)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	_, serialized, err := otherIssuer.IssueSession(standardParams(time.Now()))
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(serialized)

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	handler := AttachSession(fix.verifier, logger)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if _, ok := SessionFrom(r.Context()); ok {
			t.Error("SessionFrom ok=true with bad signature")
		}
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Macaroon "+encoded)
	handler.ServeHTTP(httptest.NewRecorder(), req)
	if !strings.Contains(buf.String(), "rejected presented macaroon") {
		t.Fatalf("expected WARN log for bad sig, got: %s", buf.String())
	}
	if strings.Contains(buf.String(), "level=ERROR") {
		t.Fatalf("bad sig should be WARN, not ERROR; log: %s", buf.String())
	}
}

func TestAttachSessionLogsErrorOnTransportFailure(t *testing.T) {
	// Resolver returns a transport error (not ErrUnknownRoot) — the
	// kind of thing a database outage would produce. AttachSession
	// must log this at ERROR, not WARN, because it's a
	// server-side failure.
	verifier, err := macaroon.NewVerifier(func(_ context.Context, _ string) ([]byte, error) {
		return nil, errors.New("simulated database outage")
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	// Need a syntactically-valid macaroon so the resolver gets called.
	key := make([]byte, macaroon.RootKeyLen)
	rand.Read(key)
	issuer, err := macaroon.NewIssuer(testRootID, key)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	_, serialized, err := issuer.IssueSession(standardParams(time.Now()))
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(serialized)

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	handler := AttachSession(verifier, logger)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Macaroon "+encoded)
	handler.ServeHTTP(httptest.NewRecorder(), req)
	if !strings.Contains(buf.String(), "resolver transport error") {
		t.Fatalf("expected transport error log, got: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "level=ERROR") {
		t.Fatalf("transport failure must be ERROR not WARN; log: %s", buf.String())
	}
}

func TestRequireSessionRejectsWithoutSession(t *testing.T) {
	fix := newSessionFixture(t)
	guard := RequireSession(fix.verifier, discardLogger(), SessionAction(opencaravan.SessionActionJourneyRead))(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("guarded handler ran without session")
	}))
	rec := httptest.NewRecorder()
	guard.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "no_session") {
		t.Fatalf("body missing no_session: %s", rec.Body.String())
	}
}

func TestRequireSessionAcceptsValidMacaroon(t *testing.T) {
	fix := newSessionFixture(t)
	// Journey-less macaroon for a non-journey action (invite.create);
	// the route only constrains on action.
	now := time.Now()
	encoded := fix.issueAndEncode(t, macaroon.SessionParams{
		UserID:      testUser,
		ClientAppID: testApp,
		Action:      opencaravan.SessionActionInviteCreate,
		Expiration:  now.Add(time.Hour),
		Now:         now,
	})

	called := false
	chain := AttachSession(fix.verifier, discardLogger())(
		RequireSession(fix.verifier, discardLogger(),
			SessionAction(opencaravan.SessionActionInviteCreate),
		)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			called = true
		})),
	)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Macaroon "+encoded)
	// Overlay identity so CheckConstraints' user= / client_app=
	// caveat checks pass.
	req = req.WithContext(WithIdentity(req.Context(), Identity{
		UserID:      string(testUser),
		ClientAppID: string(testApp),
	}))
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)
	if !called {
		t.Fatalf("handler not invoked; status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequireSessionAcceptsJourneyScopedMacaroon(t *testing.T) {
	// Companion happy-path test using a journey-scoped macaroon
	// against a SessionActionJourneyFromPath constraint.
	fix := newSessionFixture(t)
	encoded := fix.issueAndEncode(t, standardParams(time.Now()))

	mux := http.NewServeMux()
	called := false
	mux.Handle("GET /v1/journeys/{id}",
		AttachSession(fix.verifier, discardLogger())(
			RequireSession(fix.verifier, discardLogger(),
				SessionActionJourneyFromPath(opencaravan.SessionActionJourneyRead, "id"),
			)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
				called = true
			})),
		),
	)
	req := httptest.NewRequest(http.MethodGet, "/v1/journeys/"+string(testJourney), nil)
	req.Header.Set("Authorization", "Macaroon "+encoded)
	req = req.WithContext(WithIdentity(req.Context(), Identity{
		UserID:      string(testUser),
		ClientAppID: string(testApp),
	}))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if !called {
		t.Fatalf("handler not invoked despite valid journey-scoped session: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequireSessionRejectsExpiredMacaroon(t *testing.T) {
	fix := newSessionFixture(t)
	now := time.Now()
	encoded := fix.issueAndEncode(t, macaroon.SessionParams{
		UserID:      testUser,
		ClientAppID: testApp,
		JourneyID:   testJourney,
		Action:      opencaravan.SessionActionJourneyRead,
		Expiration:  now.Add(time.Minute),
		Now:         now,
	})

	// Roll the verifier's clock forward past the expiration.
	expiredVerifier := fix.verifier.WithClock(func() time.Time { return now.Add(time.Hour) })

	chain := AttachSession(expiredVerifier, discardLogger())(
		RequireSession(expiredVerifier, discardLogger(),
			SessionAction(opencaravan.SessionActionJourneyRead),
		)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			t.Fatal("handler ran with expired macaroon")
		})),
	)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Macaroon "+encoded)
	req = req.WithContext(WithIdentity(req.Context(), Identity{
		UserID:      string(testUser),
		ClientAppID: string(testApp),
	}))
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestRequireSessionRejectsWrongAction(t *testing.T) {
	fix := newSessionFixture(t)
	encoded := fix.issueAndEncode(t, standardParams(time.Now()))

	chain := AttachSession(fix.verifier, discardLogger())(
		RequireSession(fix.verifier, discardLogger(),
			SessionAction(opencaravan.SessionActionTelemetryWrite), // mismatch
		)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			t.Fatal("handler ran with wrong action")
		})),
	)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Macaroon "+encoded)
	req = req.WithContext(WithIdentity(req.Context(), Identity{
		UserID:      string(testUser),
		ClientAppID: string(testApp),
	}))
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "session_constraint_failed") {
		t.Fatalf("body missing session_constraint_failed: %s", rec.Body.String())
	}
}

func TestRequireSessionRejectsAppendedJourneyCaveatAttack(t *testing.T) {
	// CRITICAL: macaroons attenuate by appending caveats without
	// needing the root key. An attacker holding a macaroon scoped
	// to journey A could append journey=evil and try to use it
	// against the evil journey's route. Macaroon AND semantics
	// say both caveats must be satisfied — impossible for any
	// single request. RequireSession must reject because of
	// CheckConstraints, not because a projected field happened
	// to be "evil".
	fix := newSessionFixture(t)
	now := time.Now()
	_, serialized, err := fix.issuer.IssueSession(standardParams(now))
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}
	// Attenuate by appending a second journey= caveat.
	var m macaroonv2.Macaroon
	if err := m.UnmarshalBinary(serialized); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	evilJourney := opencaravan.UUID("44444444-4444-4444-8444-444444444444")
	if err := m.AddFirstPartyCaveat([]byte(opencaravan.CaveatJourney(evilJourney))); err != nil {
		t.Fatalf("AddFirstPartyCaveat: %v", err)
	}
	tampered, err := m.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal tampered: %v", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(tampered)

	mux := http.NewServeMux()
	mux.Handle("GET /v1/journeys/{id}",
		AttachSession(fix.verifier, discardLogger())(
			RequireSession(fix.verifier, discardLogger(),
				SessionActionJourneyFromPath(opencaravan.SessionActionJourneyRead, "id"),
			)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
				t.Fatal("handler ran despite attenuator-appended journey caveat")
			})),
		),
	)

	// The attacker targets the evil journey, hoping the appended
	// caveat overrides the original.
	req := httptest.NewRequest(http.MethodGet, "/v1/journeys/"+string(evilJourney), nil)
	req.Header.Set("Authorization", "Macaroon "+encoded)
	req = req.WithContext(WithIdentity(req.Context(), Identity{
		UserID:      string(testUser),
		ClientAppID: string(testApp),
	}))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("appended journey caveat let request through: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRequireSessionRejectsAppendedActionCaveatAttack(t *testing.T) {
	// Companion to the journey attack: appending a second action=
	// caveat for a different verb must not let the macaroon
	// authorize the appended action.
	fix := newSessionFixture(t)
	_, serialized, err := fix.issuer.IssueSession(standardParams(time.Now()))
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}
	var m macaroonv2.Macaroon
	if err := m.UnmarshalBinary(serialized); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := m.AddFirstPartyCaveat([]byte(opencaravan.CaveatAction(opencaravan.SessionActionTelemetryWrite))); err != nil {
		t.Fatalf("AddFirstPartyCaveat: %v", err)
	}
	tampered, err := m.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(tampered)

	chain := AttachSession(fix.verifier, discardLogger())(
		RequireSession(fix.verifier, discardLogger(),
			SessionAction(opencaravan.SessionActionTelemetryWrite), // matches the appended caveat
		)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			t.Fatal("handler ran despite attenuator-appended action caveat")
		})),
	)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Macaroon "+encoded)
	req = req.WithContext(WithIdentity(req.Context(), Identity{
		UserID:      string(testUser),
		ClientAppID: string(testApp),
	}))
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("appended action caveat let request through: status=%d", rec.Code)
	}
}

func TestRequireSessionConstraintsBuilderError(t *testing.T) {
	fix := newSessionFixture(t)
	encoded := fix.issueAndEncode(t, standardParams(time.Now()))

	// Use SessionActionJourneyFromPath but don't register a mux
	// pattern declaring the {id} parameter; PathValue returns
	// empty and the builder returns an error.
	chain := AttachSession(fix.verifier, discardLogger())(
		RequireSession(fix.verifier, discardLogger(),
			SessionActionJourneyFromPath(opencaravan.SessionActionJourneyRead, "id"),
		)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			t.Fatal("handler ran despite builder error")
		})),
	)
	req := httptest.NewRequest(http.MethodGet, "/v1/journeys/foo", nil)
	req.Header.Set("Authorization", "Macaroon "+encoded)
	req = req.WithContext(WithIdentity(req.Context(), Identity{
		UserID: string(testUser), ClientAppID: string(testApp),
	}))
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "constraints_builder_failed") {
		t.Fatalf("body missing constraints_builder_failed: %s", rec.Body.String())
	}
}

func TestSessionFromMissingReturnsFalse(t *testing.T) {
	if _, ok := SessionFrom(context.Background()); ok {
		t.Fatal("SessionFrom on bare context returned ok=true")
	}
}

func TestRequireSessionPanicOnNilVerifier(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on nil verifier")
		}
	}()
	RequireSession(nil, discardLogger(), SessionAction(opencaravan.SessionActionJourneyRead))
}

func TestRequireSessionPanicOnNilBuilder(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on nil builder")
		}
	}()
	fix := newSessionFixture(t)
	RequireSession(fix.verifier, discardLogger(), nil)
}

// Compile-time guard that *macaroon.Verifier satisfies the narrow
// SessionVerifier interface AttachSession depends on.
var _ SessionVerifier = (*macaroon.Verifier)(nil)
