package middleware

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/opencaravan/opencaravan-go"

	"github.com/wheelsdown/spivot-server/internal/platform/auth/macaroon"
)

const (
	testRootID  = "session-test-root"
	testUser    = opencaravan.UUID("11111111-1111-4111-8111-111111111111")
	testApp     = opencaravan.UUID("22222222-2222-4222-8222-222222222222")
	testJourney = opencaravan.UUID("33333333-3333-4333-8333-333333333333")
)

// sessionFixture bundles an issuer/verifier pair with a fresh
// random root key so every test gets an isolated signing key. The
// verifier's resolver is a closure over the test's rootKey/rootID
// — no storage layer involved.
type sessionFixture struct {
	rootKey  []byte
	issuer   *macaroon.Issuer
	verifier *macaroon.Verifier
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
	return &sessionFixture{
		rootKey:  key,
		issuer:   issuer,
		verifier: verifier,
	}
}

// issueAndEncode mints a session macaroon for the supplied params
// and returns its unpadded-base64url encoding (the form
// Authorization: Macaroon clients send).
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
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

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
}

func TestAttachSessionPassesThroughNoHeader(t *testing.T) {
	fix := newSessionFixture(t)
	called := false
	handler := AttachSession(fix.verifier, discardLogger())(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		called = true
		if _, ok := SessionFrom(r.Context()); ok {
			t.Error("SessionFrom ok=true with no header")
		}
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if !called {
		t.Fatal("downstream handler not invoked")
	}
}

func TestAttachSessionPassesThroughWrongScheme(t *testing.T) {
	fix := newSessionFixture(t)
	handler := AttachSession(fix.verifier, discardLogger())(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if _, ok := SessionFrom(r.Context()); ok {
			t.Error("SessionFrom ok=true with Bearer header")
		}
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	handler.ServeHTTP(httptest.NewRecorder(), req)
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

func TestAttachSessionPassesThroughMalformedBase64(t *testing.T) {
	fix := newSessionFixture(t)
	handler := AttachSession(fix.verifier, discardLogger())(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if _, ok := SessionFrom(r.Context()); ok {
			t.Error("SessionFrom ok=true with malformed base64")
		}
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Macaroon !!!not-base64!!!")
	handler.ServeHTTP(httptest.NewRecorder(), req)
}

func TestAttachSessionPassesThroughBadSignature(t *testing.T) {
	fix := newSessionFixture(t)
	// Issue with one key, but the verifier the test uses resolves
	// the id to a different key — simulating either tampering or
	// signing under a key the server doesn't know.
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

	handler := AttachSession(fix.verifier, discardLogger())(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if _, ok := SessionFrom(r.Context()); ok {
			t.Error("SessionFrom ok=true with bad signature")
		}
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Macaroon "+encoded)
	handler.ServeHTTP(httptest.NewRecorder(), req)
}

func TestRequireSessionRejectsWithoutSession(t *testing.T) {
	guard := RequireSession(discardLogger())(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("guarded handler ran without session")
	}))
	rec := httptest.NewRecorder()
	guard.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/problem+json" {
		t.Fatalf("Content-Type = %q", got)
	}
}

func TestRequireSessionAcceptsValidSession(t *testing.T) {
	called := false
	guard := RequireSession(discardLogger())(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		called = true
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(WithSession(req.Context(), Session{
		UserID:      testUser,
		ClientAppID: testApp,
		Expiration:  time.Now().Add(time.Hour),
	}))
	rec := httptest.NewRecorder()
	guard.ServeHTTP(rec, req)
	if !called {
		t.Fatal("guarded handler not invoked")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestRequireSessionRejectsExpiredSession(t *testing.T) {
	guard := RequireSession(discardLogger())(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("guarded handler ran with expired session")
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(WithSession(req.Context(), Session{
		Expiration: time.Now().Add(-time.Minute),
	}))
	rec := httptest.NewRecorder()
	guard.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "session_expired") {
		t.Fatalf("body missing session_expired: %s", rec.Body.String())
	}
}

func TestRequireSessionActionConstraint(t *testing.T) {
	guard := RequireSession(discardLogger(), RequireSessionAction(opencaravan.SessionActionTelemetryWrite))(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("guarded handler ran with wrong action")
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(WithSession(req.Context(), Session{
		Action:     opencaravan.SessionActionJourneyRead,
		Expiration: time.Now().Add(time.Hour),
	}))
	rec := httptest.NewRecorder()
	guard.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "session_constraint_failed") {
		t.Fatalf("body missing session_constraint_failed: %s", rec.Body.String())
	}
}

func TestRequireSessionActionConstraintPasses(t *testing.T) {
	called := false
	guard := RequireSession(discardLogger(), RequireSessionAction(opencaravan.SessionActionJourneyRead))(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		called = true
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(WithSession(req.Context(), Session{
		Action:     opencaravan.SessionActionJourneyRead,
		Expiration: time.Now().Add(time.Hour),
	}))
	guard.ServeHTTP(httptest.NewRecorder(), req)
	if !called {
		t.Fatal("guarded handler not invoked despite matching action")
	}
}

func TestRequireSessionJourneyParamMismatch(t *testing.T) {
	// Build a mux so PathValue is populated.
	mux := http.NewServeMux()
	mux.Handle("GET /v1/journeys/{id}", RequireSession(discardLogger(), RequireSessionJourneyParam("id"))(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("handler ran with mismatched journey")
	})))

	req := httptest.NewRequest(http.MethodGet, "/v1/journeys/44444444-4444-4444-8444-444444444444", nil)
	req = req.WithContext(WithSession(req.Context(), Session{
		JourneyID:  testJourney,
		Expiration: time.Now().Add(time.Hour),
	}))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestRequireSessionJourneyParamMatches(t *testing.T) {
	mux := http.NewServeMux()
	called := false
	mux.Handle("GET /v1/journeys/{id}", RequireSession(discardLogger(), RequireSessionJourneyParam("id"))(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		called = true
	})))

	req := httptest.NewRequest(http.MethodGet, "/v1/journeys/"+string(testJourney), nil)
	req = req.WithContext(WithSession(req.Context(), Session{
		JourneyID:  testJourney,
		Expiration: time.Now().Add(time.Hour),
	}))
	mux.ServeHTTP(httptest.NewRecorder(), req)
	if !called {
		t.Fatal("handler not invoked despite matching journey")
	}
}

func TestRequireSessionEndToEnd(t *testing.T) {
	// Verifier-backed attach + guard composed, identical to the
	// production middleware chain.
	fix := newSessionFixture(t)
	encoded := fix.issueAndEncode(t, standardParams(time.Now()))

	called := false
	handler := AttachSession(fix.verifier, discardLogger())(
		RequireSession(discardLogger(),
			RequireSessionAction(opencaravan.SessionActionJourneyRead),
		)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			called = true
		})),
	)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Macaroon "+encoded)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called {
		t.Fatalf("handler not invoked; status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSessionFromMissingReturnsFalse(t *testing.T) {
	if _, ok := SessionFrom(context.Background()); ok {
		t.Fatal("SessionFrom on bare context returned ok=true")
	}
}

// Compile-time guard that *macaroon.Verifier satisfies the narrow
// SessionVerifier interface AttachSession depends on. If this
// breaks, the production wiring would fail at runtime.
var _ SessionVerifier = (*macaroon.Verifier)(nil)

// errors.Is sentinel test — middleware should match against
// macaroon.ErrVerifyFailed via errors.Is from outside this file.
// Smoke-test the import path here.
func TestErrVerifyFailedReachable(t *testing.T) {
	if !errors.Is(macaroon.ErrVerifyFailed, macaroon.ErrVerifyFailed) {
		t.Fatal("errors.Is reflexive failed; macaroon package import wrong?")
	}
}
