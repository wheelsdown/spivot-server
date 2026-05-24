package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/opencaravan/opencaravan-go"
	"github.com/wheelsdown/spivot-server/internal/platform/identity"
	"github.com/wheelsdown/spivot-server/internal/platform/storage"
)

func TestClientAppEnrollHappyPath(t *testing.T) {
	env := newEnrollmentEnv(t)

	token, _, err := env.store.IssueInvite(context.Background(), opencaravan.InviteScopeServerRegistration, time.Hour)
	if err != nil {
		t.Fatalf("seed invite: %v", err)
	}

	csrPEM := generateClientCSR(t, "client-app")
	reqBody := opencaravan.NewClientAppEnrollmentRequest(token.Value, csrPEM)
	reqBody.DisplayName = "Riley's iPhone"

	resp := env.do(t, reqBody)
	if resp.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", resp.Code, resp.Body.String())
	}

	var decoded opencaravan.ClientAppEnrollmentResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatalf("response validate: %v", err)
	}
	if len(decoded.Enrollment.CertificateChain) != 1 {
		t.Fatalf("cert chain len = %d, want 1", len(decoded.Enrollment.CertificateChain))
	}
	if len(decoded.ServerCAChain) != 1 {
		t.Fatalf("server ca chain len = %d, want 1", len(decoded.ServerCAChain))
	}

	// The leaf must verify against the CA root.
	leafBlock, _ := pem.Decode([]byte(decoded.Enrollment.CertificateChain[0]))
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(env.ca.Certificate())
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("leaf does not verify against CA: %v", err)
	}

	// Storage side-effects: account + client_app exist, invite consumed.
	if got, err := env.store.AccountCount(context.Background()); err != nil || got != 1 {
		t.Fatalf("AccountCount = (%d, %v), want (1, nil)", got, err)
	}
	if _, err := env.store.ClientAppByID(context.Background(), string(decoded.Enrollment.ID)); err != nil {
		t.Fatalf("ClientAppByID after enroll: %v", err)
	}
	if _, err := env.store.LookupInvite(context.Background(), token.Value); err == nil {
		t.Fatal("invite still active after enroll, want ErrInviteAlreadyUsed")
	}
}

func TestClientAppEnrollRejectsJourneyScopedInvite(t *testing.T) {
	env := newEnrollmentEnv(t)

	token, _, err := env.store.IssueInvite(context.Background(), opencaravan.InviteScopeJourney, time.Hour)
	if err != nil {
		t.Fatalf("seed invite: %v", err)
	}
	req := opencaravan.NewClientAppEnrollmentRequest(token.Value, generateClientCSR(t, "client-app"))

	resp := env.do(t, req)
	if resp.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body = %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "invite_scope_mismatch") {
		t.Fatalf("body missing scope_mismatch code: %s", resp.Body.String())
	}
}

func TestClientAppEnrollRejectsUnknownInvite(t *testing.T) {
	env := newEnrollmentEnv(t)
	req := opencaravan.NewClientAppEnrollmentRequest(makeValidInviteTokenValue(), generateClientCSR(t, "client-app"))

	resp := env.do(t, req)
	if resp.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body = %s", resp.Code, resp.Body.String())
	}
}

func TestClientAppEnrollRejectsAlreadyUsedInvite(t *testing.T) {
	env := newEnrollmentEnv(t)
	token, _, err := env.store.IssueInvite(context.Background(), opencaravan.InviteScopeServerRegistration, time.Hour)
	if err != nil {
		t.Fatalf("seed invite: %v", err)
	}
	if _, err := env.store.ConsumeInvite(context.Background(), token.Value, "preexisting-app"); err != nil {
		t.Fatalf("pre-consume: %v", err)
	}
	req := opencaravan.NewClientAppEnrollmentRequest(token.Value, generateClientCSR(t, "client-app"))

	resp := env.do(t, req)
	if resp.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body = %s", resp.Code, resp.Body.String())
	}
}

func TestClientAppEnrollRejectsExpiredInvite(t *testing.T) {
	env := newEnrollmentEnv(t)
	token, _, err := env.store.IssueInvite(context.Background(), opencaravan.InviteScopeServerRegistration, time.Millisecond)
	if err != nil {
		t.Fatalf("seed invite: %v", err)
	}
	time.Sleep(30 * time.Millisecond)
	req := opencaravan.NewClientAppEnrollmentRequest(token.Value, generateClientCSR(t, "client-app"))

	resp := env.do(t, req)
	if resp.Code != http.StatusGone {
		t.Fatalf("status = %d, want 410; body = %s", resp.Code, resp.Body.String())
	}
}

func TestClientAppEnrollRejectsMalformedJSON(t *testing.T) {
	env := newEnrollmentEnv(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/client-apps/enroll", bytes.NewBufferString("{not-json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}
}

func TestClientAppEnrollRejectsCSRWithWrongKeyAlgorithm(t *testing.T) {
	env := newEnrollmentEnv(t)
	token, _, err := env.store.IssueInvite(context.Background(), opencaravan.InviteScopeServerRegistration, time.Hour)
	if err != nil {
		t.Fatalf("seed invite: %v", err)
	}
	// RSA CSR — protocol requires P-256 ECDSA, so this must be rejected.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "client-app"},
	}, rsaKey)
	if err != nil {
		t.Fatalf("rsa csr: %v", err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	body := opencaravan.NewClientAppEnrollmentRequest(token.Value, csrPEM)

	resp := env.do(t, body)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "ECDSA") {
		t.Fatalf("error body did not mention ECDSA requirement: %s", resp.Body.String())
	}
}

func TestClientAppEnroll503sWhenDependenciesMissing(t *testing.T) {
	server := NewServer(Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	req := opencaravan.NewClientAppEnrollmentRequest(makeValidInviteTokenValue(), "irrelevant")
	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/client-apps/enroll", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, httpReq)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

type enrollmentEnv struct {
	server *Server
	store  *storage.Store
	ca     *identity.CA
}

func newEnrollmentEnv(t *testing.T) *enrollmentEnv {
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

	keyStore, err := identity.NewFileKeyStore(filepath.Join(dir, "identity"))
	if err != nil {
		t.Fatalf("NewFileKeyStore: %v", err)
	}
	ca, err := identity.LoadOrCreate(ctx, keyStore, identity.Config{Dir: filepath.Join(dir, "identity")})
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	server := NewServer(Config{
		Address:         "127.0.0.1",
		Port:            8080,
		Store:           store,
		EnrollmentStore: store,
		CA:              ca,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	return &enrollmentEnv{server: server, store: store, ca: ca}
}

func (e *enrollmentEnv) do(t *testing.T, body opencaravan.ClientAppEnrollmentRequest) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/client-apps/enroll", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.server.Handler().ServeHTTP(rec, req)
	return rec
}

func generateClientCSR(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
}

// makeValidInviteTokenValue returns a syntactically-valid but
// unrecognized invite token value. Used by tests that exercise the
// unknown-token path without going through IssueInvite.
func makeValidInviteTokenValue() string {
	// 43 chars of unpadded base64url == 32 bytes; opencaravan-go's
	// InviteToken validator requires this shape.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var sb strings.Builder
	for i := 0; i < 43; i++ {
		sb.WriteByte(alphabet[i%len(alphabet)])
	}
	return sb.String()
}
