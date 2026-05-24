package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

type pingStore struct {
	err error
}

func (s pingStore) Ping(context.Context) error {
	return s.err
}

func TestHealthEndpoint(t *testing.T) {
	server := NewServer(Config{Address: "127.0.0.1", Port: 8080}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got["status"] != "healthy" {
		t.Fatalf("status = %q, want healthy", got["status"])
	}
}

func TestVersionEndpoint(t *testing.T) {
	server := NewServer(Config{Address: "127.0.0.1", Port: 8080}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	req := httptest.NewRequest(http.MethodGet, "/v1/version", nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got["version"] == "" {
		t.Fatal("version is empty")
	}
	if got["uptime"] == "" {
		t.Fatal("uptime is empty")
	}
}

func TestServerInfoEndpoint(t *testing.T) {
	publicURL, err := url.Parse("https://spivot.example.com")
	if err != nil {
		t.Fatalf("parse public URL: %v", err)
	}
	server := NewServer(Config{
		Address:   "127.0.0.1",
		Port:      8080,
		PublicURL: publicURL,
		PolicySnapshot: ServerPolicySnapshot{
			ID:          "sha256:test",
			Hash:        "sha256:test",
			CreatedTime: "2026-05-24T00:00:00Z",
			Document:    json.RawMessage(`{"version":"test"}`),
		},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	req := httptest.NewRequest(http.MethodGet, "/v1/server", nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var got struct {
		Name      string `json:"name"`
		PublicURL string `json:"public_url"`
		Protocol  struct {
			Name string `json:"name"`
		} `json:"protocol"`
		Policy struct {
			Hash     string          `json:"policy_hash"`
			Document json.RawMessage `json:"document"`
		} `json:"policy"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Name != "Spivot Server" {
		t.Fatalf("name = %q, want Spivot Server", got.Name)
	}
	if got.PublicURL != "https://spivot.example.com" {
		t.Fatalf("public_url = %q, want https://spivot.example.com", got.PublicURL)
	}
	if got.Protocol.Name != "OpenCaravan" {
		t.Fatalf("protocol name = %q, want OpenCaravan", got.Protocol.Name)
	}
	if got.Policy.Hash != "sha256:test" {
		t.Fatalf("policy hash = %q, want sha256:test", got.Policy.Hash)
	}
	if string(got.Policy.Document) != `{"version":"test"}` {
		t.Fatalf("policy document = %s", got.Policy.Document)
	}
}

func TestReadyEndpointChecksStore(t *testing.T) {
	server := NewServer(Config{
		Address: "127.0.0.1",
		Port:    8080,
		Store:   pingStore{},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got["status"] != "ready" {
		t.Fatalf("status = %q, want ready", got["status"])
	}
}

func TestReadyEndpointReportsStoreFailure(t *testing.T) {
	server := NewServer(Config{
		Address: "127.0.0.1",
		Port:    8080,
		Store:   pingStore{err: errors.New("database offline")},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}

	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got["status"] != "unready" {
		t.Fatalf("status = %q, want unready", got["status"])
	}
}

func TestRootEndpointIncludesPublicURL(t *testing.T) {
	publicURL, err := url.Parse("https://spivot.example.com")
	if err != nil {
		t.Fatalf("parse public URL: %v", err)
	}
	server := NewServer(Config{
		Address:   "127.0.0.1",
		Port:      8080,
		PublicURL: publicURL,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got["public_url"] != "https://spivot.example.com" {
		t.Fatalf("public_url = %q, want https://spivot.example.com", got["public_url"])
	}
}
