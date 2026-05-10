package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

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
