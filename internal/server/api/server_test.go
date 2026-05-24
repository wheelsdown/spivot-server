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
	policyDocument := ServerPolicyDocument{
		Version: "test",
		Registration: RegistrationPolicy{
			Mode: "closed",
		},
		Journeys: JourneyPolicy{
			Visibility:      "invite_only",
			InviteLinks:     true,
			InviteUseLimits: false,
		},
		Data: DataPolicy{
			RetentionControl: "journey_deletion_time",
		},
	}
	policyJSON, err := json.Marshal(policyDocument)
	if err != nil {
		t.Fatalf("marshal policy document: %v", err)
	}
	server := NewServer(Config{
		Address:   "127.0.0.1",
		Port:      8080,
		PublicURL: publicURL,
		PolicySnapshot: ServerPolicySnapshot{
			ID:          "sha256:test",
			Hash:        "sha256:test",
			CreatedTime: "2026-05-24T00:00:00Z",
			Document:    policyJSON,
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
		Capabilities struct {
			Registration struct {
				Mode string `json:"mode"`
			} `json:"registration"`
			Journeys struct {
				InviteOnly          bool `json:"invite_only"`
				InviteLinks         bool `json:"invite_links"`
				InviteUseLimits     bool `json:"invite_use_limits"`
				DeletionTimePerItem bool `json:"deletion_time_per_item"`
			} `json:"journeys"`
			Data struct {
				SQLiteStorage       bool `json:"sqlite_storage"`
				TelemetryStorage    bool `json:"telemetry_storage"`
				ImageResourceUpload bool `json:"image_resource_upload"`
			} `json:"data"`
		} `json:"capabilities"`
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
	if got.Capabilities.Registration.Mode != "closed" {
		t.Fatalf("registration mode = %q, want closed", got.Capabilities.Registration.Mode)
	}
	if !got.Capabilities.Journeys.InviteOnly {
		t.Fatal("journey invite_only = false, want true")
	}
	if !got.Capabilities.Journeys.InviteLinks {
		t.Fatal("journey invite_links = false, want true")
	}
	if got.Capabilities.Journeys.InviteUseLimits {
		t.Fatal("journey invite_use_limits = true, want false")
	}
	if !got.Capabilities.Journeys.DeletionTimePerItem {
		t.Fatal("journey deletion_time_per_item = false, want true")
	}
	if !got.Capabilities.Data.SQLiteStorage {
		t.Fatal("data sqlite_storage = false, want true")
	}
	if got.Capabilities.Data.TelemetryStorage {
		t.Fatal("data telemetry_storage = true, want false")
	}
	if got.Capabilities.Data.ImageResourceUpload {
		t.Fatal("data image_resource_upload = true, want false")
	}
	if got.Policy.Hash != "sha256:test" {
		t.Fatalf("policy hash = %q, want sha256:test", got.Policy.Hash)
	}
	if string(got.Policy.Document) != string(policyJSON) {
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
