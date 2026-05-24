package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunVersionJSON(t *testing.T) {
	var stdout bytes.Buffer

	if err := run(context.Background(), &stdout, &bytes.Buffer{}, []string{"-o", "json", "version"}); err != nil {
		t.Fatalf("run version: %v", err)
	}

	var got map[string]string
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode version JSON: %v", err)
	}
	if got["version"] == "" {
		t.Fatal("version is empty")
	}
}

func TestRunVersionJSONFlagForms(t *testing.T) {
	tests := [][]string{
		{"-o=json", "version"},
		{"--output", "json", "version"},
		{"--output=json", "version"},
	}

	for _, args := range tests {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var stdout bytes.Buffer

			if err := run(context.Background(), &stdout, &bytes.Buffer{}, args); err != nil {
				t.Fatalf("run version: %v", err)
			}

			var got map[string]string
			if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
				t.Fatalf("decode version JSON: %v", err)
			}
			if got["version"] == "" {
				t.Fatal("version is empty")
			}
		})
	}
}

func TestRunPrintsUsageWithoutArgs(t *testing.T) {
	var stdout bytes.Buffer

	if err := run(context.Background(), &stdout, &bytes.Buffer{}, nil); err != nil {
		t.Fatalf("run usage: %v", err)
	}
	if !strings.Contains(stdout.String(), "spivot-server [flags] <command>") {
		t.Fatalf("usage output missing command synopsis:\n%s", stdout.String())
	}
}

func TestRunRejectsUnknownGlobalFlag(t *testing.T) {
	err := run(context.Background(), &bytes.Buffer{}, &bytes.Buffer{}, []string{"--bogus", "version"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unknown flag") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunRejectsUnknownCommand(t *testing.T) {
	err := run(context.Background(), &bytes.Buffer{}, &bytes.Buffer{}, []string{"bogus"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseServeConfigProxySettings(t *testing.T) {
	t.Setenv("SPIVOT_PUBLIC_URL", "https://spivot.example.com/")
	t.Setenv("SPIVOT_TRUST_PROXY", "true")
	t.Setenv("SPIVOT_TRUSTED_PROXY_CIDRS", "127.0.0.1/8,10.0.0.0/8")

	cfg, err := parseServeConfig(nil)
	if err != nil {
		t.Fatalf("parse serve config: %v", err)
	}

	if cfg.publicURL.String() != "https://spivot.example.com" {
		t.Fatalf("publicURL = %q, want https://spivot.example.com", cfg.publicURL.String())
	}
	if !cfg.trustProxy {
		t.Fatal("trustProxy = false, want true")
	}
	if len(cfg.trustedProxyRanges) != 2 {
		t.Fatalf("trustedProxyRanges len = %d, want 2", len(cfg.trustedProxyRanges))
	}
}

func TestParseServeConfigRuntimePaths(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "state")
	configDir := filepath.Join(t.TempDir(), "config")
	t.Setenv("SPIVOT_DATA_DIR", dataDir)
	t.Setenv("SPIVOT_CONFIG_DIR", configDir)

	cfg, err := parseServeConfig(nil)
	if err != nil {
		t.Fatalf("parse serve config: %v", err)
	}

	if cfg.dataDir != dataDir {
		t.Fatalf("dataDir = %q, want %q", cfg.dataDir, dataDir)
	}
	if cfg.configDir != configDir {
		t.Fatalf("configDir = %q, want %q", cfg.configDir, configDir)
	}
	wantDatabasePath := filepath.Join(dataDir, "spivot.db")
	if cfg.databasePath != wantDatabasePath {
		t.Fatalf("databasePath = %q, want %q", cfg.databasePath, wantDatabasePath)
	}
}

func TestParseServeConfigDatabasePathOverride(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "custom.db")

	cfg, err := parseServeConfig([]string{"-database-path", databasePath})
	if err != nil {
		t.Fatalf("parse serve config: %v", err)
	}

	if cfg.databasePath != databasePath {
		t.Fatalf("databasePath = %q, want %q", cfg.databasePath, databasePath)
	}
}

func TestEnsureRuntimePathsCreatesWritableDataDirectory(t *testing.T) {
	root := t.TempDir()
	cfg := serveConfig{
		configDir:    filepath.Join(root, "config"),
		dataDir:      filepath.Join(root, "data"),
		databasePath: filepath.Join(root, "data", "spivot.db"),
	}

	if err := ensureRuntimePaths(cfg); err != nil {
		t.Fatalf("ensure runtime paths: %v", err)
	}
}

func TestParseServeConfigRejectsInvalidPublicURL(t *testing.T) {
	t.Setenv("SPIVOT_PUBLIC_URL", "spivot.example.com")

	_, err := parseServeConfig(nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "must use http or https") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHealthcheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	err := runHealthcheck(context.Background(), []string{"-url", server.URL})
	if err != nil {
		t.Fatalf("healthcheck: %v", err)
	}
}
