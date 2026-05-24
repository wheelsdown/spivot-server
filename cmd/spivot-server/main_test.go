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

func TestCABootstrapInitAndCert(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("SPIVOT_DATA_DIR", dataDir)

	var initOut bytes.Buffer
	if err := run(context.Background(), &initOut, &bytes.Buffer{}, []string{"ca", "init"}); err != nil {
		t.Fatalf("ca init: %v", err)
	}
	out := initOut.String()
	for _, want := range []string{"CA initialized", "fingerprint:", "Spivot Server CA"} {
		if !strings.Contains(out, want) {
			t.Fatalf("ca init output missing %q:\n%s", want, out)
		}
	}

	var certOut bytes.Buffer
	if err := run(context.Background(), &certOut, &bytes.Buffer{}, []string{"ca", "cert"}); err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	if !strings.HasPrefix(certOut.String(), "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("ca cert output did not start with CERTIFICATE PEM block:\n%s", certOut.String())
	}

	// Re-running init must be idempotent: same fingerprint.
	var reInit bytes.Buffer
	if err := run(context.Background(), &reInit, &bytes.Buffer{}, []string{"ca", "init"}); err != nil {
		t.Fatalf("ca init (reload): %v", err)
	}
	firstFP := fingerprintLine(t, initOut.String())
	secondFP := fingerprintLine(t, reInit.String())
	if firstFP != secondFP {
		t.Fatalf("fingerprint changed across init runs: %q vs %q", firstFP, secondFP)
	}
}

func TestCARejectsUnknownSubcommand(t *testing.T) {
	t.Setenv("SPIVOT_DATA_DIR", t.TempDir())

	err := run(context.Background(), &bytes.Buffer{}, &bytes.Buffer{}, []string{"ca", "bogus"})
	if err == nil {
		t.Fatal("ca bogus: expected error")
	}
	if !strings.Contains(err.Error(), "unknown ca subcommand") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCARequiresSubcommand(t *testing.T) {
	err := run(context.Background(), &bytes.Buffer{}, &bytes.Buffer{}, []string{"ca"})
	if err == nil {
		t.Fatal("ca: expected error")
	}
	if !strings.Contains(err.Error(), "requires a subcommand") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func fingerprintLine(t *testing.T, output string) string {
	t.Helper()
	for line := range strings.SplitSeq(output, "\n") {
		if strings.Contains(line, "fingerprint:") {
			return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "fingerprint:"))
		}
	}
	t.Fatalf("no fingerprint line in output:\n%s", output)
	return ""
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
