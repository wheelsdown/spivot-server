package main

import (
	"bytes"
	"context"
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
	"github.com/wheelsdown/spivot-server/internal/platform/storage"
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

func TestParseServeConfigInviteMintPolicy(t *testing.T) {
	t.Run("defaults to any-user", func(t *testing.T) {
		cfg, err := parseServeConfig(nil)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if cfg.inviteMintPolicy != "any-user" {
			t.Fatalf("default invite mint policy = %q, want any-user", cfg.inviteMintPolicy)
		}
	})
	t.Run("accepts each valid mode", func(t *testing.T) {
		for _, mode := range []string{"denied", "admin-only", "any-user"} {
			cfg, err := parseServeConfig([]string{"-invite-mint-policy", mode})
			if err != nil {
				t.Fatalf("mode %q: %v", mode, err)
			}
			if cfg.inviteMintPolicy != mode {
				t.Fatalf("mode %q: got %q", mode, cfg.inviteMintPolicy)
			}
		}
	})
	t.Run("rejects garbage", func(t *testing.T) {
		if _, err := parseServeConfig([]string{"-invite-mint-policy", "everyone"}); err == nil {
			t.Fatal("expected error for invalid invite mint policy")
		}
	})
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

func TestInviteCreatePrintsToken(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("SPIVOT_DATA_DIR", dataDir)

	var stdout bytes.Buffer
	if err := run(context.Background(), &stdout, &bytes.Buffer{}, []string{"invite", "create"}); err != nil {
		t.Fatalf("invite create: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{"invite issued", "scope:", "server_registration", "token_hash:", "token:"} {
		if !strings.Contains(out, want) {
			t.Fatalf("invite create output missing %q:\n%s", want, out)
		}
	}
}

func TestInviteCreateAcceptsScopeAndLifetime(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("SPIVOT_DATA_DIR", dataDir)

	var stdout bytes.Buffer
	args := []string{"invite", "create", "-scope", "journey", "-lifetime", "1h"}
	if err := run(context.Background(), &stdout, &bytes.Buffer{}, args); err != nil {
		t.Fatalf("invite create journey: %v", err)
	}
	if !strings.Contains(stdout.String(), "journey") {
		t.Fatalf("output missing journey scope:\n%s", stdout.String())
	}
}

func TestInviteRejectsUnknownSubcommand(t *testing.T) {
	t.Setenv("SPIVOT_DATA_DIR", t.TempDir())

	err := run(context.Background(), &bytes.Buffer{}, &bytes.Buffer{}, []string{"invite", "bogus"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unknown invite subcommand") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInviteRequiresSubcommand(t *testing.T) {
	err := run(context.Background(), &bytes.Buffer{}, &bytes.Buffer{}, []string{"invite"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "requires a subcommand") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFormatBootstrapBannerOmitsIOSHint(t *testing.T) {
	tok, err := opencaravan.NewInviteToken(time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}
	banner := formatBootstrapBanner(tok)
	for _, forbidden := range []string{"Settings", "Add Account", "iOS app", "Use Invite"} {
		if strings.Contains(banner, forbidden) {
			t.Fatalf("banner still mentions %q (was written before the iOS app existed):\n%s", forbidden, banner)
		}
	}
	// The token value still appears prominently.
	if !strings.Contains(banner, tok.Value) {
		t.Fatalf("banner missing the token value:\n%s", banner)
	}
}

func TestDataDirEphemeralWarning(t *testing.T) {
	t.Run("no proc returns no warning", func(t *testing.T) {
		orig := procSelfMountInfo
		t.Cleanup(func() { procSelfMountInfo = orig })
		procSelfMountInfo = func() ([]byte, error) {
			return nil, &mockMountInfoErr{}
		}
		if got := dataDirEphemeralWarning("/var/lib/spivot"); got != "" {
			t.Fatalf("want empty warning on non-Linux host; got %q", got)
		}
	})
	t.Run("dir is a mount point returns no warning", func(t *testing.T) {
		orig := procSelfMountInfo
		t.Cleanup(func() { procSelfMountInfo = orig })
		procSelfMountInfo = func() ([]byte, error) {
			// Field 5 (mountPoint) is /var/lib/spivot — a mount exists.
			return []byte("85 1 0:55 / /var/lib/spivot rw,relatime - ext4 /dev/sdb rw\n"), nil
		}
		if got := dataDirEphemeralWarning("/var/lib/spivot"); got != "" {
			t.Fatalf("want empty warning when dir is mounted; got %q", got)
		}
	})
	t.Run("dir is not a mount point returns warning", func(t *testing.T) {
		orig := procSelfMountInfo
		t.Cleanup(func() { procSelfMountInfo = orig })
		procSelfMountInfo = func() ([]byte, error) {
			// Only / is a mount; /var/lib/spivot is NOT.
			return []byte("1 0 0:1 / / rw,relatime - overlay overlay rw\n"), nil
		}
		got := dataDirEphemeralWarning("/var/lib/spivot")
		if got == "" {
			t.Fatal("want warning when dir is not a mount; got empty")
		}
		if !strings.Contains(got, "/var/lib/spivot") {
			t.Fatalf("warning should mention the data_dir path; got %q", got)
		}
	})
	t.Run("operator mapped to wrong in-container path produces warning", func(t *testing.T) {
		// Reproduces the production incident: volume mounted at
		// /usr/lib/spivot instead of /var/lib/spivot. The Dockerfile
		// sets SPIVOT_DATA_DIR=/var/lib/spivot, so dataDir is that —
		// but only /usr/lib/spivot appears in mountinfo. Expect a
		// warning about /var/lib/spivot.
		orig := procSelfMountInfo
		t.Cleanup(func() { procSelfMountInfo = orig })
		procSelfMountInfo = func() ([]byte, error) {
			return []byte("1 0 0:1 / / rw,relatime - overlay overlay rw\n" +
				"42 1 0:55 / /usr/lib/spivot rw,relatime - ext4 /dev/sdb rw\n"), nil
		}
		got := dataDirEphemeralWarning("/var/lib/spivot")
		if got == "" {
			t.Fatal("want warning when operator mapped volume to wrong path")
		}
	})
}

type mockMountInfoErr struct{}

func (mockMountInfoErr) Error() string { return "mock: /proc unavailable" }

func TestEmitBootstrapInviteOnEmptyServer(t *testing.T) {
	store := newBootstrapTestStore(t)

	var stdout bytes.Buffer
	logger := newTestLogger(t)
	if err := emitBootstrapInviteIfNeeded(context.Background(), store, &stdout, logger); err != nil {
		t.Fatalf("emit bootstrap: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{"SPIVOT SERVER FIRST-RUN BOOTSTRAP", "server_registration", "Single-use, 24h"} {
		if !strings.Contains(out, want) {
			t.Fatalf("banner missing %q:\n%s", want, out)
		}
	}

	count, err := store.UnconsumedInviteCount(context.Background(), opencaravan.InviteScopeServerRegistration)
	if err != nil {
		t.Fatalf("UnconsumedInviteCount: %v", err)
	}
	if count != 1 {
		t.Fatalf("invite count after emit = %d, want 1", count)
	}
}

func TestEmitBootstrapInviteSkipsWhenAlreadyActive(t *testing.T) {
	store := newBootstrapTestStore(t)
	ctx := context.Background()
	if _, _, err := store.IssueInvite(ctx, opencaravan.InviteScopeServerRegistration, 24*time.Hour); err != nil {
		t.Fatalf("seed invite: %v", err)
	}

	var stdout bytes.Buffer
	logger := newTestLogger(t)
	if err := emitBootstrapInviteIfNeeded(ctx, store, &stdout, logger); err != nil {
		t.Fatalf("emit bootstrap (skip path): %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("banner emitted despite active invite:\n%s", stdout.String())
	}

	count, err := store.UnconsumedInviteCount(ctx, opencaravan.InviteScopeServerRegistration)
	if err != nil {
		t.Fatalf("UnconsumedInviteCount: %v", err)
	}
	if count != 1 {
		t.Fatalf("invite count after skip = %d, want 1 (existing seed)", count)
	}
}

func newBootstrapTestStore(t *testing.T) *storage.Store {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.Open(context.Background(), storage.Config{Path: filepath.Join(dir, "spivot.db")})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	})
	return store
}

func newTestLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(io.Discard, nil))
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
