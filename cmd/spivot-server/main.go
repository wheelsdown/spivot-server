// Spivot Server is the backend API service for the Spivot iOS app.
//
// Usage:
//
//	spivot-server serve              Start the API server
//	spivot-server healthcheck        Check a running server's health endpoint
//	spivot-server version            Print version and build information
//	spivot-server -o json version    Output version information as JSON
package main

import (
	"context"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/opencaravan/opencaravan-go"
	"github.com/wheelsdown/spivot-server/internal/app"
	"github.com/wheelsdown/spivot-server/internal/platform/buildinfo"
	"github.com/wheelsdown/spivot-server/internal/platform/identity"
	"github.com/wheelsdown/spivot-server/internal/platform/proxy"
	"github.com/wheelsdown/spivot-server/internal/platform/storage"
	"github.com/wheelsdown/spivot-server/internal/server/api"
)

const (
	defaultAddress   = "0.0.0.0"
	defaultPort      = 8080
	defaultLogFormat = "text"
	defaultConfigDir = "config"
	defaultDataDir   = "data"
	envPublicURL     = "SPIVOT_PUBLIC_URL"
)

// main is intentionally minimal. It constructs the OS-level environment
// (context, stdio, argv) and delegates immediately to run. This keeps
// os.Exit, os.Stdout, os.Stderr, and os.Args out of the application logic so
// tests can drive the full command lifecycle with curated process inputs.
func main() {
	ctx := context.Background()

	if err := run(ctx, os.Stdout, os.Stderr, os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

// run is the real entry point for the spivot-server command. All OS-level
// dependencies are injected as parameters:
//
//   - ctx controls the lifetime of the process.
//   - stdout and stderr receive program output.
//   - args is os.Args[1:], the command-line arguments after the program name.
//
// run returns nil for clean command completion and a non-nil error for
// failures. The caller is responsible for printing the error and exiting.
func run(ctx context.Context, stdout io.Writer, stderr io.Writer, args []string) error {
	if len(args) == 0 {
		return printUsage(stdout)
	}
	_ = stderr

	inv, err := parseInvocation(args)
	if err != nil {
		return err
	}
	if inv.outputFmt != "text" && inv.outputFmt != "json" {
		return fmt.Errorf("unknown output format: %q (expected text or json)", inv.outputFmt)
	}

	switch inv.command {
	case "-h", "-help", "--help", "help":
		return printUsage(stdout)
	case "serve":
		return runServe(ctx, stdout, stderr, inv.cmdArgs)
	case "healthcheck":
		return runHealthcheck(ctx, inv.cmdArgs)
	case "ca":
		return runCA(ctx, stdout, inv.cmdArgs)
	case "invite":
		return runInvite(ctx, stdout, inv.cmdArgs)
	case "version":
		return runVersion(stdout, inv.outputFmt)
	case "":
		return printUsage(stdout)
	default:
		return fmt.Errorf("unknown command: %s", inv.command)
	}
}

type invocation struct {
	outputFmt string
	command   string
	cmdArgs   []string
}

// parseInvocation parses global flags without package-level flag state. The
// command surface is small enough that manual parsing is clearer than pulling
// command parsing into globals, and it keeps run safe to call from parallel
// tests.
func parseInvocation(args []string) (invocation, error) {
	inv := invocation{outputFmt: "text"}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-h" || arg == "-help" || arg == "--help" {
			inv.command = arg
			return inv, nil
		}
		switch {
		case arg == "-o" || arg == "--output":
			if i+1 >= len(args) {
				return inv, fmt.Errorf("missing value for %s", arg)
			}
			inv.outputFmt = args[i+1]
			i++
		case strings.HasPrefix(arg, "-o="):
			inv.outputFmt = strings.TrimPrefix(arg, "-o=")
		case strings.HasPrefix(arg, "--output="):
			inv.outputFmt = strings.TrimPrefix(arg, "--output=")
		case strings.HasPrefix(arg, "-"):
			return inv, fmt.Errorf("unknown flag: %s", arg)
		default:
			inv.command = arg
			inv.cmdArgs = args[i+1:]
			return inv, nil
		}
	}

	return inv, nil
}

func runServe(ctx context.Context, stdout io.Writer, stderr io.Writer, args []string) error {
	cfg, err := parseServeConfig(args)
	if err != nil {
		return err
	}
	_ = stderr

	logger := newLogger(stdout, slog.LevelInfo, cfg.logFormat)
	if err := ensureRuntimePaths(cfg); err != nil {
		return err
	}
	logger.Info("starting Spivot Server",
		"version", buildinfo.Version,
		"commit", buildinfo.GitCommit,
		"branch", buildinfo.GitBranch,
		"built", buildinfo.BuildTime,
		"config_dir", cfg.configDir,
		"data_dir", cfg.dataDir,
		"database_path", cfg.databasePath,
	)
	store, err := storage.Open(ctx, storage.Config{Path: cfg.databasePath})
	if err != nil {
		return err
	}
	defer func() {
		if err := store.Close(); err != nil {
			logger.Error("storage close failed", "error", err)
		}
	}()
	appliedMigrations, err := store.AppliedMigrations(ctx)
	if err != nil {
		return err
	}
	logger.Info("storage ready",
		"database_path", store.Path(),
		"applied_migrations", len(appliedMigrations),
	)
	if err := emitBootstrapInviteIfNeeded(ctx, store, stdout, logger); err != nil {
		return fmt.Errorf("emit bootstrap invite: %w", err)
	}
	policyDocument, err := json.Marshal(api.DefaultServerPolicyDocument())
	if err != nil {
		return fmt.Errorf("marshal default server policy: %w", err)
	}
	storedPolicy, err := store.EnsureServerPolicySnapshot(ctx, policyDocument)
	if err != nil {
		return fmt.Errorf("ensure default server policy snapshot: %w", err)
	}
	policySnapshot := api.ServerPolicySnapshot{
		ID:          storedPolicy.ID,
		Hash:        storedPolicy.PolicyHash,
		CreatedTime: storedPolicy.CreatedTime,
		Document:    json.RawMessage(storedPolicy.DocumentJSON),
	}
	logger.Info("server policy ready",
		"policy_hash", policySnapshot.Hash,
		"policy_snapshot_id", policySnapshot.ID,
	)

	identityDir := filepath.Join(cfg.dataDir, "identity")
	if err := ensureWritableDir(identityDir); err != nil {
		return fmt.Errorf("prepare identity directory %q: %w", identityDir, err)
	}
	keyStore, err := identity.NewFileKeyStore(identityDir)
	if err != nil {
		return fmt.Errorf("init key store: %w", err)
	}
	ca, err := identity.LoadOrCreate(ctx, keyStore, identity.Config{Dir: identityDir})
	if err != nil {
		return fmt.Errorf("init ca: %w", err)
	}
	logger.Info("certificate authority ready",
		"identity_dir", identityDir,
		"subject", ca.Certificate().Subject.CommonName,
		"fingerprint", ca.Fingerprint(),
		"not_after", ca.Certificate().NotAfter.UTC().Format(time.RFC3339),
	)

	parentCtx := ctx
	ctx, cancel := context.WithCancel(parentCtx)
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case sig := <-sigCh:
			logger.Info("received shutdown signal, stopping gracefully", "signal", sig)
			cancel()
		case <-parentCtx.Done():
			return
		}

		sig, ok := <-sigCh
		if ok {
			logger.Warn("received second signal, forcing exit", "signal", sig)
			os.Exit(1)
		}
	}()

	stopSignals := func() {
		signal.Stop(sigCh)
		close(sigCh)
	}
	defer stopSignals()
	defer cancel()

	server := api.NewServer(api.Config{
		Address:   cfg.address,
		Port:      cfg.port,
		PublicURL: cfg.publicURL,
		Proxy: proxy.Config{
			TrustForwardedHeaders:  cfg.trustProxy,
			TrustClientCertHeaders: cfg.trustClientCertHeaders,
			TrustedNetworks:        cfg.trustedProxyRanges,
		},
		Store:           store,
		EnrollmentStore: store,
		CA:              ca,
		PolicySnapshot:  policySnapshot,
	}, logger)
	return app.New(server, logger).Serve(ctx)
}

type serveConfig struct {
	address                string
	port                   int
	logFormat              string
	configDir              string
	dataDir                string
	databasePath           string
	publicURL              *url.URL
	trustProxy             bool
	trustClientCertHeaders bool
	trustedProxyCIDRs      []string
	trustedProxyRanges     []*net.IPNet
}

func parseServeConfig(args []string) (serveConfig, error) {
	trustedProxyCIDRs := envString("SPIVOT_TRUSTED_PROXY_CIDRS", strings.Join(proxy.DefaultTrustedProxyCIDRs(), ","))
	trustProxy, err := envBool("SPIVOT_TRUST_PROXY", false)
	if err != nil {
		return serveConfig{}, err
	}
	trustClientCertHeaders, err := envBool("SPIVOT_TRUST_CLIENT_CERT_HEADERS", false)
	if err != nil {
		return serveConfig{}, err
	}
	cfg := serveConfig{
		address:                envString("SPIVOT_ADDR", defaultAddress),
		port:                   envInt("SPIVOT_PORT", defaultPort),
		logFormat:              envString("SPIVOT_LOG_FORMAT", defaultLogFormat),
		configDir:              envString("SPIVOT_CONFIG_DIR", defaultConfigDir),
		dataDir:                envString("SPIVOT_DATA_DIR", defaultDataDir),
		databasePath:           envString("SPIVOT_DATABASE_PATH", ""),
		trustProxy:             trustProxy,
		trustClientCertHeaders: trustClientCertHeaders,
		trustedProxyCIDRs:      splitCSV(trustedProxyCIDRs),
	}

	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&cfg.address, "addr", cfg.address, "listen address")
	flags.IntVar(&cfg.port, "port", cfg.port, "listen port")
	flags.StringVar(&cfg.logFormat, "log-format", cfg.logFormat, "log format: text or json")
	flags.StringVar(&cfg.configDir, "config-dir", cfg.configDir, "configuration directory")
	flags.StringVar(&cfg.dataDir, "data-dir", cfg.dataDir, "persistent data directory")
	flags.StringVar(&cfg.databasePath, "database-path", cfg.databasePath, "SQLite database path")
	flags.BoolVar(&cfg.trustProxy, "trust-proxy", cfg.trustProxy, "trust X-Forwarded-* headers from trusted proxy CIDRs")
	flags.BoolVar(&cfg.trustClientCertHeaders, "trust-client-cert-headers", cfg.trustClientCertHeaders, "trust X-Forwarded-Tls-Client-Cert* headers from trusted proxy CIDRs")
	flags.Func("public-url", "public base URL advertised by the edge proxy", func(value string) error {
		publicURL, err := parsePublicURL(value)
		if err != nil {
			return err
		}
		cfg.publicURL = publicURL
		return nil
	})
	flags.Func("trusted-proxy-cidrs", "comma-separated trusted proxy CIDRs", func(value string) error {
		cfg.trustedProxyCIDRs = splitCSV(value)
		return nil
	})
	if err := flags.Parse(args); err != nil {
		return cfg, fmt.Errorf("parse serve flags: %w", err)
	}
	if flags.NArg() != 0 {
		return cfg, fmt.Errorf("unexpected serve argument: %s", flags.Arg(0))
	}
	if cfg.port <= 0 || cfg.port > 65535 {
		return cfg, fmt.Errorf("invalid port: %d", cfg.port)
	}
	if cfg.logFormat != "text" && cfg.logFormat != "json" {
		return cfg, fmt.Errorf("unknown log format: %q (expected text or json)", cfg.logFormat)
	}
	cfg.configDir = filepath.Clean(cfg.configDir)
	cfg.dataDir = filepath.Clean(cfg.dataDir)
	if cfg.databasePath == "" {
		cfg.databasePath = filepath.Join(cfg.dataDir, "spivot.db")
	} else {
		cfg.databasePath = filepath.Clean(cfg.databasePath)
	}
	if cfg.publicURL == nil {
		publicURL, err := parsePublicURL(envString(envPublicURL, ""))
		if err != nil {
			return cfg, err
		}
		cfg.publicURL = publicURL
	}
	cfg.trustedProxyRanges, err = proxy.ParseCIDRs(cfg.trustedProxyCIDRs)
	if err != nil {
		return cfg, fmt.Errorf("parse trusted proxy CIDRs: %w", err)
	}
	return cfg, nil
}

func ensureRuntimePaths(cfg serveConfig) error {
	if err := ensureWritableDir(cfg.dataDir); err != nil {
		return fmt.Errorf("prepare data directory %q: %w", cfg.dataDir, err)
	}
	databaseDir := filepath.Dir(cfg.databasePath)
	if err := ensureWritableDir(databaseDir); err != nil {
		return fmt.Errorf("prepare database directory %q: %w", databaseDir, err)
	}
	if err := ensureOptionalConfigDir(cfg.configDir); err != nil {
		return err
	}
	return nil
}

func ensureWritableDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("not a directory")
	}
	f, err := os.CreateTemp(dir, ".spivot-write-test-*")
	if err != nil {
		return fmt.Errorf("write test: %w", err)
	}
	name := f.Name()
	if err := f.Close(); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("close write test: %w", err)
	}
	if err := os.Remove(name); err != nil {
		return fmt.Errorf("remove write test: %w", err)
	}
	return nil
}

func ensureOptionalConfigDir(dir string) error {
	info, err := os.Stat(dir)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("config path %q is not a directory", dir)
		}
		return nil
	}
	if os.IsNotExist(err) {
		return nil
	}
	return fmt.Errorf("stat config directory %q: %w", dir, err)
}

func runHealthcheck(ctx context.Context, args []string) error {
	url := envString("SPIVOT_HEALTHCHECK_URL", "http://127.0.0.1:8080/health")
	timeout := 3 * time.Second

	flags := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&url, "url", url, "health endpoint URL")
	flags.DurationVar(&timeout, "timeout", timeout, "request timeout")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("parse healthcheck flags: %w", err)
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected healthcheck argument: %s", flags.Arg(0))
	}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build healthcheck request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("healthcheck request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("healthcheck failed: %s", resp.Status)
	}
	return nil
}

// bootstrapInviteLifetime is how long a self-issued first-run invite stays
// valid. Long enough that an operator can copy it from their container
// logs into the first administrator's app without urgency; short enough
// that a leaked log line that nobody notices for a day stops mattering.
const bootstrapInviteLifetime = 24 * time.Hour

// emitBootstrapInviteIfNeeded mints and announces a fresh
// server_registration invite when the server has never registered a
// user and has no active bootstrap invite outstanding. It is the
// operator-facing "first run" UX for unattended container deployments:
// the operator runs the container, watches stdout (or `docker logs`),
// copies the printed token, and uses it to enroll the first
// administrator.
//
// The function makes two storage observations (AccountCount,
// UnconsumedInviteCount) and one mutation (IssueInvite). When the
// observations both return zero it mints a single-use invite of
// [bootstrapInviteLifetime] duration, writes a fenced banner to stdout,
// and emits a structured slog audit record naming the token hash and
// expiry.
//
// Lifecycle invariants:
//
//   - When the accounts table is non-empty (some user has registered)
//     this is a no-op for the lifetime of the deployment.
//   - When a server_registration invite is already active, a single
//     informational slog event ("bootstrap invite already active") is
//     emitted and stdout is untouched, so operator restarts during the
//     24-hour window stay quiet.
//   - When the previous bootstrap invite has expired unconsumed,
//     UnconsumedInviteCount returns zero again and a fresh banner is
//     emitted on the next call.
//
// The check-then-act sequence (read counts, then mint) is not
// transactional. Two processes starting concurrently against the same
// database could each pass both checks and each call IssueInvite,
// producing two bootstrap invites instead of one. This is intentional:
// both invites are single-use, both expire in 24 hours, and the
// duplicate is operator-visible noise rather than a correctness bug.
// Production deployments run a single spivot-server process per
// database, so the race is not actually reachable today.
func emitBootstrapInviteIfNeeded(ctx context.Context, store *storage.Store, stdout io.Writer, logger *slog.Logger) error {
	accountCount, err := store.AccountCount(ctx)
	if err != nil {
		return fmt.Errorf("count accounts: %w", err)
	}
	if accountCount > 0 {
		return nil
	}
	pending, err := store.UnconsumedInviteCount(ctx, opencaravan.InviteScopeServerRegistration)
	if err != nil {
		return fmt.Errorf("count unconsumed bootstrap invites: %w", err)
	}
	if pending > 0 {
		logger.Info("bootstrap invite already active; not re-emitting",
			"scope", opencaravan.InviteScopeServerRegistration,
			"active_count", pending,
		)
		return nil
	}

	token, invite, err := store.IssueInvite(ctx, opencaravan.InviteScopeServerRegistration, bootstrapInviteLifetime)
	if err != nil {
		return fmt.Errorf("issue bootstrap invite: %w", err)
	}

	if _, err := io.WriteString(stdout, formatBootstrapBanner(token)); err != nil {
		return fmt.Errorf("print bootstrap banner: %w", err)
	}
	logger.Info("bootstrap invite issued",
		"scope", invite.Scope,
		"token_hash", invite.TokenHash,
		"expiration_time", invite.ExpirationTime,
		"lifetime", bootstrapInviteLifetime,
	)
	return nil
}

func formatBootstrapBanner(token opencaravan.InviteToken) string {
	const bar = "████████████████████████████████████████████████████████████████████"
	const div = "  ────────────────────────────────────────────────────────────────"
	return "\n" + bar + "\n" +
		"  SPIVOT SERVER FIRST-RUN BOOTSTRAP\n" +
		div + "\n" +
		"  No administrator is registered. Use this server_registration\n" +
		"  invite to enroll the first user. Single-use, 24h expiry.\n" +
		"\n" +
		"      " + token.Value + "\n" +
		"\n" +
		"  iOS app: Settings → Add Account → Use Invite\n" +
		bar + "\n"
}

func runInvite(ctx context.Context, stdout io.Writer, args []string) error {
	if len(args) == 0 {
		return errors.New("invite requires a subcommand: create")
	}
	sub := args[0]
	flags := flag.NewFlagSet("invite "+sub, flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	dataDir := envString("SPIVOT_DATA_DIR", defaultDataDir)
	databasePath := envString("SPIVOT_DATABASE_PATH", "")
	scope := envString("SPIVOT_INVITE_SCOPE", string(opencaravan.InviteScopeServerRegistration))
	lifetime := 24 * time.Hour
	flags.StringVar(&dataDir, "data-dir", dataDir, "persistent data directory")
	flags.StringVar(&databasePath, "database-path", databasePath, "SQLite database path (default: <data-dir>/spivot.db)")
	flags.StringVar(&scope, "scope", scope, "invite scope: server_registration or journey")
	flags.DurationVar(&lifetime, "lifetime", lifetime, "invite lifetime")
	if err := flags.Parse(args[1:]); err != nil {
		return fmt.Errorf("parse invite %s flags: %w", sub, err)
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected invite %s argument: %s", sub, flags.Arg(0))
	}

	switch sub {
	case "create":
		dataDir = filepath.Clean(dataDir)
		if databasePath == "" {
			databasePath = filepath.Join(dataDir, "spivot.db")
		}
		if err := ensureWritableDir(dataDir); err != nil {
			return fmt.Errorf("prepare data directory %q: %w", dataDir, err)
		}
		if err := ensureWritableDir(filepath.Dir(databasePath)); err != nil {
			return fmt.Errorf("prepare database directory: %w", err)
		}

		store, err := storage.Open(ctx, storage.Config{Path: databasePath})
		if err != nil {
			return err
		}
		defer func() {
			_ = store.Close()
		}()

		inviteScope := opencaravan.InviteScope(scope)
		token, invite, err := store.IssueInvite(ctx, inviteScope, lifetime)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout,
			"invite issued\n  scope:           %s\n  expiration_time: %s\n  token_hash:      %s\n\n  token:           %s\n",
			invite.Scope,
			invite.ExpirationTime.Format(time.RFC3339),
			invite.TokenHash,
			token.Value,
		)
		return err
	default:
		return fmt.Errorf("unknown invite subcommand: %s (expected create)", sub)
	}
}

func runCA(ctx context.Context, stdout io.Writer, args []string) error {
	if len(args) == 0 {
		return errors.New("ca requires a subcommand: init or cert")
	}
	sub := args[0]
	flags := flag.NewFlagSet("ca "+sub, flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	dataDir := envString("SPIVOT_DATA_DIR", defaultDataDir)
	flags.StringVar(&dataDir, "data-dir", dataDir, "persistent data directory")
	commonName := envString("SPIVOT_CA_COMMON_NAME", "")
	organization := envString("SPIVOT_CA_ORGANIZATION", "")
	flags.StringVar(&commonName, "common-name", commonName, "CA certificate subject common name (init only)")
	flags.StringVar(&organization, "organization", organization, "CA certificate subject organization (init only)")
	if err := flags.Parse(args[1:]); err != nil {
		return fmt.Errorf("parse ca %s flags: %w", sub, err)
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected ca %s argument: %s", sub, flags.Arg(0))
	}

	identityDir := filepath.Join(filepath.Clean(dataDir), "identity")
	if err := ensureWritableDir(identityDir); err != nil {
		return fmt.Errorf("prepare identity directory %q: %w", identityDir, err)
	}
	keyStore, err := identity.NewFileKeyStore(identityDir)
	if err != nil {
		return err
	}

	switch sub {
	case "init":
		subject := pkix.Name{}
		if commonName != "" {
			subject.CommonName = commonName
		}
		if organization != "" {
			subject.Organization = []string{organization}
		}
		ca, err := identity.LoadOrCreate(ctx, keyStore, identity.Config{
			Dir:     identityDir,
			Subject: subject,
		})
		if err != nil {
			return err
		}
		cert := ca.Certificate()
		_, err = fmt.Fprintf(stdout,
			"CA initialized at %s\n  subject:     %s\n  not_before:  %s\n  not_after:   %s\n  fingerprint: %s\n",
			identityDir,
			cert.Subject,
			cert.NotBefore.Format(time.RFC3339),
			cert.NotAfter.Format(time.RFC3339),
			ca.Fingerprint(),
		)
		return err
	case "cert":
		ca, err := identity.LoadOrCreate(ctx, keyStore, identity.Config{Dir: identityDir})
		if err != nil {
			return err
		}
		_, err = stdout.Write(ca.CertificatePEM())
		return err
	default:
		return fmt.Errorf("unknown ca subcommand: %s (expected init or cert)", sub)
	}
}

func runVersion(w io.Writer, outputFmt string) error {
	info := buildinfo.BuildInfo()
	if outputFmt == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(info)
	}

	output := buildinfo.String() + "\n"
	for _, k := range []string{"version", "git_commit", "git_branch", "build_time", "go_version", "os", "arch"} {
		if v, ok := info[k]; ok {
			output += fmt.Sprintf("  %-12s %s\n", k+":", v)
		}
	}
	_, err := io.WriteString(w, output)
	return err
}

func printUsage(w io.Writer) error {
	_, err := io.WriteString(w, `Spivot Server - backend API service

Usage: spivot-server [flags] <command> [args]

Commands:
  serve         Start the API server
  healthcheck   Check a running server's health endpoint
  ca            Manage the server-local certificate authority
  invite        Issue invite tokens for client app enrollment
  version       Show version information

Global flags:
  -o, --output fmt  Output format: text (default) or json

Serve flags:
  -addr value        Listen address (default: SPIVOT_ADDR or 0.0.0.0)
  -port value        Listen port (default: SPIVOT_PORT or 8080)
  -log-format value  Log format: text or json (default: SPIVOT_LOG_FORMAT or text)
  -config-dir value  Configuration directory (default: SPIVOT_CONFIG_DIR or config)
  -data-dir value    Persistent data directory (default: SPIVOT_DATA_DIR or data)
  -database-path value
                    SQLite database path (default: SPIVOT_DATABASE_PATH or <data-dir>/spivot.db)
  -public-url value  Public base URL served by the edge proxy (default: SPIVOT_PUBLIC_URL)
  -trust-proxy       Trust X-Forwarded-* headers from configured proxy CIDRs
  -trust-client-cert-headers
                     Trust X-Forwarded-Tls-Client-Cert* headers from trusted
                     proxy CIDRs (default: SPIVOT_TRUST_CLIENT_CERT_HEADERS)
  -trusted-proxy-cidrs value
                    Comma-separated trusted proxy CIDRs (default: SPIVOT_TRUSTED_PROXY_CIDRS)

CA subcommands:
  ca init       Generate the server-local CA keypair and self-signed root
                certificate if they do not already exist. Re-running on an
                existing CA loads it and prints its fingerprint.
  ca cert       Print the CA's self-signed certificate as PEM. Useful for
                bundling with clients so they can validate server-issued
                leaf certificates.

CA flags:
  -data-dir value      Persistent data directory (default: SPIVOT_DATA_DIR or data)
  -common-name value   CA subject common name (default: "Spivot Server CA")
  -organization value  CA subject organization (default: unset)

Invite subcommands:
  invite create  Issue an invite token for client app enrollment. Prints the
                 plaintext token exactly once; only its hash is persisted.

Invite flags:
  -data-dir value       Persistent data directory (default: SPIVOT_DATA_DIR or data)
  -database-path value  SQLite database path (default: <data-dir>/spivot.db)
  -scope value          Invite scope: server_registration (default) or journey
  -lifetime value       Invite lifetime (default: 24h, accepts Go duration syntax)
`)
	return err
}

func newLogger(w io.Writer, level slog.Level, format string) *slog.Logger {
	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: true,
	}
	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(w, opts)
	} else {
		handler = slog.NewTextHandler(w, opts)
	}
	return slog.New(handler).With(
		"spivot_version", buildinfo.Version,
		"spivot_commit", buildinfo.GitCommit,
	)
}

func envString(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func envBool(key string, fallback bool) (bool, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}
	b, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("parse %s: %w", key, err)
	}
	return b, nil
}

func envInt(key string, fallback int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		i, err := strconv.Atoi(v)
		if err == nil {
			return i
		}
	}
	return fallback
}

func parsePublicURL(value string) (*url.URL, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	publicURL, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", envPublicURL, err)
	}
	if publicURL.Scheme != "http" && publicURL.Scheme != "https" {
		return nil, fmt.Errorf("%s must use http or https: %s", envPublicURL, value)
	}
	if publicURL.Host == "" {
		return nil, fmt.Errorf("%s must include a host: %s", envPublicURL, value)
	}
	if publicURL.RawQuery != "" || publicURL.Fragment != "" {
		return nil, fmt.Errorf("%s must not include query or fragment: %s", envPublicURL, value)
	}
	publicURL.Path = strings.TrimRight(publicURL.Path, "/")
	return publicURL, nil
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			values = append(values, part)
		}
	}
	return values
}
