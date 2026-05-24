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
	"encoding/json"
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

	"github.com/wheelsdown/spivot-server/internal/app"
	"github.com/wheelsdown/spivot-server/internal/platform/buildinfo"
	"github.com/wheelsdown/spivot-server/internal/platform/proxy"
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
			TrustForwardedHeaders: cfg.trustProxy,
			TrustedNetworks:       cfg.trustedProxyRanges,
		},
	}, logger)
	return app.New(server, logger).Serve(ctx)
}

type serveConfig struct {
	address            string
	port               int
	logFormat          string
	configDir          string
	dataDir            string
	databasePath       string
	publicURL          *url.URL
	trustProxy         bool
	trustedProxyCIDRs  []string
	trustedProxyRanges []*net.IPNet
}

func parseServeConfig(args []string) (serveConfig, error) {
	trustedProxyCIDRs := envString("SPIVOT_TRUSTED_PROXY_CIDRS", strings.Join(proxy.DefaultTrustedProxyCIDRs(), ","))
	trustProxy, err := envBool("SPIVOT_TRUST_PROXY", false)
	if err != nil {
		return serveConfig{}, err
	}
	cfg := serveConfig{
		address:           envString("SPIVOT_ADDR", defaultAddress),
		port:              envInt("SPIVOT_PORT", defaultPort),
		logFormat:         envString("SPIVOT_LOG_FORMAT", defaultLogFormat),
		configDir:         envString("SPIVOT_CONFIG_DIR", defaultConfigDir),
		dataDir:           envString("SPIVOT_DATA_DIR", defaultDataDir),
		databasePath:      envString("SPIVOT_DATABASE_PATH", ""),
		trustProxy:        trustProxy,
		trustedProxyCIDRs: splitCSV(trustedProxyCIDRs),
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
  -trusted-proxy-cidrs value
                    Comma-separated trusted proxy CIDRs (default: SPIVOT_TRUSTED_PROXY_CIDRS)
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
