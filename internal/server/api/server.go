// Package api implements the Spivot HTTP API.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/wheelsdown/spivot-server/internal/platform/buildinfo"
	"github.com/wheelsdown/spivot-server/internal/platform/identity"
	"github.com/wheelsdown/spivot-server/internal/platform/logging"
	"github.com/wheelsdown/spivot-server/internal/platform/proxy"
	"github.com/wheelsdown/spivot-server/internal/platform/storage"
	"github.com/wheelsdown/spivot-server/internal/server/middleware"
)

// Store is the narrow database behavior the API server needs for the
// readiness probe. Defined as an interface so server_test.go can pass a
// minimal fake without standing up a real SQLite store; concrete callers
// pass [*storage.Store].
type Store interface {
	// Ping verifies that the backing store is reachable.
	Ping(context.Context) error
}

// EnrollmentStore is the narrow subset of storage operations the
// client-app enrollment handler needs. Kept distinct from [Store] so
// each handler depends only on the capabilities it exercises and so
// readiness-only tests do not have to implement enrollment plumbing.
// The production implementation is [*storage.Store], which satisfies
// both interfaces via duck-typing.
type EnrollmentStore interface {
	// LookupInvite returns the persisted invite for the supplied
	// plaintext token. See [storage.Store.LookupInvite].
	LookupInvite(ctx context.Context, tokenValue string) (storage.Invite, error)
	// RegisterClientApp atomically writes the four-table state change
	// for a successful enrollment. See [storage.Store.RegisterClientApp].
	RegisterClientApp(ctx context.Context, reg storage.ClientAppRegistration) (storage.Invite, error)
}

// IdentityStore is the narrow subset of storage operations the
// identity middleware needs to resolve a client certificate to the
// enrolled identity it authorizes. Satisfied by [*storage.Store] via
// duck-typing; the same separation rationale as EnrollmentStore.
type IdentityStore = middleware.IdentityStore

// Config describes the HTTP API server's listen and deployment metadata.
type Config struct {
	// Address is the local TCP address to bind.
	Address string
	// Port is the local TCP port to bind.
	Port int
	// PublicURL is the canonical URL served by the edge proxy.
	PublicURL *url.URL
	// Proxy controls whether forwarded request metadata is trusted.
	Proxy proxy.Config
	// Store is the runtime database dependency used by the readiness
	// probe. May be nil; the probe degrades to "always ready" when no
	// store is wired (useful for the health-only test surface).
	Store Store
	// EnrollmentStore backs the client-app enrollment handler. May be
	// nil, in which case POST /v1/client-apps/enroll responds 503 so
	// readiness-only deployments are not silently routing enrollment
	// requests into a void.
	EnrollmentStore EnrollmentStore
	// CA signs the leaf certificates returned by the enrollment
	// handler. May be nil with the same semantics as EnrollmentStore;
	// both must be set for enrollment to succeed.
	CA *identity.CA
	// IdentityStore backs the [middleware.AttachIdentity] pass. When
	// nil, [Server.Handler] omits the attach pass and no request ever
	// carries a context-attached identity; [middleware.RequireIdentity]-
	// guarded handlers (none exist today, Phase 4 will add the first)
	// would always 401. Production wires [*storage.Store] here.
	IdentityStore IdentityStore
	// PolicySnapshot is captured by value at server startup and advertised to
	// clients until the process restarts. Runtime policy rotation should make
	// that lifecycle explicit rather than mutating this value in place.
	PolicySnapshot ServerPolicySnapshot
}

// ListenAddr returns the TCP address used by the HTTP server.
func (c Config) ListenAddr() string {
	return net.JoinHostPort(c.Address, strconv.Itoa(c.Port))
}

// Server is the HTTP API server.
type Server struct {
	cfg    Config
	logger *slog.Logger
	server *http.Server
}

// NewServer creates a Spivot API server with the provided configuration.
func NewServer(cfg Config, logger *slog.Logger) *Server {
	return &Server{
		cfg:    cfg,
		logger: logger,
	}
}

// Handler returns the API HTTP handler.
//
// Middleware composition (outermost first):
//
//  1. withLogging — emits the per-request access log; runs outermost
//     so an attached identity (added by AttachIdentity below) shows
//     up in the log line.
//  2. AttachIdentity — when [Config.IdentityStore] is set, resolves
//     any inbound client cert to a server-side Identity and attaches
//     it to the request context. Never rejects; unauthenticated
//     requests pass through.
//  3. The route mux. Individual handlers wrap themselves in
//     [middleware.RequireIdentity] at the registration site when they
//     require an Identity to be present.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.handleRoot)
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	mux.HandleFunc("GET /v1/server", s.handleServerInfo)
	mux.HandleFunc("GET /v1/version", s.handleVersion)
	mux.HandleFunc("POST /v1/client-apps/enroll", s.handleClientAppEnroll)

	var inner http.Handler = mux
	if s.cfg.IdentityStore != nil {
		inner = middleware.AttachIdentity(s.cfg.IdentityStore, s.cfg.Proxy, s.logger)(inner)
	}
	return s.withLogging(inner)
}

// Start begins serving HTTP requests until the server shuts down.
func (s *Server) Start(ctx context.Context) error {
	s.server = &http.Server{
		Addr:              s.cfg.ListenAddr(),
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		BaseContext: func(net.Listener) context.Context {
			return ctx
		},
	}

	displayAddress := s.cfg.Address
	if displayAddress == "" || displayAddress == "0.0.0.0" {
		displayAddress = "0.0.0.0"
	}
	s.logger.Info("starting API server",
		"address", displayAddress,
		"port", s.cfg.Port,
		"public_url", s.publicURLString(),
		"trust_proxy", s.cfg.Proxy.TrustForwardedHeaders,
		"trusted_proxy_networks", len(s.cfg.Proxy.TrustedNetworks),
	)
	err := s.server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.server == nil {
		return nil
	}
	return s.server.Shutdown(ctx)
}

func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := logging.NewAccessResponseWriter(w)
		next.ServeHTTP(rw, r)
		reqInfo := proxy.RequestInfoFrom(r, s.cfg.Proxy)
		s.logger.Info("request handled",
			"kind", "http_access",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.StatusCode(),
			"response_bytes", rw.BytesWritten(),
			"duration_ms", time.Since(start).Milliseconds(),
			"client_ip", reqInfo.ClientIP,
			"scheme", reqInfo.Scheme,
			"host", reqInfo.Host,
			"trusted_proxy", reqInfo.TrustedProxy,
		)
	})
}

func (s *Server) handleRoot(w http.ResponseWriter, _ *http.Request) {
	response := map[string]string{
		"name":    "Spivot Server",
		"version": buildinfo.Version,
		"status":  "ok",
	}
	if publicURL := s.publicURLString(); publicURL != "" {
		response["public_url"] = publicURL
	}
	writeJSON(w, response, s.logger)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]string{
		"status":  "healthy",
		"version": buildinfo.Version,
		"uptime":  buildinfo.Uptime().String(),
	}, s.logger)
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Store != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := s.cfg.Store.Ping(ctx); err != nil {
			s.logger.Warn("readiness check failed", "error", err)
			writeJSONStatus(w, http.StatusServiceUnavailable, map[string]string{
				"status":  "unready",
				"version": buildinfo.Version,
			}, s.logger)
			return
		}
	}

	writeJSON(w, map[string]string{
		"status":  "ready",
		"version": buildinfo.Version,
	}, s.logger)
}

func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, buildinfo.RuntimeInfo(), s.logger)
}

func (s *Server) handleServerInfo(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.serverInfo(), s.logger)
}

func writeJSON(w http.ResponseWriter, v any, logger *slog.Logger) {
	writeJSONStatus(w, http.StatusOK, v, logger)
}

func writeJSONStatus(w http.ResponseWriter, status int, v any, logger *slog.Logger) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		logger.Debug("failed to write JSON response", "error", err)
	}
}

// URL returns the public URL when configured, otherwise the local listen URL.
func (s *Server) URL() string {
	if publicURL := s.publicURLString(); publicURL != "" {
		return publicURL
	}
	return fmt.Sprintf("http://%s", s.cfg.ListenAddr())
}

func (s *Server) publicURLString() string {
	if s.cfg.PublicURL == nil {
		return ""
	}
	return s.cfg.PublicURL.String()
}
