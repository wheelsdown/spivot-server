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

	"github.com/opencaravan/opencaravan-go"
	"github.com/wheelsdown/spivot-server/internal/platform/auth/macaroon"
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

// JourneyStore is the narrow subset of storage operations the
// Phase 5 journey + telemetry handlers depend on. Satisfied by
// [*storage.Store] via duck-typing.
type JourneyStore interface {
	// CreateJourney inserts a journeys row and a host
	// journey_participants row in one transaction. See
	// [storage.Store.CreateJourney].
	CreateJourney(ctx context.Context, params storage.JourneyCreateParams) (storage.Journey, error)
	// JourneyByID returns the journey with the supplied id.
	// Returns [storage.ErrJourneyNotFound] when no row matches.
	JourneyByID(ctx context.Context, id string) (storage.Journey, error)
	// JourneyParticipantByUserAndJourney looks up the joined
	// participant row for the (user, journey) pair. Used by the
	// telemetry handler to resolve the per-batch participant_id
	// and enforce "the caller is actually in this journey"
	// beyond the macaroon's journey= caveat check.
	JourneyParticipantByUserAndJourney(ctx context.Context, userID, journeyID string) (storage.JourneyParticipant, error)
	// RecordTelemetryBatch inserts a telemetry_batches row.
	RecordTelemetryBatch(ctx context.Context, params storage.TelemetryBatchParams) (storage.TelemetryBatch, error)
}

// VehicleStore is the narrow subset of storage operations the
// Phase 2 journey-vehicle handlers depend on. Satisfied by
// [*storage.Store] via duck-typing.
type VehicleStore interface {
	// CreateJourneyVehicle persists a journey-scoped Vehicle and
	// its initial signed ACL revision in one transaction. See
	// [storage.Store.CreateJourneyVehicle].
	CreateJourneyVehicle(ctx context.Context, params storage.JourneyVehicleCreateParams) (storage.JourneyVehicleRecord, error)
	// JourneyVehicleByID returns the persisted vehicle with the
	// supplied (journey_id, vehicle_id) pair. Returns
	// [storage.ErrJourneyVehicleNotFound] when no row matches.
	JourneyVehicleByID(ctx context.Context, journeyID, vehicleID string) (storage.JourneyVehicleRecord, error)
	// ListJourneyVehicles returns every vehicle uploaded against
	// a journey, ordered by created_at ascending.
	ListJourneyVehicles(ctx context.Context, journeyID string) ([]storage.JourneyVehicleRecord, error)
	// AppendJourneyVehicleACL records a new VehicleACL revision
	// and advances the journey vehicle's current_acl_version
	// pointer when the supplied revision is strictly greater than
	// the existing version. See
	// [storage.Store.AppendJourneyVehicleACL].
	AppendJourneyVehicleACL(ctx context.Context, params storage.JourneyVehicleACLAppendParams) (storage.JourneyVehicleACLRevision, error)
}

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
	// carries a context-attached identity; every
	// [middleware.RequireIdentity]-guarded handler (POST /v1/sessions
	// today, more in later phases) would always 401. Production wires
	// [*storage.Store] here.
	IdentityStore IdentityStore
	// MacaroonIssuer backs POST /v1/sessions. May be nil with the
	// same semantics as EnrollmentStore: the handler responds 503
	// when not wired so a misconfigured deployment surfaces
	// explicitly rather than silently 401-ing.
	MacaroonIssuer *macaroon.Issuer
	// MacaroonVerifier backs the [middleware.AttachSession] broad
	// attach pass. When nil, [Server.Handler] omits the attach
	// pass and no request ever carries a context-attached
	// session; every [middleware.RequireSession]-guarded handler
	// (POST /v1/journeys/{id}/* today, more in later phases)
	// would always 401. Production wires a verifier whose root
	// resolver delegates to [*storage.Store.MacaroonRootByID].
	MacaroonVerifier *macaroon.Verifier
	// JourneyStore backs the Phase 5 journey + telemetry
	// handlers. May be nil; the handlers respond 503 when not
	// wired so a misconfigured deployment surfaces explicitly.
	JourneyStore JourneyStore
	// VehicleStore backs the Phase 2 journey-vehicle handlers
	// (POST/GET /v1/journeys/{id}/vehicles and the ACL revision
	// endpoint). May be nil; the handlers respond 503 when not
	// wired so a misconfigured deployment surfaces explicitly.
	VehicleStore VehicleStore
	// AccessLogger receives the per-request "request handled" log
	// line emitted by [Server.Handler]'s access-logging
	// middleware. When nil, the server-level application logger
	// passed to [NewServer] is used, so application logs and
	// access logs share the same destination (the historical
	// behavior and the local-dev default). When set, access logs
	// route to this logger only — typically a file handle so an
	// operator can run a separate log shipper, rotate
	// independently of stdout, or simply keep container stdout
	// focused on application events. The level, format, and
	// handler are the caller's choice; this package only writes
	// records.
	AccessLogger *slog.Logger
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
//  1. withRequestInfo — parses forwarded headers and TLS peer state
//     into a [proxy.RequestInfo] exactly once per request and stashes
//     it on the context. Downstream middleware reads from the cache
//     instead of repeating the PEM decode + x509 parse + SHA-256
//     work.
//  2. AttachIdentity — when [Config.IdentityStore] is set, resolves
//     any inbound client cert (via the cached RequestInfo) to a
//     server-side Identity and attaches it to the request context.
//     Never rejects; unauthenticated requests pass through.
//  3. AttachSession — when [Config.MacaroonVerifier] is set, lifts
//     any inbound Authorization: Macaroon header, verifies the
//     macaroon signature, and attaches a server-side Session to
//     the request context. Never rejects; the per-handler
//     [middleware.RequireSession] guard is the place that 401s.
//  4. withLogging — emits the per-request access log. Runs inside
//     the two attach passes so withLogging's request context
//     carries the cached RequestInfo, the resolved Identity, and
//     (when present) the verified Session — every observable
//     dimension surfaces on the access log line.
//  5. The route mux. Individual handlers wrap themselves in
//     [middleware.RequireIdentity] or [middleware.RequireSession]
//     at the registration site when they require those layers.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.handleRoot)
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	mux.HandleFunc("GET /v1/server", s.handleServerInfo)
	mux.HandleFunc("GET /v1/version", s.handleVersion)
	mux.HandleFunc("POST /v1/client-apps/enroll", s.handleClientAppEnroll)
	// POST /v1/sessions requires a resolved identity. Wrapping
	// here at the registration site keeps the auth requirement
	// visible in the route table — anyone reading Handler() can
	// see at a glance which routes are public and which require
	// an enrolled client app.
	mux.Handle("POST /v1/sessions", middleware.RequireIdentity(s.logger, http.HandlerFunc(s.handleSessionCreate)))
	// POST /v1/journeys is identity-only (the caller creates a new
	// journey before any macaroon could reference it), so it is
	// registered unconditionally — deployments that intentionally
	// omit the session stack still need to be able to create
	// journeys. The handler's own 503 path covers the
	// JourneyStore-not-wired case.
	mux.Handle("POST /v1/journeys", middleware.RequireIdentity(s.logger, http.HandlerFunc(s.handleJourneyCreate)))
	// The journey-scoped routes require a session macaroon naming
	// the requested journey and the appropriate action; the
	// per-handler constraints run through
	// verifier.CheckConstraints so attenuator attacks against the
	// journey caveat are defeated by macaroon AND semantics.
	// Registered only when MacaroonVerifier is wired: without a
	// verifier, RequireSession would always 401 and the routes
	// would be dead code.
	if s.cfg.MacaroonVerifier != nil {
		mux.Handle("GET /v1/journeys/{id}", middleware.RequireSession(s.cfg.MacaroonVerifier, s.logger,
			middleware.SessionActionJourneyFromPath(opencaravan.SessionActionJourneyRead, "id"),
		)(http.HandlerFunc(s.handleJourneyGet)))
		mux.Handle("POST /v1/journeys/{id}/telemetry", middleware.RequireSession(s.cfg.MacaroonVerifier, s.logger,
			middleware.SessionActionJourneyFromPath(opencaravan.SessionActionTelemetryWrite, "id"),
		)(http.HandlerFunc(s.handleJourneyTelemetry)))
		mux.Handle("POST /v1/journeys/{id}/vehicles", middleware.RequireSession(s.cfg.MacaroonVerifier, s.logger,
			middleware.SessionActionJourneyFromPath(opencaravan.SessionActionJourneyWrite, "id"),
		)(http.HandlerFunc(s.handleJourneyVehicleCreate)))
		mux.Handle("GET /v1/journeys/{id}/vehicles", middleware.RequireSession(s.cfg.MacaroonVerifier, s.logger,
			middleware.SessionActionJourneyFromPath(opencaravan.SessionActionJourneyRead, "id"),
		)(http.HandlerFunc(s.handleJourneyVehicleList)))
		mux.Handle("GET /v1/journeys/{id}/vehicles/{vid}", middleware.RequireSession(s.cfg.MacaroonVerifier, s.logger,
			middleware.SessionActionJourneyFromPath(opencaravan.SessionActionJourneyRead, "id"),
		)(http.HandlerFunc(s.handleJourneyVehicleGet)))
		mux.Handle("POST /v1/journeys/{id}/vehicles/{vid}/acl-revisions", middleware.RequireSession(s.cfg.MacaroonVerifier, s.logger,
			middleware.SessionActionJourneyFromPath(opencaravan.SessionActionJourneyWrite, "id"),
		)(http.HandlerFunc(s.handleJourneyVehicleACLAppend)))
	}

	h := s.withLogging(mux)
	if s.cfg.MacaroonVerifier != nil {
		h = middleware.AttachSession(s.cfg.MacaroonVerifier, s.logger)(h)
	}
	if s.cfg.IdentityStore != nil {
		h = middleware.AttachIdentity(s.cfg.IdentityStore, s.cfg.Proxy, s.logger)(h)
	}
	return s.withRequestInfo(h)
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

// withRequestInfo parses the forwarded request metadata once per
// request and stashes the resulting [proxy.RequestInfo] on the
// context. Subsequent middleware ([middleware.AttachIdentity]) and
// the access log read from the cache via [proxy.RequestInfoFromContext]
// rather than repeating the parse, which previously included an x509
// parse + SHA-256 fingerprint on every request when client-cert
// headers were present.
func (s *Server) withRequestInfo(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info := proxy.RequestInfoFrom(r, s.cfg.Proxy)
		next.ServeHTTP(w, r.WithContext(proxy.WithRequestInfo(r.Context(), info)))
	})
}

func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := logging.NewAccessResponseWriter(w)
		next.ServeHTTP(rw, r)
		reqInfo, ok := proxy.RequestInfoFromContext(r.Context())
		if !ok {
			reqInfo = proxy.RequestInfoFrom(r, s.cfg.Proxy)
		}
		attrs := []any{
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
		}
		if id, ok := middleware.IdentityFrom(r.Context()); ok {
			attrs = append(attrs,
				"identity_user_id", id.UserID,
				"identity_client_app_id", id.ClientAppID,
				"identity_subject_cn", id.SubjectCN,
			)
		}
		if session, ok := middleware.SessionFrom(r.Context()); ok {
			attrs = append(attrs,
				"session_root_id", session.RootID,
				"session_action", string(session.Action),
			)
			if session.JourneyID != "" {
				attrs = append(attrs, "session_journey_id", string(session.JourneyID))
			}
		}
		s.accessLogger().Info("request handled", attrs...)
	})
}

// accessLogger returns the destination for per-request access log
// lines: [Config.AccessLogger] when set, otherwise the main
// application logger. Keeping the resolution in one place means a
// future change to the fallback policy (per-route loggers, severity
// filters, etc.) lands in a single function.
func (s *Server) accessLogger() *slog.Logger {
	if s.cfg.AccessLogger != nil {
		return s.cfg.AccessLogger
	}
	return s.logger
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
