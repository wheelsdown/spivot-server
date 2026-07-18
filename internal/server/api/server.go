// Package api implements the Spivot HTTP API.
package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"time"

	"github.com/opencaravan/opencaravan-go"
	"github.com/wheelsdown/spivot-server/internal/platform/auth/integrity"
	"github.com/wheelsdown/spivot-server/internal/platform/auth/macaroon"
	"github.com/wheelsdown/spivot-server/internal/platform/buildinfo"
	"github.com/wheelsdown/spivot-server/internal/platform/identity"
	"github.com/wheelsdown/spivot-server/internal/platform/logging"
	"github.com/wheelsdown/spivot-server/internal/platform/proxy"
	"github.com/wheelsdown/spivot-server/internal/platform/storage"
	"github.com/wheelsdown/spivot-server/internal/server/api/spec"
	"github.com/wheelsdown/spivot-server/internal/server/docs"
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
	// AppendJourneyVehicleRevision records a new signed Vehicle
	// metadata bundle and advances the journey vehicle's
	// current_revision_version pointer when the supplied
	// revision is strictly greater than the existing version.
	// See [storage.Store.AppendJourneyVehicleRevision].
	AppendJourneyVehicleRevision(ctx context.Context, params storage.JourneyVehicleRevisionAppendParams) (storage.JourneyVehicleRevisionRecord, error)
	// JourneyVehicleACLAt returns the ACL revision that was
	// current at the supplied time. Used by the Phase 3 driver
	// attestation trust evaluator to resolve "what could the
	// driver have known about the ACL at handoff time?"
	JourneyVehicleACLAt(ctx context.Context, journeyVehicleID string, at time.Time) (storage.JourneyVehicleACLRevision, error)
	// EnrolledCertByClientAppID returns the enrolled client app's
	// cert (with parsed *x509.Certificate carrying the public
	// key) so the handler can cross-check the signer's identity
	// against the payload's claimed owner before — and after —
	// signature verification.
	EnrolledCertByClientAppID(ctx context.Context, clientAppID string) (storage.EnrolledCertRecord, error)
}

// DriverAttestationStore is the narrow subset of storage
// operations the Phase 3 driver-attestation handlers depend on.
// Satisfied by [*storage.Store] via duck-typing.
type DriverAttestationStore interface {
	// RecordDriverAttestation persists a single driver attestation
	// with its server-evaluated trust flag. Returns
	// [storage.ErrDriverAttestationDuplicate] when the
	// (journey_vehicle_id, driver_user_id, effective_time) tuple
	// is already on file.
	RecordDriverAttestation(ctx context.Context, params storage.DriverAttestationRecordParams) (storage.DriverAttestationRecord, error)
	// DriverAttestationByReplayKey returns the existing record
	// matching the supplied tuple; used to surface the already-
	// stored record on a gossiped replay.
	DriverAttestationByReplayKey(ctx context.Context, journeyVehicleID, driverUserID string, effectiveTime time.Time) (storage.DriverAttestationRecord, error)
	// ListDriverAttestations returns every attestation for a
	// journey vehicle, ordered by effective_time ascending.
	ListDriverAttestations(ctx context.Context, journeyVehicleID string) ([]storage.DriverAttestationRecord, error)
	// DriverAttestationForkSiblings returns every attestation
	// referencing the supplied prior_attestation_hash, so the
	// handler can surface a fork warning when two drivers
	// concurrently claim the same predecessor.
	DriverAttestationForkSiblings(ctx context.Context, journeyVehicleID, priorHash string) ([]storage.DriverAttestationRecord, error)
	// CurrentDriverForJourneyVehicle returns the attestation in
	// effect at the supplied time (the highest effective_time
	// value <= at). Used by the current-driver query endpoint.
	CurrentDriverForJourneyVehicle(ctx context.Context, journeyVehicleID string, at time.Time) (storage.DriverAttestationRecord, error)
}

// GarageStore is the narrow subset of storage operations the
// garage-container handlers depend on. Satisfied by
// [*storage.Store] via duck-typing.
type GarageStore interface {
	// CreateGarage persists a new garage at revision_version = 1.
	CreateGarage(ctx context.Context, params storage.GarageCreateParams) (storage.GarageRecord, error)
	// AppendGarageRevision records a new signed Garage payload and
	// reconciles the materialized owner list. Returns
	// [storage.ErrGarageRevisionVersionConflict] when the supplied
	// version is not strictly greater than the current head.
	AppendGarageRevision(ctx context.Context, params storage.GarageAppendRevisionParams) (storage.GarageRevisionRecord, error)
	// AcceptGarageOwnership records a signed acceptance and moves
	// the corresponding owner row from pending to accepted.
	AcceptGarageOwnership(ctx context.Context, params storage.GarageAcceptOwnershipParams) (storage.GarageOwnershipAcceptanceRecord, error)
	// GarageByID returns the head-pointer projection of the supplied
	// garage. Returns [storage.ErrGarageNotFound] when no row matches.
	GarageByID(ctx context.Context, garageID string) (storage.GarageRecord, error)
	// ListGarageOwners returns every owner row for the supplied
	// garage, accepted and pending alike.
	ListGarageOwners(ctx context.Context, garageID string) ([]storage.GarageOwnerRecord, error)
	// ListGaragesForUser returns every garage in which the supplied
	// user appears as an owner (accepted or pending).
	ListGaragesForUser(ctx context.Context, userID string) ([]storage.GarageRecord, error)
	// GarageOwnerByUserAndGarage is the "is this user an owner?"
	// authorization gate. Returns [storage.ErrGarageNotFound] when
	// no row matches.
	GarageOwnerByUserAndGarage(ctx context.Context, userID, garageID string) (storage.GarageOwnerRecord, error)
	// GarageOwnershipAcceptanceByKey returns the recorded
	// acceptance matching the supplied triple. Used by the
	// handler to surface canonical stored values after an
	// idempotent replay.
	GarageOwnershipAcceptanceByKey(ctx context.Context, garageID, accepterUserID string, revisionVersion int) (storage.GarageOwnershipAcceptanceRecord, error)
	// CreateGarageVehicle persists a new garage vehicle at
	// revision_version = 1 with its initial signed revision row.
	CreateGarageVehicle(ctx context.Context, params storage.GarageVehicleCreateParams) (storage.GarageVehicleRecord, error)
	// AppendGarageVehicleRevision records a new signed
	// GarageVehicle payload and advances the head pointer.
	AppendGarageVehicleRevision(ctx context.Context, params storage.GarageVehicleAppendRevisionParams) (storage.GarageVehicleRevisionRecord, error)
	// GarageVehicleByID returns the head-pointer projection of
	// the supplied garage vehicle, scoped to garageID.
	GarageVehicleByID(ctx context.Context, garageID, vehicleID string) (storage.GarageVehicleRecord, error)
	// ListGarageVehicles returns every vehicle in the supplied
	// garage, ordered by created_at ascending.
	ListGarageVehicles(ctx context.Context, garageID string) ([]storage.GarageVehicleRecord, error)
	// EnrolledCertByClientAppID returns the enrolled client app's
	// cert (with parsed *x509.Certificate carrying the public
	// key) so garage handlers can cross-check the signer's
	// identity against the payload's claimed signer before
	// running cryptographic verification.
	EnrolledCertByClientAppID(ctx context.Context, clientAppID string) (storage.EnrolledCertRecord, error)
	// IssueGarageInvite mints a fresh invite token for the supplied
	// garage. Returns the plaintext token (shown once) and the
	// persisted metadata record.
	IssueGarageInvite(ctx context.Context, params storage.GarageInviteIssueParams) (opencaravan.InviteToken, storage.GarageInviteRecord, error)
	// ListGarageInvites returns every invite ever issued for the
	// supplied garage, including expired/revoked/exhausted rows.
	ListGarageInvites(ctx context.Context, garageID string) ([]storage.GarageInviteRecord, error)
	// RevokeGarageInvite marks an invite revoked. Idempotent —
	// revoking an already-revoked invite returns nil.
	RevokeGarageInvite(ctx context.Context, garageID, inviteID string) error
	// RedeemGarageInvite verifies the supplied plaintext token,
	// records the redemption, and adds the redeemer to
	// garage_owners as an accepted owner.
	RedeemGarageInvite(ctx context.Context, tokenValue, redeemerUserID string) (storage.GarageInviteRedemptionResult, error)
}

// InviteIssuerStore is the narrow subset of storage operations the
// authenticated server-registration invite-mint + list handlers depend
// on. Satisfied by [*storage.Store] via duck-typing. Kept distinct from
// [EnrollmentStore] (which backs the unauthenticated invite-consume
// path) so producer and consumer capabilities don't bleed into one
// contract.
type InviteIssuerStore interface {
	// IssueInviteBy mints an invite attributed to the supplied user,
	// enforcing a per-user cap on outstanding invites of the scope.
	// Returns [storage.ErrInviteOutstandingLimit] when the cap is met.
	IssueInviteBy(ctx context.Context, scope opencaravan.InviteScope, lifetime time.Duration, createdByUserID string, maxOutstanding int) (opencaravan.InviteToken, storage.Invite, error)
	// InvitesCreatedBy returns every invite minted by the supplied
	// user, newest first, for the audit list endpoint.
	InvitesCreatedBy(ctx context.Context, createdByUserID string) ([]storage.Invite, error)
	// IsFoundingAdmin reports whether the supplied user is the founding
	// administrator (the earliest-enrolled, non-disabled account). Used
	// by the admin-only invite-mint policy gate.
	IsFoundingAdmin(ctx context.Context, userID string) (bool, error)
}

// InviteMintPolicy gates who may mint server_registration invites via
// POST /v1/client-apps/invites. It governs the HTTP endpoint only — the
// CLI and the first-run bootstrap mint directly through storage and are
// never subject to it (shell access is the ultimate authority).
type InviteMintPolicy string

const (
	// InviteMintDenied disables API minting for everyone.
	InviteMintDenied InviteMintPolicy = "denied"
	// InviteMintAdminOnly permits only the founding administrator.
	InviteMintAdminOnly InviteMintPolicy = "admin-only"
	// InviteMintAnyUser permits any enrolled user (the per-user
	// outstanding cap still applies).
	InviteMintAnyUser InviteMintPolicy = "any-user"
)

// ParseInviteMintPolicy validates s against the known modes. The empty
// string is NOT accepted — callers resolve the default before parsing
// so an unset value is an explicit choice, not a silent fallback.
func ParseInviteMintPolicy(s string) (InviteMintPolicy, error) {
	switch InviteMintPolicy(s) {
	case InviteMintDenied, InviteMintAdminOnly, InviteMintAnyUser:
		return InviteMintPolicy(s), nil
	default:
		return "", fmt.Errorf("invalid invite mint policy %q (want denied, admin-only, or any-user)", s)
	}
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
	// IntegrityVerifier verifies ecdsa-p256-sha256 signatures
	// over OpenCaravan signed payloads (Vehicle, VehicleACL,
	// DriverAttestation, Garage, GarageVehicle,
	// GarageOwnershipAcceptance). When nil, handlers that
	// perform signature verification respond 503 so a
	// misconfigured deployment surfaces explicitly rather than
	// silently accepting unverified payloads. Production wires
	// an [*integrity.Verifier] backed by a store-backed key
	// resolver.
	IntegrityVerifier *integrity.Verifier
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
	// DriverAttestationStore backs the Phase 3 driver
	// attestation handlers (POST/GET
	// /v1/journeys/{id}/vehicles/{vid}/driver-attestations).
	// May be nil; the handlers respond 503 when not wired so a
	// misconfigured deployment surfaces explicitly.
	DriverAttestationStore DriverAttestationStore
	// GarageStore backs the garage container handlers
	// (POST/GET /v1/garages and the revision + acceptance
	// endpoints). May be nil; the handlers respond 503 when not
	// wired.
	GarageStore GarageStore
	// InviteIssuerStore backs the authenticated server-registration
	// invite-mint + list handlers (POST/GET /v1/client-apps/invites).
	// May be nil; the handlers respond 503 when not wired.
	InviteIssuerStore InviteIssuerStore
	// InviteMintPolicy gates POST /v1/client-apps/invites. The zero
	// value ("") is treated as InviteMintAnyUser by the handler so a
	// Config that never set it preserves the open default; production
	// resolves + validates the value in parseServeConfig.
	InviteMintPolicy InviteMintPolicy
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
// Routes are registered from the declarative table returned by
// [Routes]; each entry's [AuthPosture] selects the middleware wrapped
// around the handler at the registration site, so the table is both
// the documentation and the enforcement of every route's auth
// requirement. AuthSession routes are registered only when
// [Config.MacaroonVerifier] is wired: without a verifier,
// [middleware.RequireSession] would always 401 and the routes would
// be dead code. Their per-handler constraints run through
// verifier.CheckConstraints so attenuator attacks against the
// journey caveat are defeated by macaroon AND semantics.
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
//  5. The route mux, registered from the table.
func (s *Server) Handler() http.Handler {
	routes := Routes()
	// Fail closed: a table that fails validation (unknown posture,
	// incoherent session metadata, colliding registrations) must
	// never reach the mux. This is a programmer error, also caught
	// by the table integrity test before it can ship.
	if err := ValidateRoutes(routes); err != nil {
		panic(fmt.Sprintf("api: invalid route table: %v", err))
	}
	mux := http.NewServeMux()
	for _, rt := range routes {
		h := rt.handler(s)
		switch rt.Auth {
		case AuthPublic:
			// No wrapping; the handler serves unauthenticated
			// requests.
		case AuthIdentity:
			h = middleware.RequireIdentity(s.logger, h)
		case AuthSession:
			if s.cfg.MacaroonVerifier == nil {
				continue
			}
			h = middleware.RequireSession(s.cfg.MacaroonVerifier, s.logger,
				middleware.SessionActionJourneyFromPath(rt.SessionAction, rt.JourneyPathParam),
			)(h)
		}
		mux.Handle(rt.Method+" "+rt.Path, h)
	}
	// The contract meta-surface: the generated OpenAPI document and
	// the embedded Scalar explorer. Served by the same process but
	// deliberately absent from the route table — they describe the
	// API, they are not part of the versioned API contract.
	mux.HandleFunc("GET /openapi.json", s.handleOpenAPIJSON)
	mux.HandleFunc("GET /openapi.yaml", s.handleOpenAPIYAML)
	mux.Handle("GET /docs/{$}", docs.PageHandler("/openapi.json"))
	mux.Handle("GET /docs/"+docs.ScalarAssetName, docs.ScalarAssetHandler())

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

// RootResponse is the identity banner served at GET /.
type RootResponse struct {
	// Name is the human-readable server product name.
	Name string `json:"name"`
	// Version is the running spivot-server release version.
	Version string `json:"version"`
	// Status is "ok" whenever the process is serving requests.
	Status string `json:"status"`
	// PublicURL is the canonical URL served by the edge proxy.
	// Omitted when no public URL is configured.
	PublicURL string `json:"public_url,omitempty"`
}

// HealthResponse is the liveness payload served at GET /health.
type HealthResponse struct {
	// Status is "healthy" whenever the process is serving requests.
	Status string `json:"status"`
	// Version is the running spivot-server release version.
	Version string `json:"version"`
	// Uptime is the process uptime as a Go duration string.
	Uptime string `json:"uptime"`
}

// ReadinessResponse is the readiness payload served at GET /readyz.
// Status is "ready" with a 200 when the backing store answers a ping
// (or none is wired), "unready" with a 503 when it does not.
type ReadinessResponse struct {
	// Status is "ready" or "unready".
	Status string `json:"status"`
	// Version is the running spivot-server release version.
	Version string `json:"version"`
}

// VersionResponse is the build/runtime detail served at GET
// /v1/version: the same information [buildinfo.RuntimeInfo] reports
// on the CLI, as a typed wire contract.
type VersionResponse struct {
	// Version is the release version injected at build time.
	Version string `json:"version"`
	// GitCommit is the short commit hash the binary was built from.
	GitCommit string `json:"git_commit"`
	// GitBranch is the branch the binary was built from.
	GitBranch string `json:"git_branch"`
	// BuildTime is the UTC build timestamp (RFC 3339).
	BuildTime string `json:"build_time"`
	// GoVersion is the Go toolchain that produced the binary.
	GoVersion string `json:"go_version"`
	// OS is the runtime operating system (GOOS).
	OS string `json:"os"`
	// Arch is the runtime architecture (GOARCH).
	Arch string `json:"arch"`
	// Uptime is the process uptime as a Go duration string.
	Uptime string `json:"uptime"`
}

func (s *Server) handleRoot(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, RootResponse{
		Name:      "Spivot Server",
		Version:   buildinfo.Version,
		Status:    "ok",
		PublicURL: s.publicURLString(),
	}, s.logger)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, HealthResponse{
		Status:  "healthy",
		Version: buildinfo.Version,
		Uptime:  buildinfo.Uptime().String(),
	}, s.logger)
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Store != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := s.cfg.Store.Ping(ctx); err != nil {
			s.logger.Warn("readiness check failed", "error", err)
			writeJSONStatus(w, http.StatusServiceUnavailable, ReadinessResponse{
				Status:  "unready",
				Version: buildinfo.Version,
			}, s.logger)
			return
		}
	}

	writeJSON(w, ReadinessResponse{
		Status:  "ready",
		Version: buildinfo.Version,
	}, s.logger)
}

func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, VersionResponse{
		Version:   buildinfo.Version,
		GitCommit: buildinfo.GitCommit,
		GitBranch: buildinfo.GitBranch,
		BuildTime: buildinfo.BuildTime,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		Uptime:    buildinfo.Uptime().String(),
	}, s.logger)
}

// Spec artifact ETags, computed once: the bytes are embedded at build
// time and immutable for the life of the binary, so a strong hash
// lets the Scalar explorer's per-page-load /openapi.json fetch
// collapse to a 304 on every visit after the first.
var (
	specJSONETag = fmt.Sprintf(`"%x"`, sha256.Sum256(spec.JSON))
	specYAMLETag = fmt.Sprintf(`"%x"`, sha256.Sum256(spec.YAML))
)

// handleOpenAPIJSON serves the generated OpenAPI document in JSON
// form. The bytes are embedded at build time from the spec package;
// regeneration happens via `just generate`, never at runtime.
func (s *Server) handleOpenAPIJSON(w http.ResponseWriter, r *http.Request) {
	s.serveSpec(w, r, "application/json", specJSONETag, spec.JSON)
}

// handleOpenAPIYAML serves the generated OpenAPI document in YAML
// form.
func (s *Server) handleOpenAPIYAML(w http.ResponseWriter, r *http.Request) {
	s.serveSpec(w, r, "application/yaml", specYAMLETag, spec.YAML)
}

// serveSpec writes an embedded spec artifact with revalidation
// caching: no-cache forces clients to ask every time, the ETag lets
// the answer be an empty 304 until the binary (and therefore the
// spec) changes.
func (s *Server) serveSpec(w http.ResponseWriter, r *http.Request, contentType, etag string, body []byte) {
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", contentType)
	if _, err := w.Write(body); err != nil {
		s.logger.Debug("failed to write OpenAPI response", "error", err, "content_type", contentType)
	}
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
