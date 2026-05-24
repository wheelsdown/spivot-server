package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/wheelsdown/spivot-server/internal/platform/proxy"
	"github.com/wheelsdown/spivot-server/internal/platform/storage"
)

// Identity is the server-side authenticated identity attached to a
// request by [AttachIdentity]. It is the join of the cert the client
// presented (Serial, SubjectCN, NotAfter, Fingerprint when available)
// with the IDs the issued_certificates audit table resolves the cert
// to (UserID, ClientAppID).
//
// Downstream handlers read Identity via [IdentityFrom]. Identity is
// safe to share across goroutines — every field is a value type and no
// post-construction mutation happens.
type Identity struct {
	UserID      string
	ClientAppID string
	Serial      string
	SubjectCN   string
	NotAfter    time.Time
	Fingerprint string
}

// IdentityStore is the narrow storage interface AttachIdentity needs.
// [*storage.Store] satisfies it via duck-typing; tests may pass
// in-memory fakes. Defining the interface here rather than in storage
// keeps the dependency direction clean: middleware imports storage
// only for the value types (CertIdentity, ErrCertNotEnrolled).
type IdentityStore interface {
	// IdentityBySerial resolves an active (non-revoked) issued
	// certificate serial to its CertIdentity. Returns
	// [storage.ErrCertNotEnrolled] for unknown or revoked serials.
	IdentityBySerial(ctx context.Context, serial string) (storage.CertIdentity, error)
}

type identityKey struct{}

// AttachIdentity returns a middleware that lifts the inbound client
// cert (when present and verified by the layer below) into a resolved
// [Identity] and attaches it to the request context.
//
// Behavior:
//
//   - If [proxy.RequestInfoFrom] returns a non-nil ClientCert and the
//     cert's Serial resolves to an active enrollment, the Identity is
//     attached and the request continues.
//   - If no cert was presented, the request continues with no
//     attached Identity. The attach pass never rejects;
//     unauthenticated routes (health checks, the enrollment endpoint)
//     work normally.
//   - If a cert was presented but its serial does not resolve
//     (unknown serial, or known-but-revoked), no Identity is attached
//     and a WARN-level audit log records the rejected attempt. Any
//     handler that later calls [RequireIdentity] will return 401.
//   - If the storage lookup itself errors (transport-level failure),
//     no Identity is attached, an ERROR log is emitted, and the
//     request proceeds. The caller's [RequireIdentity] guard will
//     still 401 the request, surfacing the upstream issue to the
//     client without leaking storage details.
func AttachIdentity(store IdentityStore, proxyCfg proxy.Config, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Prefer the RequestInfo already cached on the context by
			// the outer withRequestInfo middleware so we don't repeat
			// the PEM decode + x509 parse + SHA-256 work that
			// RequestInfoFrom performs. Falls back to a direct parse
			// when tests (or any caller that hasn't wired the cache
			// pass) invoke this middleware in isolation.
			info, ok := proxy.RequestInfoFromContext(r.Context())
			if !ok {
				info = proxy.RequestInfoFrom(r, proxyCfg)
			}
			cert := info.ClientCert
			if cert == nil || cert.Serial == "" {
				next.ServeHTTP(w, r)
				return
			}

			ctx := r.Context()
			resolved, err := store.IdentityBySerial(ctx, cert.Serial)
			switch {
			case err == nil:
				identity := Identity{
					UserID:      resolved.UserID,
					ClientAppID: resolved.ClientAppID,
					Serial:      resolved.Serial,
					SubjectCN:   resolved.SubjectCN,
					NotAfter:    resolved.NotAfter,
					Fingerprint: cert.Fingerprint,
				}
				ctx = withIdentity(ctx, identity)
			case errors.Is(err, storage.ErrCertNotEnrolled):
				logger.Warn("rejected client cert: serial not enrolled or revoked",
					"serial", cert.Serial,
					"subject_cn", cert.SubjectCN,
					"fingerprint", cert.Fingerprint,
				)
			default:
				logger.Error("resolve client cert identity failed",
					"serial", cert.Serial,
					"error", err,
				)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireIdentity wraps a handler so it only runs when an [Identity]
// has been attached to the request context. Requests missing an
// Identity receive a 401 with an application/problem+json body.
//
// This is the per-handler guard half of the two-tier pattern. Wrap at
// the registration site so the route table makes the auth
// requirement visible:
//
//	mux.Handle("POST /v1/sessions", middleware.RequireIdentity(logger, http.HandlerFunc(handleSession)))
//
// The logger receives an ERROR if writing the problem+json body
// fails (rare, but worth recording so an operator notices). Public
// routes (health, version, enrollment) skip the wrap and remain
// reachable to unauthenticated callers.
func RequireIdentity(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := IdentityFrom(r.Context()); !ok {
			writeProblem(w, logger, http.StatusUnauthorized, "unauthenticated",
				"This endpoint requires a client certificate that resolves to an enrolled client app.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// IdentityFrom returns the Identity that [AttachIdentity] attached to
// ctx, plus a bool indicating presence. The Identity is the zero
// value when ok is false.
//
// Handlers protected by [RequireIdentity] can call IdentityFrom and
// rely on ok being true; the guard would have rejected the request
// otherwise. Handlers that want optional-identity behavior (logging
// the caller when known, anonymous fall-through otherwise) can use
// the same call and branch on ok.
func IdentityFrom(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(Identity)
	return id, ok
}

// WithIdentity attaches an Identity to ctx for tests that need to
// drive identity-aware handlers without spinning up the full
// AttachIdentity → IdentityStore pipeline. Exported so test code in
// other packages can use it.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return withIdentity(ctx, id)
}

func withIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, id)
}

// writeProblem writes an application/problem+json error response. A
// trimmed-down copy of the same shape the enrollment handler uses;
// kept here so the middleware package does not have to import api.
// When the shape evolves (e.g., to include a request-id field), both
// call sites should track together.
//
// Encode failures (rare — the body is a tiny static map) are logged
// at ERROR for operator diagnostics. A nil logger is tolerated so
// callers without one (legacy tests) don't have to manufacture one;
// in that case encode failures are silently dropped.
func writeProblem(w http.ResponseWriter, logger *slog.Logger, status int, code, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	body := map[string]any{
		"status": status,
		"code":   code,
		"detail": detail,
	}
	if err := json.NewEncoder(w).Encode(body); err != nil && logger != nil {
		// Body already half-written; the logger sees the encode failure
		// for operator diagnostics but the client gets whatever made it
		// onto the wire.
		logger.Error("middleware: write problem response", "error", err)
	}
}
