package middleware

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/opencaravan/opencaravan-go"
	"github.com/wheelsdown/spivot-server/internal/platform/auth/macaroon"
)

// Session is the server-side view of a verified session macaroon
// attached to a request by [AttachSession]. It carries the raw
// verified macaroon view (which security gates use through
// [RequireSession] -> [SessionVerifier.CheckConstraints]) plus a
// few convenience fields the access log emits for observability.
//
// Important: the convenience fields (UserID, ClientAppID,
// JourneyID, Action) are derived from caveat singletons. If the
// presented macaroon carries zero or multiple caveats of a kind
// (a legitimate macaroon will not, but an attenuator can append
// caveats without the key), the corresponding convenience field
// is left empty. Security decisions MUST go through Verified.Caveats
// — typically by letting [RequireSession] drive
// [SessionVerifier.CheckConstraints], which enforces the macaroon's
// AND-of-caveats semantics so duplicate caveats with conflicting
// values are unsatisfiable (the way macaroon attenuation is
// supposed to work).
//
// Session is safe to share across goroutines: every field is a
// value type or an immutable slice and no post-construction
// mutation happens.
type Session struct {
	// Verified is the raw structural view returned by
	// [SessionVerifier.VerifySignature]. RequireSession passes
	// this to CheckConstraints; handlers that need to introspect
	// caveats beyond the convenience fields walk Verified.Caveats
	// directly.
	Verified macaroon.Verified

	// RootID is the macaroon root id this session was signed
	// against. Stable across rotation: macaroons signed by a
	// since-rotated root still verify (storage retains rotated
	// rows).
	RootID string
	// UserID is the user= caveat value when the macaroon carries
	// exactly one such caveat; otherwise empty. Observability
	// only — do not gate on this field.
	UserID opencaravan.UUID
	// ClientAppID is the client_app= caveat value, with the same
	// singleton-or-empty contract as UserID.
	ClientAppID opencaravan.UUID
	// JourneyID is the journey= caveat value, with the same
	// singleton-or-empty contract as UserID.
	JourneyID opencaravan.UUID
	// Action is the action= caveat value, with the same
	// singleton-or-empty contract as UserID.
	Action opencaravan.SessionAction
	// Expiration is the effective expiration of the macaroon —
	// the earliest time<T caveat across the whole list. Always
	// non-zero in an attached Session because VerifySignature
	// rejects macaroons that don't carry a time<T caveat.
	Expiration time.Time
}

// SessionVerifier is the narrow [macaroon.Verifier] surface
// [AttachSession] and [RequireSession] depend on. Defined here so
// tests can pass an in-memory fake without standing up the full
// storage-backed resolver. The concrete production implementation
// is *[macaroon.Verifier].
type SessionVerifier interface {
	VerifySignature(ctx context.Context, serialized []byte) (macaroon.Verified, error)
	CheckConstraints(verified macaroon.Verified, c macaroon.Constraints) error
}

type sessionKey struct{}

// AttachSession returns a middleware that lifts the
// "Authorization: Macaroon <base64>" header (when present),
// verifies the macaroon's signature via [SessionVerifier.VerifySignature],
// and attaches a structured [Session] to the request context.
//
// Behavior:
//
//   - No Authorization header at all: pass through silently with
//     no session attached. (Health probes and the enrollment
//     endpoint flow this way; logging "no auth header" would
//     spam the access log.)
//   - Header present but malformed (wrong scheme, bad base64):
//     WARN log + pass through with no session attached.
//   - Header present and decodes, but signature verification
//     fails (unknown root, bad signature, malformed caveats,
//     missing time<T): WARN log + pass through.
//   - Verifier transport error (e.g. the storage-backed root
//     resolver failed): ERROR log + pass through. Distinguished
//     from auth-level failures via
//     [macaroon.ErrTransportFailure] so a database outage shows
//     up loudly without being confused with bad client input.
//   - Header verifies cleanly: attach Session to context and
//     continue.
//
// The pass-through-on-failure stance matches AttachIdentity. The
// per-handler guard ([RequireSession]) translates "no attached
// session" into 401.
func AttachSession(verifier SessionVerifier, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			serialized, headerErr := extractMacaroonHeader(r)
			if headerErr != nil {
				if !errors.Is(headerErr, errNoAuthHeader) {
					logger.Warn("rejected Authorization header",
						"error", headerErr,
					)
				}
				next.ServeHTTP(w, r)
				return
			}
			verified, err := verifier.VerifySignature(r.Context(), serialized)
			if err != nil {
				switch {
				case errors.Is(err, macaroon.ErrTransportFailure):
					logger.Error("verify macaroon signature: resolver transport error",
						"error", err,
					)
				case errors.Is(err, macaroon.ErrVerifyFailed):
					logger.Warn("rejected presented macaroon",
						"error", err,
					)
				default:
					// Defensive: VerifySignature contract says
					// failures wrap either ErrVerifyFailed or
					// ErrTransportFailure. If a future code path
					// added an un-classified error, treat as ERROR
					// so it doesn't disappear silently.
					logger.Error("verify macaroon signature: unclassified failure",
						"error", err,
					)
				}
				next.ServeHTTP(w, r)
				return
			}
			session := sessionFromVerified(verified)
			next.ServeHTTP(w, r.WithContext(withSession(r.Context(), session)))
		})
	}
}

// ConstraintsForRequest is a per-route builder that produces the
// [macaroon.Constraints] [RequireSession] passes to
// [SessionVerifier.CheckConstraints]. The builder reads the
// request (typically for path parameters via [http.Request.PathValue])
// and returns the runtime constraints the route imposes.
//
// Returning an error signals a configuration mistake (e.g. the
// route declared a path parameter the builder relies on, but the
// mux didn't populate it). RequireSession treats builder errors
// as 500 so the operator notices, not as 401.
type ConstraintsForRequest func(r *http.Request) (macaroon.Constraints, error)

// RequireSession returns a middleware that 401s the request
// unless it carries a [Session] in its context AND the macaroon's
// caveats are satisfied by the constraints the supplied
// [ConstraintsForRequest] builder produces for this request.
//
// Critically, the per-handler check delegates to
// [SessionVerifier.CheckConstraints] rather than reading the
// convenience fields off [Session]. CheckConstraints walks
// [Session.Verified.Caveats] under macaroon AND semantics: every
// caveat must be satisfied independently. An attenuator who
// appended an extra journey= or action= caveat (the standard
// way to attenuate a macaroon, requiring no key) makes the
// resulting macaroon unsatisfiable for any concrete request
// rather than letting the last caveat win — which is exactly the
// invariant macaroons promise.
//
// Identity caveats (user=, client_app=) are auto-overlaid from
// the request's context Identity (set by AttachIdentity) when
// the route's builder leaves them empty. Routes don't have to
// repeat the identity scoping — it's universal and the
// AttachIdentity step already resolved it from mTLS.
//
// Failures map to:
//
//   - 401 "no_session" — no Session attached
//   - 500 "constraints_builder_failed" — builder returned an error
//   - 401 "session_constraint_failed" — CheckConstraints rejected
func RequireSession(verifier SessionVerifier, logger *slog.Logger, build ConstraintsForRequest) func(http.Handler) http.Handler {
	if verifier == nil {
		// Construction-time defensive panic — a nil verifier means
		// RequireSession can never accept a request and any wrapped
		// handler is dead code. Surface during route registration
		// rather than at the first protected request.
		panic("middleware: RequireSession verifier must be non-nil")
	}
	if build == nil {
		panic("middleware: RequireSession builder must be non-nil")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, ok := SessionFrom(r.Context())
			if !ok {
				writeProblem(w, logger, http.StatusUnauthorized, "no_session",
					"This endpoint requires a session macaroon (Authorization: Macaroon ...).")
				return
			}
			c, err := build(r)
			if err != nil {
				logger.Error("session constraints builder failed",
					"error", err,
				)
				writeProblem(w, logger, http.StatusInternalServerError, "constraints_builder_failed",
					"Could not build session constraints for this request.")
				return
			}
			// Overlay identity caveats from the request's context
			// Identity. The mTLS-resolved identity is the
			// authoritative source for user= / client_app=; routes
			// don't have to repeat it in every builder.
			if id, ok := IdentityFrom(r.Context()); ok {
				if c.UserID == "" {
					c.UserID = opencaravan.UUID(id.UserID)
				}
				if c.ClientAppID == "" {
					c.ClientAppID = opencaravan.UUID(id.ClientAppID)
				}
			}
			if err := verifier.CheckConstraints(session.Verified, c); err != nil {
				logger.Warn("session constraint check failed",
					"root_id", session.RootID,
					"error", err,
				)
				writeProblem(w, logger, http.StatusUnauthorized, "session_constraint_failed",
					"The presented session macaroon does not authorize this request.")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// SessionAction returns a [ConstraintsForRequest] that constrains
// only the action. Identity caveats (user=, client_app=) are
// overlaid from the context Identity by RequireSession.
func SessionAction(action opencaravan.SessionAction) ConstraintsForRequest {
	return func(_ *http.Request) (macaroon.Constraints, error) {
		return macaroon.Constraints{Action: action}, nil
	}
}

// SessionActionJourneyFromPath returns a [ConstraintsForRequest]
// that constrains the action and pulls the journey id from the
// request's named path value (e.g. "id" for a route declared as
// "GET /v1/journeys/{id}"). Returns an error when the path
// value is missing, surfacing as 500 from [RequireSession] so an
// operator notices the route is misconfigured.
func SessionActionJourneyFromPath(action opencaravan.SessionAction, pathParam string) ConstraintsForRequest {
	return func(r *http.Request) (macaroon.Constraints, error) {
		journey := opencaravan.UUID(r.PathValue(pathParam))
		if journey == "" {
			return macaroon.Constraints{}, fmt.Errorf("path value %q is empty", pathParam)
		}
		return macaroon.Constraints{
			Action:    action,
			JourneyID: journey,
		}, nil
	}
}

// SessionFrom returns the [Session] that [AttachSession] attached
// to ctx, plus a bool indicating presence. The Session is the
// zero value when ok is false.
func SessionFrom(ctx context.Context) (Session, bool) {
	s, ok := ctx.Value(sessionKey{}).(Session)
	return s, ok
}

// WithSession attaches a Session to ctx for tests that need to
// drive session-aware handlers without standing up the full
// AttachSession → Verifier pipeline. Exported so test code in
// other packages can use it.
func WithSession(ctx context.Context, s Session) context.Context {
	return withSession(ctx, s)
}

func withSession(ctx context.Context, s Session) context.Context {
	return context.WithValue(ctx, sessionKey{}, s)
}

// sessionFromVerified projects a verified macaroon onto the
// convenience-field Session shape. Singleton caveats populate the
// convenience field; zero or multiple caveats of a kind leave the
// field empty. See [Session]'s doc for why this is safe — the
// security gate is CheckConstraints, not the convenience fields.
func sessionFromVerified(v macaroon.Verified) Session {
	session := Session{
		Verified:   v,
		RootID:     v.RootID,
		Expiration: v.Expiration,
	}
	for _, c := range v.Caveats {
		switch c.Kind {
		case opencaravan.CaveatKindUser:
			if session.UserID == "" {
				session.UserID = c.UUID
			} else {
				session.UserID = "" // duplicate kind; null out and stop
			}
		case opencaravan.CaveatKindClientApp:
			if session.ClientAppID == "" {
				session.ClientAppID = c.UUID
			} else {
				session.ClientAppID = ""
			}
		case opencaravan.CaveatKindJourney:
			if session.JourneyID == "" {
				session.JourneyID = c.UUID
			} else {
				session.JourneyID = ""
			}
		case opencaravan.CaveatKindAction:
			if session.Action == "" {
				session.Action = c.Action
			} else {
				session.Action = ""
			}
		}
	}
	return session
}

// errNoAuthHeader is the sentinel [extractMacaroonHeader] returns
// when the Authorization header is missing entirely. AttachSession
// distinguishes this case (silent pass-through) from other
// extraction failures (WARN log + pass-through), since requests
// to unauthenticated routes shouldn't spam the log.
var errNoAuthHeader = errors.New("no Authorization header")

// extractMacaroonHeader pulls the Authorization header and
// base64url-decodes the Macaroon-scheme value. Returns the
// decoded bytes on success, or an error describing the failure
// mode:
//
//   - [errNoAuthHeader] when the header is absent (AttachSession
//     stays silent on this case).
//   - Other errors describe specific malformed conditions and
//     surface as WARN-level audit log lines.
//
// The Macaroon scheme token is matched case-insensitively per
// RFC 7235.
func extractMacaroonHeader(r *http.Request) ([]byte, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return nil, errNoAuthHeader
	}
	const prefix = "Macaroon "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return nil, errors.New("authorization scheme is not Macaroon")
	}
	token := strings.TrimSpace(header[len(prefix):])
	if token == "" {
		return nil, errors.New("macaroon token is empty")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("macaroon token is not unpadded base64url: %w", err)
	}
	return decoded, nil
}
