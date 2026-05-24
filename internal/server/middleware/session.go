package middleware

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/opencaravan/opencaravan-go"
	"github.com/wheelsdown/spivot-server/internal/platform/auth/macaroon"
)

// Session is the server-side view of a verified session macaroon
// attached to a request by [AttachSession]. It is the structured
// projection of [macaroon.Verified] onto the convenience fields
// downstream handlers actually consume.
//
// All fields are populated from the verified macaroon's caveats.
// The macaroons spivot-server issues always carry user=,
// client_app=, action=, and time<expiration caveats; journey= is
// present for journey-scoped sessions and absent for journey-less
// actions (admin / invite.create). Sessions presented by a future
// client that omits one of the always-present caveats are still
// attached — the per-handler [RequireSession] guard is the place
// that decides whether the missing field matters for the route.
//
// Session is safe to share across goroutines: every field is a
// value type and no post-construction mutation happens.
type Session struct {
	// RootID is the macaroon root id this session was signed
	// against. Stable across rotation: macaroons signed by a
	// since-rotated root still verify (storage retains rotated
	// rows) and surface here unchanged.
	RootID string
	// UserID is the user the session belongs to (user= caveat).
	UserID opencaravan.UUID
	// ClientAppID is the client app the session was issued to
	// (client_app= caveat). The mTLS identity that requested the
	// session will have the same id.
	ClientAppID opencaravan.UUID
	// JourneyID is the journey the session is scoped to (journey=
	// caveat) or empty when the macaroon is journey-less.
	JourneyID opencaravan.UUID
	// Action is the single action this session authorizes
	// (action= caveat) or empty when the macaroon is action-less
	// (no current issue path produces such a macaroon; reserved
	// for future "any action" sessions).
	Action opencaravan.SessionAction
	// Expiration is the macaroon's time<T caveat; the session is
	// invalid at or after this instant.
	Expiration time.Time
	// Caveats is the full structured caveat list for handlers
	// that need to introspect attenuations beyond the convenience
	// fields above.
	Caveats []opencaravan.Caveat
}

// SessionVerifier is the narrow [macaroon.Verifier] surface
// [AttachSession] depends on. Defined here so tests can pass an
// in-memory fake without standing up the full storage-backed
// resolver. The concrete production implementation is
// *[macaroon.Verifier].
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
//   - No Authorization header, or a header that does not use the
//     Macaroon scheme: pass through with no session attached.
//   - Header present but malformed (bad base64, unknown root,
//     signature mismatch, malformed caveats): WARN log + pass
//     through with no session attached. The per-handler
//     [RequireSession] guard will 401 the request.
//   - Header present and verifies: attach Session to context and
//     continue.
//   - Verifier transport error (e.g. the storage-backed root
//     resolver fails): ERROR log + pass through. Same operational
//     property as AttachIdentity: a storage outage does not 5xx
//     the read-only health probe.
//
// The pass-through-on-failure stance matches AttachIdentity. The
// per-handler guard is responsible for translating "no session"
// into the right user-facing status.
func AttachSession(verifier SessionVerifier, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			serialized, ok := extractMacaroonHeader(r)
			if !ok {
				next.ServeHTTP(w, r)
				return
			}
			verified, err := verifier.VerifySignature(r.Context(), serialized)
			if err != nil {
				if errors.Is(err, macaroon.ErrVerifyFailed) {
					logger.Warn("rejected presented macaroon",
						"error", err,
					)
				} else {
					logger.Error("verify macaroon signature failed",
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

// SessionConstraint is a per-request check the [RequireSession]
// middleware runs against an attached [Session]. The check sees
// the original request so constraints can extract path parameters
// (e.g. a journey id from the route), and returns nil when the
// constraint is satisfied or a descriptive error otherwise.
//
// Helpers [RequireSessionAction] and [RequireSessionJourneyParam]
// cover the common cases; ad-hoc constraints can be defined
// inline at the registration site.
type SessionConstraint func(r *http.Request, s Session) error

// RequireSession returns a middleware that 401s the request unless
// it carries a verified [Session] in its context AND every
// supplied [SessionConstraint] passes. The macaroon's
// time<expiration caveat is always checked first, before any
// custom constraint, so an expired macaroon is always rejected
// regardless of which constraints the route registers.
//
// Constraints are evaluated in supplied order. The first failure
// short-circuits and 401s the request; the logger receives a
// WARN with the reason so an operator can debug authorization
// failures without exposing the detail to the client.
//
// The constraint set is intentionally policy-light: each route
// names the action / journey / user it expects, and any deeper
// permission gating happens in the handler itself. v0's
// macaroons carry a single action= caveat, so a route asserting
// a different action via [RequireSessionAction] correctly fails
// against a wrong-action macaroon.
func RequireSession(logger *slog.Logger, constraints ...SessionConstraint) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, ok := SessionFrom(r.Context())
			if !ok {
				writeProblem(w, logger, http.StatusUnauthorized, "no_session",
					"This endpoint requires a session macaroon (Authorization: Macaroon ...).")
				return
			}
			now := time.Now()
			if !session.Expiration.IsZero() && !now.Before(session.Expiration) {
				logger.Warn("session expired",
					"user_id", session.UserID,
					"client_app_id", session.ClientAppID,
					"expiration", session.Expiration.Format(time.RFC3339Nano),
				)
				writeProblem(w, logger, http.StatusUnauthorized, "session_expired",
					"The presented session macaroon has expired; request a new one.")
				return
			}
			for _, constraint := range constraints {
				if err := constraint(r, session); err != nil {
					logger.Warn("session constraint failed",
						"user_id", session.UserID,
						"client_app_id", session.ClientAppID,
						"error", err,
					)
					writeProblem(w, logger, http.StatusUnauthorized, "session_constraint_failed",
						"The presented session macaroon does not authorize this request.")
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireSessionAction returns a [SessionConstraint] that
// requires the session's Action to equal the supplied value.
// Used by handlers that gate on a specific
// [opencaravan.SessionAction] — typically every protected route,
// since v0 issues one action per macaroon.
func RequireSessionAction(want opencaravan.SessionAction) SessionConstraint {
	return func(_ *http.Request, s Session) error {
		if s.Action != want {
			return errSessionActionMismatch{want: want, got: s.Action}
		}
		return nil
	}
}

// RequireSessionJourneyParam returns a [SessionConstraint] that
// requires the session's JourneyID to equal the [http.Request]
// path value named by pathParam. The pathParam is the same name
// the route declared in its mux pattern (e.g. "id" for a
// "/v1/journeys/{id}" route). When the path value is empty the
// constraint fails closed.
//
// This is the typical journey-scoped guard: the route knows the
// journey it's about to act on, and the macaroon's journey=
// caveat must point at the same journey.
func RequireSessionJourneyParam(pathParam string) SessionConstraint {
	return func(r *http.Request, s Session) error {
		want := opencaravan.UUID(r.PathValue(pathParam))
		if want == "" {
			return errSessionJourneyParamEmpty{param: pathParam}
		}
		if s.JourneyID != want {
			return errSessionJourneyMismatch{want: want, got: s.JourneyID}
		}
		return nil
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
// convenience-field Session shape. Walks the caveats once and
// picks out the well-known kinds; the structured Caveats slice
// is preserved verbatim for handlers that need to introspect
// further.
func sessionFromVerified(v macaroon.Verified) Session {
	session := Session{
		RootID:     v.RootID,
		Expiration: v.Expiration,
		Caveats:    v.Caveats,
	}
	for _, c := range v.Caveats {
		switch c.Kind {
		case opencaravan.CaveatKindUser:
			session.UserID = c.UUID
		case opencaravan.CaveatKindClientApp:
			session.ClientAppID = c.UUID
		case opencaravan.CaveatKindJourney:
			session.JourneyID = c.UUID
		case opencaravan.CaveatKindAction:
			session.Action = c.Action
		}
	}
	return session
}

// extractMacaroonHeader pulls the Authorization header and
// base64url-decodes the macaroon value when present and well-
// formed. Returns ok=false on any of:
//
//   - Missing Authorization header.
//   - Header does not start with the "Macaroon " scheme prefix
//     (case-insensitive — RFC 7235 scheme tokens are
//     case-insensitive).
//   - Token portion does not decode as unpadded base64url
//     (the encoding [opencaravan.SessionResponse] specifies).
//
// Ok=false is the correct response in all of these — the
// AttachSession middleware passes through unauthenticated and
// the per-handler RequireSession guard 401s. We don't surface a
// log here because the broad attach pass also runs against
// unauthenticated requests (health probes, enrollment) and we
// don't want to spam logs with "no auth header" for every such
// request.
func extractMacaroonHeader(r *http.Request) ([]byte, bool) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return nil, false
	}
	const prefix = "Macaroon "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return nil, false
	}
	token := strings.TrimSpace(header[len(prefix):])
	if token == "" {
		return nil, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, false
	}
	return decoded, true
}

// errSessionActionMismatch is a typed error so tests and the
// audit log can match on the specific failure mode without
// string-matching the human-readable message.
type errSessionActionMismatch struct {
	want, got opencaravan.SessionAction
}

func (e errSessionActionMismatch) Error() string {
	return "session action " + string(e.got) + " does not match required " + string(e.want)
}

// errSessionJourneyMismatch is the typed error counterpart for
// [RequireSessionJourneyParam] when the path's journey id does
// not match the macaroon's journey= caveat.
type errSessionJourneyMismatch struct {
	want, got opencaravan.UUID
}

func (e errSessionJourneyMismatch) Error() string {
	return "session journey " + string(e.got) + " does not match request journey " + string(e.want)
}

// errSessionJourneyParamEmpty is the typed error counterpart for
// [RequireSessionJourneyParam] when the named path parameter is
// empty on the request. Surfaces as a routing-configuration bug
// (the route was registered with a different parameter name)
// rather than as a permission failure.
type errSessionJourneyParamEmpty struct {
	param string
}

func (e errSessionJourneyParamEmpty) Error() string {
	return "session journey constraint: request has no PathValue(" + e.param + ")"
}
