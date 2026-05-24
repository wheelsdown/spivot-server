package macaroon

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/opencaravan/opencaravan-go"
	macaroonv2 "gopkg.in/macaroon.v2"
)

// RootKeyResolver is the narrow function shape [Verifier] uses to
// resolve a macaroon's embedded root id to the HMAC key it was
// signed with. The expected production wiring delegates to
// [storage.Store.MacaroonRootByID]; tests can pass a closure over an
// in-memory map.
//
// The resolver must return a wrapped [ErrUnknownRoot] (or a sentinel
// that [errors.Is] recognizes as ErrUnknownRoot) when the id is not
// known to this server. Returning any other error is treated as a
// transport-level failure and surfaces as [ErrVerifyFailed] to the
// caller.
type RootKeyResolver func(ctx context.Context, id string) ([]byte, error)

// Verifier validates the binary serialization of a presented
// macaroon against its signature and caveats. It composes three
// pieces:
//
//   - A [RootKeyResolver] for signature checks.
//   - An optional clock (`now func() time.Time`) used to evaluate
//     time<T caveats. Defaults to [time.Now]; tests override.
//   - The fixed [Location] string spivot-server expects in every
//     macaroon it accepts.
//
// Verifier is safe for concurrent use: all fields are read-only
// after construction.
type Verifier struct {
	resolve RootKeyResolver
	now     func() time.Time
}

// NewVerifier returns a Verifier that delegates signature lookups
// to resolve. A nil resolver is rejected at construction time.
func NewVerifier(resolve RootKeyResolver) (*Verifier, error) {
	if resolve == nil {
		return nil, errors.New("macaroon: resolver must be non-nil")
	}
	return &Verifier{
		resolve: resolve,
		now:     time.Now,
	}, nil
}

// WithClock returns a copy of v that reports the supplied clock
// for time<T caveat evaluation. nil restores the default [time.Now]
// behavior. The returned Verifier shares the same resolver as the
// receiver; both must remain valid for the lifetime of the
// returned value.
func (v *Verifier) WithClock(now func() time.Time) *Verifier {
	if now == nil {
		now = time.Now
	}
	return &Verifier{resolve: v.resolve, now: now}
}

// Constraints is the runtime context [Verifier.Verify] checks
// caveats against. The required surface is small by design: a
// macaroon is either acceptable for the action a caller is about
// to perform, or it is not. Fields not relevant to the action
// being authorized are left zero.
//
//   - JourneyID: the journey the request is operating against, or
//     empty if the request is journey-less. A journey=UUID caveat
//     in the macaroon must match this value exactly; a journey
//     caveat with no caller JourneyID is a rejection.
//   - Action: the single action the caller is attempting. A macaroon
//     carrying any action=NAME caveats authorizes the request only
//     if at least one of them matches this action. A macaroon with
//     zero action caveats permits any action (server policy can
//     attenuate by adding caveats; the macaroon's caveats only
//     restrict).
//   - UserID / ClientAppID: when set, must match user= and
//     client_app= caveats respectively. Set by the session-aware
//     middleware so a leaked macaroon cannot escape the identity
//     it was issued to.
type Constraints struct {
	JourneyID   opencaravan.UUID
	Action      opencaravan.SessionAction
	UserID      opencaravan.UUID
	ClientAppID opencaravan.UUID
}

// Verified is the structured view [Verifier.Verify] returns alongside
// the nil-error success case. Carries the macaroon's embedded root
// id, location, and parsed caveat list so handlers and audit log
// lines can read off the session details without re-parsing the
// macaroon.
type Verified struct {
	RootID   string
	Location string
	Caveats  []opencaravan.Caveat
	// Expiration is the latest time<T caveat in the macaroon, or
	// the zero value when the macaroon carries no time caveat.
	// Conventionally every spivot-server-issued macaroon has
	// exactly one such caveat at the end; the field is exposed so
	// callers can log "session expires at X" without having to
	// re-scan Caveats.
	Expiration time.Time
}

// ErrUnknownRoot is the sentinel a [RootKeyResolver] returns when
// the requested root id matches no known row. Verifier surfaces it
// to callers wrapped in [ErrVerifyFailed]; handlers should treat it
// like a signature mismatch and respond 401.
var ErrUnknownRoot = errors.New("macaroon: unknown root id")

// ErrVerifyFailed is the umbrella error every auth-level
// verification failure wraps. The wrapped error narrates the
// underlying reason (unknown root, signature mismatch, caveat
// violation, malformed bytes); handlers compare against this via
// [errors.Is] to decide whether to 401 the request.
//
// [Verifier.VerifySignature] surfaces auth failures (including
// the resolver-returned-ErrUnknownRoot case) wrapped in
// ErrVerifyFailed and surfaces resolver transport failures
// wrapped in [ErrTransportFailure] only. [Verifier.Verify] (the
// convenience wrapper) re-wraps transport failures so every
// failure path through Verify is reachable via
// errors.Is(err, ErrVerifyFailed) — backward-compat for single-shot
// callers that don't need to distinguish.
var ErrVerifyFailed = errors.New("macaroon: verify failed")

// ErrTransportFailure wraps errors from the [RootKeyResolver] that
// are not [ErrUnknownRoot] — i.e. infrastructure problems like a
// SQLite outage or an HSM timeout. Middleware that wants to log
// these at ERROR rather than WARN (because they reflect a server
// issue, not a client one) detects them via
// errors.Is(err, ErrTransportFailure). The wrapped error remains
// accessible via [errors.Unwrap] for diagnostic logging.
//
// ErrTransportFailure does NOT also wrap [ErrVerifyFailed]: a
// caller seeing this sentinel can tell with a single
// errors.Is check that the failure is infrastructure-side. For
// callers that don't care about the distinction (anything using
// [Verifier.Verify]), the convenience wrapper re-wraps so
// errors.Is(err, ErrVerifyFailed) still works.
var ErrTransportFailure = errors.New("macaroon: resolver transport failure")

// VerifySignature decodes the binary macaroon, looks up its root
// key, validates the HMAC signature, and parses every first-party
// caveat into a structured [opencaravan.Caveat]. It deliberately
// does NOT evaluate caveats against runtime constraints — that's
// [Verifier.CheckConstraints]'s job, called per-request once the
// handler knows what journey / action it expects.
//
// This split exists so the broad attach-pass middleware that runs
// at the top of the HTTP chain (see internal/server/middleware's
// AttachSession) can sign-check every presented macaroon once,
// surfacing the verified caveat structure on the request context,
// while per-handler guards re-evaluate the caveats against the
// route-specific constraints they care about.
//
// Failure modes:
//
//   - Malformed binary → wraps [ErrVerifyFailed]
//   - Wrong location (macaroon issued by another service) → wraps
//     [ErrVerifyFailed]
//   - Unknown root id (resolver returned [ErrUnknownRoot]) → wraps
//     [ErrVerifyFailed]
//   - Resolver transport error (database outage, HSM timeout,
//     etc. — anything that isn't ErrUnknownRoot) → wraps
//     [ErrTransportFailure] only, NOT [ErrVerifyFailed], so
//     callers can tell auth failures from infrastructure failures
//     with a single errors.Is check
//   - Signature mismatch → wraps [ErrVerifyFailed]
//   - Unknown / unparseable / third-party caveat (rejected
//     fail-closed regardless of the runtime route) → wraps
//     [ErrVerifyFailed]
//   - Macaroon missing a time<T caveat → wraps [ErrVerifyFailed]
//     (every spivot-server-issued macaroon carries one; a presented
//     macaroon without one is structurally invalid and would
//     otherwise be non-expiring at the middleware layer)
func (v *Verifier) VerifySignature(ctx context.Context, serialized []byte) (Verified, error) {
	var m macaroonv2.Macaroon
	if err := m.UnmarshalBinary(serialized); err != nil {
		return Verified{}, fmt.Errorf("%w: unmarshal: %v", ErrVerifyFailed, err)
	}
	if m.Location() != Location {
		return Verified{}, fmt.Errorf("%w: location %q not recognized", ErrVerifyFailed, m.Location())
	}
	rootID := string(m.Id())
	if rootID == "" {
		return Verified{}, fmt.Errorf("%w: root id missing from macaroon", ErrVerifyFailed)
	}
	key, err := v.resolve(ctx, rootID)
	if err != nil {
		if errors.Is(err, ErrUnknownRoot) {
			return Verified{}, fmt.Errorf("%w: %v", ErrVerifyFailed, err)
		}
		// Transport errors get only the ErrTransportFailure wrap so
		// AttachSession can log them at ERROR instead of WARN.
		return Verified{}, fmt.Errorf("%w: resolve root: %v", ErrTransportFailure, err)
	}

	// macaroon.v2's Verify wants a per-caveat predicate callback;
	// since we're skipping runtime-constraint checks here, the
	// callback's only job is to enforce the "predicate must
	// structurally parse into a known caveat kind" rule. Third-
	// party caveats are surfaced as an empty predicate (Id != "" but
	// Location != ""); macaroon.v2 invokes the callback only for
	// first-party caveats, so we still need the loop below to
	// surface third-party ones.
	if err := m.Verify(key, func(predicate string) error {
		caveat, err := opencaravan.ParseCaveat(predicate)
		if err != nil {
			return fmt.Errorf("parse caveat %q: %w", predicate, err)
		}
		if caveat.Kind == opencaravan.CaveatKindUnknown {
			return fmt.Errorf("unknown caveat predicate %q", predicate)
		}
		return nil
	}, nil); err != nil {
		return Verified{}, fmt.Errorf("%w: %v", ErrVerifyFailed, err)
	}

	parsed, latestExpiry, caveatErr := parseCaveats(m.Caveats())
	if caveatErr != nil {
		return Verified{}, fmt.Errorf("%w: %v", ErrVerifyFailed, caveatErr)
	}

	return Verified{
		RootID:     rootID,
		Location:   m.Location(),
		Caveats:    parsed,
		Expiration: latestExpiry,
	}, nil
}

// CheckConstraints evaluates the caveats in a previously-verified
// macaroon against runtime constraints. Returns nil when every
// caveat is satisfied, an error wrapping [ErrVerifyFailed]
// otherwise. The supplied [Verified] must come from
// [Verifier.VerifySignature]; passing a hand-rolled value
// bypasses the signature guard and is unsupported.
//
// The clock used for time<T evaluation is the [Verifier]'s
// injected clock (default [time.Now]), captured once per call so
// every caveat in the macaroon sees the same instant.
func (v *Verifier) CheckConstraints(verified Verified, c Constraints) error {
	now := v.now()
	for _, caveat := range verified.Caveats {
		if err := evaluateCaveat(caveat, now, c); err != nil {
			return fmt.Errorf("%w: %v", ErrVerifyFailed, err)
		}
	}
	return nil
}

// Verify decodes the binary macaroon, looks up its root key, checks
// the HMAC signature, parses caveats, and evaluates each caveat
// against the supplied [Constraints]. Returns a [Verified] view on
// success or an error wrapping [ErrVerifyFailed] on any rejection.
//
// Convenience wrapper around [Verifier.VerifySignature] +
// [Verifier.CheckConstraints]; single-shot callers (typically
// tests, or future endpoints that do not split attach/require)
// use this. The middleware path uses the two halves separately
// so signature work happens once and constraint work happens
// per-handler.
//
// Every Verify failure wraps [ErrVerifyFailed], including
// [VerifySignature]'s transport errors that are otherwise wrapped
// only in [ErrTransportFailure] — Verify re-wraps so the
// errors.Is(err, ErrVerifyFailed) contract holds for callers that
// don't need to distinguish infrastructure from auth.
func (v *Verifier) Verify(ctx context.Context, serialized []byte, c Constraints) (Verified, error) {
	verified, err := v.VerifySignature(ctx, serialized)
	if err != nil {
		if errors.Is(err, ErrVerifyFailed) {
			return Verified{}, err
		}
		// VerifySignature returned a transport error (wrapped only
		// in ErrTransportFailure). Re-wrap so the convenience
		// caller's errors.Is(err, ErrVerifyFailed) keeps working.
		return Verified{}, fmt.Errorf("%w: %v", ErrVerifyFailed, err)
	}
	if err := v.CheckConstraints(verified, c); err != nil {
		return Verified{}, err
	}
	return verified, nil
}

// parseCaveats walks every first-party caveat in the macaroon and
// builds the structured slice that surfaces on [Verified],
// recording the macaroon's effective expiration (the EARLIEST
// time<T caveat — see below).
//
// Caveat well-formedness is enforced by VerifySignature's predicate
// callback during macaroon.v2's Verify, so by the time parseCaveats
// runs every first-party caveat is guaranteed to parse into a
// known [opencaravan.CaveatKind]. The remaining error paths are:
//
//   - Third-party caveats — macaroon.v2 does not surface them to
//     the predicate callback, so we walk the list and reject
//     fail-closed.
//   - Missing time<T caveat — every spivot-server-issued macaroon
//     carries one. A presented macaroon without one would be
//     non-expiring at the middleware layer, which is unsafe;
//     reject as structurally invalid.
//
// Multiple time<T caveats compose under macaroon AND semantics: a
// macaroon attenuated with `time<earlier` on top of an existing
// `time<later` is valid only when now is before BOTH — i.e. the
// EARLIEST of the two. The Verified.Expiration field surfaces
// that effective expiration so callers logging "session expires
// at" see the tightest bound the caveat list imposes, not a
// loose upper bound. [CheckConstraints] still evaluates every
// time<T caveat individually so this convenience field has no
// security weight.
func parseCaveats(caveats []macaroonv2.Caveat) ([]opencaravan.Caveat, time.Time, error) {
	parsed := make([]opencaravan.Caveat, 0, len(caveats))
	var earliest time.Time
	for _, raw := range caveats {
		if raw.Location != "" {
			return nil, time.Time{}, fmt.Errorf("third-party caveat from %q not supported", raw.Location)
		}
		predicate := string(raw.Id)
		caveat, err := opencaravan.ParseCaveat(predicate)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("parse caveat %q: %w", predicate, err)
		}
		if caveat.Kind == opencaravan.CaveatKindUnknown {
			return nil, time.Time{}, fmt.Errorf("unknown caveat predicate %q", predicate)
		}
		parsed = append(parsed, caveat)
		if caveat.Kind == opencaravan.CaveatKindTimeBefore {
			if earliest.IsZero() || caveat.Time.Before(earliest) {
				earliest = caveat.Time
			}
		}
	}
	if earliest.IsZero() {
		return nil, time.Time{}, errors.New("macaroon has no time<T caveat")
	}
	return parsed, earliest, nil
}

// evaluateCaveat runs the OpenCaravan evaluation rule for a single
// parsed caveat against runtime constraints. Returns nil when
// the caveat is satisfied. The single evaluator used by
// [Verifier.CheckConstraints]; [VerifySignature]'s predicate
// callback does only well-formedness checks (macaroon.v2's API is
// string-based) and leaves runtime evaluation to this function
// once the caveats are in their parsed [opencaravan.Caveat] form.
func evaluateCaveat(caveat opencaravan.Caveat, now time.Time, c Constraints) error {
	switch caveat.Kind {
	case opencaravan.CaveatKindTimeBefore:
		if !now.Before(caveat.Time) {
			return fmt.Errorf("macaroon expired at %s (now=%s)", caveat.Time.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
		}
		return nil
	case opencaravan.CaveatKindJourney:
		if c.JourneyID == "" {
			return fmt.Errorf("journey caveat %q present but no journey id in constraints", caveat.UUID)
		}
		if c.JourneyID != caveat.UUID {
			return fmt.Errorf("journey caveat = %s, request journey = %s", caveat.UUID, c.JourneyID)
		}
		return nil
	case opencaravan.CaveatKindUser:
		if c.UserID == "" {
			return fmt.Errorf("user caveat %q present but no user id in constraints", caveat.UUID)
		}
		if c.UserID != caveat.UUID {
			return fmt.Errorf("user caveat = %s, request user = %s", caveat.UUID, c.UserID)
		}
		return nil
	case opencaravan.CaveatKindClientApp:
		if c.ClientAppID == "" {
			return fmt.Errorf("client_app caveat %q present but no client app id in constraints", caveat.UUID)
		}
		if c.ClientAppID != caveat.UUID {
			return fmt.Errorf("client_app caveat = %s, request client_app = %s", caveat.UUID, c.ClientAppID)
		}
		return nil
	case opencaravan.CaveatKindAction:
		if c.Action == "" {
			return fmt.Errorf("action caveat %q present but no action in constraints", caveat.Action)
		}
		if c.Action != caveat.Action {
			return fmt.Errorf("action caveat = %s, request action = %s", caveat.Action, c.Action)
		}
		return nil
	case opencaravan.CaveatKindUnknown:
		return fmt.Errorf("unknown caveat predicate %q", caveat.Raw)
	default:
		// Defensive: a future CaveatKind that the parser knows about
		// but this function does not. Fail-closed.
		return fmt.Errorf("unhandled caveat kind %q", caveat.Kind)
	}
}
