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

// ErrVerifyFailed is the umbrella error every [Verifier.Verify]
// failure wraps. The wrapped error narrates the underlying reason
// (unknown root, signature mismatch, caveat violation,
// malformed bytes); handlers compare against this via [errors.Is]
// to decide whether to 401 the request.
var ErrVerifyFailed = errors.New("macaroon: verify failed")

// Verify decodes the binary macaroon, looks up its root key, checks
// the HMAC signature, and evaluates every first-party caveat
// against the supplied [Constraints]. Returns a [Verified] view on
// success or an error wrapping [ErrVerifyFailed] on any rejection.
//
// Failure modes:
//
//   - Malformed binary: [encoding.BinaryUnmarshaler] decode error.
//   - Wrong location: macaroon was issued by another service.
//   - Unknown root id: resolver returned [ErrUnknownRoot] (or
//     equivalent via errors.Is).
//   - Signature mismatch: macaroon.v2's Verify returned an error.
//   - Caveat violation: an OpenCaravan-known caveat failed against
//     the constraints, or an unknown caveat was present (fail-closed
//     on attenuations this server cannot evaluate).
//
// All five wrap [ErrVerifyFailed].
func (v *Verifier) Verify(ctx context.Context, serialized []byte, c Constraints) (Verified, error) {
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
		return Verified{}, fmt.Errorf("%w: resolve root: %v", ErrVerifyFailed, err)
	}

	// Capture "now" once at the start of Verify so the standalone
	// caveat parse pass and the macaroon.v2 signature-verifying
	// predicate callback observe the same instant. Without this,
	// time<T evaluation could go one way in parseCaveats and the
	// other way inside the macaroon.v2 check loop for a macaroon
	// expiring within the verification window.
	now := v.now()

	parsed, latestExpiry, caveatErr := parseCaveats(m.Caveats(), now, c)
	if err := m.Verify(key, func(predicate string) error {
		return evaluatePredicate(predicate, now, c)
	}, nil); err != nil {
		return Verified{}, fmt.Errorf("%w: %v", ErrVerifyFailed, err)
	}
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

// parseCaveats walks every first-party caveat in the macaroon,
// builds the structured slice that surfaces on [Verified], records
// the latest time<T expiry, and runs each predicate through
// [evaluatePredicate] so any caveat violation is surfaced as a
// stable error. Returning the structured view + the first caveat
// error in a single pass lets [Verifier.Verify] decide which to
// surface to the caller without re-parsing the predicate strings.
func parseCaveats(caveats []macaroonv2.Caveat, now time.Time, c Constraints) ([]opencaravan.Caveat, time.Time, error) {
	parsed := make([]opencaravan.Caveat, 0, len(caveats))
	var latest time.Time
	var firstErr error
	for _, raw := range caveats {
		// Third-party caveats are out of scope for v0; this server
		// never issues them, so any non-empty Location on a presented
		// caveat means the macaroon was constructed by something
		// outside our protocol. Reject fail-closed.
		if raw.Location != "" {
			if firstErr == nil {
				firstErr = fmt.Errorf("third-party caveat from %q not supported", raw.Location)
			}
			continue
		}
		predicate := string(raw.Id)
		caveat, err := opencaravan.ParseCaveat(predicate)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("parse caveat %q: %w", predicate, err)
			}
			continue
		}
		if caveat.Kind == opencaravan.CaveatKindUnknown {
			if firstErr == nil {
				firstErr = fmt.Errorf("unknown caveat predicate %q", predicate)
			}
			continue
		}
		parsed = append(parsed, caveat)
		if caveat.Kind == opencaravan.CaveatKindTimeBefore && caveat.Time.After(latest) {
			latest = caveat.Time
		}
		if err := evaluatePredicate(predicate, now, c); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return parsed, latest, firstErr
}

// evaluatePredicate runs the OpenCaravan caveat evaluation rules for
// a single predicate. Returns nil when the caveat is satisfied by
// the supplied constraints; otherwise returns a descriptive error
// (which macaroon.v2's Verify will surface as a verification
// failure). Unknown predicates are rejected fail-closed.
func evaluatePredicate(predicate string, now time.Time, c Constraints) error {
	caveat, err := opencaravan.ParseCaveat(predicate)
	if err != nil {
		return fmt.Errorf("parse caveat %q: %w", predicate, err)
	}
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
		return fmt.Errorf("unknown caveat predicate %q", predicate)
	default:
		// Defensive: a future CaveatKind that the parser knows about
		// but this function does not. Fail-closed.
		return fmt.Errorf("unhandled caveat kind %q", caveat.Kind)
	}
}
