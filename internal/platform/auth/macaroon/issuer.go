package macaroon

import (
	"errors"
	"fmt"
	"time"

	"github.com/opencaravan/opencaravan-go"
	macaroonv2 "gopkg.in/macaroon.v2"
)

// Location is the stable macaroon "location" string spivot-server
// embeds in every issued macaroon. The macaroon spec uses this field
// to disambiguate macaroons issued by different services; spivot-
// server uses a single fixed value so the verifier never has to
// match on it. Exported so [Verifier] and downstream tests can
// reference the same constant.
const Location = "spivot-server"

// Issuer mints session-bound macaroons against a single active root
// key. The root id is embedded in every macaroon's Id field so the
// matching key can be looked up at verify time without trial
// decryption.
//
// Issuer is safe for concurrent use: it holds the root key/id by
// value and never mutates them. A single Issuer instance can serve
// every concurrent POST /v1/sessions request the server fields.
type Issuer struct {
	rootID  string
	rootKey []byte
}

// NewIssuer constructs an Issuer for the supplied root id and key.
// rootID is the public identifier written into the macaroon's Id
// field; rootKey is the HMAC secret. Both come from
// [storage.MacaroonRoot]. Returns an error if the id is empty or
// the key length is not the 32 bytes macaroon.v2 expects for
// HMAC-SHA-256.
func NewIssuer(rootID string, rootKey []byte) (*Issuer, error) {
	if rootID == "" {
		return nil, errors.New("macaroon: root id must be set")
	}
	if len(rootKey) != RootKeyLen {
		return nil, fmt.Errorf("macaroon: root key length = %d, want %d", len(rootKey), RootKeyLen)
	}
	// Defensive copy so a later mutation of the caller's slice
	// cannot silently change the signing key under live requests.
	keyCopy := make([]byte, RootKeyLen)
	copy(keyCopy, rootKey)
	return &Issuer{
		rootID:  rootID,
		rootKey: keyCopy,
	}, nil
}

// RootID returns the public identifier this Issuer signs with. The
// value is the same one written into every issued macaroon's Id
// field, suitable for log lines or test assertions.
func (i *Issuer) RootID() string {
	return i.rootID
}

// Issue creates a fresh macaroon and attaches each predicate as a
// first-party caveat. Predicates are the canonical OpenCaravan
// strings produced by [opencaravan.CaveatTimeBefore],
// [opencaravan.CaveatJourney], [opencaravan.CaveatAction], etc.;
// callers can pass any non-empty ASCII string but the [Verifier]
// will reject anything that does not parse into a known
// [opencaravan.CaveatKind].
//
// Returns the binary macaroon serialization (suitable for
// base64url-encoded transport in [opencaravan.SessionResponse.Macaroon])
// plus the structured macaroon value for callers that want to
// inspect or attenuate it further before sending.
//
// An empty predicate slice is permitted but produces a macaroon
// with no caveats — only useful for tests; production session
// macaroons always carry at least a time<expiration caveat.
func (i *Issuer) Issue(predicates []string) (*macaroonv2.Macaroon, []byte, error) {
	m, err := macaroonv2.New(i.rootKey, []byte(i.rootID), Location, macaroonv2.LatestVersion)
	if err != nil {
		return nil, nil, fmt.Errorf("macaroon: new: %w", err)
	}
	for j, predicate := range predicates {
		if predicate == "" {
			return nil, nil, fmt.Errorf("macaroon: predicates[%d] must be non-empty", j)
		}
		if err := m.AddFirstPartyCaveat([]byte(predicate)); err != nil {
			return nil, nil, fmt.Errorf("macaroon: add caveat %q: %w", predicate, err)
		}
	}
	serialized, err := m.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("macaroon: marshal: %w", err)
	}
	return m, serialized, nil
}

// IssueSession is a convenience wrapper that builds the canonical
// caveat set for an authenticated session and calls [Issue]. It is
// the production path the Phase 4b POST /v1/sessions handler will
// drive; exposed here so the package's tests can exercise the
// caveat composition rules in one place.
//
// The caveats attached, in order:
//
//	user=<UserID>                      always present
//	client_app=<ClientAppID>           always present
//	journey=<JourneyID>                only when journeyID is non-empty
//	action=<Action>                    exactly one per macaroon
//	time<expiration                    always last
//
// Macaroon caveats compose with AND semantics: every caveat must
// be satisfied for the macaroon to verify. The action= predicate
// the OpenCaravan protocol defines names a single SessionAction,
// so each issued macaroon authorizes exactly one action. If a
// client needs multiple actions in a single session, the Phase 4b
// handler issues N macaroons — one per action — rather than
// inventing a non-protocol disjunctive predicate.
//
// The exact ordering does not affect verification (caveat order is
// part of the macaroon signature but not the evaluation semantics)
// but is canonical so test assertions and debug log lines stay
// stable across server versions.
func (i *Issuer) IssueSession(req SessionParams) (*macaroonv2.Macaroon, []byte, error) {
	if err := req.validate(); err != nil {
		return nil, nil, err
	}
	predicates := make([]string, 0, 5)
	predicates = append(predicates, opencaravan.CaveatUser(req.UserID))
	predicates = append(predicates, opencaravan.CaveatClientApp(req.ClientAppID))
	if req.JourneyID != "" {
		predicates = append(predicates, opencaravan.CaveatJourney(req.JourneyID))
	}
	predicates = append(predicates, opencaravan.CaveatAction(req.Action))
	predicates = append(predicates, opencaravan.CaveatTimeBefore(req.Expiration))
	return i.Issue(predicates)
}

// SessionParams is the structured input to [Issuer.IssueSession]. It
// names the caller, the optional journey scope, the single
// permitted action, and the expiration time of the resulting
// macaroon.
//
// One macaroon authorizes exactly one [opencaravan.SessionAction]
// because macaroon caveats AND together (each caveat restricts the
// macaroon further) and the protocol's action= predicate names a
// single value. The handler that fans out a multi-action
// [opencaravan.SessionRequest] issues one macaroon per requested
// action.
//
// Validation rules (enforced by validate):
//
//   - UserID and ClientAppID must be valid OpenCaravan UUIDs.
//   - JourneyID, if set, must be a valid OpenCaravan UUID.
//   - Action must pass [opencaravan.SessionAction.Valid]. Actions
//     that reference a journey (the journey.* / telemetry.* /
//     media.* family) require JourneyID to be set.
//   - Expiration must be in the future relative to the supplied
//     Now; a zero Now defers the check to [time.Now].
type SessionParams struct {
	UserID      opencaravan.UUID
	ClientAppID opencaravan.UUID
	JourneyID   opencaravan.UUID
	Action      opencaravan.SessionAction
	Expiration  time.Time
	Now         time.Time
}

// ErrInvalidSessionParams is the sentinel every
// [SessionParams.validate] failure wraps. Callers (notably the
// Phase 4b POST /v1/sessions handler) compare against it via
// [errors.Is] to map caller-fixable session shape errors to 422
// without conflating them against the issuer's internal
// failures (marshal, AddCaveat, etc.) which carry the same
// "macaroon:" message prefix.
var ErrInvalidSessionParams = errors.New("macaroon: invalid session params")

func (p SessionParams) validate() error {
	if !p.UserID.Valid() {
		return fmt.Errorf("%w: user id must be a valid UUID", ErrInvalidSessionParams)
	}
	if !p.ClientAppID.Valid() {
		return fmt.Errorf("%w: client app id must be a valid UUID", ErrInvalidSessionParams)
	}
	if p.JourneyID != "" && !p.JourneyID.Valid() {
		return fmt.Errorf("%w: journey id must be a valid UUID when set", ErrInvalidSessionParams)
	}
	if !p.Action.Valid() {
		return fmt.Errorf("%w: action %q is not a known OpenCaravan value", ErrInvalidSessionParams, p.Action)
	}
	if requiresJourney(p.Action) && p.JourneyID == "" {
		return fmt.Errorf("%w: action %q requires a journey id", ErrInvalidSessionParams, p.Action)
	}
	now := p.Now
	if now.IsZero() {
		now = time.Now()
	}
	if !p.Expiration.After(now) {
		return fmt.Errorf("%w: expiration must be in the future", ErrInvalidSessionParams)
	}
	return nil
}

// requiresJourney reports whether the supplied session action only
// makes sense in the context of a specific journey. The action
// vocabulary is small and stable enough that an explicit switch is
// clearer than a registry lookup; when the action set grows beyond
// what fits comfortably here we'll promote it to a per-action
// metadata table.
func requiresJourney(a opencaravan.SessionAction) bool {
	switch a {
	case opencaravan.SessionActionJourneyRead,
		opencaravan.SessionActionJourneyWrite,
		opencaravan.SessionActionTelemetryWrite,
		opencaravan.SessionActionMediaUpload:
		return true
	default:
		return false
	}
}

// RootKeyLen is the required length of [Issuer]'s root key in bytes.
// 32 bytes is what macaroon.v2 expects for HMAC-SHA-256 and matches
// the size that [storage.IssueMacaroonRoot] generates. Exported so
// callers wiring storage → issuer can assert the contract at the
// boundary rather than waiting for [NewIssuer] to error.
const RootKeyLen = 32
