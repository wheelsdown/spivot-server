package macaroon

import (
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/opencaravan/opencaravan-go"
	macaroonv2 "gopkg.in/macaroon.v2"
)

func TestNewIssuerRejectsEmptyID(t *testing.T) {
	if _, err := NewIssuer("", randomKey(t)); err == nil {
		t.Fatal("err = nil, want error for empty id")
	}
}

func TestNewIssuerRejectsShortKey(t *testing.T) {
	if _, err := NewIssuer("id", []byte("too-short")); err == nil {
		t.Fatal("err = nil, want error for short key")
	}
}

func TestIssueRoundTripsThroughMacaroonV2(t *testing.T) {
	issuer := mustIssuer(t)
	predicates := []string{
		opencaravan.CaveatTimeBefore(time.Now().Add(time.Hour)),
		opencaravan.CaveatJourney(opencaravan.UUID("11111111-1111-4111-8111-111111111111")),
	}

	_, serialized, err := issuer.Issue(predicates)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(serialized) == 0 {
		t.Fatal("serialized macaroon is empty")
	}

	var decoded macaroonv2.Macaroon
	if err := decoded.UnmarshalBinary(serialized); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := decoded.Location(); got != Location {
		t.Fatalf("Location = %q, want %q", got, Location)
	}
	if got := string(decoded.Id()); got != issuer.RootID() {
		t.Fatalf("Id = %q, want %q", got, issuer.RootID())
	}
	if got := len(decoded.Caveats()); got != len(predicates) {
		t.Fatalf("caveat count = %d, want %d", got, len(predicates))
	}
}

func TestIssueRejectsEmptyPredicate(t *testing.T) {
	issuer := mustIssuer(t)
	_, _, err := issuer.Issue([]string{""})
	if err == nil {
		t.Fatal("err = nil, want rejection of empty predicate")
	}
}

func TestIssueSessionComposesCanonicalCaveats(t *testing.T) {
	issuer := mustIssuer(t)
	exp := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
	params := SessionParams{
		UserID:      opencaravan.UUID("11111111-1111-4111-8111-111111111111"),
		ClientAppID: opencaravan.UUID("22222222-2222-4222-8222-222222222222"),
		JourneyID:   opencaravan.UUID("33333333-3333-4333-8333-333333333333"),
		Action:      opencaravan.SessionActionJourneyRead,
		Expiration:  exp,
	}

	m, _, err := issuer.IssueSession(params)
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}
	want := []string{
		opencaravan.CaveatUser(params.UserID),
		opencaravan.CaveatClientApp(params.ClientAppID),
		opencaravan.CaveatJourney(params.JourneyID),
		opencaravan.CaveatAction(opencaravan.SessionActionJourneyRead),
		opencaravan.CaveatTimeBefore(exp),
	}
	got := make([]string, 0, len(m.Caveats()))
	for _, c := range m.Caveats() {
		got = append(got, string(c.Id))
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("caveats =\n  %v\nwant\n  %v", got, want)
	}
}

func TestIssueSessionRejectsJourneyActionWithoutJourney(t *testing.T) {
	issuer := mustIssuer(t)
	params := SessionParams{
		UserID:      opencaravan.UUID("11111111-1111-4111-8111-111111111111"),
		ClientAppID: opencaravan.UUID("22222222-2222-4222-8222-222222222222"),
		Action:      opencaravan.SessionActionJourneyRead,
		Expiration:  time.Now().Add(time.Hour),
	}
	_, _, err := issuer.IssueSession(params)
	if err == nil || !strings.Contains(err.Error(), "requires a journey id") {
		t.Fatalf("err = %v, want 'requires a journey id'", err)
	}
}

func TestIssueSessionRejectsExpiredExpiration(t *testing.T) {
	issuer := mustIssuer(t)
	params := SessionParams{
		UserID:      opencaravan.UUID("11111111-1111-4111-8111-111111111111"),
		ClientAppID: opencaravan.UUID("22222222-2222-4222-8222-222222222222"),
		Action:      opencaravan.SessionActionInviteCreate,
		Expiration:  time.Now().Add(-time.Minute),
		Now:         time.Now(),
	}
	_, _, err := issuer.IssueSession(params)
	if err == nil || !strings.Contains(err.Error(), "expiration must be in the future") {
		t.Fatalf("err = %v, want expiration rejection", err)
	}
}

func TestIssueSessionRejectsInvalidUUID(t *testing.T) {
	issuer := mustIssuer(t)
	params := SessionParams{
		UserID:      opencaravan.UUID("not-a-uuid"),
		ClientAppID: opencaravan.UUID("22222222-2222-4222-8222-222222222222"),
		Action:      opencaravan.SessionActionInviteCreate,
		Expiration:  time.Now().Add(time.Hour),
	}
	if _, _, err := issuer.IssueSession(params); err == nil {
		t.Fatal("err = nil, want rejection of invalid user id")
	}
}

func TestIssueSessionValidationErrorsWrapSentinel(t *testing.T) {
	issuer := mustIssuer(t)
	cases := map[string]SessionParams{
		"invalid user id": {
			UserID:      opencaravan.UUID("not-a-uuid"),
			ClientAppID: opencaravan.UUID("22222222-2222-4222-8222-222222222222"),
			Action:      opencaravan.SessionActionInviteCreate,
			Expiration:  time.Now().Add(time.Hour),
		},
		"invalid client app id": {
			UserID:      opencaravan.UUID("11111111-1111-4111-8111-111111111111"),
			ClientAppID: opencaravan.UUID("not-a-uuid"),
			Action:      opencaravan.SessionActionInviteCreate,
			Expiration:  time.Now().Add(time.Hour),
		},
		"unknown action": {
			UserID:      opencaravan.UUID("11111111-1111-4111-8111-111111111111"),
			ClientAppID: opencaravan.UUID("22222222-2222-4222-8222-222222222222"),
			Action:      opencaravan.SessionAction("ransom.demand"),
			Expiration:  time.Now().Add(time.Hour),
		},
		"journey action without journey": {
			UserID:      opencaravan.UUID("11111111-1111-4111-8111-111111111111"),
			ClientAppID: opencaravan.UUID("22222222-2222-4222-8222-222222222222"),
			Action:      opencaravan.SessionActionJourneyRead,
			Expiration:  time.Now().Add(time.Hour),
		},
		"expired expiration": {
			UserID:      opencaravan.UUID("11111111-1111-4111-8111-111111111111"),
			ClientAppID: opencaravan.UUID("22222222-2222-4222-8222-222222222222"),
			Action:      opencaravan.SessionActionInviteCreate,
			Expiration:  time.Now().Add(-time.Minute),
			Now:         time.Now(),
		},
	}
	for name, params := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := issuer.IssueSession(params)
			if err == nil {
				t.Fatal("err = nil, want validation error")
			}
			if !errors.Is(err, ErrInvalidSessionParams) {
				t.Fatalf("err = %v, want errors.Is(_, ErrInvalidSessionParams)", err)
			}
		})
	}
}

func TestIssueSessionRejectsUnknownAction(t *testing.T) {
	issuer := mustIssuer(t)
	params := SessionParams{
		UserID:      opencaravan.UUID("11111111-1111-4111-8111-111111111111"),
		ClientAppID: opencaravan.UUID("22222222-2222-4222-8222-222222222222"),
		JourneyID:   opencaravan.UUID("33333333-3333-4333-8333-333333333333"),
		Action:      opencaravan.SessionAction("ransom.demand"),
		Expiration:  time.Now().Add(time.Hour),
	}
	if _, _, err := issuer.IssueSession(params); err == nil {
		t.Fatal("err = nil, want rejection of unknown action")
	}
}

func TestIssueSessionMutationOfKeyDoesNotAffectIssuer(t *testing.T) {
	key := randomKey(t)
	issuer, err := NewIssuer("issuer-mutation-test", key)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	// Mutate the caller's slice; the issuer should have taken a
	// defensive copy and continue to sign with the original key.
	for i := range key {
		key[i] ^= 0xff
	}

	exp := time.Now().Add(time.Hour)
	_, serialized, err := issuer.Issue([]string{opencaravan.CaveatTimeBefore(exp)})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// The resulting macaroon must still verify against the original
	// (pre-mutation) key bytes. Re-derive by re-creating a fresh
	// issuer with a fresh key copy from the same source pre-mutation.
	// Here we already mutated, so reverse the mutation to recover.
	for i := range key {
		key[i] ^= 0xff
	}
	var decoded macaroonv2.Macaroon
	if err := decoded.UnmarshalBinary(serialized); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := decoded.Verify(key, func(string) error { return nil }, nil); err != nil {
		t.Fatalf("signature verify: %v", err)
	}
}

func mustIssuer(t *testing.T) *Issuer {
	t.Helper()
	issuer, err := NewIssuer("test-root-id", randomKey(t))
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	return issuer
}

func randomKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, RootKeyLen)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return key
}
