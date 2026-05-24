package macaroon

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/opencaravan/opencaravan-go"
	macaroonv2 "gopkg.in/macaroon.v2"
)

// fixedClock returns a closure suitable for [Verifier.WithClock]
// that always reports the supplied instant. Used so tests can
// drive time<T evaluation deterministically without monkey-patching
// time.Now.
func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

const (
	testUser    = opencaravan.UUID("11111111-1111-4111-8111-111111111111")
	testApp     = opencaravan.UUID("22222222-2222-4222-8222-222222222222")
	testJourney = opencaravan.UUID("33333333-3333-4333-8333-333333333333")
)

func newTestVerifier(t *testing.T, rootID string, key []byte, now time.Time) *Verifier {
	t.Helper()
	v, err := NewVerifier(func(_ context.Context, id string) ([]byte, error) {
		if id != rootID {
			return nil, ErrUnknownRoot
		}
		return key, nil
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v.WithClock(fixedClock(now))
}

func TestVerifyAcceptsFreshSessionMacaroon(t *testing.T) {
	key := randomKey(t)
	issuer, err := NewIssuer("verify-root", key)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	now := time.Now().UTC()
	exp := now.Add(time.Hour)

	_, serialized, err := issuer.IssueSession(SessionParams{
		UserID:      testUser,
		ClientAppID: testApp,
		JourneyID:   testJourney,
		Action:      opencaravan.SessionActionJourneyRead,
		Expiration:  exp,
		Now:         now,
	})
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}

	verifier := newTestVerifier(t, "verify-root", key, now)
	got, err := verifier.Verify(context.Background(), serialized, Constraints{
		JourneyID:   testJourney,
		Action:      opencaravan.SessionActionJourneyRead,
		UserID:      testUser,
		ClientAppID: testApp,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.RootID != "verify-root" {
		t.Fatalf("RootID = %q", got.RootID)
	}
	if got.Location != Location {
		t.Fatalf("Location = %q", got.Location)
	}
	if !got.Expiration.Equal(exp) {
		t.Fatalf("Expiration = %s, want %s", got.Expiration, exp)
	}
	if len(got.Caveats) == 0 {
		t.Fatal("Caveats is empty")
	}
}

func TestVerifyRejectsExpiredMacaroon(t *testing.T) {
	key := randomKey(t)
	issuer, _ := NewIssuer("verify-root", key)
	issuedAt := time.Now().UTC()
	exp := issuedAt.Add(time.Minute)
	_, serialized, err := issuer.IssueSession(SessionParams{
		UserID:      testUser,
		ClientAppID: testApp,
		JourneyID:   testJourney,
		Action:      opencaravan.SessionActionJourneyRead,
		Expiration:  exp,
		Now:         issuedAt,
	})
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}

	// Verifier's clock is past expiration.
	verifier := newTestVerifier(t, "verify-root", key, exp.Add(time.Second))
	_, err = verifier.Verify(context.Background(), serialized, Constraints{
		JourneyID:   testJourney,
		Action:      opencaravan.SessionActionJourneyRead,
		UserID:      testUser,
		ClientAppID: testApp,
	})
	if !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("err = %v, want ErrVerifyFailed", err)
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("err = %v, want expiration message", err)
	}
}

func TestVerifyRejectsJourneyMismatch(t *testing.T) {
	key := randomKey(t)
	issuer, _ := NewIssuer("verify-root", key)
	now := time.Now().UTC()
	_, serialized, err := issuer.IssueSession(SessionParams{
		UserID:      testUser,
		ClientAppID: testApp,
		JourneyID:   testJourney,
		Action:      opencaravan.SessionActionJourneyRead,
		Expiration:  now.Add(time.Hour),
		Now:         now,
	})
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}

	verifier := newTestVerifier(t, "verify-root", key, now)
	_, err = verifier.Verify(context.Background(), serialized, Constraints{
		JourneyID:   opencaravan.UUID("44444444-4444-4444-8444-444444444444"),
		Action:      opencaravan.SessionActionJourneyRead,
		UserID:      testUser,
		ClientAppID: testApp,
	})
	if !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("err = %v, want ErrVerifyFailed", err)
	}
}

func TestVerifyRejectsActionMismatch(t *testing.T) {
	key := randomKey(t)
	issuer, _ := NewIssuer("verify-root", key)
	now := time.Now().UTC()
	_, serialized, err := issuer.IssueSession(SessionParams{
		UserID:      testUser,
		ClientAppID: testApp,
		JourneyID:   testJourney,
		Action:      opencaravan.SessionActionJourneyRead,
		Expiration:  now.Add(time.Hour),
		Now:         now,
	})
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}

	verifier := newTestVerifier(t, "verify-root", key, now)
	_, err = verifier.Verify(context.Background(), serialized, Constraints{
		JourneyID:   testJourney,
		Action:      opencaravan.SessionActionTelemetryWrite, // mismatch
		UserID:      testUser,
		ClientAppID: testApp,
	})
	if !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("err = %v, want ErrVerifyFailed", err)
	}
}

func TestVerifyRejectsUnknownRoot(t *testing.T) {
	key := randomKey(t)
	issuer, _ := NewIssuer("verify-root", key)
	now := time.Now().UTC()
	_, serialized, err := issuer.IssueSession(SessionParams{
		UserID:      testUser,
		ClientAppID: testApp,
		JourneyID:   testJourney,
		Action:      opencaravan.SessionActionJourneyRead,
		Expiration:  now.Add(time.Hour),
		Now:         now,
	})
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}

	// Resolver knows a different id only.
	verifier := newTestVerifier(t, "different-root", key, now)
	_, err = verifier.Verify(context.Background(), serialized, Constraints{
		JourneyID:   testJourney,
		Action:      opencaravan.SessionActionJourneyRead,
		UserID:      testUser,
		ClientAppID: testApp,
	})
	if !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("err = %v, want ErrVerifyFailed", err)
	}
}

func TestVerifyRejectsWrongLocation(t *testing.T) {
	key := randomKey(t)
	m, err := macaroonv2.New(key, []byte("verify-root"), "some-other-service", macaroonv2.LatestVersion)
	if err != nil {
		t.Fatalf("macaroonv2.New: %v", err)
	}
	serialized, err := m.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	verifier := newTestVerifier(t, "verify-root", key, time.Now())
	_, err = verifier.Verify(context.Background(), serialized, Constraints{})
	if !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("err = %v, want ErrVerifyFailed", err)
	}
	if !strings.Contains(err.Error(), "location") {
		t.Fatalf("err = %v, want location message", err)
	}
}

func TestVerifyRejectsMalformedBinary(t *testing.T) {
	verifier := newTestVerifier(t, "verify-root", randomKey(t), time.Now())
	_, err := verifier.Verify(context.Background(), []byte("not-a-macaroon"), Constraints{})
	if !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("err = %v, want ErrVerifyFailed", err)
	}
}

func TestVerifyRejectsUnknownCaveat(t *testing.T) {
	key := randomKey(t)
	issuer, _ := NewIssuer("verify-root", key)
	now := time.Now().UTC()
	_, serialized, err := issuer.Issue([]string{
		opencaravan.CaveatTimeBefore(now.Add(time.Hour)),
		"this-predicate-does-not-parse",
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	verifier := newTestVerifier(t, "verify-root", key, now)
	_, err = verifier.Verify(context.Background(), serialized, Constraints{
		JourneyID:   testJourney,
		Action:      opencaravan.SessionActionJourneyRead,
		UserID:      testUser,
		ClientAppID: testApp,
	})
	if !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("err = %v, want ErrVerifyFailed", err)
	}
	if !strings.Contains(err.Error(), "unknown caveat") {
		t.Fatalf("err = %v, want unknown-caveat message", err)
	}
}

func TestVerifyRejectsSignatureMismatch(t *testing.T) {
	key := randomKey(t)
	issuer, _ := NewIssuer("verify-root", key)
	now := time.Now().UTC()
	_, serialized, err := issuer.IssueSession(SessionParams{
		UserID:      testUser,
		ClientAppID: testApp,
		JourneyID:   testJourney,
		Action:      opencaravan.SessionActionJourneyRead,
		Expiration:  now.Add(time.Hour),
		Now:         now,
	})
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}

	// Verifier resolves the right id but to a *different* key.
	wrongKey := randomKey(t)
	verifier, err := NewVerifier(func(_ context.Context, id string) ([]byte, error) {
		if id != "verify-root" {
			return nil, ErrUnknownRoot
		}
		return wrongKey, nil
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	verifier = verifier.WithClock(fixedClock(now))

	_, err = verifier.Verify(context.Background(), serialized, Constraints{
		JourneyID:   testJourney,
		Action:      opencaravan.SessionActionJourneyRead,
		UserID:      testUser,
		ClientAppID: testApp,
	})
	if !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("err = %v, want ErrVerifyFailed", err)
	}
}

func TestVerifySurfacesResolverTransportError(t *testing.T) {
	key := randomKey(t)
	issuer, _ := NewIssuer("verify-root", key)
	now := time.Now().UTC()
	_, serialized, err := issuer.IssueSession(SessionParams{
		UserID:      testUser,
		ClientAppID: testApp,
		JourneyID:   testJourney,
		Action:      opencaravan.SessionActionJourneyRead,
		Expiration:  now.Add(time.Hour),
		Now:         now,
	})
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}

	verifier, err := NewVerifier(func(_ context.Context, _ string) ([]byte, error) {
		return nil, errors.New("simulated db outage")
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	verifier = verifier.WithClock(fixedClock(now))

	_, err = verifier.Verify(context.Background(), serialized, Constraints{})
	if !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("err = %v, want ErrVerifyFailed", err)
	}
	if !strings.Contains(err.Error(), "resolve root") {
		t.Fatalf("err = %v, want resolve-root message", err)
	}
}

func TestVerifyNoResolverRejected(t *testing.T) {
	if _, err := NewVerifier(nil); err == nil {
		t.Fatal("err = nil, want rejection of nil resolver")
	}
}

func TestVerifySignatureRejectsUnknownCaveat(t *testing.T) {
	key := randomKey(t)
	issuer, _ := NewIssuer("verify-root", key)
	now := time.Now().UTC()
	_, serialized, err := issuer.Issue([]string{
		opencaravan.CaveatTimeBefore(now.Add(time.Hour)),
		"this-predicate-does-not-parse",
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	verifier := newTestVerifier(t, "verify-root", key, now)
	if _, err := verifier.VerifySignature(context.Background(), serialized); !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("VerifySignature err = %v, want ErrVerifyFailed", err)
	}
}

func TestVerifySignatureReturnsParsedCaveats(t *testing.T) {
	key := randomKey(t)
	issuer, _ := NewIssuer("verify-root", key)
	now := time.Now().UTC()
	exp := now.Add(time.Hour)
	_, serialized, err := issuer.IssueSession(SessionParams{
		UserID:      testUser,
		ClientAppID: testApp,
		JourneyID:   testJourney,
		Action:      opencaravan.SessionActionJourneyRead,
		Expiration:  exp,
		Now:         now,
	})
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}

	verifier := newTestVerifier(t, "verify-root", key, now)
	got, err := verifier.VerifySignature(context.Background(), serialized)
	if err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
	if got.RootID != "verify-root" {
		t.Fatalf("RootID = %q", got.RootID)
	}
	if !got.Expiration.Equal(exp) {
		t.Fatalf("Expiration = %s, want %s", got.Expiration, exp)
	}
	wantKinds := []opencaravan.CaveatKind{
		opencaravan.CaveatKindUser,
		opencaravan.CaveatKindClientApp,
		opencaravan.CaveatKindJourney,
		opencaravan.CaveatKindAction,
		opencaravan.CaveatKindTimeBefore,
	}
	if len(got.Caveats) != len(wantKinds) {
		t.Fatalf("len(Caveats) = %d, want %d", len(got.Caveats), len(wantKinds))
	}
	for i, kind := range wantKinds {
		if got.Caveats[i].Kind != kind {
			t.Fatalf("Caveats[%d].Kind = %q, want %q", i, got.Caveats[i].Kind, kind)
		}
	}
}

func TestVerifySignaturePassesEvenWhenCaveatsWouldFail(t *testing.T) {
	// VerifySignature must NOT evaluate runtime constraints. A
	// macaroon scoped to one journey must pass VerifySignature
	// regardless of what journey the request is targeting; the
	// per-handler CheckConstraints is the place that rejects.
	key := randomKey(t)
	issuer, _ := NewIssuer("verify-root", key)
	now := time.Now().UTC()
	_, serialized, err := issuer.IssueSession(SessionParams{
		UserID:      testUser,
		ClientAppID: testApp,
		JourneyID:   testJourney,
		Action:      opencaravan.SessionActionJourneyRead,
		Expiration:  now.Add(time.Hour),
		Now:         now,
	})
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}
	verifier := newTestVerifier(t, "verify-root", key, now)
	verified, err := verifier.VerifySignature(context.Background(), serialized)
	if err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}

	// Now CheckConstraints with a mismatched journey — this is the
	// layer that should fail.
	differentJourney := opencaravan.UUID("44444444-4444-4444-8444-444444444444")
	if err := verifier.CheckConstraints(verified, Constraints{
		JourneyID:   differentJourney,
		Action:      opencaravan.SessionActionJourneyRead,
		UserID:      testUser,
		ClientAppID: testApp,
	}); !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("CheckConstraints err = %v, want ErrVerifyFailed", err)
	}
}

func TestCheckConstraintsEnforcesExpiration(t *testing.T) {
	key := randomKey(t)
	issuer, _ := NewIssuer("verify-root", key)
	now := time.Now().UTC()
	_, serialized, err := issuer.IssueSession(SessionParams{
		UserID:      testUser,
		ClientAppID: testApp,
		JourneyID:   testJourney,
		Action:      opencaravan.SessionActionJourneyRead,
		Expiration:  now.Add(time.Minute),
		Now:         now,
	})
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}

	// VerifySignature passes regardless of clock; CheckConstraints
	// is where the expiration check fires.
	verifier := newTestVerifier(t, "verify-root", key, now.Add(2*time.Minute))
	verified, err := verifier.VerifySignature(context.Background(), serialized)
	if err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
	err = verifier.CheckConstraints(verified, Constraints{
		JourneyID:   testJourney,
		Action:      opencaravan.SessionActionJourneyRead,
		UserID:      testUser,
		ClientAppID: testApp,
	})
	if !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("err = %v, want ErrVerifyFailed", err)
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("err = %v, want expiration message", err)
	}
}

func TestVerifySignatureRejectsMacaroonWithoutTimeCaveat(t *testing.T) {
	key := randomKey(t)
	issuer, _ := NewIssuer("verify-root", key)
	// Issue with just user/journey caveats — no time<T. Every
	// spivot-issued macaroon has one, but a presented macaroon
	// could be hand-crafted to omit it.
	_, serialized, err := issuer.Issue([]string{
		opencaravan.CaveatUser(testUser),
		opencaravan.CaveatJourney(testJourney),
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	verifier := newTestVerifier(t, "verify-root", key, time.Now())
	_, err = verifier.VerifySignature(context.Background(), serialized)
	if !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("err = %v, want ErrVerifyFailed", err)
	}
	if !strings.Contains(err.Error(), "time<T") {
		t.Fatalf("err = %v, want time<T-caveat message", err)
	}
}

func TestVerifySignatureTransportErrorIsDistinguishable(t *testing.T) {
	// Resolver returns a non-ErrUnknownRoot error — typically a
	// database outage. VerifySignature must wrap with
	// ErrTransportFailure, NOT ErrVerifyFailed, so AttachSession
	// can log ERROR vs WARN.
	key := randomKey(t)
	issuer, _ := NewIssuer("verify-root", key)
	_, serialized, err := issuer.IssueSession(SessionParams{
		UserID:      testUser,
		ClientAppID: testApp,
		JourneyID:   testJourney,
		Action:      opencaravan.SessionActionJourneyRead,
		Expiration:  time.Now().Add(time.Hour),
		Now:         time.Now(),
	})
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}

	verifier, err := NewVerifier(func(_ context.Context, _ string) ([]byte, error) {
		return nil, errors.New("simulated database outage")
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	_, err = verifier.VerifySignature(context.Background(), serialized)
	if !errors.Is(err, ErrTransportFailure) {
		t.Fatalf("err = %v, want errors.Is(_, ErrTransportFailure)", err)
	}
	if errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("transport error must NOT also wrap ErrVerifyFailed; got %v", err)
	}
}

func TestVerifyConvenienceWrapperReWrapsTransport(t *testing.T) {
	// Verify (single-shot convenience wrapper) must re-wrap
	// transport errors in ErrVerifyFailed so existing callers'
	// errors.Is(err, ErrVerifyFailed) keeps working — that's the
	// contract the convenience wrapper documents.
	key := randomKey(t)
	issuer, _ := NewIssuer("verify-root", key)
	_, serialized, err := issuer.IssueSession(SessionParams{
		UserID:      testUser,
		ClientAppID: testApp,
		JourneyID:   testJourney,
		Action:      opencaravan.SessionActionJourneyRead,
		Expiration:  time.Now().Add(time.Hour),
		Now:         time.Now(),
	})
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}
	verifier, err := NewVerifier(func(_ context.Context, _ string) ([]byte, error) {
		return nil, errors.New("simulated outage")
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	_, err = verifier.Verify(context.Background(), serialized, Constraints{
		JourneyID:   testJourney,
		Action:      opencaravan.SessionActionJourneyRead,
		UserID:      testUser,
		ClientAppID: testApp,
	})
	if !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("Verify err = %v, want ErrVerifyFailed wrap", err)
	}
}

func TestParseCaveatsTracksEarliestExpiration(t *testing.T) {
	// A macaroon attenuated to a shorter expiration must surface
	// the SHORTER time as Verified.Expiration, since macaroon AND
	// semantics make the effective expiration the earliest
	// time<T caveat.
	key := randomKey(t)
	issuer, _ := NewIssuer("verify-root", key)
	now := time.Now().UTC()
	later := now.Add(time.Hour)
	earlier := now.Add(15 * time.Minute)
	_, serialized, err := issuer.Issue([]string{
		opencaravan.CaveatTimeBefore(later),
		opencaravan.CaveatTimeBefore(earlier),
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	verifier := newTestVerifier(t, "verify-root", key, now)
	verified, err := verifier.VerifySignature(context.Background(), serialized)
	if err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
	if !verified.Expiration.Equal(earlier) {
		t.Fatalf("Expiration = %s, want earlier (%s)", verified.Expiration, earlier)
	}
}

func TestVerifierWithClockNilRestoresDefault(t *testing.T) {
	v, err := NewVerifier(func(context.Context, string) ([]byte, error) { return nil, ErrUnknownRoot })
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	v2 := v.WithClock(nil)
	if v2.now == nil {
		t.Fatal("WithClock(nil).now is nil; want time.Now fallback")
	}
}
