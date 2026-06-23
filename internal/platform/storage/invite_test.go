package storage

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/opencaravan/opencaravan-go"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	ctx := context.Background()
	store, err := Open(ctx, Config{Path: filepath.Join(t.TempDir(), "spivot.db")})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	})
	return store
}

func TestIssueInvitePersistsHashedRecord(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	token, invite, err := store.IssueInvite(ctx, opencaravan.InviteScopeServerRegistration, time.Hour)
	if err != nil {
		t.Fatalf("IssueInvite: %v", err)
	}
	if token.Value == "" {
		t.Fatal("token value is empty")
	}
	if invite.TokenHash == "" || len(invite.TokenHash) != 64 {
		t.Fatalf("token hash = %q (len %d), want 64 hex chars", invite.TokenHash, len(invite.TokenHash))
	}
	if invite.Scope != opencaravan.InviteScopeServerRegistration {
		t.Fatalf("scope = %q", invite.Scope)
	}
	if invite.UsedTime != nil {
		t.Fatal("fresh invite already marked used")
	}
	if !invite.Active(time.Now().UTC()) {
		t.Fatal("fresh invite is not Active")
	}

	if invite.TokenHash == token.Value {
		t.Fatal("token hash equals plaintext: plaintext should never be stored")
	}
}

func TestIssueInviteRejectsBadInputs(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	if _, _, err := store.IssueInvite(ctx, opencaravan.InviteScope("unknown"), time.Hour); err == nil {
		t.Fatal("expected error for unknown scope")
	}
	if _, _, err := store.IssueInvite(ctx, opencaravan.InviteScopeJourney, 0); err == nil {
		t.Fatal("expected error for zero lifetime")
	}
	if _, _, err := store.IssueInvite(ctx, opencaravan.InviteScopeJourney, -time.Hour); err == nil {
		t.Fatal("expected error for negative lifetime")
	}
}

func TestIssueInviteByPersistsCreator(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	creator := string(mustUUID(t))
	seedHostUser(t, store, creator)

	token, invite, err := store.IssueInviteBy(ctx, opencaravan.InviteScopeServerRegistration, time.Hour, creator, maxOutstandingForTest)
	if err != nil {
		t.Fatalf("IssueInviteBy: %v", err)
	}
	if invite.CreatedByUserID != creator {
		t.Fatalf("created_by_user_id = %q, want %q", invite.CreatedByUserID, creator)
	}
	if invite.TokenHash != hashInviteToken(token.Value) {
		t.Fatal("returned hash does not match the plaintext token")
	}
	// LookupInvite (the read path) round-trips the creator too.
	got, err := store.LookupInvite(ctx, token.Value)
	if err != nil {
		t.Fatalf("LookupInvite: %v", err)
	}
	if got.CreatedByUserID != creator {
		t.Fatalf("LookupInvite created_by_user_id = %q, want %q", got.CreatedByUserID, creator)
	}
}

func TestIssueInviteByRejectsBadInputs(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	if _, _, err := store.IssueInviteBy(ctx, opencaravan.InviteScopeServerRegistration, time.Hour, "", 10); err == nil {
		t.Fatal("expected error for empty created_by_user_id")
	}
	if _, _, err := store.IssueInviteBy(ctx, opencaravan.InviteScopeServerRegistration, time.Hour, "u", 0); err == nil {
		t.Fatal("expected error for non-positive maxOutstanding")
	}
	if _, _, err := store.IssueInviteBy(ctx, opencaravan.InviteScope("unknown"), time.Hour, "u", 10); err == nil {
		t.Fatal("expected error for unknown scope")
	}
}

func TestIssueInviteByEnforcesOutstandingCap(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	creator := string(mustUUID(t))
	seedHostUser(t, store, creator)

	const cap = 3
	var firstToken opencaravan.InviteToken
	for i := 0; i < cap; i++ {
		tok, _, err := store.IssueInviteBy(ctx, opencaravan.InviteScopeServerRegistration, time.Hour, creator, cap)
		if err != nil {
			t.Fatalf("issue #%d: %v", i, err)
		}
		if i == 0 {
			firstToken = tok
		}
	}

	// At the cap: the next mint is rejected.
	if _, _, err := store.IssueInviteBy(ctx, opencaravan.InviteScopeServerRegistration, time.Hour, creator, cap); !errors.Is(err, ErrInviteOutstandingLimit) {
		t.Fatalf("at cap: got %v, want ErrInviteOutstandingLimit", err)
	}

	// Consuming one frees a slot — the next mint now succeeds.
	if _, err := store.ConsumeInvite(ctx, firstToken.Value, string(mustUUID(t))); err != nil {
		t.Fatalf("ConsumeInvite: %v", err)
	}
	if _, _, err := store.IssueInviteBy(ctx, opencaravan.InviteScopeServerRegistration, time.Hour, creator, cap); err != nil {
		t.Fatalf("after consuming one, mint should succeed: %v", err)
	}
}

func TestIssueInviteByCapIsPerUser(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	userA := string(mustUUID(t))
	userB := string(mustUUID(t))
	seedHostUser(t, store, userA)
	seedHostUser(t, store, userB)

	// User A fills their cap.
	for i := 0; i < 2; i++ {
		if _, _, err := store.IssueInviteBy(ctx, opencaravan.InviteScopeServerRegistration, time.Hour, userA, 2); err != nil {
			t.Fatalf("userA issue #%d: %v", i, err)
		}
	}
	if _, _, err := store.IssueInviteBy(ctx, opencaravan.InviteScopeServerRegistration, time.Hour, userA, 2); !errors.Is(err, ErrInviteOutstandingLimit) {
		t.Fatalf("userA over cap: got %v, want ErrInviteOutstandingLimit", err)
	}
	// User B is unaffected by user A being at their cap.
	if _, _, err := store.IssueInviteBy(ctx, opencaravan.InviteScopeServerRegistration, time.Hour, userB, 2); err != nil {
		t.Fatalf("userB should mint freely: %v", err)
	}
}

func TestInvitesCreatedByListsCallersOwnNewestFirst(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	creator := string(mustUUID(t))
	other := string(mustUUID(t))
	seedHostUser(t, store, creator)
	seedHostUser(t, store, other)

	for i := 0; i < 3; i++ {
		if _, _, err := store.IssueInviteBy(ctx, opencaravan.InviteScopeServerRegistration, time.Hour, creator, 10); err != nil {
			t.Fatalf("creator issue #%d: %v", i, err)
		}
	}
	if _, _, err := store.IssueInviteBy(ctx, opencaravan.InviteScopeServerRegistration, time.Hour, other, 10); err != nil {
		t.Fatalf("other issue: %v", err)
	}

	got, err := store.InvitesCreatedBy(ctx, creator)
	if err != nil {
		t.Fatalf("InvitesCreatedBy: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 invites for creator, got %d (other user's invite must not leak)", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i].CreatedTime.After(got[i-1].CreatedTime) {
			t.Fatalf("not ordered newest-first at index %d", i)
		}
	}
	for _, inv := range got {
		if inv.CreatedByUserID != creator {
			t.Fatalf("leaked an invite created by %q", inv.CreatedByUserID)
		}
	}
}

// maxOutstandingForTest is a generous per-user cap for tests that aren't
// exercising the cap itself.
const maxOutstandingForTest = 100

func TestLookupInviteReturnsActiveRecord(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	token, original, err := store.IssueInvite(ctx, opencaravan.InviteScopeJourney, time.Hour)
	if err != nil {
		t.Fatalf("IssueInvite: %v", err)
	}

	got, err := store.LookupInvite(ctx, token.Value)
	if err != nil {
		t.Fatalf("LookupInvite: %v", err)
	}
	if got.TokenHash != original.TokenHash {
		t.Fatalf("hash mismatch: %q vs %q", got.TokenHash, original.TokenHash)
	}
	if got.Scope != opencaravan.InviteScopeJourney {
		t.Fatalf("scope = %q", got.Scope)
	}
}

func TestLookupInviteUnknownTokenReturnsNotFound(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	if _, err := store.LookupInvite(ctx, "no-such-token"); !errors.Is(err, ErrInviteNotFound) {
		t.Fatalf("LookupInvite unknown error = %v, want ErrInviteNotFound", err)
	}
}

func TestConsumeInviteIsAtomicAndSingleUse(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	token, _, err := store.IssueInvite(ctx, opencaravan.InviteScopeServerRegistration, time.Hour)
	if err != nil {
		t.Fatalf("IssueInvite: %v", err)
	}

	first, err := store.ConsumeInvite(ctx, token.Value, "client-app-1")
	if err != nil {
		t.Fatalf("first ConsumeInvite: %v", err)
	}
	if first.UsedTime == nil {
		t.Fatal("UsedTime not populated after consume")
	}
	if first.UsedByClientAppID != "client-app-1" {
		t.Fatalf("UsedByClientAppID = %q, want client-app-1", first.UsedByClientAppID)
	}

	_, err = store.ConsumeInvite(ctx, token.Value, "client-app-2")
	if !errors.Is(err, ErrInviteAlreadyUsed) {
		t.Fatalf("second ConsumeInvite error = %v, want ErrInviteAlreadyUsed", err)
	}

	got, err := store.LookupInvite(ctx, token.Value)
	if !errors.Is(err, ErrInviteAlreadyUsed) {
		t.Fatalf("LookupInvite after consume error = %v, want ErrInviteAlreadyUsed", err)
	}
	if got.UsedByClientAppID != "client-app-1" {
		t.Fatalf("UsedByClientAppID = %q, want client-app-1", got.UsedByClientAppID)
	}
}

func TestConsumeInviteRejectsExpired(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	token, _, err := store.IssueInvite(ctx, opencaravan.InviteScopeServerRegistration, time.Millisecond)
	if err != nil {
		t.Fatalf("IssueInvite: %v", err)
	}
	time.Sleep(20 * time.Millisecond)

	_, err = store.ConsumeInvite(ctx, token.Value, "client-app-x")
	if !errors.Is(err, ErrInviteExpired) {
		t.Fatalf("ConsumeInvite expired error = %v, want ErrInviteExpired", err)
	}

	_, err = store.LookupInvite(ctx, token.Value)
	if !errors.Is(err, ErrInviteExpired) {
		t.Fatalf("LookupInvite expired error = %v, want ErrInviteExpired", err)
	}
}

func TestConsumeInviteRequiresClientAppID(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	token, _, err := store.IssueInvite(ctx, opencaravan.InviteScopeServerRegistration, time.Hour)
	if err != nil {
		t.Fatalf("IssueInvite: %v", err)
	}
	if _, err := store.ConsumeInvite(ctx, token.Value, ""); err == nil {
		t.Fatal("expected error for empty client app id")
	}
}

func TestUnconsumedInviteCountByScope(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	got, err := store.UnconsumedInviteCount(ctx, opencaravan.InviteScopeServerRegistration)
	if err != nil {
		t.Fatalf("UnconsumedInviteCount: %v", err)
	}
	if got != 0 {
		t.Fatalf("count = %d, want 0", got)
	}

	if _, _, err := store.IssueInvite(ctx, opencaravan.InviteScopeServerRegistration, time.Hour); err != nil {
		t.Fatalf("IssueInvite: %v", err)
	}
	if _, _, err := store.IssueInvite(ctx, opencaravan.InviteScopeServerRegistration, time.Hour); err != nil {
		t.Fatalf("IssueInvite: %v", err)
	}
	if _, _, err := store.IssueInvite(ctx, opencaravan.InviteScopeJourney, time.Hour); err != nil {
		t.Fatalf("IssueInvite journey: %v", err)
	}

	got, err = store.UnconsumedInviteCount(ctx, opencaravan.InviteScopeServerRegistration)
	if err != nil {
		t.Fatalf("UnconsumedInviteCount: %v", err)
	}
	if got != 2 {
		t.Fatalf("registration count = %d, want 2", got)
	}

	got, err = store.UnconsumedInviteCount(ctx, opencaravan.InviteScopeJourney)
	if err != nil {
		t.Fatalf("UnconsumedInviteCount journey: %v", err)
	}
	if got != 1 {
		t.Fatalf("journey count = %d, want 1", got)
	}
}

// TestIssueInviteConcurrentCallsProduceDistinctTokens verifies the
// concurrent-issuance claim in IssueInvite's docstring: parallel callers
// each generate independent random tokens, each successfully persists,
// and every TokenHash is distinct.
func TestIssueInviteConcurrentCallsProduceDistinctTokens(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	const racers = 8
	var (
		wg     sync.WaitGroup
		start  sync.WaitGroup
		mu     sync.Mutex
		hashes = make(map[string]struct{}, racers)
		errs   []error
	)
	start.Add(1)

	wg.Add(racers)
	for range racers {
		go func() {
			defer wg.Done()
			start.Wait()
			_, invite, err := store.IssueInvite(ctx, opencaravan.InviteScopeServerRegistration, time.Hour)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			hashes[invite.TokenHash] = struct{}{}
		}()
	}
	start.Done()
	wg.Wait()

	if len(errs) > 0 {
		t.Fatalf("%d concurrent IssueInvite calls failed: %v", len(errs), errs)
	}
	if got := len(hashes); got != racers {
		t.Fatalf("distinct token hashes = %d, want %d (concurrent issuance must produce unique tokens)", got, racers)
	}
}

// TestConsumeInviteConcurrentExactlyOneWinner verifies the atomicity
// claim in ConsumeInvite's docstring: among N goroutines redeeming the
// same token, exactly one observes a successful update; the rest get
// ErrInviteAlreadyUsed.
func TestConsumeInviteConcurrentExactlyOneWinner(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	token, _, err := store.IssueInvite(ctx, opencaravan.InviteScopeServerRegistration, time.Hour)
	if err != nil {
		t.Fatalf("IssueInvite: %v", err)
	}

	const racers = 8
	var (
		wg       sync.WaitGroup
		start    sync.WaitGroup
		wins     atomic.Int64
		conflict atomic.Int64
		others   atomic.Int64
	)
	start.Add(1)

	wg.Add(racers)
	for i := range racers {
		go func() {
			defer wg.Done()
			start.Wait()
			clientAppID := "client-app-" + strconv.Itoa(i)
			_, err := store.ConsumeInvite(ctx, token.Value, clientAppID)
			switch {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, ErrInviteAlreadyUsed):
				conflict.Add(1)
			default:
				others.Add(1)
				t.Errorf("racer %d unexpected error: %v", i, err)
			}
		}()
	}
	start.Done()
	wg.Wait()

	if wins.Load() != 1 {
		t.Fatalf("winners = %d, want exactly 1 (ConsumeInvite must be atomic single-use)", wins.Load())
	}
	if conflict.Load() != racers-1 {
		t.Fatalf("losers with ErrInviteAlreadyUsed = %d, want %d", conflict.Load(), racers-1)
	}
	if others.Load() != 0 {
		t.Fatalf("unexpected non-AlreadyUsed errors = %d", others.Load())
	}
}

func TestAccountCountReturnsZeroOnFreshDatabase(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	got, err := store.AccountCount(ctx)
	if err != nil {
		t.Fatalf("AccountCount: %v", err)
	}
	if got != 0 {
		t.Fatalf("count = %d, want 0", got)
	}
}

func TestClientAppCountReturnsZeroOnFreshDatabase(t *testing.T) {
	store := openTestStore(t)
	got, err := store.ClientAppCount(context.Background())
	if err != nil {
		t.Fatalf("ClientAppCount: %v", err)
	}
	if got != 0 {
		t.Fatalf("count = %d, want 0", got)
	}
}

func TestIssuedCertificateCountReturnsZeroOnFreshDatabase(t *testing.T) {
	store := openTestStore(t)
	got, err := store.IssuedCertificateCount(context.Background())
	if err != nil {
		t.Fatalf("IssuedCertificateCount: %v", err)
	}
	if got != 0 {
		t.Fatalf("count = %d, want 0", got)
	}
}
