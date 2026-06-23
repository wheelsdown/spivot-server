package storage

import (
	"context"
	"testing"
	"time"
)

// insertAccountAt inserts an account row with an explicit created_at and
// optional disabled_at so the founding-admin ordering + soft-disable
// behavior can be tested deterministically (the production enrollment
// path always stamps created_at = now, which gives no control over
// relative ordering within a fast test).
func insertAccountAt(t *testing.T, store *Store, id string, createdAt time.Time, disabled bool) {
	t.Helper()
	var disabledAt any
	if disabled {
		disabledAt = formatSQLiteTime(createdAt.Add(time.Minute))
	}
	if _, err := store.db.ExecContext(context.Background(), `
INSERT INTO accounts (id, open_caravan_id, display_name, created_at, disabled_at)
VALUES (?, ?, ?, ?, ?)
`, id, id, "", formatSQLiteTime(createdAt), disabledAt); err != nil {
		t.Fatalf("insert account %s: %v", id, err)
	}
}

func TestFoundingAdminUserIDEmptyDatabase(t *testing.T) {
	store := openTestStore(t)
	got, err := store.FoundingAdminUserID(context.Background())
	if err != nil {
		t.Fatalf("FoundingAdminUserID: %v", err)
	}
	if got != "" {
		t.Fatalf("empty DB: got %q, want \"\"", got)
	}
}

func TestFoundingAdminUserIDSingleAccount(t *testing.T) {
	// The already-deployed-prod case: exactly one account, created
	// before this concept existed, must be designated admin.
	store := openTestStore(t)
	insertAccountAt(t, store, "only-acct", time.Now().UTC(), false)
	got, err := store.FoundingAdminUserID(context.Background())
	if err != nil {
		t.Fatalf("FoundingAdminUserID: %v", err)
	}
	if got != "only-acct" {
		t.Fatalf("got %q, want only-acct", got)
	}
}

func TestFoundingAdminUserIDEarliestWins(t *testing.T) {
	store := openTestStore(t)
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	// Insert out of chronological order.
	insertAccountAt(t, store, "second", base.Add(5*time.Minute), false)
	insertAccountAt(t, store, "first", base, false)
	insertAccountAt(t, store, "third", base.Add(10*time.Minute), false)
	got, err := store.FoundingAdminUserID(context.Background())
	if err != nil {
		t.Fatalf("FoundingAdminUserID: %v", err)
	}
	if got != "first" {
		t.Fatalf("got %q, want first (earliest created_at)", got)
	}
}

func TestFoundingAdminUserIDTimestampTieIsDeterministic(t *testing.T) {
	// Two accounts sharing an identical created_at: the id ASC
	// tiebreaker must make the result deterministic (lower id),
	// otherwise "who is admin" depends on arbitrary row order.
	store := openTestStore(t)
	tie := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	insertAccountAt(t, store, "bbb", tie, false)
	insertAccountAt(t, store, "aaa", tie, false)
	got, err := store.FoundingAdminUserID(context.Background())
	if err != nil {
		t.Fatalf("FoundingAdminUserID: %v", err)
	}
	if got != "aaa" {
		t.Fatalf("tie: got %q, want aaa (lower id)", got)
	}
}

func TestFoundingAdminUserIDSkipsDisabledEarliest(t *testing.T) {
	// A disabled founder must not retain admin authority — the next
	// non-disabled account becomes founding admin.
	store := openTestStore(t)
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	insertAccountAt(t, store, "disabled-founder", base, true)
	insertAccountAt(t, store, "live-second", base.Add(time.Minute), false)
	got, err := store.FoundingAdminUserID(context.Background())
	if err != nil {
		t.Fatalf("FoundingAdminUserID: %v", err)
	}
	if got != "live-second" {
		t.Fatalf("got %q, want live-second (disabled founder skipped)", got)
	}
}

func TestFoundingAdminUserIDAllDisabled(t *testing.T) {
	store := openTestStore(t)
	insertAccountAt(t, store, "x", time.Now().UTC(), true)
	got, err := store.FoundingAdminUserID(context.Background())
	if err != nil {
		t.Fatalf("FoundingAdminUserID: %v", err)
	}
	if got != "" {
		t.Fatalf("all disabled: got %q, want \"\"", got)
	}
}

func TestIsFoundingAdmin(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	insertAccountAt(t, store, "founder", base, false)
	insertAccountAt(t, store, "second", base.Add(time.Minute), false)

	cases := map[string]struct {
		userID string
		want   bool
	}{
		"founder is admin": {"founder", true},
		"second is not":    {"second", false},
		"empty is not":     {"", false},
		"unknown is not":   {"nobody", false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := store.IsFoundingAdmin(ctx, tc.userID)
			if err != nil {
				t.Fatalf("IsFoundingAdmin: %v", err)
			}
			if got != tc.want {
				t.Fatalf("IsFoundingAdmin(%q) = %v, want %v", tc.userID, got, tc.want)
			}
		})
	}
}
