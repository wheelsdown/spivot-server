package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/opencaravan/opencaravan-go"
)

// seedHostUser inserts an accounts row representing the journey
// host. CreateJourney expects host_account_id to FK into accounts.
// Phase 5 tests don't go through the full enrollment path because
// that would be a huge test fixture for an integration check; we
// just need a valid row to satisfy the FK.
func seedHostUser(t *testing.T, store *Store, userID string) {
	t.Helper()
	if _, err := store.db.ExecContext(context.Background(), `
INSERT INTO accounts (id, open_caravan_id, display_name, created_at)
VALUES (?, ?, ?, ?)
`, userID, userID, "", formatSQLiteTime(time.Now())); err != nil {
		t.Fatalf("seed host account: %v", err)
	}
}

func validJourneyParams(userID string) JourneyCreateParams {
	return JourneyCreateParams{
		Title:       "Pacific Coast Drive",
		Description: "Half-day along Highway 1",
		HostUserID:  userID,
		PolicyHash:  "test-policy-hash",
		PolicyJSON:  `{"version":"v0"}`,
	}
}

func TestCreateJourneyInsertsJourneyAndHostParticipant(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	hostUUID, err := opencaravan.NewUUID()
	if err != nil {
		t.Fatalf("NewUUID: %v", err)
	}
	hostID := string(hostUUID)
	seedHostUser(t, store, hostID)

	journey, err := store.CreateJourney(ctx, validJourneyParams(hostID))
	if err != nil {
		t.Fatalf("CreateJourney: %v", err)
	}
	if journey.ID == "" {
		t.Fatal("Journey.ID is empty")
	}
	if journey.Title != "Pacific Coast Drive" {
		t.Fatalf("Title = %q", journey.Title)
	}
	if journey.HostUserID != hostID {
		t.Fatalf("HostUserID = %q, want %q", journey.HostUserID, hostID)
	}
	if journey.State != "planned" {
		t.Fatalf("State = %q, want planned", journey.State)
	}
	if journey.Visibility != "private" {
		t.Fatalf("Visibility = %q, want private", journey.Visibility)
	}

	// Companion participant exists for the host.
	participant, err := store.JourneyParticipantByUserAndJourney(ctx, hostID, journey.ID)
	if err != nil {
		t.Fatalf("JourneyParticipantByUserAndJourney: %v", err)
	}
	if participant.Role != "host" {
		t.Fatalf("participant role = %q", participant.Role)
	}
	if participant.State != "joined" {
		t.Fatalf("participant state = %q", participant.State)
	}
}

func TestCreateJourneyRejectsMissingTitle(t *testing.T) {
	store := openTestStore(t)
	hostUUID, _ := opencaravan.NewUUID()
	hostID := string(hostUUID)
	seedHostUser(t, store, hostID)
	params := validJourneyParams(hostID)
	params.Title = ""
	if _, err := store.CreateJourney(context.Background(), params); err == nil {
		t.Fatal("err = nil, want title required error")
	}
}

func TestCreateJourneyRejectsMissingHost(t *testing.T) {
	store := openTestStore(t)
	params := validJourneyParams("11111111-1111-4111-8111-111111111111")
	params.HostUserID = ""
	if _, err := store.CreateJourney(context.Background(), params); err == nil {
		t.Fatal("err = nil, want host required error")
	}
}

func TestCreateJourneyRollsBackOnPartialFailure(t *testing.T) {
	// Use a host id that doesn't exist in accounts so the
	// journeys INSERT fails its FK constraint. The participant
	// INSERT must not have left any row behind.
	store := openTestStore(t)
	ctx := context.Background()
	bogusHostID := "11111111-1111-4111-8111-111111111111"
	if _, err := store.CreateJourney(ctx, validJourneyParams(bogusHostID)); err == nil {
		t.Fatal("err = nil, want FK violation for missing host")
	}

	// No journey row exists, no participant row either.
	var journeyCount int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM journeys`).Scan(&journeyCount); err != nil {
		t.Fatalf("count journeys: %v", err)
	}
	if journeyCount != 0 {
		t.Fatalf("journey count = %d, want 0", journeyCount)
	}
	var partCount int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM journey_participants`).Scan(&partCount); err != nil {
		t.Fatalf("count participants: %v", err)
	}
	if partCount != 0 {
		t.Fatalf("participant count = %d, want 0", partCount)
	}
}

func TestJourneyByIDRoundTrip(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	hostUUID, _ := opencaravan.NewUUID()
	hostID := string(hostUUID)
	seedHostUser(t, store, hostID)
	created, err := store.CreateJourney(ctx, validJourneyParams(hostID))
	if err != nil {
		t.Fatalf("CreateJourney: %v", err)
	}

	got, err := store.JourneyByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("JourneyByID: %v", err)
	}
	if got.ID != created.ID {
		t.Fatalf("ID = %q, want %q", got.ID, created.ID)
	}
	if got.Title != created.Title {
		t.Fatalf("Title = %q, want %q", got.Title, created.Title)
	}
	if got.HostUserID != created.HostUserID {
		t.Fatalf("HostUserID = %q, want %q", got.HostUserID, created.HostUserID)
	}
}

func TestJourneyByIDNotFound(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.JourneyByID(context.Background(), "no-such-journey"); !errors.Is(err, ErrJourneyNotFound) {
		t.Fatalf("err = %v, want ErrJourneyNotFound", err)
	}
}

func TestJourneyByIDEmpty(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.JourneyByID(context.Background(), ""); !errors.Is(err, ErrJourneyNotFound) {
		t.Fatalf("err = %v, want ErrJourneyNotFound for empty id", err)
	}
}

func TestJourneyParticipantNotFound(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	if _, err := store.JourneyParticipantByUserAndJourney(ctx, "u", "j"); !errors.Is(err, ErrJourneyParticipantNotFound) {
		t.Fatalf("err = %v, want ErrJourneyParticipantNotFound", err)
	}
}

func TestJourneyParticipantSkipsNonJoinedRows(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	hostUUID, _ := opencaravan.NewUUID()
	hostID := string(hostUUID)
	seedHostUser(t, store, hostID)
	created, err := store.CreateJourney(ctx, validJourneyParams(hostID))
	if err != nil {
		t.Fatalf("CreateJourney: %v", err)
	}

	// Mark the host as left; the lookup should now miss.
	if _, err := store.db.ExecContext(ctx, `
UPDATE journey_participants SET state = 'left', left_at = ? WHERE journey_id = ?
`, formatSQLiteTime(time.Now()), created.ID); err != nil {
		t.Fatalf("mark left: %v", err)
	}
	if _, err := store.JourneyParticipantByUserAndJourney(ctx, hostID, created.ID); !errors.Is(err, ErrJourneyParticipantNotFound) {
		t.Fatalf("err = %v, want ErrJourneyParticipantNotFound for left participant", err)
	}
}
