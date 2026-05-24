package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/opencaravan/opencaravan-go"
)

// Journey is the minimal-viable storage representation of a journey
// row. Phase 5 intentionally exposes only the subset of the
// journeys table that the integration-proof endpoints exercise;
// later phases will surface participants, segments, media, etc.
// as endpoints land that need them.
type Journey struct {
	ID            string
	Title         string
	Description   string
	HostUserID    string
	State         string
	Visibility    string
	RetentionMode string
	PolicyHash    string
	CreatedAt     time.Time
}

// JourneyParticipant is the minimal storage view of one
// journey_participants row. Phase 5 creates exactly one
// participant per journey — the host — at journey creation
// time. Telemetry submission resolves the caller to a participant
// via [Store.JourneyParticipantByUserAndJourney] so the batch row
// can carry a non-NULL participant_id.
type JourneyParticipant struct {
	ID        string
	JourneyID string
	UserID    string
	Role      string
	State     string
	JoinedAt  time.Time
}

// JourneyCreateParams names the input to [Store.CreateJourney].
// Title is required; Description may be empty. HostUserID is the
// caller's user id resolved by the identity middleware. The
// participant the journey creates names the same user as the
// "host" role.
type JourneyCreateParams struct {
	Title       string
	Description string
	HostUserID  string
	// PolicyHash and PolicyJSON come from the active server
	// policy snapshot. Stored verbatim on the journey row so a
	// later policy rotation does not retroactively change what
	// the journey was created under.
	PolicyHash string
	PolicyJSON string
}

// ErrJourneyNotFound is returned when [Store.JourneyByID] cannot
// find a row matching the supplied id. Detected via [errors.Is].
var ErrJourneyNotFound = errors.New("storage: journey not found")

// ErrJourneyParticipantNotFound is returned when
// [Store.JourneyParticipantByUserAndJourney] cannot resolve a
// participant row. Detected via [errors.Is]. The telemetry
// endpoint maps this to 403 — the caller's session passed
// signature/journey/action checks but they are not actually a
// participant in this journey.
var ErrJourneyParticipantNotFound = errors.New("storage: journey participant not found")

// CreateJourney atomically inserts a new journeys row and a
// journey_participants row representing the host. Returns the
// created Journey on success.
//
// Defaults applied (Phase 5 keeps the surface narrow):
//
//   - state: planned
//   - visibility: private
//   - retention_mode: ephemeral
//   - participant role: host
//   - participant state: joined
//   - participant sharing_state: off
//
// Each of these will become caller-configurable as later phases
// add the protocol surface for it. The transaction guarantees the
// host participant exists if and only if the journey row exists,
// so the telemetry endpoint's participant lookup never has to
// reason about partial state.
func (s *Store) CreateJourney(ctx context.Context, params JourneyCreateParams) (Journey, error) {
	if s == nil || s.db == nil {
		return Journey{}, errors.New("storage: database is not open")
	}
	if params.Title == "" {
		return Journey{}, errors.New("storage: journey title must be set")
	}
	if params.HostUserID == "" {
		return Journey{}, errors.New("storage: journey host user id must be set")
	}
	if params.PolicyHash == "" || params.PolicyJSON == "" {
		return Journey{}, errors.New("storage: journey policy hash and json must be set")
	}

	now := time.Now().UTC()
	journeyUUID, err := opencaravan.NewUUID()
	if err != nil {
		return Journey{}, fmt.Errorf("storage: mint journey id: %w", err)
	}
	participantUUID, err := opencaravan.NewUUID()
	if err != nil {
		return Journey{}, fmt.Errorf("storage: mint participant id: %w", err)
	}
	journeyID := string(journeyUUID)
	participantID := string(participantUUID)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Journey{}, fmt.Errorf("storage: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
INSERT INTO journeys (
    id, open_caravan_id, host_account_id, title, description,
    visibility, state, retention_mode, policy_hash, policy_json,
    created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`,
		journeyID,
		journeyID, // open_caravan_id mirrors id for now
		params.HostUserID,
		params.Title,
		params.Description,
		"private",
		"planned",
		"ephemeral",
		params.PolicyHash,
		params.PolicyJSON,
		formatSQLiteTime(now),
	); err != nil {
		return Journey{}, fmt.Errorf("storage: insert journey: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO journey_participants (
    id, journey_id, account_id, display_name, role, state,
    sharing_state, policy_hash, joined_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
`,
		participantID,
		journeyID,
		params.HostUserID,
		"", // display_name left empty for v0; future phase pulls from accounts
		"host",
		"joined",
		"off",
		params.PolicyHash,
		formatSQLiteTime(now),
	); err != nil {
		return Journey{}, fmt.Errorf("storage: insert host participant: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return Journey{}, fmt.Errorf("storage: commit journey create: %w", err)
	}

	return Journey{
		ID:            journeyID,
		Title:         params.Title,
		Description:   params.Description,
		HostUserID:    params.HostUserID,
		State:         "planned",
		Visibility:    "private",
		RetentionMode: "ephemeral",
		PolicyHash:    params.PolicyHash,
		CreatedAt:     now,
	}, nil
}

// JourneyByID returns the journey row keyed by id. Returns
// [ErrJourneyNotFound] when no matching row exists.
func (s *Store) JourneyByID(ctx context.Context, id string) (Journey, error) {
	if s == nil || s.db == nil {
		return Journey{}, errors.New("storage: database is not open")
	}
	if id == "" {
		return Journey{}, ErrJourneyNotFound
	}
	row := s.db.QueryRowContext(ctx, `
SELECT id, title, description, host_account_id, state, visibility,
       retention_mode, policy_hash, created_at
FROM journeys
WHERE id = ? AND deleted_at IS NULL
`, id)

	var (
		j         Journey
		hostID    sql.NullString
		createdAt string
	)
	if err := row.Scan(&j.ID, &j.Title, &j.Description, &hostID, &j.State,
		&j.Visibility, &j.RetentionMode, &j.PolicyHash, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Journey{}, ErrJourneyNotFound
		}
		return Journey{}, fmt.Errorf("storage: load journey %q: %w", id, err)
	}
	if hostID.Valid {
		j.HostUserID = hostID.String
	}
	parsed, err := time.Parse(sqliteTimeFormat, createdAt)
	if err != nil {
		return Journey{}, fmt.Errorf("storage: parse journey created_at: %w", err)
	}
	j.CreatedAt = parsed
	return j, nil
}

// JourneyParticipantByUserAndJourney returns the participant row
// representing userID's membership in journeyID. Returns
// [ErrJourneyParticipantNotFound] when no such row exists or when
// the participant has left the journey (state != 'joined'). Used
// by the telemetry endpoint to resolve the per-batch
// participant_id and to enforce "the caller is actually a
// participant" beyond what the macaroon's journey= caveat checks.
func (s *Store) JourneyParticipantByUserAndJourney(ctx context.Context, userID, journeyID string) (JourneyParticipant, error) {
	if s == nil || s.db == nil {
		return JourneyParticipant{}, errors.New("storage: database is not open")
	}
	if userID == "" || journeyID == "" {
		return JourneyParticipant{}, ErrJourneyParticipantNotFound
	}
	row := s.db.QueryRowContext(ctx, `
SELECT id, journey_id, account_id, role, state, joined_at
FROM journey_participants
WHERE account_id = ? AND journey_id = ? AND state = 'joined'
LIMIT 1
`, userID, journeyID)

	var (
		p        JourneyParticipant
		joinedAt sql.NullString
	)
	if err := row.Scan(&p.ID, &p.JourneyID, &p.UserID, &p.Role, &p.State, &joinedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return JourneyParticipant{}, ErrJourneyParticipantNotFound
		}
		return JourneyParticipant{}, fmt.Errorf("storage: load participant: %w", err)
	}
	if joinedAt.Valid {
		parsed, err := time.Parse(sqliteTimeFormat, joinedAt.String)
		if err != nil {
			return JourneyParticipant{}, fmt.Errorf("storage: parse participant joined_at: %w", err)
		}
		p.JoinedAt = parsed
	}
	return p, nil
}
