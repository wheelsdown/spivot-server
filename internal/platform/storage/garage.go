package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/opencaravan/opencaravan-go"
)

// GarageRecord is the head-pointer projection of a persisted Garage.
// Carries the denormalized current-revision metadata for fast
// "load garage current state" queries; the full revision history
// is in [GarageRevisionRecord].
type GarageRecord struct {
	ID                     string
	Name                   string
	CurrentRevisionVersion int
	CurrentRevisionTime    time.Time
	CreatedAt              time.Time
}

// GarageRevisionRecord is the persisted shape of one signed Garage
// payload. The canonical signed bytes are retained verbatim so a
// verifier can reproduce signature input bytes without
// re-canonicalizing the parsed fields.
type GarageRevisionRecord struct {
	ID               string
	GarageID         string
	RevisionVersion  int
	RevisionTime     time.Time
	SignedBy         string
	Integrity        opencaravan.Integrity
	CanonicalPayload []byte
	ReceivedAt       time.Time
}

// GarageOwnerRecord names one user's stake in a garage. AcceptedTime
// is nil while the invitation is pending; non-nil once the recipient
// has published a matching GarageOwnershipAcceptance.
type GarageOwnerRecord struct {
	GarageID     string
	UserID       string
	AddedTime    time.Time
	AcceptedTime *time.Time
}

// GarageOwnershipAcceptanceRecord is the persisted shape of one
// signed acceptance an invitee published.
type GarageOwnershipAcceptanceRecord struct {
	ID                      string
	GarageID                string
	RevisionVersionAccepted int
	AccepterUserID          string
	AcceptedTime            time.Time
	Integrity               opencaravan.Integrity
	CanonicalPayload        []byte
	ReceivedAt              time.Time
}

// GarageCreateParams names the input to [Store.CreateGarage]. The
// caller is responsible for validating + verifying the wire-level
// Garage. The supplied Garage MUST carry an Integrity envelope and
// have RevisionVersion = 1 (this method is for new garages, not
// revision appends).
type GarageCreateParams struct {
	Garage           opencaravan.Garage
	CanonicalPayload []byte
}

// GarageAppendRevisionParams names the input to
// [Store.AppendGarageRevision]. The supplied Garage MUST carry an
// Integrity envelope and a strictly-greater RevisionVersion than
// the current head.
type GarageAppendRevisionParams struct {
	Garage           opencaravan.Garage
	CanonicalPayload []byte
}

// GarageAcceptOwnershipParams names the input to
// [Store.AcceptGarageOwnership]. The supplied acceptance MUST carry
// an Integrity envelope and reference a revision in which the
// AccepterUserID was added as a pending (accepted_time NULL) owner.
type GarageAcceptOwnershipParams struct {
	Acceptance       opencaravan.GarageOwnershipAcceptance
	CanonicalPayload []byte
}

// ErrGarageNotFound is returned when the supplied id has no matching row.
var ErrGarageNotFound = errors.New("storage: garage not found")

// ErrGarageRevisionVersionConflict is returned by
// [Store.AppendGarageRevision] when the supplied revision version
// is not strictly greater than the existing current_revision_version.
var ErrGarageRevisionVersionConflict = errors.New("storage: garage revision version must be strictly greater than current")

// ErrGarageOwnershipNotPending is returned by
// [Store.AcceptGarageOwnership] when no pending owner row matches
// the (garage_id, accepter_user_id) pair at the named revision.
var ErrGarageOwnershipNotPending = errors.New("storage: no pending garage ownership invitation for this user at this revision")

// ErrGarageOwnershipAlreadyAccepted is returned when an acceptance
// is replayed for an invitation that has already been accepted
// against the same revision_version_accepted.
var ErrGarageOwnershipAlreadyAccepted = errors.New("storage: garage ownership already accepted")

// CreateGarage persists a brand-new Garage at revision_version = 1
// with the caller's accepted-owner entry materialized into
// garage_owners. The garage row, the revision row, and the
// owner-list rows commit in a single transaction so a partial
// failure leaves no orphans.
func (s *Store) CreateGarage(ctx context.Context, params GarageCreateParams) (GarageRecord, error) {
	if s == nil || s.db == nil {
		return GarageRecord{}, errors.New("storage: database is not open")
	}
	if err := params.Garage.Validate(); err != nil {
		return GarageRecord{}, fmt.Errorf("storage: garage validate: %w", err)
	}
	if params.Garage.Integrity == nil {
		return GarageRecord{}, errors.New("storage: garage must carry an Integrity envelope")
	}
	if params.Garage.RevisionVersion != 1 {
		return GarageRecord{}, errors.New("storage: CreateGarage requires revision_version = 1")
	}
	if len(params.CanonicalPayload) == 0 {
		return GarageRecord{}, errors.New("storage: canonical payload must be supplied")
	}

	now := time.Now().UTC()
	revisionID, err := opencaravan.NewUUID()
	if err != nil {
		return GarageRecord{}, fmt.Errorf("storage: mint revision id: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return GarageRecord{}, fmt.Errorf("storage: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
INSERT INTO garages (id, name, current_revision_version, current_revision_time, created_at)
VALUES (?, ?, ?, ?, ?)
`,
		string(params.Garage.ID),
		params.Garage.Name,
		params.Garage.RevisionVersion,
		formatSQLiteTime(params.Garage.RevisionTime),
		formatSQLiteTime(now),
	); err != nil {
		if isUniqueViolation(err) {
			return GarageRecord{}, fmt.Errorf("storage: garage id %q already in use", params.Garage.ID)
		}
		return GarageRecord{}, fmt.Errorf("storage: insert garage: %w", err)
	}

	if err := insertGarageRevisionTx(ctx, tx, string(revisionID), params.Garage, params.CanonicalPayload, now); err != nil {
		return GarageRecord{}, err
	}

	for _, owner := range params.Garage.Owners {
		if err := insertGarageOwnerTx(ctx, tx, string(params.Garage.ID), owner); err != nil {
			return GarageRecord{}, err
		}
	}

	if err := tx.Commit(); err != nil {
		return GarageRecord{}, fmt.Errorf("storage: commit garage: %w", err)
	}

	return GarageRecord{
		ID:                     string(params.Garage.ID),
		Name:                   params.Garage.Name,
		CurrentRevisionVersion: params.Garage.RevisionVersion,
		CurrentRevisionTime:    params.Garage.RevisionTime,
		CreatedAt:              now,
	}, nil
}

// AppendGarageRevision records a new signed Garage payload and
// updates the materialized current state (head pointer + owner
// projection) atomically. Returns [ErrGarageRevisionVersionConflict]
// when the supplied version is not strictly greater than the
// current head, and [ErrGarageNotFound] when the garage does not
// exist.
//
// The owner projection is recomputed by diffing the new owner list
// against the existing one: owners absent from the new payload are
// removed (unilateral removal), owners present with non-nil
// AcceptedTime are upserted accordingly, and newly-invited owners
// (AcceptedTime nil) are added as pending.
func (s *Store) AppendGarageRevision(ctx context.Context, params GarageAppendRevisionParams) (GarageRevisionRecord, error) {
	if s == nil || s.db == nil {
		return GarageRevisionRecord{}, errors.New("storage: database is not open")
	}
	if err := params.Garage.Validate(); err != nil {
		return GarageRevisionRecord{}, fmt.Errorf("storage: garage validate: %w", err)
	}
	if params.Garage.Integrity == nil {
		return GarageRevisionRecord{}, errors.New("storage: garage must carry an Integrity envelope")
	}
	if len(params.CanonicalPayload) == 0 {
		return GarageRevisionRecord{}, errors.New("storage: canonical payload must be supplied")
	}

	now := time.Now().UTC()
	revisionID, err := opencaravan.NewUUID()
	if err != nil {
		return GarageRevisionRecord{}, fmt.Errorf("storage: mint revision id: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return GarageRevisionRecord{}, fmt.Errorf("storage: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var currentVersion int
	if err := tx.QueryRowContext(ctx,
		`SELECT current_revision_version FROM garages WHERE id = ?`,
		string(params.Garage.ID)).Scan(&currentVersion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return GarageRevisionRecord{}, ErrGarageNotFound
		}
		return GarageRevisionRecord{}, fmt.Errorf("storage: load current revision version: %w", err)
	}
	if params.Garage.RevisionVersion <= currentVersion {
		return GarageRevisionRecord{}, ErrGarageRevisionVersionConflict
	}

	if err := insertGarageRevisionTx(ctx, tx, string(revisionID), params.Garage, params.CanonicalPayload, now); err != nil {
		return GarageRevisionRecord{}, err
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE garages SET name = ?, current_revision_version = ?, current_revision_time = ? WHERE id = ?`,
		params.Garage.Name, params.Garage.RevisionVersion, formatSQLiteTime(params.Garage.RevisionTime), string(params.Garage.ID)); err != nil {
		return GarageRevisionRecord{}, fmt.Errorf("storage: update garage head pointer: %w", err)
	}

	if err := reconcileGarageOwnersTx(ctx, tx, string(params.Garage.ID), params.Garage.Owners); err != nil {
		return GarageRevisionRecord{}, err
	}

	if err := tx.Commit(); err != nil {
		return GarageRevisionRecord{}, fmt.Errorf("storage: commit revision: %w", err)
	}

	return GarageRevisionRecord{
		ID:               string(revisionID),
		GarageID:         string(params.Garage.ID),
		RevisionVersion:  params.Garage.RevisionVersion,
		RevisionTime:     params.Garage.RevisionTime,
		SignedBy:         string(params.Garage.SignedBy),
		Integrity:        *params.Garage.Integrity,
		CanonicalPayload: params.CanonicalPayload,
		ReceivedAt:       now,
	}, nil
}

// AcceptGarageOwnership records a signed acceptance and updates
// the corresponding garage_owners row's accepted_time. Returns
// [ErrGarageOwnershipNotPending] when no pending invitation exists
// for the accepter, and [ErrGarageOwnershipAlreadyAccepted] when
// the same acceptance has been replayed for an invitation that has
// already been accepted at the same revision.
func (s *Store) AcceptGarageOwnership(ctx context.Context, params GarageAcceptOwnershipParams) (GarageOwnershipAcceptanceRecord, error) {
	if s == nil || s.db == nil {
		return GarageOwnershipAcceptanceRecord{}, errors.New("storage: database is not open")
	}
	if err := params.Acceptance.Validate(); err != nil {
		return GarageOwnershipAcceptanceRecord{}, fmt.Errorf("storage: acceptance validate: %w", err)
	}
	if params.Acceptance.Integrity == nil {
		return GarageOwnershipAcceptanceRecord{}, errors.New("storage: acceptance must carry an Integrity envelope")
	}
	if len(params.CanonicalPayload) == 0 {
		return GarageOwnershipAcceptanceRecord{}, errors.New("storage: canonical payload must be supplied")
	}

	now := time.Now().UTC()
	acceptanceID, err := opencaravan.NewUUID()
	if err != nil {
		return GarageOwnershipAcceptanceRecord{}, fmt.Errorf("storage: mint acceptance id: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return GarageOwnershipAcceptanceRecord{}, fmt.Errorf("storage: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Confirm the accepter has a pending invitation row. We
	// require the row to exist with accepted_time NULL — an
	// already-accepted acceptance at the same revision returns
	// ErrGarageOwnershipAlreadyAccepted; a missing row (the
	// invitation was rescinded or never existed) returns
	// ErrGarageOwnershipNotPending.
	var existingAccepted sql.NullString
	switch err := tx.QueryRowContext(ctx, `
SELECT accepted_time FROM garage_owners
WHERE garage_id = ? AND user_id = ?
`,
		string(params.Acceptance.GarageID),
		string(params.Acceptance.AccepterUserID),
	).Scan(&existingAccepted); {
	case errors.Is(err, sql.ErrNoRows):
		return GarageOwnershipAcceptanceRecord{}, ErrGarageOwnershipNotPending
	case err != nil:
		return GarageOwnershipAcceptanceRecord{}, fmt.Errorf("storage: load owner row: %w", err)
	}
	if existingAccepted.Valid {
		// Already accepted. Insert the acceptance row anyway so
		// the audit trail records the replay, but signal the
		// idempotent state to the caller via a distinct sentinel.
		if _, err := tx.ExecContext(ctx, garageAcceptanceInsert,
			string(acceptanceID),
			string(params.Acceptance.GarageID),
			params.Acceptance.RevisionVersionAccepted,
			string(params.Acceptance.AccepterUserID),
			formatSQLiteTime(params.Acceptance.AcceptedTime),
			params.Acceptance.Integrity.Algorithm,
			params.Acceptance.Integrity.KeyID,
			params.Acceptance.Integrity.Signature,
			string(params.CanonicalPayload),
			formatSQLiteTime(now),
		); err != nil && !isUniqueViolation(err) {
			return GarageOwnershipAcceptanceRecord{}, fmt.Errorf("storage: insert replay acceptance: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return GarageOwnershipAcceptanceRecord{}, fmt.Errorf("storage: commit replay acceptance: %w", err)
		}
		return GarageOwnershipAcceptanceRecord{}, ErrGarageOwnershipAlreadyAccepted
	}

	if _, err := tx.ExecContext(ctx, garageAcceptanceInsert,
		string(acceptanceID),
		string(params.Acceptance.GarageID),
		params.Acceptance.RevisionVersionAccepted,
		string(params.Acceptance.AccepterUserID),
		formatSQLiteTime(params.Acceptance.AcceptedTime),
		params.Acceptance.Integrity.Algorithm,
		params.Acceptance.Integrity.KeyID,
		params.Acceptance.Integrity.Signature,
		string(params.CanonicalPayload),
		formatSQLiteTime(now),
	); err != nil {
		if isUniqueViolation(err) {
			return GarageOwnershipAcceptanceRecord{}, ErrGarageOwnershipAlreadyAccepted
		}
		return GarageOwnershipAcceptanceRecord{}, fmt.Errorf("storage: insert acceptance: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE garage_owners SET accepted_time = ? WHERE garage_id = ? AND user_id = ?`,
		formatSQLiteTime(params.Acceptance.AcceptedTime),
		string(params.Acceptance.GarageID),
		string(params.Acceptance.AccepterUserID),
	); err != nil {
		return GarageOwnershipAcceptanceRecord{}, fmt.Errorf("storage: update owner accepted_time: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return GarageOwnershipAcceptanceRecord{}, fmt.Errorf("storage: commit acceptance: %w", err)
	}

	return GarageOwnershipAcceptanceRecord{
		ID:                      string(acceptanceID),
		GarageID:                string(params.Acceptance.GarageID),
		RevisionVersionAccepted: params.Acceptance.RevisionVersionAccepted,
		AccepterUserID:          string(params.Acceptance.AccepterUserID),
		AcceptedTime:            params.Acceptance.AcceptedTime,
		Integrity:               *params.Acceptance.Integrity,
		CanonicalPayload:        params.CanonicalPayload,
		ReceivedAt:              now,
	}, nil
}

// GarageByID returns the head-pointer projection of the supplied
// garage. The full owner list is loaded via [Store.ListGarageOwners].
// Returns [ErrGarageNotFound] when the id does not match.
func (s *Store) GarageByID(ctx context.Context, garageID string) (GarageRecord, error) {
	if s == nil || s.db == nil {
		return GarageRecord{}, errors.New("storage: database is not open")
	}
	row := s.db.QueryRowContext(ctx, `
SELECT id, name, current_revision_version, current_revision_time, created_at
FROM garages WHERE id = ?
`, garageID)
	var (
		rec                  GarageRecord
		currentTime, created string
	)
	if err := row.Scan(&rec.ID, &rec.Name, &rec.CurrentRevisionVersion, &currentTime, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return GarageRecord{}, ErrGarageNotFound
		}
		return GarageRecord{}, fmt.Errorf("storage: scan garage: %w", err)
	}
	parsedCurrent, err := time.Parse(sqliteTimeFormat, currentTime)
	if err != nil {
		return GarageRecord{}, fmt.Errorf("storage: parse current_revision_time: %w", err)
	}
	parsedCreated, err := time.Parse(sqliteTimeFormat, created)
	if err != nil {
		return GarageRecord{}, fmt.Errorf("storage: parse created_at: %w", err)
	}
	rec.CurrentRevisionTime = parsedCurrent
	rec.CreatedAt = parsedCreated
	return rec, nil
}

// ListGarageOwners returns every owner row for the supplied
// garage, including pending invitations (accepted_time = NULL).
// Ordered by added_time ascending so the caller can render the
// owner history in arrival order.
func (s *Store) ListGarageOwners(ctx context.Context, garageID string) ([]GarageOwnerRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("storage: database is not open")
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT garage_id, user_id, added_time, accepted_time
FROM garage_owners
WHERE garage_id = ?
ORDER BY added_time ASC, user_id ASC
`, garageID)
	if err != nil {
		return nil, fmt.Errorf("storage: query garage owners: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []GarageOwnerRecord
	for rows.Next() {
		rec, err := scanGarageOwner(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// ListGaragesForUser returns every garage in which the supplied
// user appears as an owner (accepted or pending). Used by the GET
// /v1/garages handler to render "my garages" plus pending
// invitations side by side.
func (s *Store) ListGaragesForUser(ctx context.Context, userID string) ([]GarageRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("storage: database is not open")
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT g.id, g.name, g.current_revision_version, g.current_revision_time, g.created_at
FROM garages g
INNER JOIN garage_owners o ON o.garage_id = g.id
WHERE o.user_id = ?
ORDER BY g.created_at ASC
`, userID)
	if err != nil {
		return nil, fmt.Errorf("storage: query garages for user: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []GarageRecord
	for rows.Next() {
		var (
			rec                  GarageRecord
			currentTime, created string
		)
		if err := rows.Scan(&rec.ID, &rec.Name, &rec.CurrentRevisionVersion, &currentTime, &created); err != nil {
			return nil, fmt.Errorf("storage: scan garages for user: %w", err)
		}
		parsedCurrent, err := time.Parse(sqliteTimeFormat, currentTime)
		if err != nil {
			return nil, fmt.Errorf("storage: parse current_revision_time: %w", err)
		}
		parsedCreated, err := time.Parse(sqliteTimeFormat, created)
		if err != nil {
			return nil, fmt.Errorf("storage: parse created_at: %w", err)
		}
		rec.CurrentRevisionTime = parsedCurrent
		rec.CreatedAt = parsedCreated
		out = append(out, rec)
	}
	return out, rows.Err()
}

// GarageOwnerByUserAndGarage returns the owner row for the
// supplied (garage, user) pair. Returns [ErrGarageNotFound] when
// no row matches — used by handlers as the "is this user an owner?"
// authorization gate.
func (s *Store) GarageOwnerByUserAndGarage(ctx context.Context, userID, garageID string) (GarageOwnerRecord, error) {
	if s == nil || s.db == nil {
		return GarageOwnerRecord{}, errors.New("storage: database is not open")
	}
	row := s.db.QueryRowContext(ctx, `
SELECT garage_id, user_id, added_time, accepted_time
FROM garage_owners
WHERE garage_id = ? AND user_id = ?
`, garageID, userID)
	rec, err := scanGarageOwner(row)
	if err != nil {
		if errors.Is(err, ErrGarageNotFound) {
			// scanGarageOwner mapped sql.ErrNoRows; surface the
			// more specific sentinel.
			return GarageOwnerRecord{}, ErrGarageNotFound
		}
		return GarageOwnerRecord{}, err
	}
	return rec, nil
}

const garageAcceptanceInsert = `
INSERT INTO garage_ownership_acceptances (
    id, garage_id, revision_version_accepted, accepter_user_id,
    accepted_time, integrity_algorithm, integrity_key_id,
    integrity_signature, canonical_payload_json, received_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`

func insertGarageRevisionTx(ctx context.Context, tx *sql.Tx, revisionID string, g opencaravan.Garage, canonical []byte, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `
INSERT INTO garage_revisions (
    id, garage_id, revision_version, revision_time, signed_by,
    integrity_algorithm, integrity_key_id, integrity_signature,
    canonical_payload_json, received_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`,
		revisionID,
		string(g.ID),
		g.RevisionVersion,
		formatSQLiteTime(g.RevisionTime),
		string(g.SignedBy),
		g.Integrity.Algorithm,
		g.Integrity.KeyID,
		g.Integrity.Signature,
		string(canonical),
		formatSQLiteTime(now),
	); err != nil {
		return fmt.Errorf("storage: insert garage revision: %w", err)
	}
	return nil
}

func insertGarageOwnerTx(ctx context.Context, tx *sql.Tx, garageID string, owner opencaravan.GarageOwner) error {
	var acceptedArg any
	if owner.AcceptedTime != nil {
		acceptedArg = formatSQLiteTime(*owner.AcceptedTime)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO garage_owners (garage_id, user_id, added_time, accepted_time)
VALUES (?, ?, ?, ?)
`,
		garageID,
		string(owner.UserID),
		formatSQLiteTime(owner.AddedTime),
		acceptedArg,
	); err != nil {
		return fmt.Errorf("storage: insert garage owner: %w", err)
	}
	return nil
}

// reconcileGarageOwnersTx materializes the supplied owner list as
// the new authoritative state: removes rows absent from the new
// list, upserts present rows. The new revision's owner list is the
// truth — pending and accepted alike — and replaces the existing
// projection wholesale.
func reconcileGarageOwnersTx(ctx context.Context, tx *sql.Tx, garageID string, owners []opencaravan.GarageOwner) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM garage_owners WHERE garage_id = ?`, garageID); err != nil {
		return fmt.Errorf("storage: clear garage owners: %w", err)
	}
	for _, owner := range owners {
		if err := insertGarageOwnerTx(ctx, tx, garageID, owner); err != nil {
			return err
		}
	}
	return nil
}

func scanGarageOwner(row rowScanner) (GarageOwnerRecord, error) {
	var (
		rec      GarageOwnerRecord
		added    string
		accepted sql.NullString
	)
	if err := row.Scan(&rec.GarageID, &rec.UserID, &added, &accepted); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return GarageOwnerRecord{}, ErrGarageNotFound
		}
		return GarageOwnerRecord{}, fmt.Errorf("storage: scan garage owner: %w", err)
	}
	parsedAdded, err := time.Parse(sqliteTimeFormat, added)
	if err != nil {
		return GarageOwnerRecord{}, fmt.Errorf("storage: parse added_time: %w", err)
	}
	rec.AddedTime = parsedAdded
	if accepted.Valid {
		parsedAccepted, err := time.Parse(sqliteTimeFormat, accepted.String)
		if err != nil {
			return GarageOwnerRecord{}, fmt.Errorf("storage: parse accepted_time: %w", err)
		}
		rec.AcceptedTime = &parsedAccepted
	}
	return rec, nil
}
