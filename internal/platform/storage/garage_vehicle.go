package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/opencaravan/opencaravan-go"
)

// GarageVehicleRecord is the head-pointer projection of a
// persisted [opencaravan.GarageVehicle]. Carries the denormalized
// current state for fast queries; the full signed revision history
// is in [GarageVehicleRevisionRecord].
type GarageVehicleRecord struct {
	ID                     string
	GarageID               string
	CurrentRevisionVersion int
	CurrentRevisionTime    time.Time
	DisplayName            string
	Make                   string
	Model                  string
	ModelYear              int
	Color                  string
	Capacity               int
	AvatarImageRefJSON     string
	BannerImageRefJSON     string
	Notes                  string
	CreatedAt              time.Time
}

// GarageVehicleRevisionRecord is the persisted shape of one signed
// GarageVehicle payload. Canonical signed bytes retained verbatim
// so a future signature-verification pass can reproduce input
// without re-canonicalizing.
type GarageVehicleRevisionRecord struct {
	ID               string
	GarageVehicleID  string
	RevisionVersion  int
	RevisionTime     time.Time
	SignedBy         string
	Integrity        opencaravan.Integrity
	CanonicalPayload []byte
	ReceivedAt       time.Time
}

// GarageVehicleCreateParams names the input to
// [Store.CreateGarageVehicle]. The supplied GarageVehicle MUST
// carry an Integrity envelope and have RevisionVersion = 1.
type GarageVehicleCreateParams struct {
	GarageVehicle    opencaravan.GarageVehicle
	CanonicalPayload []byte
}

// GarageVehicleAppendRevisionParams names the input to
// [Store.AppendGarageVehicleRevision].
type GarageVehicleAppendRevisionParams struct {
	GarageVehicle    opencaravan.GarageVehicle
	CanonicalPayload []byte
}

// ErrGarageVehicleNotFound is returned when no row matches the
// supplied id (or garage+id pair).
var ErrGarageVehicleNotFound = errors.New("storage: garage vehicle not found")

// ErrGarageVehicleRevisionVersionConflict is returned by
// [Store.AppendGarageVehicleRevision] when the supplied version is
// not strictly greater than the current head.
var ErrGarageVehicleRevisionVersionConflict = errors.New("storage: garage vehicle revision version must be strictly greater than current")

// CreateGarageVehicle persists a new garage vehicle at
// revision_version = 1 with its initial revision row. Both writes
// commit in a single transaction.
func (s *Store) CreateGarageVehicle(ctx context.Context, params GarageVehicleCreateParams) (GarageVehicleRecord, error) {
	if s == nil || s.db == nil {
		return GarageVehicleRecord{}, errors.New("storage: database is not open")
	}
	if err := params.GarageVehicle.Validate(); err != nil {
		return GarageVehicleRecord{}, fmt.Errorf("storage: garage vehicle validate: %w", err)
	}
	if params.GarageVehicle.Integrity == nil {
		return GarageVehicleRecord{}, errors.New("storage: garage vehicle must carry an Integrity envelope")
	}
	if params.GarageVehicle.RevisionVersion != 1 {
		return GarageVehicleRecord{}, errors.New("storage: CreateGarageVehicle requires revision_version = 1")
	}
	if len(params.CanonicalPayload) == 0 {
		return GarageVehicleRecord{}, errors.New("storage: canonical payload must be supplied")
	}

	avatarJSON, err := marshalImageRef(params.GarageVehicle.AvatarImage)
	if err != nil {
		return GarageVehicleRecord{}, fmt.Errorf("storage: marshal avatar: %w", err)
	}
	bannerJSON, err := marshalImageRef(params.GarageVehicle.BannerImage)
	if err != nil {
		return GarageVehicleRecord{}, fmt.Errorf("storage: marshal banner: %w", err)
	}
	now := time.Now().UTC()
	revisionID, err := opencaravan.NewUUID()
	if err != nil {
		return GarageVehicleRecord{}, fmt.Errorf("storage: mint revision id: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return GarageVehicleRecord{}, fmt.Errorf("storage: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
INSERT INTO garage_vehicles (
    id, garage_id, current_revision_version, current_revision_time,
    display_name, make, model, model_year, color, capacity,
    avatar_image_ref_json, banner_image_ref_json, notes, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`,
		string(params.GarageVehicle.ID),
		string(params.GarageVehicle.GarageID),
		params.GarageVehicle.RevisionVersion,
		formatSQLiteTime(params.GarageVehicle.RevisionTime),
		params.GarageVehicle.DisplayName,
		params.GarageVehicle.Make,
		params.GarageVehicle.Model,
		modelYearOrNil(params.GarageVehicle.ModelYear),
		params.GarageVehicle.Color,
		params.GarageVehicle.Capacity,
		avatarJSON,
		bannerJSON,
		params.GarageVehicle.Notes,
		formatSQLiteTime(now),
	); err != nil {
		if isUniqueViolation(err) {
			return GarageVehicleRecord{}, fmt.Errorf("storage: garage vehicle id %q already in use", params.GarageVehicle.ID)
		}
		return GarageVehicleRecord{}, fmt.Errorf("storage: insert garage vehicle: %w", err)
	}

	if err := insertGarageVehicleRevisionTx(ctx, tx, string(revisionID), params.GarageVehicle, params.CanonicalPayload, now); err != nil {
		return GarageVehicleRecord{}, err
	}

	if err := tx.Commit(); err != nil {
		return GarageVehicleRecord{}, fmt.Errorf("storage: commit garage vehicle: %w", err)
	}

	return GarageVehicleRecord{
		ID:                     string(params.GarageVehicle.ID),
		GarageID:               string(params.GarageVehicle.GarageID),
		CurrentRevisionVersion: params.GarageVehicle.RevisionVersion,
		CurrentRevisionTime:    params.GarageVehicle.RevisionTime,
		DisplayName:            params.GarageVehicle.DisplayName,
		Make:                   params.GarageVehicle.Make,
		Model:                  params.GarageVehicle.Model,
		ModelYear:              params.GarageVehicle.ModelYear,
		Color:                  params.GarageVehicle.Color,
		Capacity:               params.GarageVehicle.Capacity,
		AvatarImageRefJSON:     avatarJSON,
		BannerImageRefJSON:     bannerJSON,
		Notes:                  params.GarageVehicle.Notes,
		CreatedAt:              now,
	}, nil
}

// AppendGarageVehicleRevision records a new signed GarageVehicle
// payload and advances the head pointer. Returns
// [ErrGarageVehicleNotFound] when the vehicle does not exist and
// [ErrGarageVehicleRevisionVersionConflict] when the supplied
// version is not strictly greater than the current head.
func (s *Store) AppendGarageVehicleRevision(ctx context.Context, params GarageVehicleAppendRevisionParams) (GarageVehicleRevisionRecord, error) {
	if s == nil || s.db == nil {
		return GarageVehicleRevisionRecord{}, errors.New("storage: database is not open")
	}
	if err := params.GarageVehicle.Validate(); err != nil {
		return GarageVehicleRevisionRecord{}, fmt.Errorf("storage: garage vehicle validate: %w", err)
	}
	if params.GarageVehicle.Integrity == nil {
		return GarageVehicleRevisionRecord{}, errors.New("storage: garage vehicle must carry an Integrity envelope")
	}
	if len(params.CanonicalPayload) == 0 {
		return GarageVehicleRevisionRecord{}, errors.New("storage: canonical payload must be supplied")
	}

	avatarJSON, err := marshalImageRef(params.GarageVehicle.AvatarImage)
	if err != nil {
		return GarageVehicleRevisionRecord{}, fmt.Errorf("storage: marshal avatar: %w", err)
	}
	bannerJSON, err := marshalImageRef(params.GarageVehicle.BannerImage)
	if err != nil {
		return GarageVehicleRevisionRecord{}, fmt.Errorf("storage: marshal banner: %w", err)
	}
	now := time.Now().UTC()
	revisionID, err := opencaravan.NewUUID()
	if err != nil {
		return GarageVehicleRevisionRecord{}, fmt.Errorf("storage: mint revision id: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return GarageVehicleRevisionRecord{}, fmt.Errorf("storage: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var currentVersion int
	if err := tx.QueryRowContext(ctx,
		`SELECT current_revision_version FROM garage_vehicles WHERE id = ?`,
		string(params.GarageVehicle.ID)).Scan(&currentVersion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return GarageVehicleRevisionRecord{}, ErrGarageVehicleNotFound
		}
		return GarageVehicleRevisionRecord{}, fmt.Errorf("storage: load current revision: %w", err)
	}
	if params.GarageVehicle.RevisionVersion <= currentVersion {
		return GarageVehicleRevisionRecord{}, ErrGarageVehicleRevisionVersionConflict
	}

	if err := insertGarageVehicleRevisionTx(ctx, tx, string(revisionID), params.GarageVehicle, params.CanonicalPayload, now); err != nil {
		return GarageVehicleRevisionRecord{}, err
	}

	if _, err := tx.ExecContext(ctx, `
UPDATE garage_vehicles
SET current_revision_version = ?, current_revision_time = ?,
    display_name = ?, make = ?, model = ?, model_year = ?,
    color = ?, capacity = ?, avatar_image_ref_json = ?,
    banner_image_ref_json = ?, notes = ?
WHERE id = ?
`,
		params.GarageVehicle.RevisionVersion,
		formatSQLiteTime(params.GarageVehicle.RevisionTime),
		params.GarageVehicle.DisplayName,
		params.GarageVehicle.Make,
		params.GarageVehicle.Model,
		modelYearOrNil(params.GarageVehicle.ModelYear),
		params.GarageVehicle.Color,
		params.GarageVehicle.Capacity,
		avatarJSON,
		bannerJSON,
		params.GarageVehicle.Notes,
		string(params.GarageVehicle.ID),
	); err != nil {
		return GarageVehicleRevisionRecord{}, fmt.Errorf("storage: update garage vehicle head: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return GarageVehicleRevisionRecord{}, fmt.Errorf("storage: commit revision: %w", err)
	}

	return GarageVehicleRevisionRecord{
		ID:               string(revisionID),
		GarageVehicleID:  string(params.GarageVehicle.ID),
		RevisionVersion:  params.GarageVehicle.RevisionVersion,
		RevisionTime:     params.GarageVehicle.RevisionTime,
		SignedBy:         string(params.GarageVehicle.SignedBy),
		Integrity:        *params.GarageVehicle.Integrity,
		CanonicalPayload: params.CanonicalPayload,
		ReceivedAt:       now,
	}, nil
}

// GarageVehicleByID returns the head-pointer projection of the
// supplied garage vehicle. Scopes the lookup to garageID so a
// vehicle from one garage cannot leak through the get endpoint of
// another. Returns [ErrGarageVehicleNotFound] when no row matches
// the (garage_id, id) pair.
func (s *Store) GarageVehicleByID(ctx context.Context, garageID, vehicleID string) (GarageVehicleRecord, error) {
	if s == nil || s.db == nil {
		return GarageVehicleRecord{}, errors.New("storage: database is not open")
	}
	row := s.db.QueryRowContext(ctx, `
SELECT id, garage_id, current_revision_version, current_revision_time,
       display_name, make, model, model_year, color, capacity,
       avatar_image_ref_json, banner_image_ref_json, notes, created_at
FROM garage_vehicles
WHERE garage_id = ? AND id = ?
`, garageID, vehicleID)
	return scanGarageVehicle(row)
}

// ListGarageVehicles returns every vehicle in the supplied garage,
// ordered by created_at ascending so the iOS app can render the
// list in the order vehicles were added.
func (s *Store) ListGarageVehicles(ctx context.Context, garageID string) ([]GarageVehicleRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("storage: database is not open")
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, garage_id, current_revision_version, current_revision_time,
       display_name, make, model, model_year, color, capacity,
       avatar_image_ref_json, banner_image_ref_json, notes, created_at
FROM garage_vehicles
WHERE garage_id = ?
ORDER BY created_at ASC
`, garageID)
	if err != nil {
		return nil, fmt.Errorf("storage: query garage vehicles: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []GarageVehicleRecord
	for rows.Next() {
		rec, err := scanGarageVehicle(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func insertGarageVehicleRevisionTx(ctx context.Context, tx *sql.Tx, revisionID string, gv opencaravan.GarageVehicle, canonical []byte, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `
INSERT INTO garage_vehicle_revisions (
    id, garage_vehicle_id, revision_version, revision_time, signed_by,
    integrity_algorithm, integrity_key_id, integrity_signature,
    canonical_payload_json, received_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`,
		revisionID,
		string(gv.ID),
		gv.RevisionVersion,
		formatSQLiteTime(gv.RevisionTime),
		string(gv.SignedBy),
		gv.Integrity.Algorithm,
		gv.Integrity.KeyID,
		gv.Integrity.Signature,
		string(canonical),
		formatSQLiteTime(now),
	); err != nil {
		return fmt.Errorf("storage: insert garage vehicle revision: %w", err)
	}
	return nil
}

func scanGarageVehicle(row rowScanner) (GarageVehicleRecord, error) {
	var (
		rec                  GarageVehicleRecord
		modelYear            sql.NullInt64
		currentTime, created string
	)
	if err := row.Scan(&rec.ID, &rec.GarageID, &rec.CurrentRevisionVersion,
		&currentTime, &rec.DisplayName, &rec.Make, &rec.Model, &modelYear,
		&rec.Color, &rec.Capacity, &rec.AvatarImageRefJSON,
		&rec.BannerImageRefJSON, &rec.Notes, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return GarageVehicleRecord{}, ErrGarageVehicleNotFound
		}
		return GarageVehicleRecord{}, fmt.Errorf("storage: scan garage vehicle: %w", err)
	}
	if modelYear.Valid {
		rec.ModelYear = int(modelYear.Int64)
	}
	parsedCurrent, err := time.Parse(sqliteTimeFormat, currentTime)
	if err != nil {
		return GarageVehicleRecord{}, fmt.Errorf("storage: parse current_revision_time: %w", err)
	}
	parsedCreated, err := time.Parse(sqliteTimeFormat, created)
	if err != nil {
		return GarageVehicleRecord{}, fmt.Errorf("storage: parse created_at: %w", err)
	}
	rec.CurrentRevisionTime = parsedCurrent
	rec.CreatedAt = parsedCreated
	return rec, nil
}
