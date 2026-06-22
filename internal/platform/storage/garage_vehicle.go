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
// persisted [opencaravan.GarageVehicle]. With the OpenCaravan
// 0.2-draft transition the per-attribute columns have collapsed
// into an opaque canonical bundle; the server no longer
// interprets the descriptive fields. CanonicalPayloadJSON is the
// owner-signed bundle bytes verbatim so verifiers reproduce
// signature input deterministically and clients can decode the
// latest GarageVehicle without a separate revision lookup.
//
// AvatarBlobHash / BannerBlobHash are denormalized from the
// canonical bundle so a future blob-GC sweep can find references
// without parsing every bundle.
type GarageVehicleRecord struct {
	ID                     string
	GarageID               string
	CurrentRevisionVersion int
	SignedByUserID         string
	Integrity              opencaravan.Integrity
	CanonicalPayloadJSON   []byte
	AvatarBlobHash         *string
	BannerBlobHash         *string
	ReceivedAt             time.Time
}

// GarageVehicleRevisionRecord is the persisted shape of one signed
// GarageVehicle payload. Canonical signed bytes retained verbatim
// so a verifier can reproduce signature input bytes
// deterministically.
type GarageVehicleRevisionRecord struct {
	ID                   string
	GarageVehicleID      string
	RevisionVersion      int
	RevisionTime         time.Time
	SignedByUserID       string
	Integrity            opencaravan.Integrity
	CanonicalPayloadJSON []byte
	AvatarBlobHash       *string
	BannerBlobHash       *string
	ReceivedAt           time.Time
}

// GarageVehicleCreateParams names the input to
// [Store.CreateGarageVehicle]. The supplied GarageVehicle MUST
// carry an Integrity envelope and have RevisionVersion = 1. The
// canonical bytes are supplied verbatim so the storage layer
// never re-canonicalizes.
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

	avatarHash := blobRefHash(params.GarageVehicle.AvatarBlob)
	bannerHash := blobRefHash(params.GarageVehicle.BannerBlob)
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
    id, garage_id, current_revision_version, integrity_algorithm,
    integrity_key_id, integrity_signature, canonical_payload_json,
    signed_by_user_id, avatar_blob_hash, banner_blob_hash, received_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`,
		string(params.GarageVehicle.ID),
		string(params.GarageVehicle.GarageID),
		params.GarageVehicle.RevisionVersion,
		params.GarageVehicle.Integrity.Algorithm,
		params.GarageVehicle.Integrity.KeyID,
		params.GarageVehicle.Integrity.Signature,
		string(params.CanonicalPayload),
		string(params.GarageVehicle.SignedBy),
		nullableString(avatarHash),
		nullableString(bannerHash),
		formatSQLiteTime(now),
	); err != nil {
		if isUniqueViolation(err) {
			return GarageVehicleRecord{}, fmt.Errorf("storage: garage vehicle id %q already in use", params.GarageVehicle.ID)
		}
		return GarageVehicleRecord{}, fmt.Errorf("storage: insert garage vehicle: %w", err)
	}

	if err := insertGarageVehicleRevisionTx(ctx, tx, string(revisionID), params.GarageVehicle, params.CanonicalPayload, avatarHash, bannerHash, now); err != nil {
		return GarageVehicleRecord{}, err
	}

	if err := tx.Commit(); err != nil {
		return GarageVehicleRecord{}, fmt.Errorf("storage: commit garage vehicle: %w", err)
	}

	return GarageVehicleRecord{
		ID:                     string(params.GarageVehicle.ID),
		GarageID:               string(params.GarageVehicle.GarageID),
		CurrentRevisionVersion: params.GarageVehicle.RevisionVersion,
		SignedByUserID:         string(params.GarageVehicle.SignedBy),
		Integrity:              *params.GarageVehicle.Integrity,
		CanonicalPayloadJSON:   params.CanonicalPayload,
		AvatarBlobHash:         avatarHash,
		BannerBlobHash:         bannerHash,
		ReceivedAt:             now,
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

	avatarHash := blobRefHash(params.GarageVehicle.AvatarBlob)
	bannerHash := blobRefHash(params.GarageVehicle.BannerBlob)
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

	// Scope the head lookup to (id, garage_id) so a mismatched
	// GarageVehicle.GarageID in the payload doesn't silently mutate
	// a row in the right vehicle id but the wrong garage. Returns
	// the same not-found sentinel as a fully-missing vehicle —
	// callers don't need to distinguish.
	var currentVersion int
	if err := tx.QueryRowContext(ctx,
		`SELECT current_revision_version FROM garage_vehicles WHERE id = ? AND garage_id = ?`,
		string(params.GarageVehicle.ID),
		string(params.GarageVehicle.GarageID)).Scan(&currentVersion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return GarageVehicleRevisionRecord{}, ErrGarageVehicleNotFound
		}
		return GarageVehicleRevisionRecord{}, fmt.Errorf("storage: load current revision: %w", err)
	}
	if params.GarageVehicle.RevisionVersion <= currentVersion {
		return GarageVehicleRevisionRecord{}, ErrGarageVehicleRevisionVersionConflict
	}

	if err := insertGarageVehicleRevisionTx(ctx, tx, string(revisionID), params.GarageVehicle, params.CanonicalPayload, avatarHash, bannerHash, now); err != nil {
		return GarageVehicleRevisionRecord{}, err
	}

	// Conditional head UPDATE + RowsAffected check. Defends
	// against a SELECT-then-UPDATE race where two accepted owners
	// both observe the same current_revision_version, both pass
	// the strict check above, both insert distinct revision rows
	// (the UNIQUE on (vehicle, version) allows v=2 + v=3 to
	// coexist), and a naive UPDATE would let the second writer
	// regress the head back to the lower version. RowsAffected=0
	// returns ErrGarageVehicleRevisionVersionConflict; the tx
	// rolls back so the loser revision row doesn't land in
	// history. Clients see 409 and retry with a fresh version.
	res, err := tx.ExecContext(ctx, `
UPDATE garage_vehicles
SET current_revision_version = ?, integrity_algorithm = ?,
    integrity_key_id = ?, integrity_signature = ?,
    canonical_payload_json = ?, signed_by_user_id = ?,
    avatar_blob_hash = ?, banner_blob_hash = ?
WHERE id = ? AND garage_id = ? AND current_revision_version < ?
`,
		params.GarageVehicle.RevisionVersion,
		params.GarageVehicle.Integrity.Algorithm,
		params.GarageVehicle.Integrity.KeyID,
		params.GarageVehicle.Integrity.Signature,
		string(params.CanonicalPayload),
		string(params.GarageVehicle.SignedBy),
		nullableString(avatarHash),
		nullableString(bannerHash),
		string(params.GarageVehicle.ID),
		string(params.GarageVehicle.GarageID),
		params.GarageVehicle.RevisionVersion,
	)
	if err != nil {
		return GarageVehicleRevisionRecord{}, fmt.Errorf("storage: update garage vehicle head: %w", err)
	}
	if affected, affErr := res.RowsAffected(); affErr != nil {
		return GarageVehicleRevisionRecord{}, fmt.Errorf("storage: read rows affected: %w", affErr)
	} else if affected == 0 {
		return GarageVehicleRevisionRecord{}, ErrGarageVehicleRevisionVersionConflict
	}

	if err := tx.Commit(); err != nil {
		return GarageVehicleRevisionRecord{}, fmt.Errorf("storage: commit revision: %w", err)
	}

	return GarageVehicleRevisionRecord{
		ID:                   string(revisionID),
		GarageVehicleID:      string(params.GarageVehicle.ID),
		RevisionVersion:      params.GarageVehicle.RevisionVersion,
		RevisionTime:         params.GarageVehicle.RevisionTime,
		SignedByUserID:       string(params.GarageVehicle.SignedBy),
		Integrity:            *params.GarageVehicle.Integrity,
		CanonicalPayloadJSON: params.CanonicalPayload,
		AvatarBlobHash:       avatarHash,
		BannerBlobHash:       bannerHash,
		ReceivedAt:           now,
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
SELECT id, garage_id, current_revision_version, integrity_algorithm,
       integrity_key_id, integrity_signature, canonical_payload_json,
       signed_by_user_id, avatar_blob_hash, banner_blob_hash, received_at
FROM garage_vehicles
WHERE garage_id = ? AND id = ?
`, garageID, vehicleID)
	return scanGarageVehicle(row)
}

// ListGarageVehicles returns every vehicle in the supplied garage,
// ordered by received_at ascending so the iOS app can render the
// list in the order vehicles were added.
func (s *Store) ListGarageVehicles(ctx context.Context, garageID string) ([]GarageVehicleRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("storage: database is not open")
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, garage_id, current_revision_version, integrity_algorithm,
       integrity_key_id, integrity_signature, canonical_payload_json,
       signed_by_user_id, avatar_blob_hash, banner_blob_hash, received_at
FROM garage_vehicles
WHERE garage_id = ?
ORDER BY received_at ASC
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

func insertGarageVehicleRevisionTx(ctx context.Context, tx *sql.Tx, revisionID string, gv opencaravan.GarageVehicle, canonical []byte, avatarHash, bannerHash *string, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `
INSERT INTO garage_vehicle_revisions (
    id, garage_vehicle_id, revision_version, revision_time,
    integrity_algorithm, integrity_key_id, integrity_signature,
    canonical_payload_json, signed_by_user_id,
    avatar_blob_hash, banner_blob_hash, received_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`,
		revisionID,
		string(gv.ID),
		gv.RevisionVersion,
		formatSQLiteTime(gv.RevisionTime),
		gv.Integrity.Algorithm,
		gv.Integrity.KeyID,
		gv.Integrity.Signature,
		string(canonical),
		string(gv.SignedBy),
		nullableString(avatarHash),
		nullableString(bannerHash),
		formatSQLiteTime(now),
	); err != nil {
		return fmt.Errorf("storage: insert garage vehicle revision: %w", err)
	}
	return nil
}

func scanGarageVehicle(row rowScanner) (GarageVehicleRecord, error) {
	var (
		rec        GarageVehicleRecord
		avatarHash sql.NullString
		bannerHash sql.NullString
		receivedAt string
	)
	if err := row.Scan(&rec.ID, &rec.GarageID, &rec.CurrentRevisionVersion,
		&rec.Integrity.Algorithm, &rec.Integrity.KeyID,
		&rec.Integrity.Signature, &rec.CanonicalPayloadJSON,
		&rec.SignedByUserID, &avatarHash, &bannerHash, &receivedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return GarageVehicleRecord{}, ErrGarageVehicleNotFound
		}
		return GarageVehicleRecord{}, fmt.Errorf("storage: scan garage vehicle: %w", err)
	}
	if avatarHash.Valid {
		v := avatarHash.String
		rec.AvatarBlobHash = &v
	}
	if bannerHash.Valid {
		v := bannerHash.String
		rec.BannerBlobHash = &v
	}
	parsed, err := time.Parse(sqliteTimeFormat, receivedAt)
	if err != nil {
		return GarageVehicleRecord{}, fmt.Errorf("storage: parse received_at: %w", err)
	}
	rec.ReceivedAt = parsed
	return rec, nil
}
