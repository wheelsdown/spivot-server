package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/opencaravan/opencaravan-go"
)

// JourneyVehicleRecord is the head-pointer projection of a
// persisted journey-scoped [opencaravan.Vehicle] together with its
// current ACL pointer. With the OpenCaravan 0.2-draft transition
// the per-attribute columns (display_name, make, model, …) have
// collapsed into an opaque canonical bundle; the server no longer
// interprets the descriptive fields. CanonicalPayloadJSON is the
// owner-signed Vehicle bytes verbatim so verifiers reproduce
// signature input deterministically and clients can decode the
// latest bundle without a separate revision lookup.
//
// AvatarBlobHash / BannerBlobHash are denormalized from the
// canonical bundle so a future blob-GC sweep can find references
// without parsing every bundle. Both may be nil when the owner
// has not attached a photo.
//
// The journey-scoped Vehicle is per-trip and signed by the journey
// participant who uploaded it. The persistent garage-layer
// GarageVehicle a user maintains in their account is a separate
// concept; see opencaravan-go's docs/vehicles.md for the two-layer
// model.
type JourneyVehicleRecord struct {
	ID                     string
	JourneyID              string
	OwnerUserID            string
	CurrentRevisionVersion int
	CurrentACLVersion      int
	Integrity              opencaravan.Integrity
	CanonicalPayloadJSON   []byte
	AvatarBlobHash         *string
	BannerBlobHash         *string
	ReceivedAt             time.Time
}

// JourneyVehicleRevisionRecord is the persisted shape of one
// signed Vehicle metadata bundle. Mirrors
// [JourneyVehicleACLRevision] for the metadata side: every
// revision retained so a recipient can audit how a vehicle's
// metadata (display name, photos, capacity) evolved during the
// journey, independent of the ACL chain.
type JourneyVehicleRevisionRecord struct {
	ID                   string
	JourneyVehicleID     string
	RevisionVersion      int
	RevisionTime         time.Time
	Integrity            opencaravan.Integrity
	CanonicalPayloadJSON []byte
	AvatarBlobHash       *string
	BannerBlobHash       *string
	ReceivedAt           time.Time
}

// JourneyVehicleACLRevision is the persisted shape of one signed
// [opencaravan.VehicleACL] update for a journey vehicle. Every
// revision is retained so a [DriverAttestation] referencing an
// earlier acl_version_consulted can validate against the ACL that
// was current at its effective time, even if the owner has since
// revoked someone.
type JourneyVehicleACLRevision struct {
	ID                    string
	JourneyVehicleID      string
	ACLVersion            int
	EffectiveTime         time.Time
	AuthorizedDriversJSON string
	EmergencyRuleKind     string
	Integrity             opencaravan.Integrity
	CanonicalPayload      []byte
	ReceivedAt            time.Time
}

// JourneyVehicleCreateParams names the input to
// [Store.CreateJourneyVehicle]. The caller is responsible for
// having already validated both wire-level payloads (Validate())
// and verified their signatures against the owner's enrolled
// client cert. This storage method only persists. The canonical
// payload bytes for the Vehicle and the initial VehicleACL are
// supplied verbatim by the caller so the storage layer never
// re-canonicalizes (which would risk encoder drift between Go and
// other-language clients).
type JourneyVehicleCreateParams struct {
	JourneyID               string
	Vehicle                 opencaravan.Vehicle
	InitialACL              opencaravan.VehicleACL
	CanonicalVehiclePayload []byte
	CanonicalACLPayload     []byte
}

// JourneyVehicleACLAppendParams names the input to
// [Store.AppendJourneyVehicleACL].
type JourneyVehicleACLAppendParams struct {
	JourneyVehicleID string
	ACL              opencaravan.VehicleACL
	CanonicalPayload []byte
}

// JourneyVehicleRevisionAppendParams names the input to
// [Store.AppendJourneyVehicleRevision]. The supplied Vehicle MUST
// carry an Integrity envelope and carry a RevisionVersion
// strictly greater than the head's current_revision_version.
type JourneyVehicleRevisionAppendParams struct {
	JourneyVehicleID string
	Vehicle          opencaravan.Vehicle
	CanonicalPayload []byte
}

// ErrJourneyVehicleNotFound is returned when no row matches the
// supplied id (or the supplied journey + id pair). Detected via
// [errors.Is].
var ErrJourneyVehicleNotFound = errors.New("storage: journey vehicle not found")

// ErrJourneyVehicleDuplicateOwner is returned by
// [Store.CreateJourneyVehicle] when the (journey_id, owner_user_id)
// pair already has a vehicle uploaded. v0 enforces one journey
// Vehicle per participant per trip; replays return this sentinel
// so the handler can map to 409.
var ErrJourneyVehicleDuplicateOwner = errors.New("storage: journey vehicle already exists for this owner")

// ErrJourneyVehicleDuplicateID is returned by
// [Store.CreateJourneyVehicle] when the supplied Vehicle.ID is
// already present in the journey_vehicles table (anywhere — IDs
// are globally unique). Distinct from
// [ErrJourneyVehicleDuplicateOwner] so a UUID collision is not
// mis-reported as "this user already uploaded a vehicle." In
// practice, well-behaved clients mint fresh UUIDs and never see
// this; the sentinel exists so an accidental id reuse surfaces
// with an honest message instead of an inscrutable owner conflict.
var ErrJourneyVehicleDuplicateID = errors.New("storage: journey vehicle id already in use")

// ErrJourneyVehicleACLVersionConflict is returned by
// [Store.AppendJourneyVehicleACL] when the supplied ACL version
// is not strictly greater than the vehicle's current_acl_version.
// The protocol's monotonic-version contract requires each
// published revision to advance the counter; replays of an
// already-seen version and stale uploads of an older version
// both return this sentinel so the handler can map to 409.
var ErrJourneyVehicleACLVersionConflict = errors.New("storage: journey vehicle acl version must be strictly greater than current")

// ErrJourneyVehicleRevisionConflict is returned by
// [Store.AppendJourneyVehicleRevision] when the supplied
// metadata revision_version is not strictly greater than the
// vehicle's current_revision_version. The protocol's
// monotonic-version contract requires each published metadata
// bundle to advance the counter; replays of an already-seen
// version and stale uploads both return this sentinel so the
// handler can map to 409. Distinct sentinel from the ACL conflict
// so handlers (and structured logs) can tell which chain regressed.
var ErrJourneyVehicleRevisionConflict = errors.New("storage: journey vehicle revision version must be strictly greater than current")

// CreateJourneyVehicle persists a journey-scoped Vehicle and its
// initial ACL revision atomically. Three rows land in one
// transaction:
//
//  1. journey_vehicles — the head pointer (current_revision_version,
//     current_acl_version, denormalized blob hashes).
//  2. journey_vehicle_revisions — the v=1 metadata bundle.
//  3. journey_vehicle_acl_revisions — the v=1 ACL bundle.
//
// The canonical Vehicle and VehicleACL bytes are persisted
// verbatim so verifiers reproduce signature input deterministically
// without re-canonicalizing from parsed fields.
func (s *Store) CreateJourneyVehicle(ctx context.Context, params JourneyVehicleCreateParams) (JourneyVehicleRecord, error) {
	if s == nil || s.db == nil {
		return JourneyVehicleRecord{}, errors.New("storage: database is not open")
	}
	if params.JourneyID == "" {
		return JourneyVehicleRecord{}, errors.New("storage: journey id must be set")
	}
	if len(params.CanonicalVehiclePayload) == 0 {
		return JourneyVehicleRecord{}, errors.New("storage: canonical vehicle payload must be supplied")
	}
	if len(params.CanonicalACLPayload) == 0 {
		return JourneyVehicleRecord{}, errors.New("storage: canonical acl payload must be supplied")
	}
	if err := params.Vehicle.Validate(); err != nil {
		return JourneyVehicleRecord{}, fmt.Errorf("storage: vehicle validate: %w", err)
	}
	if params.Vehicle.Integrity == nil {
		return JourneyVehicleRecord{}, errors.New("storage: vehicle must carry an Integrity envelope")
	}
	if err := params.InitialACL.Validate(); err != nil {
		return JourneyVehicleRecord{}, fmt.Errorf("storage: initial acl validate: %w", err)
	}
	if params.InitialACL.Integrity == nil {
		return JourneyVehicleRecord{}, errors.New("storage: initial acl must carry an Integrity envelope")
	}
	if params.InitialACL.VehicleID != params.Vehicle.ID {
		return JourneyVehicleRecord{}, errors.New("storage: initial acl vehicle_id must match vehicle id")
	}
	if params.InitialACL.OwnerUserID != params.Vehicle.OwnerUserID {
		return JourneyVehicleRecord{}, errors.New("storage: initial acl owner_user_id must match vehicle owner_user_id")
	}

	avatarHash := blobRefHash(params.Vehicle.AvatarBlob)
	bannerHash := blobRefHash(params.Vehicle.BannerBlob)
	emergencyKind := emergencyRuleKind(params.InitialACL.EmergencyRule)
	authorizedDrivers, err := json.Marshal(params.InitialACL.AuthorizedDrivers)
	if err != nil {
		return JourneyVehicleRecord{}, fmt.Errorf("storage: marshal authorized_drivers: %w", err)
	}
	now := time.Now().UTC()
	revisionID, err := opencaravan.NewUUID()
	if err != nil {
		return JourneyVehicleRecord{}, fmt.Errorf("storage: mint revision id: %w", err)
	}
	aclRevID, err := opencaravan.NewUUID()
	if err != nil {
		return JourneyVehicleRecord{}, fmt.Errorf("storage: mint acl revision id: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return JourneyVehicleRecord{}, fmt.Errorf("storage: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Pre-check ID uniqueness inside the transaction so we can
	// return the right sentinel when the INSERT's UNIQUE failure
	// is ambiguous. SQLite serializes writes; another transaction
	// cannot insert this id between the SELECT and INSERT, so the
	// pre-check + UNIQUE-on-INSERT pair has no race. The remaining
	// UNIQUE failure after the pre-check is necessarily the
	// (journey_id, owner_user_id) index, so map cleanly to
	// ErrJourneyVehicleDuplicateOwner.
	var existing string
	switch err := tx.QueryRowContext(ctx,
		`SELECT id FROM journey_vehicles WHERE id = ?`,
		string(params.Vehicle.ID)).Scan(&existing); {
	case errors.Is(err, sql.ErrNoRows):
		// expected — id is fresh, proceed to INSERT.
	case err != nil:
		return JourneyVehicleRecord{}, fmt.Errorf("storage: pre-check vehicle id: %w", err)
	default:
		return JourneyVehicleRecord{}, ErrJourneyVehicleDuplicateID
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO journey_vehicles (
    id, journey_id, owner_user_id, current_revision_version,
    current_acl_version, integrity_algorithm, integrity_key_id,
    integrity_signature, canonical_payload_json,
    avatar_blob_hash, banner_blob_hash, received_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`,
		string(params.Vehicle.ID),
		params.JourneyID,
		string(params.Vehicle.OwnerUserID),
		params.Vehicle.RevisionVersion,
		params.InitialACL.ACLVersion,
		params.Vehicle.Integrity.Algorithm,
		params.Vehicle.Integrity.KeyID,
		params.Vehicle.Integrity.Signature,
		string(params.CanonicalVehiclePayload),
		nullableString(avatarHash),
		nullableString(bannerHash),
		formatSQLiteTime(now),
	); err != nil {
		if isUniqueViolation(err) {
			return JourneyVehicleRecord{}, ErrJourneyVehicleDuplicateOwner
		}
		return JourneyVehicleRecord{}, fmt.Errorf("storage: insert journey vehicle: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO journey_vehicle_revisions (
    id, journey_vehicle_id, revision_version, revision_time,
    integrity_algorithm, integrity_key_id, integrity_signature,
    canonical_payload_json, avatar_blob_hash, banner_blob_hash,
    received_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`,
		string(revisionID),
		string(params.Vehicle.ID),
		params.Vehicle.RevisionVersion,
		formatSQLiteTime(params.Vehicle.RevisionTime),
		params.Vehicle.Integrity.Algorithm,
		params.Vehicle.Integrity.KeyID,
		params.Vehicle.Integrity.Signature,
		string(params.CanonicalVehiclePayload),
		nullableString(avatarHash),
		nullableString(bannerHash),
		formatSQLiteTime(now),
	); err != nil {
		return JourneyVehicleRecord{}, fmt.Errorf("storage: insert initial vehicle revision: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO journey_vehicle_acl_revisions (
    id, journey_vehicle_id, acl_version, effective_time,
    authorized_drivers_json, emergency_rule_kind,
    integrity_algorithm, integrity_key_id, integrity_signature,
    canonical_payload_json, received_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`,
		string(aclRevID),
		string(params.Vehicle.ID),
		params.InitialACL.ACLVersion,
		formatSQLiteTime(params.InitialACL.EffectiveTime),
		string(authorizedDrivers),
		emergencyKind,
		params.InitialACL.Integrity.Algorithm,
		params.InitialACL.Integrity.KeyID,
		params.InitialACL.Integrity.Signature,
		string(params.CanonicalACLPayload),
		formatSQLiteTime(now),
	); err != nil {
		return JourneyVehicleRecord{}, fmt.Errorf("storage: insert initial acl revision: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return JourneyVehicleRecord{}, fmt.Errorf("storage: commit journey vehicle: %w", err)
	}

	return JourneyVehicleRecord{
		ID:                     string(params.Vehicle.ID),
		JourneyID:              params.JourneyID,
		OwnerUserID:            string(params.Vehicle.OwnerUserID),
		CurrentRevisionVersion: params.Vehicle.RevisionVersion,
		CurrentACLVersion:      params.InitialACL.ACLVersion,
		Integrity:              *params.Vehicle.Integrity,
		CanonicalPayloadJSON:   params.CanonicalVehiclePayload,
		AvatarBlobHash:         avatarHash,
		BannerBlobHash:         bannerHash,
		ReceivedAt:             now,
	}, nil
}

// JourneyVehicleByID returns the persisted vehicle's head-pointer
// projection. Returns [ErrJourneyVehicleNotFound] when the id does
// not match.
func (s *Store) JourneyVehicleByID(ctx context.Context, journeyID, vehicleID string) (JourneyVehicleRecord, error) {
	if s == nil || s.db == nil {
		return JourneyVehicleRecord{}, errors.New("storage: database is not open")
	}
	if journeyID == "" || vehicleID == "" {
		return JourneyVehicleRecord{}, ErrJourneyVehicleNotFound
	}
	row := s.db.QueryRowContext(ctx, `
SELECT id, journey_id, owner_user_id, current_revision_version,
       current_acl_version, integrity_algorithm, integrity_key_id,
       integrity_signature, canonical_payload_json,
       avatar_blob_hash, banner_blob_hash, received_at
FROM journey_vehicles
WHERE journey_id = ? AND id = ?
`, journeyID, vehicleID)
	return scanJourneyVehicle(row)
}

// ListJourneyVehicles returns every vehicle uploaded against a journey,
// ordered by received_at ascending so callers see the order participants
// joined.
func (s *Store) ListJourneyVehicles(ctx context.Context, journeyID string) ([]JourneyVehicleRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("storage: database is not open")
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, journey_id, owner_user_id, current_revision_version,
       current_acl_version, integrity_algorithm, integrity_key_id,
       integrity_signature, canonical_payload_json,
       avatar_blob_hash, banner_blob_hash, received_at
FROM journey_vehicles
WHERE journey_id = ?
ORDER BY received_at ASC
`, journeyID)
	if err != nil {
		return nil, fmt.Errorf("storage: query journey vehicles: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []JourneyVehicleRecord
	for rows.Next() {
		rec, err := scanJourneyVehicleRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// AppendJourneyVehicleACL records a new VehicleACL revision and
// advances the journey vehicle's current_acl_version pointer.
// Returns [ErrJourneyVehicleACLVersionConflict] when the supplied
// ACL version is not strictly greater than the existing
// current_acl_version. Strict monotonicity is the protocol's
// contract: owners publish revisions in order, and the server
// rejects both duplicates and stale uploads of older versions —
// either would let a v=2 revoke be reversed by a replay of v=1.
//
// Returns [ErrJourneyVehicleNotFound] when the journey vehicle id
// does not exist.
func (s *Store) AppendJourneyVehicleACL(ctx context.Context, params JourneyVehicleACLAppendParams) (JourneyVehicleACLRevision, error) {
	if s == nil || s.db == nil {
		return JourneyVehicleACLRevision{}, errors.New("storage: database is not open")
	}
	if err := params.ACL.Validate(); err != nil {
		return JourneyVehicleACLRevision{}, fmt.Errorf("storage: acl validate: %w", err)
	}
	if params.ACL.Integrity == nil {
		return JourneyVehicleACLRevision{}, errors.New("storage: acl must carry an Integrity envelope")
	}
	if len(params.CanonicalPayload) == 0 {
		return JourneyVehicleACLRevision{}, errors.New("storage: canonical payload must be supplied")
	}

	authorizedDriversJSON, err := json.Marshal(params.ACL.AuthorizedDrivers)
	if err != nil {
		return JourneyVehicleACLRevision{}, fmt.Errorf("storage: marshal authorized_drivers: %w", err)
	}
	emergencyKind := emergencyRuleKind(params.ACL.EmergencyRule)
	now := time.Now().UTC()
	revID, err := opencaravan.NewUUID()
	if err != nil {
		return JourneyVehicleACLRevision{}, fmt.Errorf("storage: mint acl revision id: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return JourneyVehicleACLRevision{}, fmt.Errorf("storage: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var currentVersion int
	if err := tx.QueryRowContext(ctx,
		`SELECT current_acl_version FROM journey_vehicles WHERE id = ?`,
		params.JourneyVehicleID).Scan(&currentVersion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return JourneyVehicleACLRevision{}, ErrJourneyVehicleNotFound
		}
		return JourneyVehicleACLRevision{}, fmt.Errorf("storage: load current acl version: %w", err)
	}
	if params.ACL.ACLVersion <= currentVersion {
		return JourneyVehicleACLRevision{}, ErrJourneyVehicleACLVersionConflict
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO journey_vehicle_acl_revisions (
    id, journey_vehicle_id, acl_version, effective_time,
    authorized_drivers_json, emergency_rule_kind,
    integrity_algorithm, integrity_key_id, integrity_signature,
    canonical_payload_json, received_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`,
		string(revID),
		params.JourneyVehicleID,
		params.ACL.ACLVersion,
		formatSQLiteTime(params.ACL.EffectiveTime),
		string(authorizedDriversJSON),
		emergencyKind,
		params.ACL.Integrity.Algorithm,
		params.ACL.Integrity.KeyID,
		params.ACL.Integrity.Signature,
		string(params.CanonicalPayload),
		formatSQLiteTime(now),
	); err != nil {
		if isUniqueViolation(err) {
			return JourneyVehicleACLRevision{}, ErrJourneyVehicleACLVersionConflict
		}
		return JourneyVehicleACLRevision{}, fmt.Errorf("storage: insert acl revision: %w", err)
	}

	// Conditional head UPDATE — only advance when our supplied
	// version is strictly greater than whatever's currently in the
	// row. Defends against a SELECT-then-UPDATE race where two
	// concurrent writers both observe the same current_acl_version,
	// both pass the strict version check above, both insert
	// distinct ACL revision rows (the UNIQUE constraint on
	// (vehicle, version) allows v=2 + v=3 to coexist), and a naive
	// UPDATE would let the second writer regress the head back to
	// the lower version. RowsAffected = 0 means another writer
	// raced ahead; we return ErrJourneyVehicleACLVersionConflict
	// and the tx rolls back so the loser revision row never lands
	// in the audit log either — clients see 409 and retry with a
	// fresh version number.
	res, err := tx.ExecContext(ctx,
		`UPDATE journey_vehicles SET current_acl_version = ? WHERE id = ? AND current_acl_version < ?`,
		params.ACL.ACLVersion, params.JourneyVehicleID, params.ACL.ACLVersion)
	if err != nil {
		return JourneyVehicleACLRevision{}, fmt.Errorf("storage: advance current acl: %w", err)
	}
	if affected, affErr := res.RowsAffected(); affErr != nil {
		return JourneyVehicleACLRevision{}, fmt.Errorf("storage: read rows affected: %w", affErr)
	} else if affected == 0 {
		return JourneyVehicleACLRevision{}, ErrJourneyVehicleACLVersionConflict
	}

	if err := tx.Commit(); err != nil {
		return JourneyVehicleACLRevision{}, fmt.Errorf("storage: commit acl revision: %w", err)
	}

	return JourneyVehicleACLRevision{
		ID:                    string(revID),
		JourneyVehicleID:      params.JourneyVehicleID,
		ACLVersion:            params.ACL.ACLVersion,
		EffectiveTime:         params.ACL.EffectiveTime,
		AuthorizedDriversJSON: string(authorizedDriversJSON),
		EmergencyRuleKind:     emergencyKind,
		Integrity:             *params.ACL.Integrity,
		CanonicalPayload:      params.CanonicalPayload,
		ReceivedAt:            now,
	}, nil
}

// AppendJourneyVehicleRevision records a new signed Vehicle
// metadata bundle and advances the journey vehicle's
// current_revision_version pointer. Mirrors
// [Store.AppendJourneyVehicleACL] in shape: monotonic version
// contract, conditional UPDATE for race protection,
// canonical-payload retention verbatim. The metadata chain is
// independent of the ACL chain — bumping a photo doesn't require
// a new ACL revision and vice-versa.
//
// Returns [ErrJourneyVehicleRevisionConflict] when the supplied
// revision_version is not strictly greater than the existing
// current_revision_version, and [ErrJourneyVehicleNotFound] when
// the journey vehicle id does not exist.
func (s *Store) AppendJourneyVehicleRevision(ctx context.Context, params JourneyVehicleRevisionAppendParams) (JourneyVehicleRevisionRecord, error) {
	if s == nil || s.db == nil {
		return JourneyVehicleRevisionRecord{}, errors.New("storage: database is not open")
	}
	if err := params.Vehicle.Validate(); err != nil {
		return JourneyVehicleRevisionRecord{}, fmt.Errorf("storage: vehicle validate: %w", err)
	}
	if params.Vehicle.Integrity == nil {
		return JourneyVehicleRevisionRecord{}, errors.New("storage: vehicle must carry an Integrity envelope")
	}
	if len(params.CanonicalPayload) == 0 {
		return JourneyVehicleRevisionRecord{}, errors.New("storage: canonical payload must be supplied")
	}

	avatarHash := blobRefHash(params.Vehicle.AvatarBlob)
	bannerHash := blobRefHash(params.Vehicle.BannerBlob)
	now := time.Now().UTC()
	revID, err := opencaravan.NewUUID()
	if err != nil {
		return JourneyVehicleRevisionRecord{}, fmt.Errorf("storage: mint revision id: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return JourneyVehicleRevisionRecord{}, fmt.Errorf("storage: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var currentVersion int
	if err := tx.QueryRowContext(ctx,
		`SELECT current_revision_version FROM journey_vehicles WHERE id = ?`,
		params.JourneyVehicleID).Scan(&currentVersion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return JourneyVehicleRevisionRecord{}, ErrJourneyVehicleNotFound
		}
		return JourneyVehicleRevisionRecord{}, fmt.Errorf("storage: load current revision: %w", err)
	}
	if params.Vehicle.RevisionVersion <= currentVersion {
		return JourneyVehicleRevisionRecord{}, ErrJourneyVehicleRevisionConflict
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO journey_vehicle_revisions (
    id, journey_vehicle_id, revision_version, revision_time,
    integrity_algorithm, integrity_key_id, integrity_signature,
    canonical_payload_json, avatar_blob_hash, banner_blob_hash,
    received_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`,
		string(revID),
		params.JourneyVehicleID,
		params.Vehicle.RevisionVersion,
		formatSQLiteTime(params.Vehicle.RevisionTime),
		params.Vehicle.Integrity.Algorithm,
		params.Vehicle.Integrity.KeyID,
		params.Vehicle.Integrity.Signature,
		string(params.CanonicalPayload),
		nullableString(avatarHash),
		nullableString(bannerHash),
		formatSQLiteTime(now),
	); err != nil {
		if isUniqueViolation(err) {
			return JourneyVehicleRevisionRecord{}, ErrJourneyVehicleRevisionConflict
		}
		return JourneyVehicleRevisionRecord{}, fmt.Errorf("storage: insert vehicle revision: %w", err)
	}

	// Conditional head UPDATE + RowsAffected check. Same race
	// rationale as AppendJourneyVehicleACL above. RowsAffected = 0
	// means another writer raced ahead; we return
	// ErrJourneyVehicleRevisionConflict and the tx rolls back so
	// the loser revision row never lands in the history table.
	res, err := tx.ExecContext(ctx, `
UPDATE journey_vehicles
SET current_revision_version = ?, integrity_algorithm = ?,
    integrity_key_id = ?, integrity_signature = ?,
    canonical_payload_json = ?, avatar_blob_hash = ?,
    banner_blob_hash = ?
WHERE id = ? AND current_revision_version < ?
`,
		params.Vehicle.RevisionVersion,
		params.Vehicle.Integrity.Algorithm,
		params.Vehicle.Integrity.KeyID,
		params.Vehicle.Integrity.Signature,
		string(params.CanonicalPayload),
		nullableString(avatarHash),
		nullableString(bannerHash),
		params.JourneyVehicleID,
		params.Vehicle.RevisionVersion,
	)
	if err != nil {
		return JourneyVehicleRevisionRecord{}, fmt.Errorf("storage: advance current revision: %w", err)
	}
	if affected, affErr := res.RowsAffected(); affErr != nil {
		return JourneyVehicleRevisionRecord{}, fmt.Errorf("storage: read rows affected: %w", affErr)
	} else if affected == 0 {
		return JourneyVehicleRevisionRecord{}, ErrJourneyVehicleRevisionConflict
	}

	if err := tx.Commit(); err != nil {
		return JourneyVehicleRevisionRecord{}, fmt.Errorf("storage: commit vehicle revision: %w", err)
	}

	return JourneyVehicleRevisionRecord{
		ID:                   string(revID),
		JourneyVehicleID:     params.JourneyVehicleID,
		RevisionVersion:      params.Vehicle.RevisionVersion,
		RevisionTime:         params.Vehicle.RevisionTime,
		Integrity:            *params.Vehicle.Integrity,
		CanonicalPayloadJSON: params.CanonicalPayload,
		AvatarBlobHash:       avatarHash,
		BannerBlobHash:       bannerHash,
		ReceivedAt:           now,
	}, nil
}

// JourneyVehicleACLAt returns the ACL revision that was current at
// the supplied time — the highest acl_version row whose
// effective_time <= at. Used by the [DriverAttestation] sync path
// to validate an attestation's acl_version_consulted against the
// right baseline.
//
// Returns [ErrJourneyVehicleNotFound] when no ACL revision exists
// at or before the requested time (which also covers the case where
// the vehicle itself doesn't exist).
func (s *Store) JourneyVehicleACLAt(ctx context.Context, journeyVehicleID string, at time.Time) (JourneyVehicleACLRevision, error) {
	if s == nil || s.db == nil {
		return JourneyVehicleACLRevision{}, errors.New("storage: database is not open")
	}
	row := s.db.QueryRowContext(ctx, `
SELECT id, journey_vehicle_id, acl_version, effective_time,
       authorized_drivers_json, emergency_rule_kind,
       integrity_algorithm, integrity_key_id, integrity_signature,
       canonical_payload_json, received_at
FROM journey_vehicle_acl_revisions
WHERE journey_vehicle_id = ? AND effective_time <= ?
ORDER BY acl_version DESC
LIMIT 1
`, journeyVehicleID, formatSQLiteTime(at))
	var (
		rec              JourneyVehicleACLRevision
		effectiveTimeStr string
		receivedAtStr    string
	)
	if err := row.Scan(&rec.ID, &rec.JourneyVehicleID, &rec.ACLVersion,
		&effectiveTimeStr, &rec.AuthorizedDriversJSON, &rec.EmergencyRuleKind,
		&rec.Integrity.Algorithm, &rec.Integrity.KeyID, &rec.Integrity.Signature,
		&rec.CanonicalPayload, &receivedAtStr); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return JourneyVehicleACLRevision{}, ErrJourneyVehicleNotFound
		}
		return JourneyVehicleACLRevision{}, fmt.Errorf("storage: load acl at %s: %w", at.Format(time.RFC3339Nano), err)
	}
	parsedEffective, err := time.Parse(sqliteTimeFormat, effectiveTimeStr)
	if err != nil {
		return JourneyVehicleACLRevision{}, fmt.Errorf("storage: parse effective_time: %w", err)
	}
	parsedReceived, err := time.Parse(sqliteTimeFormat, receivedAtStr)
	if err != nil {
		return JourneyVehicleACLRevision{}, fmt.Errorf("storage: parse received_at: %w", err)
	}
	rec.EffectiveTime = parsedEffective
	rec.ReceivedAt = parsedReceived
	return rec, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanJourneyVehicle(row rowScanner) (JourneyVehicleRecord, error) {
	var (
		rec        JourneyVehicleRecord
		avatarHash sql.NullString
		bannerHash sql.NullString
		receivedAt string
	)
	if err := row.Scan(&rec.ID, &rec.JourneyID, &rec.OwnerUserID,
		&rec.CurrentRevisionVersion, &rec.CurrentACLVersion,
		&rec.Integrity.Algorithm, &rec.Integrity.KeyID,
		&rec.Integrity.Signature, &rec.CanonicalPayloadJSON,
		&avatarHash, &bannerHash, &receivedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return JourneyVehicleRecord{}, ErrJourneyVehicleNotFound
		}
		return JourneyVehicleRecord{}, fmt.Errorf("storage: scan journey vehicle: %w", err)
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
		return JourneyVehicleRecord{}, fmt.Errorf("storage: parse journey vehicle received_at: %w", err)
	}
	rec.ReceivedAt = parsed
	return rec, nil
}

func scanJourneyVehicleRows(rows *sql.Rows) (JourneyVehicleRecord, error) {
	return scanJourneyVehicle(rows)
}

// blobRefHash returns the hash string of a *BlobRef when non-nil,
// or nil when the ref is absent. Used to denormalize the
// canonical-bundle's optional avatar/banner refs into the
// indexed columns the future blob-GC sweep needs.
func blobRefHash(ref *opencaravan.BlobRef) *string {
	if ref == nil {
		return nil
	}
	h := ref.Hash
	return &h
}

// nullableString returns an interface value suitable for SQL
// driver binding: nil for a nil pointer (writes SQL NULL) or
// the dereferenced string otherwise. Pairs with blobRefHash for
// the optional blob columns.
func nullableString(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

func emergencyRuleKind(rule *opencaravan.VehicleEmergencyRule) string {
	if rule == nil {
		return ""
	}
	return string(rule.Kind)
}
