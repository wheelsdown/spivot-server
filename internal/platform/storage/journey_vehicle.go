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

// JourneyVehicleRecord is the persisted shape of a journey-scoped
// [opencaravan.Vehicle] together with its current ACL pointer. The
// canonical signed payload is retained verbatim so a verifier can
// reproduce the signature input bytes without re-canonicalizing from
// the parsed fields (which would risk encoder-drift between Go and
// other-language clients).
//
// The journey-scoped Vehicle is per-trip and signed by the journey
// participant who uploaded it. The persistent garage-layer Vehicle a
// user maintains in their account is a separate concept; see
// opencaravan-go's docs/vehicles.md for the two-layer model.
type JourneyVehicleRecord struct {
	ID                 string
	JourneyID          string
	OwnerUserID        string
	DisplayName        string
	Make               string
	Model              string
	ModelYear          int
	Color              string
	Capacity           int
	AvatarImageRefJSON string
	BannerImageRefJSON string
	CurrentACLVersion  int
	EmergencyRuleKind  string
	Integrity          opencaravan.Integrity
	CanonicalPayload   []byte
	CreatedAt          time.Time
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
// [Store.CreateJourneyVehicle]. The caller is responsible for having
// already validated the wire-level Vehicle (Validate()) and verified
// its signature against the owner's enrolled client cert. This
// storage method only persists.
type JourneyVehicleCreateParams struct {
	JourneyID        string
	Vehicle          opencaravan.Vehicle
	CanonicalPayload []byte
}

// JourneyVehicleACLAppendParams names the input to
// [Store.AppendJourneyVehicleACL].
type JourneyVehicleACLAppendParams struct {
	JourneyVehicleID string
	ACL              opencaravan.VehicleACL
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

// ErrJourneyVehicleACLVersionConflict is returned by
// [Store.AppendJourneyVehicleACL] when the supplied ACL version
// collides with one already on file for this vehicle. The owner
// must publish a strictly higher version than the existing
// current_acl_version.
var ErrJourneyVehicleACLVersionConflict = errors.New("storage: journey vehicle acl version not monotonically greater")

// CreateJourneyVehicle persists a journey-scoped Vehicle and its
// initial ACL revision (ACLVersion = Vehicle.ACLVersion, with the
// AuthorizedDrivers list copied from the Vehicle as the v=N
// baseline). The Vehicle's canonical payload is stored verbatim so
// verifiers reproduce signature input bytes deterministically.
//
// The two writes happen in a single transaction so the vehicle row
// and its initial ACL revision become visible together or not at
// all.
func (s *Store) CreateJourneyVehicle(ctx context.Context, params JourneyVehicleCreateParams) (JourneyVehicleRecord, error) {
	if s == nil || s.db == nil {
		return JourneyVehicleRecord{}, errors.New("storage: database is not open")
	}
	if params.JourneyID == "" {
		return JourneyVehicleRecord{}, errors.New("storage: journey id must be set")
	}
	if len(params.CanonicalPayload) == 0 {
		return JourneyVehicleRecord{}, errors.New("storage: canonical payload must be supplied")
	}
	if err := params.Vehicle.Validate(); err != nil {
		return JourneyVehicleRecord{}, fmt.Errorf("storage: vehicle validate: %w", err)
	}
	if params.Vehicle.Integrity == nil {
		return JourneyVehicleRecord{}, errors.New("storage: vehicle must carry an Integrity envelope")
	}

	avatarJSON, err := marshalImageRef(params.Vehicle.AvatarImage)
	if err != nil {
		return JourneyVehicleRecord{}, fmt.Errorf("storage: marshal avatar: %w", err)
	}
	bannerJSON, err := marshalImageRef(params.Vehicle.BannerImage)
	if err != nil {
		return JourneyVehicleRecord{}, fmt.Errorf("storage: marshal banner: %w", err)
	}
	authorizedDrivers, err := json.Marshal(params.Vehicle.AuthorizedDrivers)
	if err != nil {
		return JourneyVehicleRecord{}, fmt.Errorf("storage: marshal authorized_drivers: %w", err)
	}
	emergencyKind := emergencyRuleKind(params.Vehicle.EmergencyRule)
	now := time.Now().UTC()
	aclRevID, err := opencaravan.NewUUID()
	if err != nil {
		return JourneyVehicleRecord{}, fmt.Errorf("storage: mint acl revision id: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return JourneyVehicleRecord{}, fmt.Errorf("storage: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
INSERT INTO journey_vehicles (
    id, journey_id, owner_user_id, display_name, make, model, model_year,
    color, capacity, avatar_image_ref_json, banner_image_ref_json,
    current_acl_version, emergency_rule_kind, integrity_algorithm,
    integrity_key_id, integrity_signature, canonical_payload_json, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`,
		string(params.Vehicle.ID),
		params.JourneyID,
		string(params.Vehicle.OwnerUserID),
		params.Vehicle.DisplayName,
		params.Vehicle.Make,
		params.Vehicle.Model,
		modelYearOrNil(params.Vehicle.ModelYear),
		params.Vehicle.Color,
		params.Vehicle.Capacity,
		avatarJSON,
		bannerJSON,
		params.Vehicle.ACLVersion,
		emergencyKind,
		params.Vehicle.Integrity.Algorithm,
		params.Vehicle.Integrity.KeyID,
		params.Vehicle.Integrity.Signature,
		string(params.CanonicalPayload),
		formatSQLiteTime(now),
	); err != nil {
		if isUniqueViolation(err) {
			return JourneyVehicleRecord{}, ErrJourneyVehicleDuplicateOwner
		}
		return JourneyVehicleRecord{}, fmt.Errorf("storage: insert journey vehicle: %w", err)
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
		params.Vehicle.ACLVersion,
		formatSQLiteTime(now),
		string(authorizedDrivers),
		emergencyKind,
		params.Vehicle.Integrity.Algorithm,
		params.Vehicle.Integrity.KeyID,
		params.Vehicle.Integrity.Signature,
		string(params.CanonicalPayload),
		formatSQLiteTime(now),
	); err != nil {
		return JourneyVehicleRecord{}, fmt.Errorf("storage: insert initial acl revision: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return JourneyVehicleRecord{}, fmt.Errorf("storage: commit journey vehicle: %w", err)
	}

	return JourneyVehicleRecord{
		ID:                 string(params.Vehicle.ID),
		JourneyID:          params.JourneyID,
		OwnerUserID:        string(params.Vehicle.OwnerUserID),
		DisplayName:        params.Vehicle.DisplayName,
		Make:               params.Vehicle.Make,
		Model:              params.Vehicle.Model,
		ModelYear:          params.Vehicle.ModelYear,
		Color:              params.Vehicle.Color,
		Capacity:           params.Vehicle.Capacity,
		AvatarImageRefJSON: avatarJSON,
		BannerImageRefJSON: bannerJSON,
		CurrentACLVersion:  params.Vehicle.ACLVersion,
		EmergencyRuleKind:  emergencyKind,
		Integrity:          *params.Vehicle.Integrity,
		CanonicalPayload:   params.CanonicalPayload,
		CreatedAt:          now,
	}, nil
}

// JourneyVehicleByID returns the persisted vehicle and its current
// ACL pointer. Returns [ErrJourneyVehicleNotFound] when the id does
// not match.
func (s *Store) JourneyVehicleByID(ctx context.Context, journeyID, vehicleID string) (JourneyVehicleRecord, error) {
	if s == nil || s.db == nil {
		return JourneyVehicleRecord{}, errors.New("storage: database is not open")
	}
	if journeyID == "" || vehicleID == "" {
		return JourneyVehicleRecord{}, ErrJourneyVehicleNotFound
	}
	row := s.db.QueryRowContext(ctx, `
SELECT id, journey_id, owner_user_id, display_name, make, model, model_year,
       color, capacity, avatar_image_ref_json, banner_image_ref_json,
       current_acl_version, emergency_rule_kind, integrity_algorithm,
       integrity_key_id, integrity_signature, canonical_payload_json,
       created_at
FROM journey_vehicles
WHERE journey_id = ? AND id = ?
`, journeyID, vehicleID)
	return scanJourneyVehicle(row)
}

// ListJourneyVehicles returns every vehicle uploaded against a journey,
// ordered by created_at ascending so callers see the order participants
// joined.
func (s *Store) ListJourneyVehicles(ctx context.Context, journeyID string) ([]JourneyVehicleRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("storage: database is not open")
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, journey_id, owner_user_id, display_name, make, model, model_year,
       color, capacity, avatar_image_ref_json, banner_image_ref_json,
       current_acl_version, emergency_rule_kind, integrity_algorithm,
       integrity_key_id, integrity_signature, canonical_payload_json,
       created_at
FROM journey_vehicles
WHERE journey_id = ?
ORDER BY created_at ASC
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
// advances the journey vehicle's current_acl_version pointer if the
// new revision is strictly greater than the one currently on file.
// Returns [ErrJourneyVehicleACLVersionConflict] when the supplied
// ACL version is not greater than the existing version.
//
// The advancing of current_acl_version is conditional: a strictly
// later revision can be inserted that retroactively pre-dates a
// later-effective ACL (e.g. a backfill upload during sync) without
// rewinding the current pointer.
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

	if params.ACL.ACLVersion > currentVersion {
		if _, err := tx.ExecContext(ctx,
			`UPDATE journey_vehicles SET current_acl_version = ?, emergency_rule_kind = ? WHERE id = ?`,
			params.ACL.ACLVersion, emergencyKind, params.JourneyVehicleID); err != nil {
			return JourneyVehicleACLRevision{}, fmt.Errorf("storage: advance current acl: %w", err)
		}
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
		rec       JourneyVehicleRecord
		modelYear sql.NullInt64
		createdAt string
	)
	if err := row.Scan(&rec.ID, &rec.JourneyID, &rec.OwnerUserID,
		&rec.DisplayName, &rec.Make, &rec.Model, &modelYear, &rec.Color,
		&rec.Capacity, &rec.AvatarImageRefJSON, &rec.BannerImageRefJSON,
		&rec.CurrentACLVersion, &rec.EmergencyRuleKind,
		&rec.Integrity.Algorithm, &rec.Integrity.KeyID,
		&rec.Integrity.Signature, &rec.CanonicalPayload, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return JourneyVehicleRecord{}, ErrJourneyVehicleNotFound
		}
		return JourneyVehicleRecord{}, fmt.Errorf("storage: scan journey vehicle: %w", err)
	}
	if modelYear.Valid {
		rec.ModelYear = int(modelYear.Int64)
	}
	parsed, err := time.Parse(sqliteTimeFormat, createdAt)
	if err != nil {
		return JourneyVehicleRecord{}, fmt.Errorf("storage: parse journey vehicle created_at: %w", err)
	}
	rec.CreatedAt = parsed
	return rec, nil
}

func scanJourneyVehicleRows(rows *sql.Rows) (JourneyVehicleRecord, error) {
	return scanJourneyVehicle(rows)
}

func marshalImageRef(ref *opencaravan.ImageResourceRef) (string, error) {
	if ref == nil {
		return "", nil
	}
	b, err := json.Marshal(ref)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func modelYearOrNil(year int) any {
	if year == 0 {
		return nil
	}
	return year
}

func emergencyRuleKind(rule *opencaravan.VehicleEmergencyRule) string {
	if rule == nil {
		return ""
	}
	return string(rule.Kind)
}
