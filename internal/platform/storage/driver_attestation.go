package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/opencaravan/opencaravan-go"
)

// DriverAttestationRecord is the persisted shape of one driver
// handoff. Carries the parsed fields, the server-computed
// trust_flag (so consumers can filter without re-running the
// trust evaluation), and the canonical signed bytes verbatim for
// reproducible signature verification.
//
// Per the OpenCaravan spec, the server never deletes a recorded
// attestation on trust failure — every claim is preserved as
// evidence and the trust_flag tells readers what to make of it.
type DriverAttestationRecord struct {
	ID                   string
	JourneyVehicleID     string
	SegmentID            string
	DriverUserID         string
	EffectiveTime        time.Time
	ACLVersionConsulted  int
	PriorAttestationHash *string
	TrustFlag            DriverAttestationTrust
	Integrity            opencaravan.Integrity
	CanonicalPayload     []byte
	ReceivedAt           time.Time
}

// DriverAttestationTrust enumerates the trust outcomes the
// server's evaluator can assign to a recorded attestation.
type DriverAttestationTrust string

const (
	// DriverAttestationTrustAuthorized means the driver was in
	// the AuthorizedDrivers list of the ACL revision current at
	// EffectiveTime. Normal, high-confidence case.
	DriverAttestationTrustAuthorized DriverAttestationTrust = "authorized"
	// DriverAttestationTrustEmergencyFallback means the driver was
	// NOT in the ACL but the vehicle's emergency_rule permitted a
	// journey-participant fallback and the driver is a confirmed
	// journey participant. Recorded with reduced trust; clients
	// should surface a "non-ACL emergency driver" indicator.
	DriverAttestationTrustEmergencyFallback DriverAttestationTrust = "emergency_fallback"
	// DriverAttestationTrustACLViolation means the driver was not
	// in the ACL and no fallback applied (emergency_rule was nil,
	// "none", or required journey participation the driver
	// lacked). The record is retained as evidence; consumers must
	// treat it as untrusted.
	DriverAttestationTrustACLViolation DriverAttestationTrust = "acl_violation"
)

// Valid reports whether trust is a known OpenCaravan value.
func (t DriverAttestationTrust) Valid() bool {
	switch t {
	case DriverAttestationTrustAuthorized,
		DriverAttestationTrustEmergencyFallback,
		DriverAttestationTrustACLViolation:
		return true
	default:
		return false
	}
}

// DriverAttestationRecordParams names the input to
// [Store.RecordDriverAttestation]. The caller is responsible for
// having computed TrustFlag from the ACL-at-time evaluator before
// calling — the storage layer trusts what it's given so the
// classification policy can evolve without re-touching SQL.
type DriverAttestationRecordParams struct {
	Attestation      opencaravan.DriverAttestation
	JourneyVehicleID string
	TrustFlag        DriverAttestationTrust
	CanonicalPayload []byte
}

// ErrDriverAttestationDuplicate is returned when an attestation
// matching an existing (journey_vehicle_id, driver_user_id,
// effective_time) tuple is replayed. The handler maps this to a
// 200-with-existing rather than a 409 because gossiped replays
// from peers are the normal case, not a fault.
var ErrDriverAttestationDuplicate = errors.New("storage: driver attestation already recorded")

// ErrDriverAttestationNotFound is returned by lookups that find no
// matching row.
var ErrDriverAttestationNotFound = errors.New("storage: driver attestation not found")

// RecordDriverAttestation persists the supplied attestation.
// Returns [ErrDriverAttestationDuplicate] when the
// (journey_vehicle_id, driver_user_id, effective_time) tuple is
// already on file; the caller can fetch the existing record via
// [Store.DriverAttestationByReplayKey] to return it idempotently.
func (s *Store) RecordDriverAttestation(ctx context.Context, params DriverAttestationRecordParams) (DriverAttestationRecord, error) {
	if s == nil || s.db == nil {
		return DriverAttestationRecord{}, errors.New("storage: database is not open")
	}
	if params.JourneyVehicleID == "" {
		return DriverAttestationRecord{}, errors.New("storage: journey vehicle id must be set")
	}
	if !params.TrustFlag.Valid() {
		return DriverAttestationRecord{}, fmt.Errorf("storage: trust flag %q is not a known value", params.TrustFlag)
	}
	if len(params.CanonicalPayload) == 0 {
		return DriverAttestationRecord{}, errors.New("storage: canonical payload must be supplied")
	}
	if err := params.Attestation.Validate(); err != nil {
		return DriverAttestationRecord{}, fmt.Errorf("storage: attestation validate: %w", err)
	}
	if params.Attestation.Integrity == nil {
		return DriverAttestationRecord{}, errors.New("storage: attestation must carry an Integrity envelope")
	}

	now := time.Now().UTC()
	recordID, err := opencaravan.NewUUID()
	if err != nil {
		return DriverAttestationRecord{}, fmt.Errorf("storage: mint attestation id: %w", err)
	}

	var priorHashArg any
	if params.Attestation.PriorAttestationHash != nil {
		priorHashArg = *params.Attestation.PriorAttestationHash
	}

	if _, err := s.db.ExecContext(ctx, `
INSERT INTO driver_attestations (
    id, journey_vehicle_id, segment_id, driver_user_id, effective_time,
    acl_version_consulted, prior_attestation_hash, trust_flag,
    integrity_algorithm, integrity_key_id, integrity_signature,
    canonical_payload_json, received_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`,
		string(recordID),
		params.JourneyVehicleID,
		string(params.Attestation.SegmentID),
		string(params.Attestation.DriverUserID),
		formatSQLiteTime(params.Attestation.EffectiveTime),
		params.Attestation.ACLVersionConsulted,
		priorHashArg,
		string(params.TrustFlag),
		params.Attestation.Integrity.Algorithm,
		params.Attestation.Integrity.KeyID,
		params.Attestation.Integrity.Signature,
		string(params.CanonicalPayload),
		formatSQLiteTime(now),
	); err != nil {
		if isUniqueViolation(err) {
			return DriverAttestationRecord{}, ErrDriverAttestationDuplicate
		}
		return DriverAttestationRecord{}, fmt.Errorf("storage: insert driver attestation: %w", err)
	}

	return DriverAttestationRecord{
		ID:                   string(recordID),
		JourneyVehicleID:     params.JourneyVehicleID,
		SegmentID:            string(params.Attestation.SegmentID),
		DriverUserID:         string(params.Attestation.DriverUserID),
		EffectiveTime:        params.Attestation.EffectiveTime,
		ACLVersionConsulted:  params.Attestation.ACLVersionConsulted,
		PriorAttestationHash: params.Attestation.PriorAttestationHash,
		TrustFlag:            params.TrustFlag,
		Integrity:            *params.Attestation.Integrity,
		CanonicalPayload:     params.CanonicalPayload,
		ReceivedAt:           now,
	}, nil
}

// DriverAttestationByReplayKey returns the existing attestation
// matching the supplied (journey_vehicle_id, driver_user_id,
// effective_time) tuple. Used by the handler to return the
// already-stored record after a duplicate-insert from a gossiped
// replay. Returns [ErrDriverAttestationNotFound] when the tuple
// does not match.
func (s *Store) DriverAttestationByReplayKey(ctx context.Context, journeyVehicleID, driverUserID string, effectiveTime time.Time) (DriverAttestationRecord, error) {
	if s == nil || s.db == nil {
		return DriverAttestationRecord{}, errors.New("storage: database is not open")
	}
	row := s.db.QueryRowContext(ctx, `
SELECT id, journey_vehicle_id, segment_id, driver_user_id, effective_time,
       acl_version_consulted, prior_attestation_hash, trust_flag,
       integrity_algorithm, integrity_key_id, integrity_signature,
       canonical_payload_json, received_at
FROM driver_attestations
WHERE journey_vehicle_id = ? AND driver_user_id = ? AND effective_time = ?
`, journeyVehicleID, driverUserID, formatSQLiteTime(effectiveTime))
	return scanDriverAttestation(row)
}

// ListDriverAttestations returns every recorded attestation for a
// journey vehicle, ordered by effective_time ascending so callers
// can reconstruct the handoff timeline. Includes low-trust rows;
// readers filter by TrustFlag when "show me only authorized
// drivers" is desired.
func (s *Store) ListDriverAttestations(ctx context.Context, journeyVehicleID string) ([]DriverAttestationRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("storage: database is not open")
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, journey_vehicle_id, segment_id, driver_user_id, effective_time,
       acl_version_consulted, prior_attestation_hash, trust_flag,
       integrity_algorithm, integrity_key_id, integrity_signature,
       canonical_payload_json, received_at
FROM driver_attestations
WHERE journey_vehicle_id = ?
ORDER BY effective_time ASC, received_at ASC
`, journeyVehicleID)
	if err != nil {
		return nil, fmt.Errorf("storage: query driver attestations: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []DriverAttestationRecord
	for rows.Next() {
		rec, err := scanDriverAttestation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// DriverAttestationForkSiblings returns every attestation that
// references the same prior_attestation_hash (the supplied digest
// included). Used by the handler to surface a fork warning when
// two drivers concurrently claim the same predecessor. Returns an
// empty slice when no rows match, not an error.
func (s *Store) DriverAttestationForkSiblings(ctx context.Context, journeyVehicleID, priorHash string) ([]DriverAttestationRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("storage: database is not open")
	}
	if priorHash == "" {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, journey_vehicle_id, segment_id, driver_user_id, effective_time,
       acl_version_consulted, prior_attestation_hash, trust_flag,
       integrity_algorithm, integrity_key_id, integrity_signature,
       canonical_payload_json, received_at
FROM driver_attestations
WHERE journey_vehicle_id = ? AND prior_attestation_hash = ?
ORDER BY effective_time ASC, received_at ASC
`, journeyVehicleID, priorHash)
	if err != nil {
		return nil, fmt.Errorf("storage: query fork siblings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []DriverAttestationRecord
	for rows.Next() {
		rec, err := scanDriverAttestation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func scanDriverAttestation(row rowScanner) (DriverAttestationRecord, error) {
	var (
		rec              DriverAttestationRecord
		priorHash        sql.NullString
		effectiveTimeStr string
		receivedAtStr    string
	)
	if err := row.Scan(&rec.ID, &rec.JourneyVehicleID, &rec.SegmentID,
		&rec.DriverUserID, &effectiveTimeStr, &rec.ACLVersionConsulted,
		&priorHash, &rec.TrustFlag, &rec.Integrity.Algorithm,
		&rec.Integrity.KeyID, &rec.Integrity.Signature,
		&rec.CanonicalPayload, &receivedAtStr); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return DriverAttestationRecord{}, ErrDriverAttestationNotFound
		}
		return DriverAttestationRecord{}, fmt.Errorf("storage: scan driver attestation: %w", err)
	}
	if priorHash.Valid {
		s := priorHash.String
		rec.PriorAttestationHash = &s
	}
	effective, err := time.Parse(sqliteTimeFormat, effectiveTimeStr)
	if err != nil {
		return DriverAttestationRecord{}, fmt.Errorf("storage: parse effective_time: %w", err)
	}
	received, err := time.Parse(sqliteTimeFormat, receivedAtStr)
	if err != nil {
		return DriverAttestationRecord{}, fmt.Errorf("storage: parse received_at: %w", err)
	}
	rec.EffectiveTime = effective
	rec.ReceivedAt = received
	return rec, nil
}
