package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/opencaravan/opencaravan-go"
)

// TelemetryBatch is the minimal-viable storage view of one row in
// telemetry_batches. Phase 5 records the batch envelope (id,
// journey, participant, client batch id, sample count, payload
// digest, received_at) but does not yet expand individual samples
// into position_samples — that's a follow-up phase, since the
// integration-proof endpoint only needs to confirm the auth stack
// gates writes correctly.
type TelemetryBatch struct {
	ID            string
	JourneyID     string
	ParticipantID string
	ClientBatchID string
	SampleCount   int
	PayloadDigest string
	ReceivedAt    time.Time
}

// TelemetryBatchParams names the input to
// [Store.RecordTelemetryBatch]. JourneyID and ParticipantID must
// reference existing rows (FK enforces this). ClientBatchID is
// client-supplied and acts as the idempotency key — the
// UNIQUE(device_id, client_batch_id) constraint on
// telemetry_batches means a retry with the same id either
// succeeds (if it's the same request) or returns an error.
// PayloadDigest is typically SHA-256 of the canonical batch body
// so an operator can correlate batches across logs.
type TelemetryBatchParams struct {
	JourneyID     string
	ParticipantID string
	ClientBatchID string
	SampleCount   int
	PayloadDigest string
}

// ErrTelemetryBatchDuplicate is returned by
// [Store.RecordTelemetryBatch] when a row with the same
// (device_id, client_batch_id) already exists. The handler maps
// this to 409 — the caller already submitted this batch. Used as
// the canonical "lost the retry race" signal. Detected via
// [errors.Is].
var ErrTelemetryBatchDuplicate = errors.New("storage: telemetry batch already recorded")

// RecordTelemetryBatch inserts a new telemetry_batches row.
// Individual position_samples are not expanded in Phase 5 — the
// row carries the sample count and a digest so an operator can
// see that a batch was received and how big it was, without the
// per-sample storage Phase 5+ will add.
//
// device_id is left NULL: v0 doesn't track devices as first-class
// records (the issued_certificates audit table covers what the
// device path eventually will, until that gets promoted).
func (s *Store) RecordTelemetryBatch(ctx context.Context, params TelemetryBatchParams) (TelemetryBatch, error) {
	if s == nil || s.db == nil {
		return TelemetryBatch{}, errors.New("storage: database is not open")
	}
	if params.JourneyID == "" {
		return TelemetryBatch{}, errors.New("storage: telemetry journey id must be set")
	}
	if params.ParticipantID == "" {
		return TelemetryBatch{}, errors.New("storage: telemetry participant id must be set")
	}
	if params.ClientBatchID == "" {
		return TelemetryBatch{}, errors.New("storage: telemetry client batch id must be set")
	}
	if params.SampleCount < 0 {
		return TelemetryBatch{}, errors.New("storage: telemetry sample count must be non-negative")
	}
	if params.PayloadDigest == "" {
		return TelemetryBatch{}, errors.New("storage: telemetry payload digest must be set")
	}

	batchUUID, err := opencaravan.NewUUID()
	if err != nil {
		return TelemetryBatch{}, fmt.Errorf("storage: mint telemetry batch id: %w", err)
	}
	batchID := string(batchUUID)
	now := time.Now().UTC()

	_, err = s.db.ExecContext(ctx, `
INSERT INTO telemetry_batches (
    id, journey_id, participant_id, client_batch_id, sample_count,
    received_at, payload_digest
) VALUES (?, ?, ?, ?, ?, ?, ?)
`,
		batchID,
		params.JourneyID,
		params.ParticipantID,
		params.ClientBatchID,
		params.SampleCount,
		formatSQLiteTime(now),
		params.PayloadDigest,
	)
	if err != nil {
		// SQLite surfaces UNIQUE violation as "UNIQUE constraint
		// failed: telemetry_batches.device_id, telemetry_batches.client_batch_id".
		// Since device_id is NULL in v0 and SQLite treats NULL as
		// distinct in UNIQUE, this collision actually can't fire
		// today — but the contract is the right shape for when
		// device_id becomes populated. Surface the sentinel either
		// way so callers can detect duplicates as v0 evolves.
		if isUniqueViolation(err) {
			return TelemetryBatch{}, ErrTelemetryBatchDuplicate
		}
		return TelemetryBatch{}, fmt.Errorf("storage: insert telemetry batch: %w", err)
	}

	return TelemetryBatch{
		ID:            batchID,
		JourneyID:     params.JourneyID,
		ParticipantID: params.ParticipantID,
		ClientBatchID: params.ClientBatchID,
		SampleCount:   params.SampleCount,
		PayloadDigest: params.PayloadDigest,
		ReceivedAt:    now,
	}, nil
}

// isUniqueViolation reports whether err looks like a SQLite UNIQUE
// constraint failure. modernc/sqlite surfaces these with an
// "UNIQUE constraint" substring in the error message; matching
// the substring is more durable than scraping a non-public
// SQLite error code.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "UNIQUE constraint")
}
