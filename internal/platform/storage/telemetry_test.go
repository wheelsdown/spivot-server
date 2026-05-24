package storage

import (
	"context"
	"testing"

	"github.com/opencaravan/opencaravan-go"
)

// seedJourneyWithHost is the standard setup for telemetry tests:
// account → journey + host participant. Returns the host user id,
// the journey id, and the participant id.
func seedJourneyWithHost(t *testing.T, store *Store) (hostID, journeyID, participantID string) {
	t.Helper()
	hostUUID, err := opencaravan.NewUUID()
	if err != nil {
		t.Fatalf("NewUUID: %v", err)
	}
	hostID = string(hostUUID)
	seedHostUser(t, store, hostID)
	journey, err := store.CreateJourney(context.Background(), validJourneyParams(hostID))
	if err != nil {
		t.Fatalf("CreateJourney: %v", err)
	}
	participant, err := store.JourneyParticipantByUserAndJourney(context.Background(), hostID, journey.ID)
	if err != nil {
		t.Fatalf("lookup host participant: %v", err)
	}
	return hostID, journey.ID, participant.ID
}

func validTelemetryParams(journeyID, participantID string) TelemetryBatchParams {
	return TelemetryBatchParams{
		JourneyID:     journeyID,
		ParticipantID: participantID,
		ClientBatchID: "client-batch-1",
		SampleCount:   5,
		PayloadDigest: "sha256:deadbeef",
	}
}

func TestRecordTelemetryBatchInsertsRow(t *testing.T) {
	store := openTestStore(t)
	_, journeyID, participantID := seedJourneyWithHost(t, store)

	batch, err := store.RecordTelemetryBatch(context.Background(), validTelemetryParams(journeyID, participantID))
	if err != nil {
		t.Fatalf("RecordTelemetryBatch: %v", err)
	}
	if batch.ID == "" {
		t.Fatal("batch ID is empty")
	}
	if batch.JourneyID != journeyID {
		t.Fatalf("JourneyID = %q", batch.JourneyID)
	}
	if batch.ParticipantID != participantID {
		t.Fatalf("ParticipantID = %q", batch.ParticipantID)
	}
	if batch.SampleCount != 5 {
		t.Fatalf("SampleCount = %d", batch.SampleCount)
	}
	if batch.ReceivedAt.IsZero() {
		t.Fatal("ReceivedAt is zero")
	}
}

func TestRecordTelemetryBatchRejectsMissingFields(t *testing.T) {
	store := openTestStore(t)
	tests := map[string]TelemetryBatchParams{
		"missing journey":        {ParticipantID: "p", ClientBatchID: "c", SampleCount: 1, PayloadDigest: "d"},
		"missing participant":    {JourneyID: "j", ClientBatchID: "c", SampleCount: 1, PayloadDigest: "d"},
		"missing client batch":   {JourneyID: "j", ParticipantID: "p", SampleCount: 1, PayloadDigest: "d"},
		"negative sample count":  {JourneyID: "j", ParticipantID: "p", ClientBatchID: "c", SampleCount: -1, PayloadDigest: "d"},
		"missing payload digest": {JourneyID: "j", ParticipantID: "p", ClientBatchID: "c", SampleCount: 1},
	}
	for name, params := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := store.RecordTelemetryBatch(context.Background(), params); err == nil {
				t.Fatal("err = nil, want validation error")
			}
		})
	}
}

func TestRecordTelemetryBatchFKEnforcement(t *testing.T) {
	store := openTestStore(t)
	// Reference a journey id that doesn't exist — FK should
	// reject regardless of validation passing.
	params := validTelemetryParams("00000000-0000-4000-8000-000000000000", "00000000-0000-4000-8000-000000000001")
	if _, err := store.RecordTelemetryBatch(context.Background(), params); err == nil {
		t.Fatal("err = nil, want FK rejection")
	}
}

func TestRecordTelemetryBatchAllowsZeroSamples(t *testing.T) {
	store := openTestStore(t)
	_, journeyID, participantID := seedJourneyWithHost(t, store)
	params := validTelemetryParams(journeyID, participantID)
	params.SampleCount = 0
	if _, err := store.RecordTelemetryBatch(context.Background(), params); err != nil {
		t.Fatalf("RecordTelemetryBatch: %v", err)
	}
}

func TestRecordTelemetryBatchRetryWithDifferentClientBatchID(t *testing.T) {
	// With device_id NULL (v0), the UNIQUE(device_id, client_batch_id)
	// constraint allows duplicate client_batch_ids across "different"
	// (NULL-distinct) device rows. Document this by inserting twice
	// with the same client_batch_id — both must succeed.
	store := openTestStore(t)
	_, journeyID, participantID := seedJourneyWithHost(t, store)
	params := validTelemetryParams(journeyID, participantID)
	if _, err := store.RecordTelemetryBatch(context.Background(), params); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if _, err := store.RecordTelemetryBatch(context.Background(), params); err != nil {
		t.Fatalf("second insert (NULL-distinct device_id): %v", err)
	}
}
