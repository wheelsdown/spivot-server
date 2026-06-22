-- Add an optional driver_attestation_hash column to
-- telemetry_batches so clients submitting samples can link the
-- batch to the DriverAttestation that was in effect when the
-- samples were captured. The server stores the hash verbatim
-- (no FK to driver_attestations — the attestation may be
-- gossipped to this server later, or may live only on a peer
-- device) so a future audit replay can correlate position
-- samples back to their handoff record once the attestation
-- arrives.
--
-- Per [opencaravan-go/docs/vehicles.md], if the linked
-- attestation later fails verification, the telemetry rows are
-- flagged with downgraded chain of custody — never deleted.
-- This column is the join key that future flagging logic walks.
--
-- Existing rows stay NULL. No backfill: historical batches
-- predate the attestation system and have no meaningful link.
-- The column accepts the canonical `sha256:<64 lowercase hex>`
-- shape opencaravan-go validates on DriverAttestation
-- prior_attestation_hash, but the storage layer does not enforce
-- the format — clients send whatever hash they computed, and the
-- audit replay validates at correlation time.

ALTER TABLE telemetry_batches ADD COLUMN driver_attestation_hash TEXT;

CREATE INDEX idx_telemetry_batches_driver_attestation_hash
    ON telemetry_batches(driver_attestation_hash)
    WHERE driver_attestation_hash IS NOT NULL;
