-- driver_attestations records the per-handoff signed payloads a
-- journey participant produces when taking over driving a vehicle
-- at a waypoint. Each row is the canonical driver-signed payload
-- at upload time, retained verbatim so a verifier can reproduce
-- signature input bytes without re-canonicalizing from the parsed
-- fields.
--
-- The server-side trust classification (authorized vs
-- emergency_fallback vs acl_violation) is computed at record time
-- by resolving the ACL revision current at effective_time and
-- checking driver_user_id against AuthorizedDrivers and the
-- vehicle's emergency_rule. Per the spec, the server NEVER drops a
-- recorded payload on trust failure: chain of custody is
-- information, not a gate. Trust is surfaced via trust_flag so
-- downstream readers can decide what to do with low-trust rows.
--
-- prior_attestation_hash is the sha256:hex digest of the prior
-- attestation's CanonicalEncoding. Two attestations sharing the
-- same prior_attestation_hash signal a fork (concurrent claims on
-- the same predecessor); the server records both and surfaces the
-- fork to clients. NULL when the attestation is the first in its
-- chain.
--
-- segment_id is an opaque UUID at this layer — the server does not
-- yet enforce that the segment exists. A future migration will
-- introduce the journey_segments table and add a FK; until then the
-- field is a structural anchor for client-side reasoning.

CREATE TABLE driver_attestations (
    id                       TEXT PRIMARY KEY,
    journey_vehicle_id       TEXT NOT NULL REFERENCES journey_vehicles(id) ON DELETE CASCADE,
    segment_id               TEXT NOT NULL,
    driver_user_id           TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    effective_time           TEXT NOT NULL,
    acl_version_consulted    INTEGER NOT NULL CHECK (acl_version_consulted >= 1),
    prior_attestation_hash   TEXT,
    trust_flag               TEXT NOT NULL CHECK (
        trust_flag IN ('authorized', 'emergency_fallback', 'acl_violation')
    ),
    integrity_algorithm      TEXT NOT NULL,
    integrity_key_id         TEXT NOT NULL,
    integrity_signature      TEXT NOT NULL,
    canonical_payload_json   TEXT NOT NULL,
    received_at              TEXT NOT NULL
);

-- A single (vehicle, driver, effective_time) tuple uniquely
-- identifies a handoff record. Replays of an already-uploaded
-- attestation surface as a UNIQUE conflict the handler maps to a
-- 200-with-existing rather than a 409 — idempotent retries from a
-- gossiping peer are the common case, not a fault.
CREATE UNIQUE INDEX idx_driver_attestations_replay_key
    ON driver_attestations(journey_vehicle_id, driver_user_id, effective_time);

CREATE INDEX idx_driver_attestations_vehicle_effective
    ON driver_attestations(journey_vehicle_id, effective_time);

CREATE INDEX idx_driver_attestations_segment
    ON driver_attestations(segment_id);

-- prior_attestation_hash indexed so fork-detection lookups (which
-- ask "do any other attestations share this prior?") are O(log n)
-- rather than a full scan. The index excludes NULL rows because
-- root attestations cannot fork by definition.
CREATE INDEX idx_driver_attestations_prior_hash
    ON driver_attestations(prior_attestation_hash)
    WHERE prior_attestation_hash IS NOT NULL;
