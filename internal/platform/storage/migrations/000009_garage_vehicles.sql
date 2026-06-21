-- garage_vehicles persists the cars inside a [Garage]: the
-- household-level vehicle library, distinct from the per-journey
-- [Vehicle] uploaded when a participant joins a trip. Garage
-- vehicles are persistent across journeys, editable by any
-- accepted owner of the containing garage, and revision-tracked
-- so a co-owner edit (rename, change photo, update capacity) is
-- visible in the audit log.
--
-- The head-pointer projection (garage_vehicles row) carries the
-- denormalized current state for fast list/get queries; the full
-- signed revision history is in garage_vehicle_revisions. Each
-- revision is signed by the owner who edited it, and the server
-- cross-checks SignedBy against the garage_owners projection
-- (accepted_time NOT NULL) before recording — non-owners and
-- pending invitees cannot mutate.
--
-- The protocol-level link between a garage vehicle and a journey
-- vehicle is intentionally absent: a client copies metadata from a
-- garage vehicle into a fresh [Vehicle] when joining a journey, so
-- non-owner participants cannot correlate the same garage car
-- appearing in multiple journeys. Cross-journey aggregation for an
-- owner's own view is a downstream concern.

CREATE TABLE garage_vehicles (
    id                          TEXT PRIMARY KEY,
    garage_id                   TEXT NOT NULL REFERENCES garages(id) ON DELETE CASCADE,
    current_revision_version    INTEGER NOT NULL CHECK (current_revision_version >= 1),
    current_revision_time       TEXT NOT NULL,
    display_name                TEXT NOT NULL,
    make                        TEXT NOT NULL DEFAULT '',
    model                       TEXT NOT NULL DEFAULT '',
    model_year                  INTEGER,
    color                       TEXT NOT NULL DEFAULT '',
    capacity                    INTEGER NOT NULL CHECK (capacity >= 1),
    avatar_image_ref_json       TEXT NOT NULL DEFAULT '',
    banner_image_ref_json       TEXT NOT NULL DEFAULT '',
    notes                       TEXT NOT NULL DEFAULT '',
    created_at                  TEXT NOT NULL
);

CREATE INDEX idx_garage_vehicles_garage
    ON garage_vehicles(garage_id);

-- garage_vehicle_revisions records every signed GarageVehicle
-- payload. The head pointer (garage_vehicles.current_revision_version)
-- advances whenever a strictly-greater revision is appended; older
-- revisions stay queryable for the audit log + future cross-checks.
CREATE TABLE garage_vehicle_revisions (
    id                          TEXT PRIMARY KEY,
    garage_vehicle_id           TEXT NOT NULL REFERENCES garage_vehicles(id) ON DELETE CASCADE,
    revision_version            INTEGER NOT NULL CHECK (revision_version >= 1),
    revision_time               TEXT NOT NULL,
    signed_by                   TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    integrity_algorithm         TEXT NOT NULL,
    integrity_key_id            TEXT NOT NULL,
    integrity_signature         TEXT NOT NULL,
    canonical_payload_json      TEXT NOT NULL,
    received_at                 TEXT NOT NULL,
    UNIQUE (garage_vehicle_id, revision_version)
);

CREATE INDEX idx_garage_vehicle_revisions_vehicle_version
    ON garage_vehicle_revisions(garage_vehicle_id, revision_version);
