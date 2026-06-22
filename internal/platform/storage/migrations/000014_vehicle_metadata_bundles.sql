-- Migration 000014 brings the schema in line with OpenCaravan
-- 0.2-draft: the journey-scoped Vehicle becomes a metadata-only
-- signed bundle (authorization moves to VehicleACL exclusively),
-- AvatarImage/BannerImage become content-addressed BlobRefs, and
-- a new blobs table backs the protocol's blob storage layer.
--
-- Migration shape: DROP + CREATE rather than ALTER TABLE for
-- journey_vehicles and garage_vehicles. SQLite's ALTER TABLE
-- only drops one column per statement; recreating is simpler and
-- the migration runs at the bottom of a long version chain on
-- pre-1.0 draft schemas with no production data to preserve
-- (the latest prod incident wiped the singleton deployment's
-- vehicle data; no other deployment has shipped enough scale to
-- carry meaningful state).
--
-- The opaque-bundle shape: server stores canonical_payload_json
-- verbatim and the integrity_* sig metadata for re-verification.
-- The avatar_blob_hash / banner_blob_hash columns are denormalized
-- from the bundle so a future blob-GC sweep can find references
-- without parsing every bundle. Per-attribute columns
-- (make/model/year/color/display_name/capacity/notes) are
-- dropped — the server no longer interprets them.

-- ---- journey_vehicles ----

DROP TABLE IF EXISTS journey_vehicle_acl_revisions;
DROP TABLE IF EXISTS journey_vehicles;

CREATE TABLE journey_vehicles (
    id                          TEXT PRIMARY KEY,
    journey_id                  TEXT NOT NULL REFERENCES journeys(id) ON DELETE CASCADE,
    owner_user_id               TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    current_revision_version    INTEGER NOT NULL CHECK (current_revision_version >= 1),
    current_acl_version         INTEGER NOT NULL CHECK (current_acl_version >= 1),
    integrity_algorithm         TEXT NOT NULL,
    integrity_key_id            TEXT NOT NULL,
    integrity_signature         TEXT NOT NULL,
    canonical_payload_json      TEXT NOT NULL,
    avatar_blob_hash            TEXT,
    banner_blob_hash            TEXT,
    received_at                 TEXT NOT NULL,
    UNIQUE (journey_id, owner_user_id)
);

CREATE INDEX idx_journey_vehicles_journey ON journey_vehicles(journey_id);
CREATE INDEX idx_journey_vehicles_avatar_blob
    ON journey_vehicles(avatar_blob_hash) WHERE avatar_blob_hash IS NOT NULL;
CREATE INDEX idx_journey_vehicles_banner_blob
    ON journey_vehicles(banner_blob_hash) WHERE banner_blob_hash IS NOT NULL;

-- journey_vehicle_revisions: NEW. Metadata bundle revision history,
-- parallel to journey_vehicle_acl_revisions for the authorization
-- side. Lets a vehicle owner publish "I updated the photo" without
-- creating a new ACL revision (and vice-versa).
CREATE TABLE journey_vehicle_revisions (
    id                          TEXT PRIMARY KEY,
    journey_vehicle_id          TEXT NOT NULL REFERENCES journey_vehicles(id) ON DELETE CASCADE,
    revision_version            INTEGER NOT NULL CHECK (revision_version >= 1),
    revision_time               TEXT NOT NULL,
    integrity_algorithm         TEXT NOT NULL,
    integrity_key_id            TEXT NOT NULL,
    integrity_signature         TEXT NOT NULL,
    canonical_payload_json      TEXT NOT NULL,
    avatar_blob_hash            TEXT,
    banner_blob_hash            TEXT,
    received_at                 TEXT NOT NULL,
    UNIQUE (journey_vehicle_id, revision_version)
);

CREATE INDEX idx_journey_vehicle_revisions_vehicle
    ON journey_vehicle_revisions(journey_vehicle_id);

CREATE TABLE journey_vehicle_acl_revisions (
    id                          TEXT PRIMARY KEY,
    journey_vehicle_id          TEXT NOT NULL REFERENCES journey_vehicles(id) ON DELETE CASCADE,
    acl_version                 INTEGER NOT NULL CHECK (acl_version >= 1),
    effective_time              TEXT NOT NULL,
    authorized_drivers_json     TEXT NOT NULL,
    emergency_rule_kind         TEXT NOT NULL DEFAULT '' CHECK (
        emergency_rule_kind IN ('', 'none', 'any_journey_participant')
    ),
    integrity_algorithm         TEXT NOT NULL,
    integrity_key_id            TEXT NOT NULL,
    integrity_signature         TEXT NOT NULL,
    canonical_payload_json      TEXT NOT NULL,
    received_at                 TEXT NOT NULL,
    UNIQUE (journey_vehicle_id, acl_version)
);

CREATE INDEX idx_journey_vehicle_acl_revisions_vehicle_effective
    ON journey_vehicle_acl_revisions(journey_vehicle_id, effective_time);

-- ---- garage_vehicles ----

DROP TABLE IF EXISTS garage_vehicle_revisions;
DROP TABLE IF EXISTS garage_vehicles;

CREATE TABLE garage_vehicles (
    id                          TEXT PRIMARY KEY,
    garage_id                   TEXT NOT NULL REFERENCES garages(id) ON DELETE CASCADE,
    current_revision_version    INTEGER NOT NULL CHECK (current_revision_version >= 1),
    integrity_algorithm         TEXT NOT NULL,
    integrity_key_id            TEXT NOT NULL,
    integrity_signature         TEXT NOT NULL,
    canonical_payload_json      TEXT NOT NULL,
    signed_by_user_id           TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    avatar_blob_hash            TEXT,
    banner_blob_hash            TEXT,
    received_at                 TEXT NOT NULL
);

CREATE INDEX idx_garage_vehicles_garage ON garage_vehicles(garage_id);
CREATE INDEX idx_garage_vehicles_avatar_blob
    ON garage_vehicles(avatar_blob_hash) WHERE avatar_blob_hash IS NOT NULL;
CREATE INDEX idx_garage_vehicles_banner_blob
    ON garage_vehicles(banner_blob_hash) WHERE banner_blob_hash IS NOT NULL;

CREATE TABLE garage_vehicle_revisions (
    id                          TEXT PRIMARY KEY,
    garage_vehicle_id           TEXT NOT NULL REFERENCES garage_vehicles(id) ON DELETE CASCADE,
    revision_version            INTEGER NOT NULL CHECK (revision_version >= 1),
    revision_time               TEXT NOT NULL,
    integrity_algorithm         TEXT NOT NULL,
    integrity_key_id            TEXT NOT NULL,
    integrity_signature         TEXT NOT NULL,
    canonical_payload_json      TEXT NOT NULL,
    signed_by_user_id           TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    avatar_blob_hash            TEXT,
    banner_blob_hash            TEXT,
    received_at                 TEXT NOT NULL,
    UNIQUE (garage_vehicle_id, revision_version)
);

CREATE INDEX idx_garage_vehicle_revisions_vehicle
    ON garage_vehicle_revisions(garage_vehicle_id);

-- Note: this migration ships the denormalized avatar_blob_hash /
-- banner_blob_hash columns but NOT the blobs table or any
-- POST/GET/HEAD /v1/blobs endpoints. Vehicle bundles can already
-- reference BlobRef hashes; until the blob endpoints land in a
-- follow-up PR, clients should treat hash references as
-- forward-looking metadata — the server stores the hash but does
-- not yet host the bytes. A future migration adds the blobs
-- table; the denormalized hash columns here are the future GC
-- sweep's join key.
