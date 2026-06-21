-- journey_vehicles persists the journey-scoped Vehicle records that
-- participants upload when joining a journey. Each row is the
-- canonical owner-signed payload at upload time; subsequent
-- AuthorizedDrivers / EmergencyRule changes are recorded in
-- journey_vehicle_acl_revisions and the journey_vehicles row's
-- current_acl_version pointer advances.
--
-- The row carries both the parsed fields (for query convenience) and
-- the raw canonical JSON the signature was computed over (so a
-- verifier can reproduce signature input bytes byte-for-byte without
-- re-canonicalizing from the parsed fields and risking drift).
--
-- Per the OpenCaravan spec (opencaravan-go docs/vehicles.md), the
-- Vehicle is owner-signed and its AuthorizedDrivers list evolves via
-- VehicleACL revisions retained per-version so a DriverAttestation
-- can validate against the ACL current at its EffectiveTime — not
-- whatever the ACL has since become.

CREATE TABLE journey_vehicles (
    id                       TEXT PRIMARY KEY,
    journey_id               TEXT NOT NULL REFERENCES journeys(id) ON DELETE CASCADE,
    owner_user_id            TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    display_name             TEXT NOT NULL,
    make                     TEXT NOT NULL DEFAULT '',
    model                    TEXT NOT NULL DEFAULT '',
    model_year               INTEGER,
    color                    TEXT NOT NULL DEFAULT '',
    capacity                 INTEGER NOT NULL CHECK (capacity >= 1),
    avatar_image_ref_json    TEXT NOT NULL DEFAULT '',
    banner_image_ref_json    TEXT NOT NULL DEFAULT '',
    current_acl_version      INTEGER NOT NULL CHECK (current_acl_version >= 1),
    emergency_rule_kind      TEXT NOT NULL DEFAULT '' CHECK (
        emergency_rule_kind IN ('', 'none', 'any_journey_participant')
    ),
    integrity_algorithm      TEXT NOT NULL,
    integrity_key_id         TEXT NOT NULL,
    integrity_signature      TEXT NOT NULL,
    canonical_payload_json   TEXT NOT NULL,
    created_at               TEXT NOT NULL,
    UNIQUE (journey_id, id)
);

-- A journey participant uploads exactly one Vehicle per journey. The
-- journey_id + owner_user_id pair is uniquely scoped to avoid two
-- vehicles attributed to the same caller in the same trip.
CREATE UNIQUE INDEX idx_journey_vehicles_journey_owner
    ON journey_vehicles(journey_id, owner_user_id);

CREATE INDEX idx_journey_vehicles_journey
    ON journey_vehicles(journey_id);

-- journey_vehicle_acl_revisions records every signed VehicleACL
-- update the owner has published for a journey vehicle. The "current"
-- ACL is the highest acl_version with effective_time <= now; older
-- versions remain queryable so a DriverAttestation referencing an
-- earlier acl_version_consulted resolves against the right ACL even
-- if the owner has since revoked someone. Server replay never
-- retroactively invalidates an attestation that was valid against
-- the ACL current at its effective time.
CREATE TABLE journey_vehicle_acl_revisions (
    id                       TEXT PRIMARY KEY,
    journey_vehicle_id       TEXT NOT NULL REFERENCES journey_vehicles(id) ON DELETE CASCADE,
    acl_version              INTEGER NOT NULL CHECK (acl_version >= 1),
    effective_time           TEXT NOT NULL,
    authorized_drivers_json  TEXT NOT NULL,
    emergency_rule_kind      TEXT NOT NULL DEFAULT '' CHECK (
        emergency_rule_kind IN ('', 'none', 'any_journey_participant')
    ),
    integrity_algorithm      TEXT NOT NULL,
    integrity_key_id         TEXT NOT NULL,
    integrity_signature      TEXT NOT NULL,
    canonical_payload_json   TEXT NOT NULL,
    received_at              TEXT NOT NULL,
    UNIQUE (journey_vehicle_id, acl_version)
);

CREATE INDEX idx_journey_vehicle_acl_revisions_vehicle_effective
    ON journey_vehicle_acl_revisions(journey_vehicle_id, effective_time);
