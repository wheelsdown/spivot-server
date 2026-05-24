-- OpenCaravan foundation schema.
--
-- This migration intentionally uses a conservative relational subset: TEXT
-- identifiers, RFC 3339 UTC timestamps in TEXT columns, INTEGER booleans, and
-- JSON documents stored as TEXT. That keeps the protocol data model clear and
-- portable while Spivot Server runs the schema on SQLite.

CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TEXT NOT NULL
);

-- The initial implementation uses policy_hash as id so snapshots are
-- content-addressed. The columns remain separate so a future server-local
-- identifier can diverge from the digest without reshaping foreign keys.
CREATE TABLE server_policy_snapshots (
    id TEXT PRIMARY KEY,
    policy_hash TEXT NOT NULL UNIQUE,
    document_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE federated_servers (
    id TEXT PRIMARY KEY,
    canonical_url TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL DEFAULT '',
    public_key_pem TEXT NOT NULL DEFAULT '',
    policy_hash TEXT NOT NULL DEFAULT '',
    policy_json TEXT NOT NULL DEFAULT '{}',
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    blocked_at TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE accounts (
    id TEXT PRIMARY KEY,
    open_caravan_id TEXT NOT NULL UNIQUE,
    home_server_id TEXT REFERENCES federated_servers(id) ON DELETE SET NULL,
    display_name TEXT NOT NULL,
    handle TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    disabled_at TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE account_devices (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    open_caravan_id TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL DEFAULT '',
    credential_type TEXT NOT NULL CHECK (credential_type IN ('public_key', 'x509')),
    public_key TEXT NOT NULL,
    certificate_pem TEXT,
    created_at TEXT NOT NULL,
    last_seen_at TEXT,
    revoked_at TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE vehicles (
    id TEXT PRIMARY KEY,
    account_id TEXT REFERENCES accounts(id) ON DELETE SET NULL,
    display_name TEXT NOT NULL,
    make TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL DEFAULT '',
    model_year INTEGER,
    color TEXT NOT NULL DEFAULT '',
    license_plate_hash TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    archived_at TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE journeys (
    id TEXT PRIMARY KEY,
    open_caravan_id TEXT NOT NULL UNIQUE,
    origin_server_id TEXT REFERENCES federated_servers(id) ON DELETE SET NULL,
    host_account_id TEXT REFERENCES accounts(id) ON DELETE SET NULL,
    server_policy_snapshot_id TEXT REFERENCES server_policy_snapshots(id) ON DELETE SET NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    visibility TEXT NOT NULL CHECK (visibility IN ('private', 'invite', 'server', 'public')),
    state TEXT NOT NULL CHECK (state IN ('planned', 'active', 'closed', 'expired', 'deleted')),
    retention_mode TEXT NOT NULL CHECK (retention_mode IN ('ephemeral', 'retained')),
    policy_hash TEXT NOT NULL,
    policy_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    starts_at TEXT,
    started_at TEXT,
    closed_at TEXT,
    retention_expires_at TEXT,
    deleted_at TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE journey_invites (
    id TEXT PRIMARY KEY,
    journey_id TEXT NOT NULL REFERENCES journeys(id) ON DELETE CASCADE,
    created_by_account_id TEXT REFERENCES accounts(id) ON DELETE SET NULL,
    token_hash TEXT NOT NULL UNIQUE,
    manual_code_hash TEXT UNIQUE,
    payload_json TEXT NOT NULL,
    max_uses INTEGER NOT NULL DEFAULT 1 CHECK (max_uses > 0),
    use_count INTEGER NOT NULL DEFAULT 0 CHECK (use_count >= 0),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE journey_participants (
    id TEXT PRIMARY KEY,
    journey_id TEXT NOT NULL REFERENCES journeys(id) ON DELETE CASCADE,
    account_id TEXT REFERENCES accounts(id) ON DELETE SET NULL,
    device_id TEXT REFERENCES account_devices(id) ON DELETE SET NULL,
    vehicle_id TEXT REFERENCES vehicles(id) ON DELETE SET NULL,
    invite_id TEXT REFERENCES journey_invites(id) ON DELETE SET NULL,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('host', 'driver', 'passenger', 'observer')),
    state TEXT NOT NULL CHECK (state IN ('invited', 'joined', 'left', 'removed')),
    sharing_state TEXT NOT NULL CHECK (sharing_state IN ('off', 'live', 'paused')),
    policy_hash TEXT NOT NULL,
    policy_accepted_at TEXT,
    joined_at TEXT,
    last_seen_at TEXT,
    left_at TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE journey_policy_acceptances (
    id TEXT PRIMARY KEY,
    journey_id TEXT NOT NULL REFERENCES journeys(id) ON DELETE CASCADE,
    participant_id TEXT NOT NULL REFERENCES journey_participants(id) ON DELETE CASCADE,
    policy_hash TEXT NOT NULL,
    accepted_at TEXT NOT NULL,
    client_name TEXT NOT NULL DEFAULT '',
    client_version TEXT NOT NULL DEFAULT '',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE (journey_id, participant_id, policy_hash)
);

CREATE TABLE participant_sessions (
    id TEXT PRIMARY KEY,
    journey_id TEXT NOT NULL REFERENCES journeys(id) ON DELETE CASCADE,
    participant_id TEXT NOT NULL REFERENCES journey_participants(id) ON DELETE CASCADE,
    device_id TEXT REFERENCES account_devices(id) ON DELETE SET NULL,
    started_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    ended_at TEXT,
    end_reason TEXT NOT NULL DEFAULT '',
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE journey_segments (
    id TEXT PRIMARY KEY,
    journey_id TEXT NOT NULL REFERENCES journeys(id) ON DELETE CASCADE,
    participant_id TEXT REFERENCES journey_participants(id) ON DELETE SET NULL,
    vehicle_id TEXT REFERENCES vehicles(id) ON DELETE SET NULL,
    name TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL CHECK (state IN ('active', 'closed', 'discarded')),
    started_at TEXT NOT NULL,
    ended_at TEXT,
    summary_json TEXT NOT NULL DEFAULT '{}',
    retention_expires_at TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE telemetry_batches (
    id TEXT PRIMARY KEY,
    journey_id TEXT NOT NULL REFERENCES journeys(id) ON DELETE CASCADE,
    participant_id TEXT NOT NULL REFERENCES journey_participants(id) ON DELETE CASCADE,
    device_id TEXT REFERENCES account_devices(id) ON DELETE SET NULL,
    client_batch_id TEXT NOT NULL,
    first_client_sequence INTEGER,
    last_client_sequence INTEGER,
    sample_count INTEGER NOT NULL CHECK (sample_count >= 0),
    captured_start_at TEXT,
    captured_end_at TEXT,
    received_at TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE (device_id, client_batch_id)
);

CREATE TABLE position_samples (
    id TEXT PRIMARY KEY,
    journey_id TEXT NOT NULL REFERENCES journeys(id) ON DELETE CASCADE,
    segment_id TEXT REFERENCES journey_segments(id) ON DELETE SET NULL,
    participant_id TEXT NOT NULL REFERENCES journey_participants(id) ON DELETE CASCADE,
    device_id TEXT REFERENCES account_devices(id) ON DELETE SET NULL,
    batch_id TEXT REFERENCES telemetry_batches(id) ON DELETE SET NULL,
    client_sequence INTEGER NOT NULL,
    captured_at TEXT NOT NULL,
    received_at TEXT NOT NULL,
    latitude_e7 INTEGER NOT NULL CHECK (latitude_e7 >= -900000000 AND latitude_e7 <= 900000000),
    longitude_e7 INTEGER NOT NULL CHECK (longitude_e7 >= -1800000000 AND longitude_e7 <= 1800000000),
    altitude_mm INTEGER,
    horizontal_accuracy_mm INTEGER,
    vertical_accuracy_mm INTEGER,
    speed_mm_s INTEGER,
    heading_deg_e2 INTEGER CHECK (heading_deg_e2 IS NULL OR (heading_deg_e2 >= 0 AND heading_deg_e2 < 36000)),
    source TEXT NOT NULL DEFAULT 'gnss',
    motion_state TEXT NOT NULL DEFAULT 'unknown',
    battery_level_permille INTEGER CHECK (battery_level_permille IS NULL OR (battery_level_permille >= 0 AND battery_level_permille <= 1000)),
    metadata_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE (journey_id, participant_id, client_sequence)
);

CREATE INDEX idx_federated_servers_canonical_url ON federated_servers(canonical_url);
CREATE INDEX idx_accounts_home_server ON accounts(home_server_id);
CREATE INDEX idx_account_devices_account ON account_devices(account_id);
CREATE INDEX idx_vehicles_account ON vehicles(account_id);
CREATE INDEX idx_journeys_state ON journeys(state);
CREATE INDEX idx_journeys_retention_expires_at ON journeys(retention_expires_at);
CREATE INDEX idx_journey_invites_journey ON journey_invites(journey_id);
CREATE INDEX idx_journey_invites_expires_at ON journey_invites(expires_at);
CREATE INDEX idx_journey_participants_journey ON journey_participants(journey_id);
CREATE INDEX idx_journey_participants_account ON journey_participants(account_id);
CREATE INDEX idx_journey_policy_acceptances_participant ON journey_policy_acceptances(participant_id);
CREATE INDEX idx_participant_sessions_journey_ended_at ON participant_sessions(journey_id, ended_at);
CREATE INDEX idx_journey_segments_journey_started_at ON journey_segments(journey_id, started_at);
CREATE INDEX idx_telemetry_batches_journey_received_at ON telemetry_batches(journey_id, received_at);
CREATE INDEX idx_position_samples_journey_captured_at ON position_samples(journey_id, captured_at);
CREATE INDEX idx_position_samples_participant_captured_at ON position_samples(participant_id, captured_at);
CREATE INDEX idx_position_samples_segment_captured_at ON position_samples(segment_id, captured_at);
