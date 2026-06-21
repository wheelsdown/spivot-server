-- garages persists the account-scoped, multi-owner garage container
-- that holds a user's library of vehicles. The container itself
-- (this migration) is what enables household sharing — a future
-- migration will add garage_vehicles and link them to a containing
-- garage. Each garage is owned by one or more accounts; ownership
-- additions require recipient consent via signed
-- GarageOwnershipAcceptance, while removals are unilateral (any
-- accepted owner may remove any other owner — the lost-account
-- problem motivates this asymmetry).
--
-- Each Garage revision is a full signed payload retained verbatim
-- in garage_revisions; the garages row carries the head pointer for
-- fast lookup. The garage_owners table is a denormalized projection
-- of the current revision's owner list so "list garages I own" is a
-- direct index probe rather than a payload scan.

CREATE TABLE garages (
    id                          TEXT PRIMARY KEY,
    name                        TEXT NOT NULL,
    current_revision_version    INTEGER NOT NULL CHECK (current_revision_version >= 1),
    current_revision_time       TEXT NOT NULL,
    created_at                  TEXT NOT NULL
);

-- garage_revisions records every signed Garage update. The garages
-- head pointer (current_revision_version) advances whenever a
-- strictly-greater revision is appended; older revisions stay
-- queryable so a GarageOwnershipAcceptance carrying
-- revision_version_accepted can validate against the right
-- baseline even if the garage has since moved on.
CREATE TABLE garage_revisions (
    id                          TEXT PRIMARY KEY,
    garage_id                   TEXT NOT NULL REFERENCES garages(id) ON DELETE CASCADE,
    revision_version            INTEGER NOT NULL CHECK (revision_version >= 1),
    revision_time               TEXT NOT NULL,
    signed_by                   TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    integrity_algorithm         TEXT NOT NULL,
    integrity_key_id            TEXT NOT NULL,
    integrity_signature         TEXT NOT NULL,
    canonical_payload_json      TEXT NOT NULL,
    received_at                 TEXT NOT NULL,
    UNIQUE (garage_id, revision_version)
);

CREATE INDEX idx_garage_revisions_garage_version
    ON garage_revisions(garage_id, revision_version);

-- garage_owners is the materialized current owner list. One row
-- per (garage, user). accepted_time is NULL while the invitation
-- is pending; non-NULL once the recipient has published a
-- matching GarageOwnershipAcceptance.
--
-- Removing an owner deletes the row outright (no soft-delete
-- tombstone in this layer; the revision history retains every
-- past owner list).
CREATE TABLE garage_owners (
    garage_id                   TEXT NOT NULL REFERENCES garages(id) ON DELETE CASCADE,
    user_id                     TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    added_time                  TEXT NOT NULL,
    accepted_time               TEXT,
    PRIMARY KEY (garage_id, user_id)
);

-- Index for "list garages where I am an owner (accepted or pending)".
-- iOS shows pending invitations + accepted memberships side by side.
CREATE INDEX idx_garage_owners_user
    ON garage_owners(user_id);

-- garage_ownership_acceptances records every signed acceptance an
-- invitee publishes. A handler that receives an acceptance updates
-- the corresponding garage_owners row to set accepted_time; the
-- acceptance row stays for audit. revision_version_accepted binds
-- the acceptance to the specific garage revision in which the
-- invitee was added — replays against later revisions are
-- rejected by the validate step before reaching this table.
CREATE TABLE garage_ownership_acceptances (
    id                          TEXT PRIMARY KEY,
    garage_id                   TEXT NOT NULL REFERENCES garages(id) ON DELETE CASCADE,
    revision_version_accepted   INTEGER NOT NULL CHECK (revision_version_accepted >= 1),
    accepter_user_id            TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    accepted_time               TEXT NOT NULL,
    integrity_algorithm         TEXT NOT NULL,
    integrity_key_id            TEXT NOT NULL,
    integrity_signature         TEXT NOT NULL,
    canonical_payload_json      TEXT NOT NULL,
    received_at                 TEXT NOT NULL,
    UNIQUE (garage_id, accepter_user_id, revision_version_accepted)
);
