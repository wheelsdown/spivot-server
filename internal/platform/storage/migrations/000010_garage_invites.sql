-- garage_invites is the token-based onboarding path for sharing a
-- garage. An accepted owner mints an invite (POST
-- /v1/garages/{id}/invites) and shares the plaintext token
-- out-of-band — text message, in-person, QR code in the app — with
-- the person they want to add. The recipient then redeems the
-- token (POST /v1/garage-invites/{token}/redeem) and is added to
-- the garage as an accepted owner directly. The redemption IS the
-- acceptance; no separate signed GarageOwnershipAcceptance step.
--
-- This sidesteps the signed-revision invariant for invite-driven
-- adds: there's no [opencaravan.Garage] revision payload signing
-- the addition. The audit trail is the redemption row instead, and
-- the resulting garage_owners entry records added_in_revision_version
-- pointing at the head revision at redemption time (purely
-- informational; no acceptance flow needs to bind to it).
--
-- Tokens are stored as SHA-256 hashes; the plaintext value is
-- returned to the inviter once at creation and never retrievable.
-- Lost tokens are forgotten, not recovered — the inviter mints a
-- new one.

CREATE TABLE garage_invites (
    id                          TEXT PRIMARY KEY,
    garage_id                   TEXT NOT NULL REFERENCES garages(id) ON DELETE CASCADE,
    created_by_user_id          TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    token_hash                  TEXT NOT NULL UNIQUE,
    created_at                  TEXT NOT NULL,
    expires_at                  TEXT NOT NULL,
    max_redemptions             INTEGER NOT NULL DEFAULT 1 CHECK (max_redemptions >= 1),
    redemption_count            INTEGER NOT NULL DEFAULT 0 CHECK (redemption_count >= 0),
    revoked_at                  TEXT
);

CREATE INDEX idx_garage_invites_garage
    ON garage_invites(garage_id);

CREATE INDEX idx_garage_invites_expires_at
    ON garage_invites(expires_at);

-- garage_invite_redemptions records every successful redeem. The
-- UNIQUE on (invite, redeemer) prevents a single user from
-- consuming an invite slot twice; max_redemptions controls the
-- multi-redeemer case for "send the same link to N people" use
-- cases (default 1 = one-shot).
CREATE TABLE garage_invite_redemptions (
    id                          TEXT PRIMARY KEY,
    garage_invite_id            TEXT NOT NULL REFERENCES garage_invites(id) ON DELETE CASCADE,
    redeemer_user_id            TEXT NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    redeemed_at                 TEXT NOT NULL,
    UNIQUE (garage_invite_id, redeemer_user_id)
);

CREATE INDEX idx_garage_invite_redemptions_invite
    ON garage_invite_redemptions(garage_invite_id);
