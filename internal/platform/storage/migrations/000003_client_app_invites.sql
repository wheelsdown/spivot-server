-- client_app_invites is the persistence layer for invite tokens that grant
-- the right to enroll a ClientApp on this server. Each row records the
-- SHA-256 hash of the token value (the plaintext is never stored), the
-- scope, lifecycle timestamps, and -- once redeemed -- the ClientApp ID
-- that consumed the invite.
--
-- The CHECK constraint on scope mirrors the InviteScope enum defined in
-- opencaravan-go: 'journey' for journey-join invites,
-- 'server_registration' for new-user enrollment invites.

CREATE TABLE client_app_invites (
    token_hash             TEXT PRIMARY KEY,
    scope                  TEXT NOT NULL CHECK (scope IN ('journey', 'server_registration')),
    created_time           TEXT NOT NULL,
    expiration_time        TEXT NOT NULL,
    used_time              TEXT,
    used_by_client_app_id  TEXT
);

CREATE INDEX idx_client_app_invites_scope_used ON client_app_invites(scope, used_time);
CREATE INDEX idx_client_app_invites_expiration ON client_app_invites(expiration_time);
