-- client_apps is the descriptive record for every enrolled app
-- installation that has presented a valid invite and CSR and received
-- a signed leaf certificate. The cryptographic credential lives in
-- issued_certificates; this table carries the human-facing metadata
-- (display name, owning user) that operators and journey participants
-- want to see.
--
-- Each client_app belongs to exactly one user (accounts.id). When the
-- account is deleted the client_apps cascade, which in turn means the
-- corresponding issued_certificates rows lose their client_app_id
-- linkage (set NULL — audit history is preserved).

CREATE TABLE client_apps (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    display_name  TEXT NOT NULL DEFAULT '',
    created_time  TEXT NOT NULL
);

CREATE INDEX idx_client_apps_user_id ON client_apps(user_id);

-- issued_certificates gains links to the requesting user and ClientApp.
-- Both columns are NULL-allowed + ON DELETE SET NULL so cascading
-- account deletion preserves audit history rather than destroying the
-- record of what was issued. Phase 3a is the only insert path today and
-- always populates both columns; the nullable shape is the right
-- contract for any future operator-driven account or app cleanup.

ALTER TABLE issued_certificates ADD COLUMN user_id       TEXT REFERENCES accounts(id) ON DELETE SET NULL;
ALTER TABLE issued_certificates ADD COLUMN client_app_id TEXT REFERENCES client_apps(id) ON DELETE SET NULL;

CREATE INDEX idx_issued_certificates_user_id       ON issued_certificates(user_id);
CREATE INDEX idx_issued_certificates_client_app_id ON issued_certificates(client_app_id);
