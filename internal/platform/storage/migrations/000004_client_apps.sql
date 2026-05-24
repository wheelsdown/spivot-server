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
-- Both are NULL-allowed for backwards compatibility with rows written
-- before Phase 3a (none today, but the CLI ca init path issues the CA's
-- self-signed root and does not have a requesting user) and so cascading
-- account deletion can null the references without losing audit rows.

ALTER TABLE issued_certificates ADD COLUMN user_id       TEXT REFERENCES accounts(id) ON DELETE SET NULL;
ALTER TABLE issued_certificates ADD COLUMN client_app_id TEXT REFERENCES client_apps(id) ON DELETE SET NULL;

CREATE INDEX idx_issued_certificates_user_id       ON issued_certificates(user_id);
CREATE INDEX idx_issued_certificates_client_app_id ON issued_certificates(client_app_id);
