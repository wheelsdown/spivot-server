-- issued_certificates is the audit trail for every leaf certificate the
-- Spivot Server CA has signed. Each row records the certificate's serial,
-- subject CN, validity window, issuance time, and (later) revocation time.
--
-- Phase 2a creates the foundational columns. Phase 3a (client app
-- enrollment) will extend this table with optional user_id and
-- client_app_id columns to link an issued cert back to the enrolled
-- ClientApp that requested it.

CREATE TABLE issued_certificates (
    serial      TEXT PRIMARY KEY,
    subject_cn  TEXT NOT NULL,
    not_before  TEXT NOT NULL,
    not_after   TEXT NOT NULL,
    issued_at   TEXT NOT NULL,
    revoked_at  TEXT
);

CREATE INDEX idx_issued_certificates_not_after ON issued_certificates(not_after);
CREATE INDEX idx_issued_certificates_subject_cn ON issued_certificates(subject_cn);
