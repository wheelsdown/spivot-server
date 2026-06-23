-- Migration 000015 attributes server_registration invites minted via the
-- authenticated POST /v1/client-apps/invites endpoint to the user who
-- created them. The column is NULLable: rows written by the first-run
-- bootstrap path and the `spivot-server invite create` CLI have no
-- enrolled creator and keep created_by_user_id NULL. ON DELETE SET NULL
-- mirrors the nullable-creator FKs in migration 000001 — deleting the
-- creator's account must neither cascade away a still-redeemable invite
-- nor block the account delete.
--
-- This is an additive, metadata-only ALTER (no default to backfill). The
-- enrollment redeem path (the conditional UPDATE in RegisterClientApp)
-- writes only used_time/used_by_client_app_id and reads no other columns,
-- so it is unaffected.
--
-- The index backs both the per-user outstanding-invite count enforced by
-- IssueInviteBy and the InvitesCreatedBy list query.

ALTER TABLE client_app_invites
    ADD COLUMN created_by_user_id TEXT REFERENCES accounts(id) ON DELETE SET NULL;

CREATE INDEX idx_client_app_invites_created_by
    ON client_app_invites(created_by_user_id);
