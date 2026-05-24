-- macaroon_roots persists the HMAC root keys this server uses to mint
-- and validate session macaroons. Each row holds one key; the row's id
-- is the public identifier embedded in macaroons so the verifier can
-- look up the right key without having to try them all.
--
-- Lifecycle:
--
--   created_time   -- always set; when the key was minted
--   rotated_time   -- NULL while the key is the active issuer; set
--                     once a successor is minted. Macaroons signed by
--                     a rotated key remain verifiable until they
--                     expire, so verification consults every row in
--                     this table, not just the active one.
--
-- Phase 4a populates exactly one row (a single active root) on first
-- run; later phases add explicit rotation that flips rotated_time on
-- the previous active row inside the same transaction that issues the
-- successor.

CREATE TABLE macaroon_roots (
    id           TEXT PRIMARY KEY,
    key          BLOB NOT NULL,
    created_time TEXT NOT NULL,
    rotated_time TEXT
);

CREATE INDEX idx_macaroon_roots_active ON macaroon_roots(rotated_time);
