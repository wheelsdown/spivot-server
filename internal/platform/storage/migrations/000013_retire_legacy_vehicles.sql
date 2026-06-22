-- Retire the legacy `vehicles` table introduced by migration
-- 000001 alongside the foundational schema, plus the two
-- dangling FK columns that referenced it:
--
--   journey_participants.vehicle_id REFERENCES vehicles(id)
--   journey_segments.vehicle_id     REFERENCES vehicles(id)
--
-- The journey-side Vehicle records introduced in Phase 2 (issue
-- #24) live in `journey_vehicles` (migration 000006); the
-- garage-side vehicle records live in `garage_vehicles`
-- (migration 000009). The original `vehicles` table has had zero
-- rows on every production deployment and is unreferenced in Go
-- code — it was a placeholder for an earlier shape that the
-- protocol moved past during the design phase. The two FK
-- columns referencing it have likewise been unread / unwritten
-- by the production code path since they were added.
--
-- Order matters: drop the FK columns first so SQLite is willing
-- to drop the table they reference under PRAGMA foreign_keys=ON.
-- SQLite 3.35+ supports ALTER TABLE DROP COLUMN; modernc.org/sqlite
-- ships modern SQLite, so this is safe.

ALTER TABLE journey_participants DROP COLUMN vehicle_id;
ALTER TABLE journey_segments DROP COLUMN vehicle_id;

DROP TABLE IF EXISTS vehicles;
