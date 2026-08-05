-- Rollback of migration 0006 (persisted tool_trust), SQLite.
--
-- sqlx validates the applied set before applying anything and this repo never
-- calls `set_ignore_missing`, so a binary built before 0006 does not degrade
-- against a 0006 database — it refuses to start with "migration 6 was
-- previously applied but is missing in the resolved migrations". Roll the
-- schema back before rolling the binary back.
--
--     sqlite3 iaga.db < scripts/rollback_0006.sqlite.sql
--
-- WHAT IS LOST. Every configured `tool_trust` other than the 0.7 default. On a
-- pre-0006 binary those profiles were being scored AS IF they were 0.7 anyway,
-- so rolling back does not change any verdict — it returns the deployment to
-- the state where the knob is accepted and ignored.

-- 1. Show the operator what is about to be discarded, so an empty result is a
--    deliberate observation rather than a silent one.
.mode column
.headers on
SELECT agent_id, tool_trust AS discarded_tool_trust
  FROM agent_profiles
 WHERE tool_trust <> 0.7;

-- 2. Now the destructive part.
ALTER TABLE agent_profiles DROP COLUMN tool_trust;
DELETE FROM _sqlx_migrations WHERE version = 6;
