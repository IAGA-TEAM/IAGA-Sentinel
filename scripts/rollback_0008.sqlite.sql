-- Rollback of migration 0008 (durable capability tokens), SQLite.
--
-- sqlx validates the applied set before applying anything and this repo never
-- calls `set_ignore_missing`, so a binary built before 0008 does not degrade
-- against a 0008 database — it refuses to start with "migration 8 was
-- previously applied but is missing in the resolved migrations". Roll the
-- schema back before rolling the binary back.
--
--     sqlite3 iaga.db < scripts/rollback_0008.sqlite.sql
--
-- WHAT IS LOST. Every minted capability token, and every revocation of one.
-- That is less severe than it sounds: before 0008 these lived in a
-- process-global `HashMap`, so on a pre-0008 binary they did not survive a
-- restart in the first place. What DOES change is the authorization outcome —
-- 2.1.0 uses these tokens to let an agent-scoped key read its own
-- `/v1/profiles/{id}` and `/v1/analytics/agents/{id}`, which are otherwise
-- admin-only. After this rollback those reads need an admin key again.

-- 1. Show the operator what is about to be discarded, so an empty result is a
--    deliberate observation rather than a silent one.
.mode column
.headers on
SELECT agent_id, count(*) AS discarded_tokens
  FROM capability_tokens
 WHERE valid = 1
 GROUP BY agent_id;

-- 2. Now the destructive part.
DROP TABLE IF EXISTS capability_tokens;
DELETE FROM _sqlx_migrations WHERE version = 8;
