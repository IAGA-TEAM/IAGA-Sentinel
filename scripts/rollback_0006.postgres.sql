-- Rollback of migration 0006 (persisted tool_trust), Postgres.
-- See the sqlite twin for why this file exists and what is lost.
--
--     psql "$DATABASE_URL" -f scripts/rollback_0006.postgres.sql

\echo 'tool_trust values about to be discarded (empty result = nothing configured):'
SELECT agent_id, tool_trust AS discarded_tool_trust
  FROM agent_profiles
 WHERE tool_trust <> 0.7;

ALTER TABLE agent_profiles DROP COLUMN IF EXISTS tool_trust;
DELETE FROM _sqlx_migrations WHERE version = 6;
