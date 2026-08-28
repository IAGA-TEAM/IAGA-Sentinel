-- Rollback of migration 0009 (agent-scoped API-key binding), Postgres.
-- See the SQLite twin for the downgrade security effect.
--
--     psql "$DATABASE_URL" -f scripts/rollback_0009.postgres.sql

\echo 'agent-scoped keys that must be rotated or deleted before downgrade:'
SELECT id, label, agent_id
  FROM api_keys
 WHERE scope = 'agent';

ALTER TABLE api_keys DROP COLUMN agent_id;
DELETE FROM _sqlx_migrations WHERE version = 9;
