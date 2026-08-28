-- Rollback of migration 0009 (agent-scoped API-key binding), SQLite.
--
--     sqlite3 iaga.db < scripts/rollback_0009.sqlite.sql
--
-- SECURITY EFFECT. The older binary ignores this binding and again trusts the
-- caller's agentId. Rotate or delete every agent-scoped key before downgrading;
-- otherwise each one becomes usable as every agent.

.mode column
.headers on
SELECT id, label, agent_id
  FROM api_keys
 WHERE scope = 'agent';

ALTER TABLE api_keys DROP COLUMN agent_id;
DELETE FROM _sqlx_migrations WHERE version = 9;
