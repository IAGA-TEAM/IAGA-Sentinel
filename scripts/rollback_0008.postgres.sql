-- Rollback of migration 0008 (durable capability tokens), Postgres.
-- See the sqlite twin for why this file exists and what is lost.
--
--     psql "$DATABASE_URL" -f scripts/rollback_0008.postgres.sql

\echo 'live capability tokens about to be discarded (empty result = none outstanding):'
SELECT agent_id, count(*) AS discarded_tokens
  FROM capability_tokens
 WHERE valid
 GROUP BY agent_id;

DROP TABLE IF EXISTS capability_tokens;
DELETE FROM _sqlx_migrations WHERE version = 8;
