-- 2.1.0: capability tokens become a real authorization primitive.
--
-- Postgres twin of the SQLite 0008. See that file for the full rationale; the
-- short version is that a token which now grants access has to survive a
-- restart and a revocation has to be durable and fleet-wide, and until 2.0.2 it
-- lived only in a process-global `HashMap`.
--
-- `valid` is a real BOOLEAN here (SQLite has no boolean type and uses INTEGER),
-- which is the usual shape of the difference between the two schemas.
--
-- Numbered 0008: 0007 is `0007_audit_read_path_indexes` on both backends, and
-- reusing it returns sqlx VersionMismatch(7) on every already-migrated database.
CREATE TABLE IF NOT EXISTS capability_tokens (
    token_id     TEXT PRIMARY KEY,
    agent_id     TEXT NOT NULL,
    capabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
    issued_at    TIMESTAMPTZ NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    signature    TEXT NOT NULL,
    valid        BOOLEAN NOT NULL DEFAULT TRUE,
    tenant_id    TEXT REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_capability_tokens_agent
    ON capability_tokens(agent_id, expires_at DESC);
