-- 2.1.0: capability tokens become a real authorization primitive.
--
-- Until 2.0.2 an issued token lived only in a process-global `HashMap`, so it
-- was forgotten on restart and never crossed a replica. Nothing verified its
-- signature and nothing could revoke it (`revoke_token` had no route), which is
-- why a token that authorized nothing was safe to keep in memory. Now that it
-- grants an agent read access to its own governance data, it has to survive a
-- restart and a revocation has to be durable and fleet-wide.
--
-- `signature` is stored so verification does not depend on the row being
-- trusted: it is recomputed from the agent's derived secret and compared. Note
-- the NHI is symmetric HMAC (CRYPTO-NHI-2), so only the server can verify.
--
-- Numbered 0008: 0007 is `0007_audit_read_path_indexes` on both backends. Taking
-- 0007 again is what made an earlier 2.1.0 tree unable to open any database that
-- had already migrated - sqlx compares a SHA-384 checksum per version and
-- returns VersionMismatch(7), which is fatal inside `run_migrations()`.
CREATE TABLE IF NOT EXISTS capability_tokens (
    token_id     TEXT PRIMARY KEY,
    agent_id     TEXT NOT NULL,
    capabilities TEXT NOT NULL DEFAULT '[]',  -- JSON array
    issued_at    TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    signature    TEXT NOT NULL,
    valid        INTEGER NOT NULL DEFAULT 1,
    tenant_id    TEXT DEFAULT NULL
);

-- The verify path is a point lookup on the primary key, so it needs no index.
-- This one serves revoking or listing every token an agent holds, which is what
-- an operator does when an agent is compromised.
CREATE INDEX IF NOT EXISTS idx_capability_tokens_agent
    ON capability_tokens(agent_id, expires_at DESC);
