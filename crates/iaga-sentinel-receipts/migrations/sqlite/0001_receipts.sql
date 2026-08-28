-- IAGA Sentinel 1.0, M2 "Signed Action Receipts"
-- Table: receipts (append-only Merkle-linked log per run_id)

CREATE TABLE IF NOT EXISTS receipts (
    run_id        TEXT    NOT NULL,
    seq           INTEGER NOT NULL,
    parent_hash   TEXT,             -- hex-encoded SHA-256, NULL for seq=0
    input_hash    TEXT    NOT NULL, -- hex-encoded SHA-256
    policy_hash   TEXT    NOT NULL, -- hex-encoded SHA-256
    verdict       TEXT    NOT NULL, -- 'allow' | 'review' | 'block'
    risk_score    INTEGER NOT NULL,
    timestamp     TEXT    NOT NULL, -- RFC3339 UTC
    signer_key_id TEXT    NOT NULL,
    signature     TEXT    NOT NULL, -- hex-encoded 64-byte Ed25519 signature
    body_json     TEXT    NOT NULL, -- full ReceiptBody JSON (source of truth for replay)
    PRIMARY KEY (run_id, seq)
);

-- 2.1.0: drop the two indexes 2.0.2 created here.
--
-- They were removed from the CREATE above, which only helps a database created
-- from scratch: this file is re-executed on every open (see `run_migrations`),
-- so a database that already has them keeps them forever unless it is told to
-- drop them. Idempotent, and it is why the removal is listed as `Removed`
-- rather than "new databases only".
DROP INDEX IF EXISTS idx_receipts_timestamp;
DROP INDEX IF EXISTS idx_receipts_verdict;
