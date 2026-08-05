//! SQLite backend for `ReceiptStore`.
//!
//! The canonical source of truth for replay is the `body_json` column:
//! it stores the exact bytes that were signed, so we can reconstruct the
//! `ReceiptBody` without re-serializing it (which would risk a byte-level
//! divergence if the Rust side ever changes field order).

use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use ed25519_dalek::VerifyingKey;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use sqlx::Row;

use crate::errors::{is_unique_violation, ReceiptError, Result};
use crate::merkle::verify_chain;
use crate::receipt::{ChainStatus, Receipt, ReceiptBody, RunSummary, Verdict};
use crate::store::{check_append_link, ReceiptStore};

pub struct SqliteReceiptStore {
    pool: SqlitePool,
    verifying_key: VerifyingKey,
}

impl SqliteReceiptStore {
    /// Open (or create) a SQLite database at `database_url`, run the
    /// schema migration, and bind the store to the given verifying key
    /// (used by `verify_chain`).
    pub async fn new(database_url: &str, verifying_key: VerifyingKey) -> Result<Self> {
        // busy_timeout makes the append race deterministic on a file DB: a
        // second writer blocks until the first commits, then hits the PRIMARY
        // KEY and gets a clean unique-violation (-> DuplicateSeq, retried)
        // rather than a spurious SQLITE_BUSY. ponytail: no WAL pragma here, it
        // errors on the `mode=memory` URLs used by in-process tests.
        let opts =
            SqliteConnectOptions::from_str(database_url)?.busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(opts)
            .await?;
        let store = Self {
            pool,
            verifying_key,
        };
        store.run_migrations().await?;
        Ok(store)
    }

    /// Construct from an already-open pool (useful when the host app
    /// already has a SQLite pool configured, e.g. `iaga-sentinel-core`).
    pub async fn from_pool(pool: SqlitePool, verifying_key: VerifyingKey) -> Result<Self> {
        let store = Self {
            pool,
            verifying_key,
        };
        store.run_migrations().await?;
        Ok(store)
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    async fn run_migrations(&self) -> Result<()> {
        // SND-MIGRATION-SPLIT-6: deliberately NOT `sqlx::migrate!`. The receipt
        // store frequently shares one SQLite database with `iaga-sentinel-core`'s
        // storage, which owns the single `_sqlx_migrations` table via its OWN
        // migrator. A second sqlx migrator on the same DB sees core's migration
        // history (versions it doesn't know) and fails to open ("migration N was
        // previously applied but is missing"), silently disabling receipts. The
        // migration is a small idempotent `CREATE ... IF NOT EXISTS`, so applying
        // the statements directly is both safe and conflict-free. `ponytail:` the
        // `split(';')` is fine because the migration contains no `;` inside a
        // literal or trigger body.
        let sql = include_str!("../migrations/sqlite/0001_receipts.sql");
        for stmt in sql.split(';') {
            let trimmed = stmt.trim();
            if trimmed.is_empty() {
                continue;
            }
            sqlx::query(trimmed).execute(&self.pool).await?;
        }
        Ok(())
    }

    fn row_to_receipt(row: &sqlx::sqlite::SqliteRow) -> Result<Receipt> {
        let body_json: String = row.try_get("body_json")?;
        let signature: String = row.try_get("signature")?;
        let body: ReceiptBody = serde_json::from_str(&body_json)?;
        Ok(Receipt { body, signature })
    }
}

#[async_trait]
impl ReceiptStore for SqliteReceiptStore {
    async fn append(&self, receipt: &Receipt) -> Result<()> {
        let verdict_str = match receipt.body.verdict {
            Verdict::Allow => "allow",
            Verdict::Review => "review",
            Verdict::Block => "block",
        };
        let body_json = serde_json::to_string(&receipt.body)?;

        // Validate the link against the current head, then INSERT. We do NOT
        // wrap this in a transaction: a deferred SQLite txn would hold the
        // SELECT's shared read-lock across the INSERT and two writers would
        // deadlock to SQLITE_BUSY. Correctness instead rests on two guards:
        //   - `check_append_link` rejects a *direct-misuse* caller (fabricated
        //     seq / parent) — there is no concurrent advance in that case;
        //   - the PRIMARY KEY(run_id, seq) rejects a *concurrent* writer that
        //     read the same head, surfacing as DuplicateSeq (busy_timeout lets
        //     the loser's autocommit INSERT wait for the winner, then conflict).
        let head = self.head(&receipt.body.run_id).await?;
        check_append_link(head.as_ref(), receipt)?;

        let insert = sqlx::query(
            "INSERT INTO receipts (\
                run_id, seq, parent_hash, input_hash, policy_hash, \
                verdict, risk_score, timestamp, signer_key_id, signature, body_json\
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&receipt.body.run_id)
        .bind(receipt.body.seq as i64)
        .bind(&receipt.body.parent_hash)
        .bind(&receipt.body.input_hash)
        .bind(&receipt.body.policy_hash)
        .bind(verdict_str)
        .bind(receipt.body.risk_score as i64)
        .bind(&receipt.body.timestamp)
        .bind(&receipt.body.signer_key_id)
        .bind(&receipt.signature)
        .bind(&body_json)
        .execute(&self.pool)
        .await;
        match insert {
            Ok(_) => Ok(()),
            Err(e) if is_unique_violation(&e) => Err(ReceiptError::DuplicateSeq {
                seq: receipt.body.seq,
            }),
            Err(e) => Err(e.into()),
        }
    }

    async fn head(&self, run_id: &str) -> Result<Option<Receipt>> {
        let row = sqlx::query(
            "SELECT body_json, signature FROM receipts \
             WHERE run_id = ? ORDER BY seq DESC LIMIT 1",
        )
        .bind(run_id)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            None => Ok(None),
            Some(r) => Ok(Some(Self::row_to_receipt(&r)?)),
        }
    }

    async fn get_run(&self, run_id: &str) -> Result<Vec<Receipt>> {
        let rows = sqlx::query(
            "SELECT seq, body_json, signature FROM receipts \
             WHERE run_id = ? ORDER BY seq ASC",
        )
        .bind(run_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                let receipt = Self::row_to_receipt(row)?;
                // DET-SEQ-COLUMN-5: the ORDER BY uses the `seq` column, but the
                // chain verifier checks the `seq` inside `body_json`. Nothing in
                // the schema ties the two, so bind them here: a divergent row
                // (a migration or a direct writer) is caught at read time rather
                // than silently reordering or breaking the chain downstream.
                let col_seq: i64 = row.try_get("seq")?;
                if col_seq as u64 != receipt.body.seq {
                    return Err(ReceiptError::ChainViolation {
                        seq: receipt.body.seq,
                        reason: format!(
                            "stored column seq={col_seq} disagrees with body seq={}",
                            receipt.body.seq
                        ),
                    });
                }
                Ok(receipt)
            })
            .collect()
    }

    async fn verify_chain(&self, run_id: &str) -> Result<ChainStatus> {
        let receipts = self.get_run(run_id).await?;
        if receipts.is_empty() {
            return Err(ReceiptError::UnknownRun(run_id.to_string()));
        }
        verify_chain(&receipts, &self.verifying_key)
    }

    async fn list_runs(&self, limit: u32) -> Result<Vec<RunSummary>> {
        let rows = sqlx::query(
            // `last_ts` alone is not a total order: runs written in the same
            // second tie, and the tie broke differently on every call (50 run_id
            // positions moved between two identical measurement runs). `run_id`
            // is unique per run, so it makes the ordering total and paging
            // well-defined.
            "SELECT run_id, COUNT(*) as cnt, MIN(timestamp) as first_ts, \
                    MAX(timestamp) as last_ts \
             FROM receipts GROUP BY run_id \
             ORDER BY last_ts DESC, run_id ASC LIMIT ?",
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let run_id: String = r.try_get("run_id")?;
            let cnt: i64 = r.try_get("cnt")?;
            let first_ts: String = r.try_get("first_ts")?;
            let last_ts: String = r.try_get("last_ts")?;

            // Fetch terminal verdict (latest receipt's verdict).
            let verdict_row = sqlx::query(
                "SELECT verdict FROM receipts WHERE run_id = ? \
                 ORDER BY seq DESC LIMIT 1",
            )
            .bind(&run_id)
            .fetch_one(&self.pool)
            .await?;
            let verdict_str: String = verdict_row.try_get("verdict")?;
            let terminal_verdict = match verdict_str.as_str() {
                "allow" => Verdict::Allow,
                "review" => Verdict::Review,
                "block" => Verdict::Block,
                other => {
                    return Err(ReceiptError::Storage(format!(
                        "invalid verdict in DB: {}",
                        other
                    )))
                }
            };
            out.push(RunSummary {
                run_id,
                receipt_count: cnt as u64,
                first_timestamp: first_ts,
                last_timestamp: last_ts,
                terminal_verdict,
            });
        }
        Ok(out)
    }
}
