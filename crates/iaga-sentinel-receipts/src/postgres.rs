//! Postgres backend for `ReceiptStore`.
//!
//! Mirrors `sqlite.rs` with Postgres-flavored SQL (parameterized by `$N`).

use async_trait::async_trait;
use ed25519_dalek::VerifyingKey;
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;

use crate::errors::{is_unique_violation, ReceiptError, Result};
use crate::merkle::verify_chain;
use crate::receipt::{ChainStatus, Receipt, ReceiptBody, RunSummary, Verdict};
use crate::store::{check_append_link, ReceiptStore};

pub struct PgReceiptStore {
    pool: PgPool,
    verifying_key: VerifyingKey,
}

impl PgReceiptStore {
    pub async fn new(database_url: &str, verifying_key: VerifyingKey) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await?;
        let store = Self {
            pool,
            verifying_key,
        };
        store.run_migrations().await?;
        Ok(store)
    }

    pub async fn from_pool(pool: PgPool, verifying_key: VerifyingKey) -> Result<Self> {
        let store = Self {
            pool,
            verifying_key,
        };
        store.run_migrations().await?;
        Ok(store)
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    async fn run_migrations(&self) -> Result<()> {
        // SND-MIGRATION-SPLIT-6: deliberately NOT `sqlx::migrate!` — the receipt
        // store can share a database with `iaga-sentinel-core`'s storage, which
        // owns the single `_sqlx_migrations` table via its own migrator; a second
        // sqlx migrator on the same DB conflicts and silently disables receipts.
        // The migration is a small idempotent `CREATE ... IF NOT EXISTS`.
        let sql = include_str!("../migrations/postgres/0001_receipts.sql");
        for stmt in sql.split(';') {
            let trimmed = stmt.trim();
            if trimmed.is_empty() {
                continue;
            }
            sqlx::query(trimmed).execute(&self.pool).await?;
        }
        Ok(())
    }

    fn row_to_receipt(row: &sqlx::postgres::PgRow) -> Result<Receipt> {
        let body_json: String = row.try_get("body_json")?;
        let signature: String = row.try_get("signature")?;
        let body: ReceiptBody = serde_json::from_str(&body_json)?;
        Ok(Receipt { body, signature })
    }
}

#[async_trait]
impl ReceiptStore for PgReceiptStore {
    async fn append(&self, receipt: &Receipt) -> Result<()> {
        let verdict_str = match receipt.body.verdict {
            Verdict::Allow => "allow",
            Verdict::Review => "review",
            Verdict::Block => "block",
        };
        let body_json = serde_json::to_string(&receipt.body)?;

        // Validate the link against the current head, then INSERT (autocommit).
        // No explicit transaction: the PRIMARY KEY(run_id, seq) is the real
        // uniqueness guard for concurrent writers (a stale-head writer's INSERT
        // raises a unique-violation -> DuplicateSeq, retried by the caller),
        // and `check_append_link` rejects a direct-misuse caller up front.
        let head = self.head(&receipt.body.run_id).await?;
        check_append_link(head.as_ref(), receipt)?;

        let insert = sqlx::query(
            "INSERT INTO receipts (\
                run_id, seq, parent_hash, input_hash, policy_hash, \
                verdict, risk_score, timestamp, signer_key_id, signature, body_json\
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(&receipt.body.run_id)
        .bind(receipt.body.seq as i64)
        .bind(&receipt.body.parent_hash)
        .bind(&receipt.body.input_hash)
        .bind(&receipt.body.policy_hash)
        .bind(verdict_str)
        .bind(receipt.body.risk_score as i32)
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
             WHERE run_id = $1 ORDER BY seq DESC LIMIT 1",
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
             WHERE run_id = $1 ORDER BY seq ASC",
        )
        .bind(run_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                let receipt = Self::row_to_receipt(row)?;
                // DET-SEQ-COLUMN-5: bind the ordering `seq` column to the `seq`
                // inside `body_json` (the verifier checks the latter), so a
                // divergent row is caught at read time. Postgres stores `seq`
                // as BIGINT.
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
            // See the sqlite twin: `last_ts` alone is not a total order, so
            // equal-timestamp runs came back in a different order on every call.
            "SELECT run_id, COUNT(*) as cnt, MIN(timestamp) as first_ts, \
                    MAX(timestamp) as last_ts \
             FROM receipts GROUP BY run_id \
             ORDER BY last_ts DESC, run_id ASC LIMIT $1",
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

            let verdict_row = sqlx::query(
                "SELECT verdict FROM receipts WHERE run_id = $1 \
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
