use async_trait::async_trait;
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};

use super::migrations::run_sqlite_migrations;
use super::traits::*;
use super::{parse_json_opt_or_warn, parse_json_or_warn};
use crate::core::errors::SentinelError;
use crate::core::types::*;
use crate::modules::policy::rules_engine::PolicyRule;

pub struct SqliteStorage {
    pool: SqlitePool,
}

impl SqliteStorage {
    pub async fn new(database_url: &str) -> Result<Self, SentinelError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await
            .map_err(|e| SentinelError::Storage(format!("Failed to connect to SQLite: {e}")))?;

        let storage = Self { pool };
        storage.run_migrations().await?;
        Ok(storage)
    }

    async fn run_migrations(&self) -> Result<(), SentinelError> {
        run_sqlite_migrations(&self.pool).await
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

/// The `created_at` an audit row should sort by, derived from the pipeline's
/// own decision time.
///
/// `timestamp` is produced server-side (`execute_pipeline`'s `decision_ts`),
/// never taken from the request, so it is safe as a sort key: a caller cannot
/// reorder somebody else's audit trail by lying about the clock.
///
/// Falls back to now() if the string is not RFC3339. That is unreachable in the
/// pipeline, but a fallback that silently produces an empty or malformed sort
/// key would be worse than one that produces a slightly late-but-ordered one.
pub(crate) fn audit_created_at(timestamp: &str) -> String {
    const SQLITE_DATETIME: &str = "%Y-%m-%d %H:%M:%S%.6f";
    chrono::DateTime::parse_from_rfc3339(timestamp)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now())
        .format(SQLITE_DATETIME)
        .to_string()
}

// ── AuditStore ──

#[async_trait]
impl AuditStore for SqliteStorage {
    async fn append(&self, event: &StoredAuditEvent) -> Result<(), SentinelError> {
        let reasons = serde_json::to_string(&event.reasons).unwrap_or_default();
        let decision = serde_json::to_value(event.decision)
            .unwrap_or_default()
            .as_str()
            .unwrap_or("allow")
            .to_string();
        let action_type = serde_json::to_value(event.action_type)
            .unwrap_or_default()
            .as_str()
            .unwrap_or("custom")
            .to_string();
        let review_status = serde_json::to_value(event.review_status)
            .unwrap_or_default()
            .as_str()
            .unwrap_or("not_required")
            .to_string();

        let usage_json = event
            .usage
            .as_ref()
            .map(|u| serde_json::to_string(u).unwrap_or_default());
        let cost_usd = event.usage.as_ref().map(|u| u.cost_usd());
        let savings_usd = event
            .usage
            .as_ref()
            .and_then(|u| u.savings_micros)
            .map(iaga_sentinel_cost::micros_to_usd);
        let total_tokens = event
            .usage
            .as_ref()
            .and_then(|u| u.total_tokens)
            .map(|t| t as i64);
        let cache_hit = event.usage.as_ref().map(|u| u.cache_hit as i64);
        let provider = event.usage.as_ref().map(|u| u.provider.clone());
        let model = event.usage.as_ref().map(|u| u.model.clone());

        // The sort key of every audit read, supplied rather than defaulted.
        //
        // The column default is `datetime('now')` — WHOLE SECONDS — and this
        // INSERT used to omit the column, so every row written inside one
        // second tied and the `event_id DESC` tie-break (a UUID) became the
        // real order: measured on five sequential live requests, the newest
        // event came back fourth. Deriving it from the event's own decision
        // time makes the read chronological, keeps it equal to the `timestamp`
        // the API returns, and orders by when the action HAPPENED rather than
        // when the write-behind task landed.
        //
        // Same `YYYY-MM-DD HH:MM:SS[.ffffff]` shape as the default, so it still
        // compares lexicographically against rows already written at
        // second precision (a bare second is a prefix of any fraction within
        // it, and therefore sorts first — which is the correct answer).
        let created_at = audit_created_at(&event.timestamp);

        sqlx::query(
            "INSERT INTO audit_events (event_id, agent_id, tenant_id, framework, action_type, tool_name, decision, risk_score, review_status, reasons, timestamp, usage_json, cost_usd, savings_usd, total_tokens, cache_hit, provider, model, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&event.event_id)
        .bind(&event.agent_id)
        .bind(&event.tenant_id)
        .bind(&event.framework)
        .bind(&action_type)
        .bind(&event.tool_name)
        .bind(&decision)
        .bind(event.risk_score as i64)
        .bind(&review_status)
        .bind(&reasons)
        .bind(&event.timestamp)
        .bind(&usage_json)
        .bind(cost_usd)
        .bind(savings_usd)
        .bind(total_tokens)
        .bind(cache_hit)
        .bind(&provider)
        .bind(&model)
        .bind(&created_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn list(&self, limit: u32) -> Result<Vec<StoredAuditEvent>, SentinelError> {
        let rows = sqlx::query_as::<_, AuditRow>(
            // `created_at` alone is not a total order. The INSERT now supplies
            // it at microsecond precision (`audit_created_at`), so ties are
            // rare rather than the normal state — but rows written before that
            // change carry the whole-second column default, and nothing makes
            // the value unique in either case. `event_id` is the PRIMARY KEY
            // and breaks the tie, so the page boundary is stable instead of
            // being whatever SQLite happened to return. Same fix the receipts
            // store already applies to `last_ts`.
            "SELECT event_id, agent_id, tenant_id, framework, action_type, tool_name, decision, risk_score, review_status, reasons, timestamp, usage_json
             FROM audit_events ORDER BY created_at DESC, event_id DESC LIMIT ?"
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.into_stored()).collect())
    }

    async fn list_filtered(
        &self,
        filter: &AuditExportFilter,
    ) -> Result<Vec<StoredAuditEvent>, SentinelError> {
        let limit = filter
            .limit
            .unwrap_or(1000)
            .min(crate::storage::MAX_AUDIT_EXPORT_ROWS) as i64;
        let agent = filter.agent_id.clone().unwrap_or_default();
        let decision = filter.decision.clone().unwrap_or_default();
        // Parsed and normalized to a second-resolution UTC key, so any RFC3339
        // offset selects the instant it names. See `normalize_audit_boundary`.
        let from = crate::storage::normalize_audit_boundary(
            filter.from_date.as_deref().unwrap_or_default(),
            "from_date",
            false,
        )?;
        let to = crate::storage::normalize_audit_boundary(
            filter.to_date.as_deref().unwrap_or_default(),
            "to_date",
            true,
        )?;

        // `tenant_id` was destructured and then never used: four WHERE
        // predicates where the Postgres twin has five. `tenant_id` is a
        // documented query parameter of `exportAuditEvents`, so on SQLite — the
        // DEFAULT backend — it was accepted and silently ignored, and the same
        // request returned a different result set on the two backends. The
        // column was also missing from the projection, so an exported row
        // serialized `"tenantId": null` here and the real value on Postgres.
        //
        // NOT a confidentiality fix, and it should not be described as one:
        // `/v1/audit/export` is `RequireAdmin`, `AuthContext` carries no tenant
        // (auth/middleware.rs), and `GET /v1/audit` already returns every
        // tenant unfiltered to the same caller. There is no tenant
        // authorization boundary here to breach — this is a filter that did not
        // filter, and a cross-backend divergence.
        let tenant = filter.tenant_id.clone().unwrap_or_default();

        let rows = sqlx::query_as::<_, AuditRow>(
            "SELECT event_id, agent_id, tenant_id, framework, action_type, tool_name, decision, risk_score, review_status, reasons, timestamp, usage_json
             FROM audit_events
             WHERE (? = '' OR agent_id = ?)
               AND (? = '' OR decision = ?)
               AND (? = '' OR substr(timestamp, 1, 19) >= ?)
               AND (? = '' OR substr(timestamp, 1, 19) <= ?)
               AND (? = '' OR tenant_id = ?)
             ORDER BY created_at DESC, event_id DESC LIMIT ?"
        )
        .bind(&agent).bind(&agent)
        .bind(&decision).bind(&decision)
        .bind(&from).bind(&from)
        .bind(&to).bind(&to)
        .bind(&tenant).bind(&tenant)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.into_stored()).collect())
    }

    async fn stats(&self) -> Result<AuditStats, SentinelError> {
        use sqlx::Row;

        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
            .fetch_one(&self.pool)
            .await?;

        let avg: f64 =
            sqlx::query_scalar("SELECT COALESCE(AVG(risk_score), 0.0) FROM audit_events")
                .fetch_one(&self.pool)
                .await?;

        let decision_rows = sqlx::query(
            "SELECT decision, COUNT(*) as cnt FROM audit_events GROUP BY decision ORDER BY cnt DESC, decision ASC",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut decisions = std::collections::HashMap::new();
        for row in &decision_rows {
            let d: String = row.try_get("decision")?;
            let c: i64 = row.try_get("cnt")?;
            decisions.insert(d, c as u64);
        }

        let agent_rows = sqlx::query(
            // `cnt DESC` alone is not a total order: agents tied on count are
            // returned in whatever order the plan produced, so which of them
            // survives `LIMIT 10` is arbitrary and can differ between two calls
            // and between the two backends. `agent_id` breaks the tie.
            "SELECT agent_id, COUNT(*) as cnt FROM audit_events GROUP BY agent_id ORDER BY cnt DESC, agent_id ASC LIMIT 10",
        )
        .fetch_all(&self.pool)
        .await?;

        let top_agents: Vec<(String, u64)> = agent_rows
            .iter()
            .map(|r| {
                let a: String = r.try_get("agent_id").unwrap_or_default();
                let c: i64 = r.try_get("cnt").unwrap_or(0);
                (a, c as u64)
            })
            .collect();

        let tool_rows = sqlx::query(
            "SELECT tool_name, COUNT(*) as cnt FROM audit_events GROUP BY tool_name ORDER BY cnt DESC, tool_name ASC LIMIT 10",
        )
        .fetch_all(&self.pool)
        .await?;

        let top_tools: Vec<(String, u64)> = tool_rows
            .iter()
            .map(|r| {
                let t: String = r.try_get("tool_name").unwrap_or_default();
                let c: i64 = r.try_get("cnt").unwrap_or(0);
                (t, c as u64)
            })
            .collect();

        Ok(AuditStats {
            total_events: total as u64,
            decisions,
            top_agents,
            top_tools,
            avg_risk_score: avg,
        })
    }

    async fn agent_analytics(
        &self,
        agent_id: Option<&str>,
    ) -> Result<Vec<AgentAnalytics>, SentinelError> {
        use sqlx::Row;

        let agent_filter = agent_id.unwrap_or("");

        // Three grouped queries, not one plus N per agent. See the Postgres twin
        // and `fold_agent_analytics` for why the GROUP_CONCAT went away: it
        // materialized one entry per audit event to compute a top-5, split a
        // tool whose name contained a comma into two phantom tools, and left the
        // top-5 tie order non-deterministic.
        let rows = sqlx::query(
            "SELECT agent_id,
                    COUNT(*) as total,
                    AVG(risk_score) as avg_risk,
                    MAX(timestamp) as last_ts
             FROM audit_events
             WHERE ? = '' OR agent_id = ?
             GROUP BY agent_id
             ORDER BY total DESC, agent_id ASC",
        )
        .bind(agent_filter)
        .bind(agent_filter)
        .fetch_all(&self.pool)
        .await?;

        let totals: Vec<crate::storage::AgentTotalsRow> = rows
            .iter()
            .map(|row| {
                (
                    row.try_get::<String, _>("agent_id").unwrap_or_default(),
                    row.try_get::<i64, _>("total").unwrap_or(0) as u64,
                    row.try_get::<f64, _>("avg_risk").unwrap_or(0.0),
                    row.try_get::<String, _>("last_ts").unwrap_or_default(),
                )
            })
            .collect();

        let decision_rows = sqlx::query(
            "SELECT agent_id, decision, COUNT(*) as cnt
             FROM audit_events
             WHERE ? = '' OR agent_id = ?
             GROUP BY agent_id, decision",
        )
        .bind(agent_filter)
        .bind(agent_filter)
        .fetch_all(&self.pool)
        .await?;

        let tool_rows = sqlx::query(
            "SELECT agent_id, tool_name, COUNT(*) as cnt
             FROM audit_events
             WHERE ? = '' OR agent_id = ?
             GROUP BY agent_id, tool_name
             ORDER BY cnt DESC, tool_name ASC",
        )
        .bind(agent_filter)
        .bind(agent_filter)
        .fetch_all(&self.pool)
        .await?;

        let as_counts =
            |rows: &[sqlx::sqlite::SqliteRow], key: &str| -> Vec<crate::storage::AgentCountRow> {
                rows.iter()
                    .map(|row| {
                        (
                            row.try_get::<String, _>("agent_id").unwrap_or_default(),
                            row.try_get::<String, _>(key).unwrap_or_default(),
                            row.try_get::<i64, _>("cnt").unwrap_or(0) as u64,
                        )
                    })
                    .collect()
            };

        Ok(crate::storage::fold_agent_analytics(
            totals,
            as_counts(&decision_rows, "decision"),
            as_counts(&tool_rows, "tool_name"),
        ))
    }

    async fn cost_summary(
        &self,
        from: Option<&str>,
        to: Option<&str>,
    ) -> Result<CostSummary, SentinelError> {
        use sqlx::Row;
        // Normalized to a second-resolution UTC key, like the audit export.
        // The raw values were bound straight into a lexical compare on a TEXT
        // column, so `--from` in any non-UTC offset silently reported $0.00 and
        // an unparseable value did the same, both with a success exit code.
        let from =
            crate::storage::normalize_audit_boundary(from.unwrap_or_default(), "from", false)?;
        let to = crate::storage::normalize_audit_boundary(to.unwrap_or_default(), "to", true)?;
        let (from, to) = (from.as_str(), to.as_str());
        let row = sqlx::query(
            "SELECT COALESCE(SUM(cost_usd), 0.0) AS net,
                    COALESCE(SUM(savings_usd), 0.0) AS savings,
                    COALESCE(SUM(total_tokens), 0) AS tokens,
                    COALESCE(SUM(CASE WHEN cache_hit = 1 THEN 1 ELSE 0 END), 0) AS hits,
                    COALESCE(SUM(CASE WHEN usage_json IS NOT NULL THEN 1 ELSE 0 END), 0) AS actions
             FROM audit_events
             WHERE (? = '' OR substr(timestamp, 1, 19) >= ?) AND (? = '' OR substr(timestamp, 1, 19) <= ?)",
        )
        .bind(from)
        .bind(from)
        .bind(to)
        .bind(to)
        .fetch_one(&self.pool)
        .await?;
        let net: f64 = row.try_get("net").unwrap_or(0.0);
        let savings: f64 = row.try_get("savings").unwrap_or(0.0);
        let tokens: i64 = row.try_get("tokens").unwrap_or(0);
        let hits: i64 = row.try_get("hits").unwrap_or(0);
        let actions: i64 = row.try_get("actions").unwrap_or(0);
        Ok(CostSummary {
            gross_cost_usd: net + savings,
            net_cost_usd: net,
            savings_usd: savings,
            total_tokens: tokens.max(0) as u64,
            cache_hits: hits.max(0) as u64,
            total_actions: actions.max(0) as u64,
        })
    }

    async fn cost_by_agent(
        &self,
        from: Option<&str>,
        to: Option<&str>,
        limit: u32,
    ) -> Result<Vec<CostByKey>, SentinelError> {
        self.cost_by_column("agent_id", from, to, limit).await
    }

    async fn cost_by_model(
        &self,
        from: Option<&str>,
        to: Option<&str>,
        limit: u32,
    ) -> Result<Vec<CostByKey>, SentinelError> {
        self.cost_by_column("model", from, to, limit).await
    }

    async fn cost_by_tool(
        &self,
        from: Option<&str>,
        to: Option<&str>,
        limit: u32,
    ) -> Result<Vec<CostByKey>, SentinelError> {
        self.cost_by_column("tool_name", from, to, limit).await
    }

    async fn cost_over_time(
        &self,
        from: Option<&str>,
        to: Option<&str>,
        bucket: &str,
    ) -> Result<Vec<CostBucket>, SentinelError> {
        use sqlx::Row;
        // Normalized to a second-resolution UTC key, like the audit export.
        // The raw values were bound straight into a lexical compare on a TEXT
        // column, so `--from` in any non-UTC offset silently reported $0.00 and
        // an unparseable value did the same, both with a success exit code.
        let from =
            crate::storage::normalize_audit_boundary(from.unwrap_or_default(), "from", false)?;
        let to = crate::storage::normalize_audit_boundary(to.unwrap_or_default(), "to", true)?;
        let (from, to) = (from.as_str(), to.as_str());
        // `fmt` is from a fixed allow-list, never user input.
        // The day bucket renders a full timestamp so the label matches the
        // Postgres twin, which always emits YYYY-MM-DDTHH:MM:SSZ via
        // `to_char(date_trunc(...))`. They agreed on `hour` and disagreed on
        // `day` for the same data, and the handler passes the string straight
        // through. Grouping and ORDER BY are unaffected: the suffix is constant
        // within a day.
        let fmt = if bucket == "day" {
            "%Y-%m-%dT00:00:00Z"
        } else {
            "%Y-%m-%dT%H:00:00Z"
        };
        let sql = format!(
            "SELECT strftime('{fmt}', timestamp) AS bucket,
                    COALESCE(SUM(cost_usd), 0.0) AS net,
                    COALESCE(SUM(savings_usd), 0.0) AS savings,
                    COALESCE(SUM(total_tokens), 0) AS tokens,
                    COUNT(*) AS actions
             FROM audit_events
             WHERE usage_json IS NOT NULL
               AND (? = '' OR substr(timestamp, 1, 19) >= ?) AND (? = '' OR substr(timestamp, 1, 19) <= ?)
             GROUP BY bucket ORDER BY bucket ASC"
        );
        let rows = sqlx::query(&sql)
            .bind(from)
            .bind(from)
            .bind(to)
            .bind(to)
            .fetch_all(&self.pool)
            .await?;
        let mut out = Vec::new();
        for r in &rows {
            out.push(CostBucket {
                bucket: r.try_get("bucket").unwrap_or_default(),
                net_cost_usd: r.try_get("net").unwrap_or(0.0),
                savings_usd: r.try_get("savings").unwrap_or(0.0),
                total_tokens: r.try_get::<i64, _>("tokens").unwrap_or(0).max(0) as u64,
                actions: r.try_get::<i64, _>("actions").unwrap_or(0).max(0) as u64,
            });
        }
        Ok(out)
    }
}

impl SqliteStorage {
    /// Spend grouped by a fixed internal column (`agent_id`, `model`, or
    /// `tool_name` — never user input). Only rows carrying usage are counted.
    async fn cost_by_column(
        &self,
        column: &str,
        from: Option<&str>,
        to: Option<&str>,
        limit: u32,
    ) -> Result<Vec<CostByKey>, SentinelError> {
        use sqlx::Row;
        // Normalized to a second-resolution UTC key, like the audit export.
        // The raw values were bound straight into a lexical compare on a TEXT
        // column, so `--from` in any non-UTC offset silently reported $0.00 and
        // an unparseable value did the same, both with a success exit code.
        let from =
            crate::storage::normalize_audit_boundary(from.unwrap_or_default(), "from", false)?;
        let to = crate::storage::normalize_audit_boundary(to.unwrap_or_default(), "to", true)?;
        let (from, to) = (from.as_str(), to.as_str());
        let sql = format!(
            "SELECT COALESCE({col}, '') AS k,
                    COALESCE(SUM(cost_usd), 0.0) AS net,
                    COALESCE(SUM(savings_usd), 0.0) AS savings,
                    COALESCE(SUM(total_tokens), 0) AS tokens,
                    COUNT(*) AS actions,
                    COALESCE(SUM(CASE WHEN cache_hit = 1 THEN 1 ELSE 0 END), 0) AS hits
             FROM audit_events
             WHERE usage_json IS NOT NULL
               AND (? = '' OR substr(timestamp, 1, 19) >= ?) AND (? = '' OR substr(timestamp, 1, 19) <= ?)
             GROUP BY {col} ORDER BY net DESC, k ASC LIMIT ?",
            col = column
        );
        let rows = sqlx::query(&sql)
            .bind(from)
            .bind(from)
            .bind(to)
            .bind(to)
            .bind(limit as i64)
            .fetch_all(&self.pool)
            .await?;
        let mut out = Vec::new();
        for r in &rows {
            out.push(CostByKey {
                key: r.try_get("k").unwrap_or_default(),
                net_cost_usd: r.try_get("net").unwrap_or(0.0),
                savings_usd: r.try_get("savings").unwrap_or(0.0),
                total_tokens: r.try_get::<i64, _>("tokens").unwrap_or(0).max(0) as u64,
                actions: r.try_get::<i64, _>("actions").unwrap_or(0).max(0) as u64,
                cache_hits: r.try_get::<i64, _>("hits").unwrap_or(0).max(0) as u64,
            });
        }
        Ok(out)
    }
}

struct AuditRow {
    event_id: String,
    agent_id: String,
    tenant_id: Option<String>,
    framework: String,
    action_type: String,
    tool_name: String,
    decision: String,
    risk_score: i64,
    review_status: String,
    reasons: String,
    timestamp: String,
    usage_json: Option<String>,
}

impl<'r> sqlx::FromRow<'r, sqlx::sqlite::SqliteRow> for AuditRow {
    fn from_row(row: &'r sqlx::sqlite::SqliteRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            event_id: row.try_get("event_id")?,
            agent_id: row.try_get("agent_id")?,
            tenant_id: row.try_get("tenant_id").unwrap_or(None),
            framework: row.try_get("framework")?,
            action_type: row.try_get("action_type")?,
            tool_name: row.try_get("tool_name")?,
            decision: row.try_get("decision")?,
            risk_score: row.try_get("risk_score")?,
            review_status: row.try_get("review_status")?,
            reasons: row.try_get("reasons")?,
            timestamp: row.try_get("timestamp")?,
            // Tolerant: absent from SELECTs that don't project it (older callers).
            usage_json: row.try_get("usage_json").unwrap_or(None),
        })
    }
}

impl AuditRow {
    fn into_stored(self) -> StoredAuditEvent {
        StoredAuditEvent {
            event_id: self.event_id,
            agent_id: self.agent_id,
            tenant_id: self.tenant_id,
            framework: self.framework,
            action_type: serde_json::from_value(serde_json::Value::String(self.action_type))
                .unwrap_or(ActionType::Custom),
            tool_name: self.tool_name,
            // Not persisted as a column; only meaningful at receipt-creation
            // time. Empty on read-back.
            input_sha256: String::new(),
            decision: serde_json::from_value(serde_json::Value::String(self.decision))
                .unwrap_or(GovernanceDecision::Block),
            risk_score: self.risk_score as u32,
            review_status: serde_json::from_value(serde_json::Value::String(self.review_status))
                .unwrap_or(ReviewStatus::NotRequired),
            reasons: parse_json_or_warn(&self.reasons, "audit_events.reasons"),
            timestamp: self.timestamp,
            usage: self
                .usage_json
                .as_deref()
                .and_then(|s| parse_json_opt_or_warn(s, "audit_events.usage_json")),
            // Not persisted as a column: receipt run grouping uses the in-memory
            // event at request time, and the chain lives in the receipts table.
            session_id: None,
        }
    }
}

// ── ReviewStore ──

#[async_trait]
impl ReviewStore for SqliteStorage {
    async fn create(&self, review: &ReviewRequest) -> Result<(), SentinelError> {
        let reasons = serde_json::to_string(&review.reasons).unwrap_or_default();
        let decision = serde_json::to_value(review.decision)
            .unwrap_or_default()
            .as_str()
            .unwrap_or("review")
            .to_string();

        sqlx::query(
            "INSERT INTO review_requests (id, agent_id, workspace_id, tool_name, decision, status, risk_score, reasons, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&review.id)
        .bind(&review.agent_id)
        .bind(&review.workspace_id)
        .bind(&review.tool_name)
        .bind(&decision)
        .bind(&review.status)
        .bind(review.risk_score as i64)
        .bind(&reasons)
        .bind(&review.created_at)
        .bind(&review.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get(&self, id: &str) -> Result<ReviewRequest, SentinelError> {
        let row = sqlx::query_as::<_, ReviewRow>(
            "SELECT id, agent_id, workspace_id, tool_name, decision, status, risk_score, reasons, created_at, updated_at
             FROM review_requests WHERE id = ?"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| SentinelError::ReviewNotFound(id.to_string()))?;

        Ok(row.into_review())
    }

    /// Resolving a review is terminal.
    ///
    /// This was an unconditional UPDATE with no state-machine guard and no
    /// history, so an admin key could approve a request, let the console show it
    /// as settled, and then rewrite the same request to `rejected` — two `200 OK`
    /// responses, one surviving row, and nothing anywhere recording that the
    /// decision had ever been anything else. On a product whose deliverable is
    /// the evidence record, a human-in-the-loop decision that can be silently
    /// rewritten is not a record.
    ///
    /// The guard is in the WHERE clause rather than a read-then-write, so two
    /// concurrent resolutions cannot both win: exactly one updates a row, and
    /// the loser is told what the decision already is.
    async fn update_status(&self, id: &str, status: &str) -> Result<ReviewRequest, SentinelError> {
        let now = chrono::Utc::now().to_rfc3339();
        let result = sqlx::query(
            "UPDATE review_requests SET status = ?, updated_at = ?
             WHERE id = ? AND status = 'pending'",
        )
        .bind(status)
        .bind(&now)
        .bind(id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            // `get` distinguishes the two ways to affect no rows: it returns
            // ReviewNotFound for an unknown id, so reaching past it means the
            // row exists and is already resolved.
            let existing = self.get(id).await?;
            return Err(SentinelError::InvalidRequest(format!(
                "review {id} was already resolved as {}; a resolution is final",
                existing.status
            )));
        }

        self.get(id).await
    }

    async fn list(&self) -> Result<Vec<ReviewRequest>, SentinelError> {
        let rows = sqlx::query_as::<_, ReviewRow>(
            "SELECT id, agent_id, workspace_id, tool_name, decision, status, risk_score, reasons, created_at, updated_at
             FROM review_requests ORDER BY created_at ASC, id ASC"
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.into_review()).collect())
    }
}

struct ReviewRow {
    id: String,
    agent_id: String,
    workspace_id: String,
    tool_name: String,
    decision: String,
    status: String,
    risk_score: i64,
    reasons: String,
    created_at: String,
    updated_at: String,
}

impl<'r> sqlx::FromRow<'r, sqlx::sqlite::SqliteRow> for ReviewRow {
    fn from_row(row: &'r sqlx::sqlite::SqliteRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            id: row.try_get("id")?,
            agent_id: row.try_get("agent_id")?,
            workspace_id: row.try_get("workspace_id")?,
            tool_name: row.try_get("tool_name")?,
            decision: row.try_get("decision")?,
            status: row.try_get("status")?,
            risk_score: row.try_get("risk_score")?,
            reasons: row.try_get("reasons")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

impl ReviewRow {
    fn into_review(self) -> ReviewRequest {
        ReviewRequest {
            id: self.id,
            agent_id: self.agent_id,
            workspace_id: self.workspace_id,
            tool_name: self.tool_name,
            decision: serde_json::from_value(serde_json::Value::String(self.decision))
                .unwrap_or(GovernanceDecision::Review),
            status: self.status,
            risk_score: self.risk_score as u32,
            reasons: parse_json_or_warn(&self.reasons, "review_requests.reasons"),
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

// ── PolicyStore ──

#[async_trait]
impl PolicyStore for SqliteStorage {
    async fn get_agent_profile(&self, agent_id: &str) -> Result<AgentProfile, SentinelError> {
        let row = sqlx::query_as::<_, ProfileRow>(
            "SELECT agent_id, tenant_id, workspace_id, framework, role, approved_tools, approved_secrets, baseline_action_types, tool_trust
             FROM agent_profiles WHERE agent_id = ?"
        )
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| SentinelError::AgentNotFound(agent_id.to_string()))?;

        Ok(row.into_profile())
    }

    async fn get_workspace_policy(
        &self,
        workspace_id: &str,
    ) -> Result<WorkspacePolicy, SentinelError> {
        let row = sqlx::query_as::<_, WorkspaceRow>(
            "SELECT workspace_id, tenant_id, allowed_protocols, allowed_domains, tools, threshold_block, threshold_review
             FROM workspace_policies WHERE workspace_id = ?",
        )
        .bind(workspace_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| SentinelError::WorkspaceNotFound(workspace_id.to_string()))?;

        Ok(row.into_policy())
    }

    async fn list_profiles(&self) -> Result<Vec<AgentProfile>, SentinelError> {
        let rows = sqlx::query_as::<_, ProfileRow>(
            "SELECT agent_id, tenant_id, workspace_id, framework, role, approved_tools, approved_secrets, baseline_action_types, tool_trust
             FROM agent_profiles ORDER BY agent_id"
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.into_profile()).collect())
    }

    async fn list_workspace_rules(
        &self,
        workspace_id: &str,
    ) -> Result<Vec<PolicyRule>, SentinelError> {
        let rows = sqlx::query(
            "SELECT id, name, priority, match_criteria, conditions, decision, reason, enabled
             FROM policy_rules
             WHERE workspace_id = ?
             ORDER BY priority ASC, id ASC",
        )
        .bind(workspace_id)
        .fetch_all(&self.pool)
        .await?;

        rows.iter().map(sqlite_row_to_policy_rule).collect()
    }

    async fn list_workspaces(&self) -> Result<Vec<WorkspacePolicy>, SentinelError> {
        let rows = sqlx::query_as::<_, WorkspaceRow>(
            "SELECT workspace_id, tenant_id, allowed_protocols, allowed_domains, tools, threshold_block, threshold_review
             FROM workspace_policies ORDER BY workspace_id",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.into_policy()).collect())
    }

    async fn upsert_profile(&self, profile: &AgentProfile) -> Result<(), SentinelError> {
        let tools = serde_json::to_string(&profile.approved_tools).unwrap_or_default();
        let secrets = serde_json::to_string(&profile.approved_secrets).unwrap_or_default();
        let baselines = serde_json::to_string(&profile.baseline_action_types).unwrap_or_default();
        let role = serde_json::to_value(profile.role)
            .unwrap_or_default()
            .as_str()
            .unwrap_or("builder")
            .to_string();
        let now = chrono::Utc::now().to_rfc3339();

        sqlx::query(
            "INSERT INTO agent_profiles (agent_id, tenant_id, workspace_id, framework, role, approved_tools, approved_secrets, baseline_action_types, tool_trust, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(agent_id) DO UPDATE SET
                tenant_id = excluded.tenant_id,
                workspace_id = excluded.workspace_id,
                framework = excluded.framework,
                role = excluded.role,
                approved_tools = excluded.approved_tools,
                approved_secrets = excluded.approved_secrets,
                baseline_action_types = excluded.baseline_action_types,
                tool_trust = excluded.tool_trust,
                updated_at = excluded.updated_at"
        )
        .bind(&profile.agent_id)
        .bind(&profile.tenant_id)
        .bind(&profile.workspace_id)
        .bind(&profile.framework)
        .bind(&role)
        .bind(&tools)
        .bind(&secrets)
        .bind(&baselines)
        .bind(profile.tool_trust)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn upsert_workspace(&self, policy: &WorkspacePolicy) -> Result<(), SentinelError> {
        let protocols = serde_json::to_string(&policy.allowed_protocols).unwrap_or_default();
        let domains = serde_json::to_string(&policy.allowed_domains).unwrap_or_default();
        let tools = serde_json::to_string(&policy.tools).unwrap_or_default();
        let now = chrono::Utc::now().to_rfc3339();

        sqlx::query(
            "INSERT INTO workspace_policies (workspace_id, tenant_id, allowed_protocols, allowed_domains, tools, threshold_block, threshold_review, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(workspace_id) DO UPDATE SET
                tenant_id = excluded.tenant_id,
                allowed_protocols = excluded.allowed_protocols,
                allowed_domains = excluded.allowed_domains,
                tools = excluded.tools,
                threshold_block = excluded.threshold_block,
                threshold_review = excluded.threshold_review,
                updated_at = excluded.updated_at"
        )
        .bind(&policy.workspace_id)
        .bind(&policy.tenant_id)
        .bind(&protocols)
        .bind(&domains)
        .bind(&tools)
        .bind(policy.threshold_block as i64)
        .bind(policy.threshold_review as i64)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn upsert_workspace_rule(
        &self,
        workspace_id: &str,
        rule: &PolicyRule,
    ) -> Result<(), SentinelError> {
        let match_criteria = serde_json::to_string(&rule.match_criteria).unwrap_or_default();
        let conditions = serde_json::to_string(&rule.conditions).unwrap_or_default();
        let decision = serde_json::to_value(rule.decision)
            .unwrap_or_default()
            .as_str()
            .unwrap_or("review")
            .to_string();
        let now = chrono::Utc::now().to_rfc3339();

        sqlx::query(
            "INSERT INTO policy_rules (id, workspace_id, name, priority, match_criteria, conditions, decision, reason, enabled, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET
                workspace_id = excluded.workspace_id,
                name = excluded.name,
                priority = excluded.priority,
                match_criteria = excluded.match_criteria,
                conditions = excluded.conditions,
                decision = excluded.decision,
                reason = excluded.reason,
                enabled = excluded.enabled,
                updated_at = excluded.updated_at"
        )
        .bind(&rule.id)
        .bind(workspace_id)
        .bind(&rule.name)
        .bind(rule.priority)
        .bind(&match_criteria)
        .bind(&conditions)
        .bind(&decision)
        .bind(&rule.reason)
        .bind(rule.enabled as i64)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete_profile(&self, agent_id: &str) -> Result<(), SentinelError> {
        sqlx::query("DELETE FROM agent_profiles WHERE agent_id = ?")
            .bind(agent_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete_workspace(&self, workspace_id: &str) -> Result<(), SentinelError> {
        sqlx::query("DELETE FROM workspace_policies WHERE workspace_id = ?")
            .bind(workspace_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

struct ProfileRow {
    agent_id: String,
    tenant_id: Option<String>,
    workspace_id: String,
    framework: String,
    role: String,
    approved_tools: String,
    approved_secrets: String,
    baseline_action_types: String,
    tool_trust: f64,
}

impl<'r> sqlx::FromRow<'r, sqlx::sqlite::SqliteRow> for ProfileRow {
    fn from_row(row: &'r sqlx::sqlite::SqliteRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            agent_id: row.try_get("agent_id")?,
            tenant_id: row.try_get("tenant_id").unwrap_or(None),
            workspace_id: row.try_get("workspace_id")?,
            framework: row.try_get("framework")?,
            role: row.try_get("role")?,
            approved_tools: row.try_get("approved_tools")?,
            approved_secrets: row.try_get("approved_secrets")?,
            baseline_action_types: row.try_get("baseline_action_types")?,
            // Databases created before migration 0007 have no column. The
            // fallback is the same 0.7 those rows were being scored with, so an
            // un-migrated database keeps its current behaviour exactly.
            tool_trust: row.try_get("tool_trust").unwrap_or(0.7),
        })
    }
}

impl ProfileRow {
    fn into_profile(self) -> AgentProfile {
        AgentProfile {
            agent_id: self.agent_id,
            tenant_id: self.tenant_id,
            workspace_id: self.workspace_id,
            framework: self.framework,
            role: serde_json::from_value(serde_json::Value::String(self.role))
                .unwrap_or(AgentRole::Builder),
            approved_tools: parse_json_or_warn(
                &self.approved_tools,
                "agent_profiles.approved_tools",
            ),
            approved_secrets: parse_json_or_warn(
                &self.approved_secrets,
                "agent_profiles.approved_secrets",
            ),
            baseline_action_types: parse_json_or_warn(
                &self.baseline_action_types,
                "agent_profiles.baseline_action_types",
            ),
            tool_trust: self.tool_trust,
        }
    }
}

struct WorkspaceRow {
    workspace_id: String,
    tenant_id: Option<String>,
    allowed_protocols: String,
    allowed_domains: String,
    tools: String,
    threshold_block: i64,
    threshold_review: i64,
}

impl<'r> sqlx::FromRow<'r, sqlx::sqlite::SqliteRow> for WorkspaceRow {
    fn from_row(row: &'r sqlx::sqlite::SqliteRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            workspace_id: row.try_get("workspace_id")?,
            tenant_id: row.try_get("tenant_id").unwrap_or(None),
            allowed_protocols: row.try_get("allowed_protocols")?,
            allowed_domains: row.try_get("allowed_domains")?,
            tools: row.try_get("tools")?,
            threshold_block: row.try_get("threshold_block").unwrap_or(70),
            threshold_review: row.try_get("threshold_review").unwrap_or(35),
        })
    }
}

impl WorkspaceRow {
    fn into_policy(self) -> WorkspacePolicy {
        WorkspacePolicy {
            workspace_id: self.workspace_id,
            tenant_id: self.tenant_id,
            allowed_protocols: parse_json_or_warn(
                &self.allowed_protocols,
                "workspace_policies.allowed_protocols",
            ),
            allowed_domains: parse_json_or_warn(
                &self.allowed_domains,
                "workspace_policies.allowed_domains",
            ),
            tools: parse_json_or_warn(&self.tools, "workspace_policies.tools"),
            threshold_block: self.threshold_block as u32,
            threshold_review: self.threshold_review as u32,
        }
    }
}

fn sqlite_row_to_policy_rule(row: &sqlx::sqlite::SqliteRow) -> Result<PolicyRule, SentinelError> {
    use sqlx::Row;

    let match_criteria: String = row.try_get("match_criteria")?;
    let conditions: String = row.try_get("conditions")?;
    let decision: String = row.try_get("decision")?;
    let enabled: i64 = row.try_get("enabled").unwrap_or(1);

    Ok(PolicyRule {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        priority: row.try_get("priority").unwrap_or(0),
        match_criteria: parse_json_or_warn(&match_criteria, "workspace_rules.match_criteria"),
        conditions: parse_json_or_warn(&conditions, "workspace_rules.conditions"),
        decision: serde_json::from_value(serde_json::Value::String(decision))
            .unwrap_or(GovernanceDecision::Review),
        reason: row.try_get("reason").unwrap_or(None),
        enabled: enabled != 0,
    })
}

// ── ApiKeyStore ──

#[async_trait]
impl ApiKeyStore for SqliteStorage {
    async fn store_key(
        &self,
        key_id: &str,
        key_hash: &str,
        label: &str,
        raw_key: &str,
    ) -> Result<(), SentinelError> {
        let prefix = &raw_key[..raw_key.len().min(8)];
        sqlx::query("INSERT INTO api_keys (id, key_hash, key_prefix, label) VALUES (?, ?, ?, ?)")
            .bind(key_id)
            .bind(key_hash)
            .bind(prefix)
            .bind(label)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn verify_raw_key(&self, raw_key: &str) -> Result<bool, SentinelError> {
        let prefix = &raw_key[..raw_key.len().min(8)];
        let hashes =
            sqlx::query_scalar::<_, String>("SELECT key_hash FROM api_keys WHERE key_prefix = ?")
                .bind(prefix)
                .fetch_all(&self.pool)
                .await?;

        for stored_hash in &hashes {
            if crate::auth::api_keys::verify_key(raw_key, stored_hash) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn delete_key(&self, key_id: &str) -> Result<(), SentinelError> {
        sqlx::query("DELETE FROM api_keys WHERE id = ?")
            .bind(key_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn list_keys(&self) -> Result<Vec<ApiKeyRecord>, SentinelError> {
        let rows = sqlx::query_as::<_, ApiKeyRow>(
            // `created_at` is a whole-second default here too; `id` is the PK.
            "SELECT id, label, created_at, scope, agent_id FROM api_keys ORDER BY created_at DESC, id DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| ApiKeyRecord {
                id: r.id,
                label: r.label,
                created_at: r.created_at,
                scope: r.scope,
                agent_id: r.agent_id,
            })
            .collect())
    }

    async fn store_key_scoped(
        &self,
        key_id: &str,
        key_hash: &str,
        label: &str,
        raw_key: &str,
        scope: KeyScope,
        agent_id: Option<&str>,
    ) -> Result<(), SentinelError> {
        let prefix = &raw_key[..raw_key.len().min(8)];
        sqlx::query(
            "INSERT INTO api_keys (id, key_hash, key_prefix, label, scope, agent_id) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(key_id)
        .bind(key_hash)
        .bind(prefix)
        .bind(label)
        .bind(scope.as_str())
        .bind(agent_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn verify_raw_key_scoped(
        &self,
        raw_key: &str,
    ) -> Result<Option<VerifiedKey>, SentinelError> {
        let prefix = &raw_key[..raw_key.len().min(8)];
        let candidates = sqlx::query_as::<_, (String, String, String, Option<String>)>(
            "SELECT id, key_hash, scope, agent_id FROM api_keys WHERE key_prefix = ?",
        )
        .bind(prefix)
        .fetch_all(&self.pool)
        .await?;

        for (id, stored_hash, scope, agent_id) in &candidates {
            if crate::auth::api_keys::verify_key(raw_key, stored_hash) {
                return Ok(Some(VerifiedKey {
                    key_id: Some(id.clone()),
                    scope: KeyScope::from_db(scope),
                    agent_id: agent_id.clone(),
                }));
            }
        }
        Ok(None)
    }
}

struct ApiKeyRow {
    id: String,
    label: String,
    created_at: String,
    scope: String,
    agent_id: Option<String>,
}

impl<'r> sqlx::FromRow<'r, sqlx::sqlite::SqliteRow> for ApiKeyRow {
    fn from_row(row: &'r sqlx::sqlite::SqliteRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            id: row.try_get("id")?,
            label: row.try_get("label")?,
            created_at: row.try_get("created_at")?,
            // Tolerant: rows read before the 0005 migration ran report the
            // historical fully-privileged scope.
            scope: row
                .try_get("scope")
                .unwrap_or_else(|_| KeyScope::Admin.as_str().to_string()),
            agent_id: row.try_get("agent_id").unwrap_or(None),
        })
    }
}

// ── NhiStore ──

use crate::modules::nhi::crypto_identity::{AgentIdentity, PendingChallenge};

#[async_trait]
impl NhiStore for SqliteStorage {
    async fn store_identity(
        &self,
        identity: &AgentIdentity,
        secret_key_hex: &str,
    ) -> Result<(), SentinelError> {
        let capabilities = serde_json::to_string(&identity.capabilities).unwrap_or_default();
        let now = chrono::Utc::now().to_rfc3339();

        sqlx::query(
            "INSERT INTO nhi_identities (agent_id, spiffe_id, public_key_hex, secret_key_hex, attestation_status, trust_score, capabilities, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(agent_id) DO UPDATE SET
                spiffe_id = excluded.spiffe_id,
                public_key_hex = excluded.public_key_hex,
                secret_key_hex = excluded.secret_key_hex,
                attestation_status = excluded.attestation_status,
                trust_score = excluded.trust_score,
                capabilities = excluded.capabilities,
                updated_at = excluded.updated_at"
        )
        .bind(&identity.agent_id)
        .bind(&identity.spiffe_id)
        .bind(&identity.key_commitment)
        .bind(secret_key_hex)
        .bind(&identity.attestation_status)
        .bind(identity.trust_score)
        .bind(&capabilities)
        .bind(&identity.created_at)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_identity(&self, agent_id: &str) -> Result<Option<AgentIdentity>, SentinelError> {
        use sqlx::Row;

        let row = sqlx::query(
            "SELECT agent_id, spiffe_id, public_key_hex, attestation_status, trust_score, capabilities, created_at
             FROM nhi_identities WHERE agent_id = ?"
        )
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => {
                let caps_json: String = r.try_get("capabilities").unwrap_or_default();
                Ok(Some(AgentIdentity {
                    agent_id: r.try_get("agent_id")?,
                    spiffe_id: r.try_get("spiffe_id")?,
                    key_commitment: r.try_get("public_key_hex")?,
                    created_at: r.try_get("created_at")?,
                    attestation_status: r.try_get("attestation_status")?,
                    trust_score: r.try_get("trust_score").unwrap_or(0.5),
                    capabilities: parse_json_or_warn(&caps_json, "nhi_identities.capabilities"),
                }))
            }
            None => Ok(None),
        }
    }

    async fn get_secret_key_hex(&self, agent_id: &str) -> Result<Option<String>, SentinelError> {
        let key: Option<String> =
            sqlx::query_scalar("SELECT secret_key_hex FROM nhi_identities WHERE agent_id = ?")
                .bind(agent_id)
                .fetch_optional(&self.pool)
                .await?;

        Ok(key)
    }

    async fn list_identities(&self) -> Result<Vec<AgentIdentity>, SentinelError> {
        use sqlx::Row;

        let rows = sqlx::query(
            "SELECT agent_id, spiffe_id, public_key_hex, attestation_status, trust_score, capabilities, created_at
             FROM nhi_identities ORDER BY created_at, agent_id"
        )
        .fetch_all(&self.pool)
        .await?;

        let mut identities = Vec::new();
        for r in &rows {
            let caps_json: String = r.try_get("capabilities").unwrap_or_default();
            identities.push(AgentIdentity {
                agent_id: r.try_get("agent_id")?,
                spiffe_id: r.try_get("spiffe_id")?,
                key_commitment: r.try_get("public_key_hex")?,
                created_at: r.try_get("created_at")?,
                attestation_status: r.try_get("attestation_status")?,
                trust_score: r.try_get("trust_score").unwrap_or(0.5),
                capabilities: parse_json_or_warn(&caps_json, "nhi_identities.capabilities"),
            });
        }
        Ok(identities)
    }

    async fn update_trust(&self, agent_id: &str, trust_score: f64) -> Result<(), SentinelError> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query("UPDATE nhi_identities SET trust_score = ?, updated_at = ? WHERE agent_id = ?")
            .bind(trust_score)
            .bind(&now)
            .bind(agent_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn store_challenge(&self, challenge: &PendingChallenge) -> Result<(), SentinelError> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO nhi_challenges (challenge_id, agent_id, nonce, expires_at, created_at)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(challenge_id) DO UPDATE SET
                agent_id = excluded.agent_id,
                nonce = excluded.nonce,
                expires_at = excluded.expires_at,
                created_at = excluded.created_at",
        )
        .bind(&challenge.challenge_id)
        .bind(&challenge.agent_id)
        .bind(&challenge.nonce)
        .bind(&challenge.expires_at)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_challenge(
        &self,
        challenge_id: &str,
    ) -> Result<Option<PendingChallenge>, SentinelError> {
        use sqlx::Row;

        let row = sqlx::query(
            "SELECT challenge_id, agent_id, nonce, expires_at FROM nhi_challenges WHERE challenge_id = ?"
        )
        .bind(challenge_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => Ok(Some(PendingChallenge {
                challenge_id: r.try_get("challenge_id")?,
                agent_id: r.try_get("agent_id")?,
                nonce: r.try_get("nonce")?,
                expires_at: r.try_get("expires_at")?,
            })),
            None => Ok(None),
        }
    }

    async fn delete_challenge(&self, challenge_id: &str) -> Result<(), SentinelError> {
        sqlx::query("DELETE FROM nhi_challenges WHERE challenge_id = ?")
            .bind(challenge_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn prune_expired_challenges(&self) -> Result<usize, SentinelError> {
        let now = chrono::Utc::now().to_rfc3339();
        let result = sqlx::query("DELETE FROM nhi_challenges WHERE expires_at < ?")
            .bind(&now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() as usize)
    }

    async fn store_capability_token(
        &self,
        token: &crate::modules::nhi::crypto_identity::CapabilityToken,
    ) -> Result<(), SentinelError> {
        let capabilities = serde_json::to_string(&token.capabilities).unwrap_or_default();
        sqlx::query(
            "INSERT INTO capability_tokens
                (token_id, agent_id, capabilities, issued_at, expires_at, signature, valid)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(token_id) DO UPDATE SET valid = excluded.valid",
        )
        .bind(&token.token_id)
        .bind(&token.agent_id)
        .bind(&capabilities)
        .bind(&token.issued_at)
        .bind(&token.expires_at)
        .bind(&token.signature)
        .bind(token.valid)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_capability_token(
        &self,
        token_id: &str,
    ) -> Result<Option<crate::modules::nhi::crypto_identity::CapabilityToken>, SentinelError> {
        use sqlx::Row;
        let row = sqlx::query(
            "SELECT token_id, agent_id, capabilities, issued_at, expires_at, signature, valid
             FROM capability_tokens WHERE token_id = ?",
        )
        .bind(token_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| {
            let caps_str: String = r.try_get("capabilities").unwrap_or_default();
            crate::modules::nhi::crypto_identity::CapabilityToken {
                token_id: r.try_get("token_id").unwrap_or_default(),
                agent_id: r.try_get("agent_id").unwrap_or_default(),
                capabilities: crate::storage::parse_json_or_warn(
                    &caps_str,
                    "capability_tokens.capabilities",
                ),
                issued_at: r.try_get("issued_at").unwrap_or_default(),
                expires_at: r.try_get("expires_at").unwrap_or_default(),
                signature: r.try_get("signature").unwrap_or_default(),
                // Fail CLOSED on a decode error: an unreadable `valid` column
                // must not read as "still valid".
                valid: r.try_get::<bool, _>("valid").unwrap_or(false),
            }
        }))
    }

    async fn revoke_capability_token(&self, token_id: &str) -> Result<bool, SentinelError> {
        let result = sqlx::query("UPDATE capability_tokens SET valid = 0 WHERE token_id = ?")
            .bind(token_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn prune_expired_capability_tokens(&self) -> Result<usize, SentinelError> {
        let now = chrono::Utc::now().to_rfc3339();
        let result = sqlx::query("DELETE FROM capability_tokens WHERE expires_at < ?")
            .bind(&now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() as usize)
    }

    async fn list_capability_tokens(
        &self,
    ) -> Result<Vec<crate::storage::traits::CapabilityTokenRecord>, SentinelError> {
        use sqlx::Row;
        // `signature` is deliberately absent from the projection, not filtered
        // out afterwards: a column never read cannot be leaked by a later edit.
        // Ordered newest-first with a total order on ties, the same rule the
        // audit read uses, so repeated reads are byte-identical.
        let rows = sqlx::query(
            "SELECT token_id, agent_id, capabilities, issued_at, expires_at, valid
             FROM capability_tokens ORDER BY issued_at DESC, token_id DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let caps: String = r.try_get("capabilities").unwrap_or_default();
                crate::storage::traits::CapabilityTokenRecord {
                    token_id: r.try_get("token_id").unwrap_or_default(),
                    agent_id: r.try_get("agent_id").unwrap_or_default(),
                    capabilities: crate::storage::parse_json_or_warn(
                        &caps,
                        "capability_tokens.capabilities",
                    ),
                    issued_at: r.try_get("issued_at").unwrap_or_default(),
                    expires_at: r.try_get("expires_at").unwrap_or_default(),
                    valid: r.try_get::<i64, _>("valid").unwrap_or(0) != 0,
                }
            })
            .collect())
    }
}

// ── SessionStore ──

use crate::modules::session_graph::session_dag::{FSAState, SessionDAG};

#[async_trait]
impl SessionStore for SqliteStorage {
    async fn store_session(&self, session: &SessionDAG) -> Result<(), SentinelError> {
        let nodes_json = serde_json::to_string(&session.nodes).unwrap_or_default();
        let edges_json = serde_json::to_string(&session.edges).unwrap_or_default();
        let state = serde_json::to_value(session.state)
            .unwrap_or_default()
            .as_str()
            .unwrap_or("idle")
            .to_string();

        sqlx::query(
            "INSERT INTO session_graphs (session_id, agent_id, state, blocked, block_reason, blocked_at, block_count, nodes_json, edges_json, created_at, last_activity)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(session_id) DO UPDATE SET
                agent_id = excluded.agent_id,
                state = excluded.state,
                blocked = excluded.blocked,
                block_reason = excluded.block_reason,
                blocked_at = excluded.blocked_at,
                block_count = excluded.block_count,
                nodes_json = excluded.nodes_json,
                edges_json = excluded.edges_json,
                last_activity = excluded.last_activity"
        )
        .bind(&session.session_id)
        .bind(&session.agent_id)
        .bind(&state)
        .bind(session.blocked as i64)
        .bind(&session.block_reason)
        .bind(session.blocked_at as i64)
        .bind(session.block_count as i64)
        .bind(&nodes_json)
        .bind(&edges_json)
        .bind(session.created_at as i64)
        .bind(session.last_activity as i64)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_session(&self, session_id: &str) -> Result<Option<SessionDAG>, SentinelError> {
        let row = sqlx::query(
            "SELECT session_id, agent_id, state, blocked, block_reason, blocked_at, block_count, nodes_json, edges_json, created_at, last_activity
             FROM session_graphs WHERE session_id = ?"
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => Ok(Some(session_dag_from_row(&r)?)),
            None => Ok(None),
        }
    }

    async fn list_sessions(&self) -> Result<Vec<SessionDAG>, SentinelError> {
        let rows = sqlx::query(
            "SELECT session_id, agent_id, state, blocked, block_reason, blocked_at, block_count, nodes_json, edges_json, created_at, last_activity
             FROM session_graphs ORDER BY last_activity DESC"
        )
        .fetch_all(&self.pool)
        .await?;

        let mut sessions = Vec::new();
        for r in &rows {
            sessions.push(session_dag_from_row(r)?);
        }
        Ok(sessions)
    }

    async fn delete_session(&self, session_id: &str) -> Result<(), SentinelError> {
        sqlx::query("DELETE FROM session_graphs WHERE session_id = ?")
            .bind(session_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn prune_stale_sessions(&self, max_age_ms: u64) -> Result<usize, SentinelError> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let cutoff = now_ms - max_age_ms as i64;

        let result = sqlx::query("DELETE FROM session_graphs WHERE last_activity < ?")
            .bind(cutoff)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() as usize)
    }
}

fn session_dag_from_row(r: &sqlx::sqlite::SqliteRow) -> Result<SessionDAG, SentinelError> {
    use sqlx::Row;

    let nodes_json: String = r.try_get("nodes_json").unwrap_or_default();
    let edges_json: String = r.try_get("edges_json").unwrap_or_default();
    let state_str: String = r.try_get("state").unwrap_or_else(|_| "idle".to_string());
    let blocked_int: i64 = r.try_get("blocked").unwrap_or(0);

    Ok(SessionDAG {
        session_id: r.try_get("session_id")?,
        agent_id: r.try_get("agent_id")?,
        nodes: parse_json_or_warn(&nodes_json, "sessions.nodes_json"),
        edges: parse_json_or_warn(&edges_json, "sessions.edges_json"),
        created_at: r.try_get::<i64, _>("created_at").unwrap_or(0) as u64,
        last_activity: r.try_get::<i64, _>("last_activity").unwrap_or(0) as u64,
        state: serde_json::from_value(serde_json::Value::String(state_str))
            .unwrap_or(FSAState::Idle),
        blocked: blocked_int != 0,
        block_reason: r.try_get("block_reason").unwrap_or(None),
        blocked_at: r.try_get::<i64, _>("blocked_at").unwrap_or(0) as u64,
        block_count: r.try_get::<i64, _>("block_count").unwrap_or(0) as u32,
    })
}

// ── TaintStore ──

use std::collections::HashSet;

#[async_trait]
impl TaintStore for SqliteStorage {
    async fn get_session_taint(&self, session_id: &str) -> Result<HashSet<String>, SentinelError> {
        use sqlx::Row;

        let row = sqlx::query("SELECT labels_json FROM taint_sessions WHERE session_id = ?")
            .bind(session_id)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(r) => {
                let labels_json: String = r.try_get("labels_json").unwrap_or_default();
                Ok(parse_json_or_warn(
                    &labels_json,
                    "taint_sessions.labels_json",
                ))
            }
            None => Ok(HashSet::new()),
        }
    }

    async fn update_session_taint(
        &self,
        session_id: &str,
        labels: &HashSet<String>,
    ) -> Result<(), SentinelError> {
        let labels_json = serde_json::to_string(labels).unwrap_or_default();
        let now = chrono::Utc::now().to_rfc3339();

        sqlx::query(
            "INSERT INTO taint_sessions (session_id, labels_json, updated_at)
             VALUES (?, ?, ?)
             ON CONFLICT(session_id) DO UPDATE SET
                labels_json = excluded.labels_json,
                updated_at = excluded.updated_at",
        )
        .bind(session_id)
        .bind(&labels_json)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn prune_stale_sessions(&self, max_age_secs: u64) -> Result<usize, SentinelError> {
        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(max_age_secs as i64);
        let cutoff_str = cutoff.to_rfc3339();

        let result = sqlx::query("DELETE FROM taint_sessions WHERE updated_at < ?")
            .bind(&cutoff_str)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() as usize)
    }
}

// ── FingerprintStore ──

use crate::modules::fingerprint::behavioral::AgentFingerprint;

#[async_trait]
impl FingerprintStore for SqliteStorage {
    async fn get_fingerprint(
        &self,
        agent_id: &str,
    ) -> Result<Option<AgentFingerprint>, SentinelError> {
        let row = sqlx::query(
            "SELECT agent_id, total_requests, tool_usage, action_types, avg_risk_score, peak_risk_score, hourly_pattern, anomaly_score, first_seen, last_seen, flags
             FROM fingerprints WHERE agent_id = ?"
        )
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => Ok(Some(fingerprint_from_row(&r)?)),
            None => Ok(None),
        }
    }

    async fn upsert_fingerprint(&self, fp: &AgentFingerprint) -> Result<(), SentinelError> {
        let tool_usage = serde_json::to_string(&fp.tool_usage).unwrap_or_default();
        let action_types = serde_json::to_string(&fp.action_types).unwrap_or_default();
        let hourly_pattern = serde_json::to_string(&fp.hourly_pattern).unwrap_or_default();
        let flags = serde_json::to_string(&fp.flags).unwrap_or_default();
        let now = chrono::Utc::now().to_rfc3339();

        sqlx::query(
            "INSERT INTO fingerprints (agent_id, total_requests, tool_usage, action_types, avg_risk_score, peak_risk_score, hourly_pattern, anomaly_score, first_seen, last_seen, flags, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(agent_id) DO UPDATE SET
                total_requests = excluded.total_requests,
                tool_usage = excluded.tool_usage,
                action_types = excluded.action_types,
                avg_risk_score = excluded.avg_risk_score,
                peak_risk_score = excluded.peak_risk_score,
                hourly_pattern = excluded.hourly_pattern,
                anomaly_score = excluded.anomaly_score,
                first_seen = excluded.first_seen,
                last_seen = excluded.last_seen,
                flags = excluded.flags,
                updated_at = excluded.updated_at"
        )
        .bind(&fp.agent_id)
        .bind(fp.total_requests as i64)
        .bind(&tool_usage)
        .bind(&action_types)
        .bind(fp.avg_risk_score)
        .bind(fp.peak_risk_score)
        .bind(&hourly_pattern)
        .bind(fp.anomaly_score)
        .bind(&fp.first_seen)
        .bind(&fp.last_seen)
        .bind(&flags)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn list_fingerprints(&self) -> Result<Vec<AgentFingerprint>, SentinelError> {
        let rows = sqlx::query(
            "SELECT agent_id, total_requests, tool_usage, action_types, avg_risk_score, peak_risk_score, hourly_pattern, anomaly_score, first_seen, last_seen, flags
             FROM fingerprints ORDER BY last_seen DESC"
        )
        .fetch_all(&self.pool)
        .await?;

        let mut fingerprints = Vec::new();
        for r in &rows {
            fingerprints.push(fingerprint_from_row(r)?);
        }
        Ok(fingerprints)
    }

    async fn delete_fingerprint(&self, agent_id: &str) -> Result<(), SentinelError> {
        sqlx::query("DELETE FROM fingerprints WHERE agent_id = ?")
            .bind(agent_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

fn fingerprint_from_row(r: &sqlx::sqlite::SqliteRow) -> Result<AgentFingerprint, SentinelError> {
    use sqlx::Row;

    let tool_usage_json: String = r.try_get("tool_usage").unwrap_or_default();
    let action_types_json: String = r.try_get("action_types").unwrap_or_default();
    let hourly_json: String = r.try_get("hourly_pattern").unwrap_or_default();
    let flags_json: String = r.try_get("flags").unwrap_or_default();

    let hourly_vec: Vec<u64> =
        serde_json::from_str(&hourly_json).unwrap_or_else(|_| vec![0u64; 24]);
    let mut hourly_pattern = [0u64; 24];
    for (i, v) in hourly_vec.iter().enumerate().take(24) {
        hourly_pattern[i] = *v;
    }

    Ok(AgentFingerprint {
        agent_id: r.try_get("agent_id")?,
        total_requests: r.try_get::<i64, _>("total_requests").unwrap_or(0) as u64,
        tool_usage: parse_json_or_warn(&tool_usage_json, "fingerprints.tool_usage"),
        action_types: parse_json_or_warn(&action_types_json, "fingerprints.action_types"),
        avg_risk_score: r.try_get("avg_risk_score").unwrap_or(0.0),
        peak_risk_score: r.try_get("peak_risk_score").unwrap_or(0.0),
        hourly_pattern,
        anomaly_score: r.try_get("anomaly_score").unwrap_or(0.0),
        first_seen: r.try_get("first_seen")?,
        last_seen: r.try_get("last_seen")?,
        flags: parse_json_or_warn(&flags_json, "fingerprints.flags"),
    })
}

// ── RateLimitStore ──

#[async_trait]
impl RateLimitStore for SqliteStorage {
    async fn load_config(&self) -> Result<Option<RateLimitConfig>, SentinelError> {
        use sqlx::Row;

        let row = sqlx::query(
            "SELECT max_per_minute, max_per_hour, burst_limit FROM rate_limit_config WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => Ok(Some(RateLimitConfig {
                max_per_minute: r.try_get::<i64, _>("max_per_minute").unwrap_or(60) as u32,
                // 1000: see the Postgres twin. The two backends agreed with
                // each other and with nothing else.
                max_per_hour: r.try_get::<i64, _>("max_per_hour").unwrap_or(1000) as u32,
                burst_limit: r.try_get::<i64, _>("burst_limit").unwrap_or(10) as u32,
            })),
            None => Ok(None),
        }
    }

    async fn save_config(&self, config: &RateLimitConfig) -> Result<(), SentinelError> {
        let now = chrono::Utc::now().to_rfc3339();

        sqlx::query(
            "INSERT INTO rate_limit_config (id, max_per_minute, max_per_hour, burst_limit, updated_at)
             VALUES (1, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET
                max_per_minute = excluded.max_per_minute,
                max_per_hour = excluded.max_per_hour,
                burst_limit = excluded.burst_limit,
                updated_at = excluded.updated_at"
        )
        .bind(config.max_per_minute as i64)
        .bind(config.max_per_hour as i64)
        .bind(config.burst_limit as i64)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

#[cfg(test)]
mod audit_created_at_tests {
    use super::audit_created_at;

    /// The shape has to match the column default it replaces, or old and new
    /// rows stop comparing correctly in the same `ORDER BY`.
    #[test]
    fn keeps_the_sqlite_datetime_shape_and_sorts_against_whole_seconds() {
        let got = audit_created_at("2026-08-09T12:00:00.300000Z");
        assert_eq!(got, "2026-08-09 12:00:00.300000");

        // A row written by an older build, at whole-second precision.
        let legacy = "2026-08-09 12:00:00".to_string();
        assert!(
            legacy < got,
            "a bare second must sort before any fraction within it"
        );
        assert!(audit_created_at("2026-08-09T11:59:59.999999Z") < legacy);
    }

    /// Offsets are normalised, so two rows written from differently-configured
    /// processes still order against each other.
    #[test]
    fn normalises_to_utc() {
        assert_eq!(
            audit_created_at("2026-08-09T14:00:00.500000+02:00"),
            audit_created_at("2026-08-09T12:00:00.500000Z")
        );
    }
}
