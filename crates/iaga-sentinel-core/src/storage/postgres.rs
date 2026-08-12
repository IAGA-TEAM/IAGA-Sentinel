use async_trait::async_trait;
use sqlx::postgres::{PgPool, PgPoolOptions};

use super::migrations::run_postgres_migrations;
use super::traits::*;
use super::{parse_json_opt_or_warn, parse_json_or_warn};
use crate::core::errors::SentinelError;
use crate::core::types::*;
use crate::modules::policy::rules_engine::PolicyRule;

pub struct PostgresStorage {
    pool: PgPool,
}

impl PostgresStorage {
    pub async fn new(database_url: &str) -> Result<Self, SentinelError> {
        let pool = PgPoolOptions::new()
            .max_connections(20)
            .min_connections(2)
            .acquire_timeout(std::time::Duration::from_secs(10))
            .idle_timeout(std::time::Duration::from_secs(300))
            // D11. Every rendering of a timestamp in this file is
            // session-`TimeZone`-dependent, and the code assumed UTC without
            // ever asking for it:
            //
            //  * `cost_over_time` truncates with `date_trunc(unit, ts)` and then
            //    formats with a LITERAL `"Z"` suffix. On a server whose
            //    `TimeZone` is not UTC the truncation lands on local midnight
            //    and the label claims it is UTC. The SQLite twin buckets on
            //    UTC-normalised text, so the two backends silently disagree
            //    about which bucket a row belongs to while emitting
            //    byte-identical labels — the divergence is invisible in a diff
            //    of the two outputs.
            //  * `created_at::text` (api_keys, tenants, nhi_identities) renders
            //    a `timestamptz` in the session zone, with an offset that is not
            //    `+00`, into fields the API documents as UTC.
            //
            // Setting it on the connection fixes every one of those at once. A
            // surgical `AT TIME ZONE 'UTC'` on the bucket query would have left
            // the three `::text` renders wrong, which is the harder class to
            // notice because nothing formats a claim about them.
            .after_connect(|conn, _meta| {
                Box::pin(async move {
                    sqlx::query("SET TIME ZONE 'UTC'").execute(conn).await?;
                    Ok(())
                })
            })
            .connect(database_url)
            .await
            .map_err(|e| SentinelError::Storage(format!("Failed to connect to PostgreSQL: {e}")))?;

        let storage = Self { pool };
        storage.run_migrations().await?;
        Ok(storage)
    }

    async fn run_migrations(&self) -> Result<(), SentinelError> {
        run_postgres_migrations(&self.pool).await
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

// ── AuditStore ──

#[async_trait]
impl AuditStore for PostgresStorage {
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
        let cache_hit = event.usage.as_ref().map(|u| u.cache_hit);
        let provider = event.usage.as_ref().map(|u| u.provider.clone());
        let model = event.usage.as_ref().map(|u| u.model.clone());

        // Supplied, not defaulted — the same reason as SQLite, for a different
        // failure. `NOW()` here has microsecond resolution so rows do not tie,
        // but it is the time the write-behind task LANDED, not the time the
        // decision was made; under load those reorder. Binding the pipeline's
        // decision time makes `ORDER BY created_at DESC` chronological, and
        // makes the two backends answer identically for identical traffic
        // (they did not: `tests/backend_parity.rs` covers the rest, and the
        // audit read order was the one column where they disagreed).
        let created_at = chrono::DateTime::parse_from_rfc3339(&event.timestamp)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or_else(|_| chrono::Utc::now());

        sqlx::query(
            "INSERT INTO audit_events (event_id, agent_id, tenant_id, framework, action_type, tool_name, decision, risk_score, review_status, reasons, timestamp, usage_json, cost_usd, savings_usd, total_tokens, cache_hit, provider, model, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, $12, $13, $14, $15, $16, $17, $18, $19)"
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
        .bind(created_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn list(&self, limit: u32) -> Result<Vec<StoredAuditEvent>, SentinelError> {
        let rows = sqlx::query(
            "SELECT event_id, agent_id, tenant_id, framework, action_type, tool_name, decision, risk_score, review_status, reasons::text, timestamp, usage_json
             FROM audit_events ORDER BY created_at DESC, event_id DESC LIMIT $1"
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(pg_row_to_audit).collect())
    }

    async fn list_filtered(
        &self,
        filter: &AuditExportFilter,
    ) -> Result<Vec<StoredAuditEvent>, SentinelError> {
        let limit = filter.limit.unwrap_or(1000) as i64;
        let agent = filter.agent_id.clone().unwrap_or_default();
        let decision = filter.decision.clone().unwrap_or_default();
        let from = filter.from_date.clone().unwrap_or_default();
        let to = filter.to_date.clone().unwrap_or_default();
        let tenant = filter.tenant_id.clone().unwrap_or_default();

        let rows = sqlx::query(
            "SELECT event_id, agent_id, tenant_id, framework, action_type, tool_name, decision, risk_score, review_status, reasons::text, timestamp, usage_json
             FROM audit_events
             WHERE ($1 = '' OR agent_id = $1)
               AND ($2 = '' OR decision = $2)
               AND ($3 = '' OR timestamp >= $3)
               AND ($4 = '' OR timestamp <= $4)
               AND ($5 = '' OR tenant_id = $5)
             ORDER BY created_at DESC, event_id DESC LIMIT $6"
        )
        .bind(&agent)
        .bind(&decision)
        .bind(&from)
        .bind(&to)
        .bind(&tenant)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(pg_row_to_audit).collect())
    }

    async fn stats(&self) -> Result<AuditStats, SentinelError> {
        use sqlx::Row;

        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
            .fetch_one(&self.pool)
            .await?;

        let avg: f64 = sqlx::query_scalar(
            "SELECT COALESCE(AVG(risk_score), 0.0)::double precision FROM audit_events",
        )
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
            // See the SQLite twin: `cnt DESC` alone leaves the LIMIT 10 boundary
            // to the planner, so two backends with the same rows can return
            // different top-tens.
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

        let rows = sqlx::query(
            "SELECT agent_id,
                    COUNT(*) as total,
                    AVG(risk_score)::double precision as avg_risk,
                    MAX(timestamp) as last_ts,
                    STRING_AGG(DISTINCT decision, ',') as decisions_csv,
                    STRING_AGG(tool_name, ',') as tools_csv
             FROM audit_events
             WHERE $1 = '' OR agent_id = $1
             GROUP BY agent_id
             ORDER BY total DESC, agent_id ASC",
        )
        .bind(agent_filter)
        .fetch_all(&self.pool)
        .await?;

        let mut results = Vec::new();
        for row in &rows {
            let aid: String = row.try_get("agent_id").unwrap_or_default();
            let total: i64 = row.try_get("total").unwrap_or(0);
            let avg_risk: f64 = row.try_get("avg_risk").unwrap_or(0.0);
            let last_ts: String = row.try_get("last_ts").unwrap_or_default();
            let tools_csv: String = row.try_get("tools_csv").unwrap_or_default();

            let decision_rows = sqlx::query(
                "SELECT decision, COUNT(*) as cnt FROM audit_events WHERE agent_id = $1 GROUP BY decision",
            )
            .bind(&aid)
            .fetch_all(&self.pool)
            .await?;

            let mut decisions = std::collections::HashMap::new();
            for dr in &decision_rows {
                let d: String = dr.try_get("decision").unwrap_or_default();
                let c: i64 = dr.try_get("cnt").unwrap_or(0);
                decisions.insert(d, c as u64);
            }

            let mut tool_counts: std::collections::HashMap<String, u64> =
                std::collections::HashMap::new();
            for tool in tools_csv.split(',') {
                let t = tool.trim().to_string();
                if !t.is_empty() {
                    *tool_counts.entry(t).or_insert(0) += 1;
                }
            }
            let mut top_tools: Vec<(String, u64)> = tool_counts.into_iter().collect();
            top_tools.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
            top_tools.truncate(5);

            let trust = crate::modules::nhi::crypto_identity::get_agent_trust(&aid);

            results.push(AgentAnalytics {
                agent_id: aid,
                total_requests: total as u64,
                decisions,
                avg_risk_score: avg_risk,
                top_tools,
                last_activity: last_ts,
                trust_score: trust,
            });
        }

        Ok(results)
    }

    async fn cost_summary(
        &self,
        from: Option<&str>,
        to: Option<&str>,
    ) -> Result<CostSummary, SentinelError> {
        use sqlx::Row;
        let from = from.unwrap_or("");
        let to = to.unwrap_or("");
        let row = sqlx::query(
            "SELECT COALESCE(SUM(cost_usd), 0.0)::double precision AS net,
                    COALESCE(SUM(savings_usd), 0.0)::double precision AS savings,
                    COALESCE(SUM(total_tokens), 0)::bigint AS tokens,
                    COALESCE(SUM(CASE WHEN cache_hit THEN 1 ELSE 0 END), 0)::bigint AS hits,
                    COALESCE(SUM(CASE WHEN usage_json IS NOT NULL THEN 1 ELSE 0 END), 0)::bigint AS actions
             FROM audit_events
             WHERE ($1 = '' OR timestamp >= $1) AND ($2 = '' OR timestamp <= $2)",
        )
        .bind(from)
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
        let from = from.unwrap_or("");
        let to = to.unwrap_or("");
        let unit = if bucket == "day" { "day" } else { "hour" };
        let rows = sqlx::query(
            "SELECT to_char(date_trunc($1::text, (timestamp)::timestamptz), 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS bucket,
                    COALESCE(SUM(cost_usd), 0.0)::double precision AS net,
                    COALESCE(SUM(savings_usd), 0.0)::double precision AS savings,
                    COALESCE(SUM(total_tokens), 0)::bigint AS tokens,
                    COUNT(*)::bigint AS actions
             FROM audit_events
             WHERE usage_json IS NOT NULL
               AND ($2 = '' OR timestamp >= $2) AND ($3 = '' OR timestamp <= $3)
             GROUP BY bucket ORDER BY bucket ASC",
        )
        .bind(unit)
        .bind(from)
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

impl PostgresStorage {
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
        let from = from.unwrap_or("");
        let to = to.unwrap_or("");
        let sql = format!(
            "SELECT COALESCE({col}, '') AS k,
                    COALESCE(SUM(cost_usd), 0.0)::double precision AS net,
                    COALESCE(SUM(savings_usd), 0.0)::double precision AS savings,
                    COALESCE(SUM(total_tokens), 0)::bigint AS tokens,
                    COUNT(*)::bigint AS actions,
                    COALESCE(SUM(CASE WHEN cache_hit THEN 1 ELSE 0 END), 0)::bigint AS hits
             FROM audit_events
             WHERE usage_json IS NOT NULL
               AND ($1 = '' OR timestamp >= $1) AND ($2 = '' OR timestamp <= $2)
             GROUP BY {col} ORDER BY net DESC, k ASC LIMIT $3",
            col = column
        );
        let rows = sqlx::query(&sql)
            .bind(from)
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

// ── ReviewStore ──

#[async_trait]
impl ReviewStore for PostgresStorage {
    async fn create(&self, review: &ReviewRequest) -> Result<(), SentinelError> {
        let reasons = serde_json::to_string(&review.reasons).unwrap_or_default();
        let decision = serde_json::to_value(review.decision)
            .unwrap_or_default()
            .as_str()
            .unwrap_or("review")
            .to_string();

        sqlx::query(
            "INSERT INTO review_requests (id, agent_id, workspace_id, tool_name, decision, status, risk_score, reasons, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10)"
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
        let row = sqlx::query(
            "SELECT id, agent_id, workspace_id, tool_name, decision, status, risk_score, reasons::text, created_at, updated_at
             FROM review_requests WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| SentinelError::ReviewNotFound(id.to_string()))?;

        Ok(pg_row_to_review(&row))
    }

    async fn update_status(&self, id: &str, status: &str) -> Result<ReviewRequest, SentinelError> {
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query("UPDATE review_requests SET status = $1, updated_at = $2 WHERE id = $3")
            .bind(status)
            .bind(&now)
            .bind(id)
            .execute(&self.pool)
            .await?;

        self.get(id).await
    }

    async fn list(&self) -> Result<Vec<ReviewRequest>, SentinelError> {
        let rows = sqlx::query(
            "SELECT id, agent_id, workspace_id, tool_name, decision, status, risk_score, reasons::text, created_at, updated_at
             FROM review_requests ORDER BY created_at ASC, id ASC"
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(pg_row_to_review).collect())
    }
}

// ── PolicyStore ──

#[async_trait]
impl PolicyStore for PostgresStorage {
    async fn get_agent_profile(&self, agent_id: &str) -> Result<AgentProfile, SentinelError> {
        let row = sqlx::query(
            "SELECT agent_id, tenant_id, workspace_id, framework, role, approved_tools::text, approved_secrets::text, baseline_action_types::text, tool_trust
             FROM agent_profiles WHERE agent_id = $1"
        )
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| SentinelError::AgentNotFound(agent_id.to_string()))?;

        Ok(pg_row_to_profile(&row))
    }

    async fn get_workspace_policy(
        &self,
        workspace_id: &str,
    ) -> Result<WorkspacePolicy, SentinelError> {
        let row = sqlx::query(
            "SELECT workspace_id, tenant_id, allowed_protocols::text, allowed_domains::text, tools::text, threshold_block, threshold_review
             FROM workspace_policies WHERE workspace_id = $1",
        )
        .bind(workspace_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| SentinelError::WorkspaceNotFound(workspace_id.to_string()))?;

        Ok(pg_row_to_workspace(&row))
    }

    async fn list_profiles(&self) -> Result<Vec<AgentProfile>, SentinelError> {
        let rows = sqlx::query(
            "SELECT agent_id, tenant_id, workspace_id, framework, role, approved_tools::text, approved_secrets::text, baseline_action_types::text, tool_trust
             FROM agent_profiles ORDER BY agent_id"
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(pg_row_to_profile).collect())
    }

    async fn list_workspace_rules(
        &self,
        workspace_id: &str,
    ) -> Result<Vec<PolicyRule>, SentinelError> {
        let rows = sqlx::query(
            "SELECT id, name, priority, match_criteria::text, conditions::text, decision, reason, enabled
             FROM policy_rules
             WHERE workspace_id = $1
             ORDER BY priority ASC, id ASC",
        )
        .bind(workspace_id)
        .fetch_all(&self.pool)
        .await?;

        rows.iter().map(pg_row_to_policy_rule).collect()
    }

    async fn list_workspaces(&self) -> Result<Vec<WorkspacePolicy>, SentinelError> {
        let rows = sqlx::query(
            "SELECT workspace_id, tenant_id, allowed_protocols::text, allowed_domains::text, tools::text, threshold_block, threshold_review
             FROM workspace_policies ORDER BY workspace_id",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(pg_row_to_workspace).collect())
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

        sqlx::query(
            "INSERT INTO agent_profiles (agent_id, tenant_id, workspace_id, framework, role, approved_tools, approved_secrets, baseline_action_types, tool_trust, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8::jsonb, $9, NOW())
             ON CONFLICT(agent_id) DO UPDATE SET
                tenant_id = EXCLUDED.tenant_id,
                workspace_id = EXCLUDED.workspace_id,
                framework = EXCLUDED.framework,
                role = EXCLUDED.role,
                approved_tools = EXCLUDED.approved_tools,
                approved_secrets = EXCLUDED.approved_secrets,
                baseline_action_types = EXCLUDED.baseline_action_types,
                tool_trust = EXCLUDED.tool_trust,
                updated_at = NOW()"
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
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn upsert_workspace(&self, policy: &WorkspacePolicy) -> Result<(), SentinelError> {
        let protocols = serde_json::to_string(&policy.allowed_protocols).unwrap_or_default();
        let domains = serde_json::to_string(&policy.allowed_domains).unwrap_or_default();
        let tools = serde_json::to_string(&policy.tools).unwrap_or_default();

        sqlx::query(
            "INSERT INTO workspace_policies (workspace_id, tenant_id, allowed_protocols, allowed_domains, tools, threshold_block, threshold_review, updated_at)
             VALUES ($1, $2, $3::jsonb, $4::jsonb, $5::jsonb, $6, $7, NOW())
             ON CONFLICT(workspace_id) DO UPDATE SET
                tenant_id = EXCLUDED.tenant_id,
                allowed_protocols = EXCLUDED.allowed_protocols,
                allowed_domains = EXCLUDED.allowed_domains,
                tools = EXCLUDED.tools,
                threshold_block = EXCLUDED.threshold_block,
                threshold_review = EXCLUDED.threshold_review,
                updated_at = NOW()"
        )
        .bind(&policy.workspace_id)
        .bind(&policy.tenant_id)
        .bind(&protocols)
        .bind(&domains)
        .bind(&tools)
        .bind(policy.threshold_block as i64)
        .bind(policy.threshold_review as i64)
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

        sqlx::query(
            "INSERT INTO policy_rules (id, workspace_id, name, priority, match_criteria, conditions, decision, reason, enabled, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7, $8, $9, NOW(), NOW())
             ON CONFLICT(id) DO UPDATE SET
                workspace_id = EXCLUDED.workspace_id,
                name = EXCLUDED.name,
                priority = EXCLUDED.priority,
                match_criteria = EXCLUDED.match_criteria,
                conditions = EXCLUDED.conditions,
                decision = EXCLUDED.decision,
                reason = EXCLUDED.reason,
                enabled = EXCLUDED.enabled,
                updated_at = NOW()"
        )
        .bind(&rule.id)
        .bind(workspace_id)
        .bind(&rule.name)
        .bind(rule.priority)
        .bind(&match_criteria)
        .bind(&conditions)
        .bind(&decision)
        .bind(&rule.reason)
        .bind(rule.enabled)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete_profile(&self, agent_id: &str) -> Result<(), SentinelError> {
        sqlx::query("DELETE FROM agent_profiles WHERE agent_id = $1")
            .bind(agent_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn delete_workspace(&self, workspace_id: &str) -> Result<(), SentinelError> {
        sqlx::query("DELETE FROM workspace_policies WHERE workspace_id = $1")
            .bind(workspace_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

// ── ApiKeyStore ──

#[async_trait]
impl ApiKeyStore for PostgresStorage {
    async fn store_key(
        &self,
        key_id: &str,
        key_hash: &str,
        label: &str,
        raw_key: &str,
    ) -> Result<(), SentinelError> {
        let prefix = &raw_key[..raw_key.len().min(8)];
        sqlx::query(
            "INSERT INTO api_keys (id, key_hash, key_prefix, label) VALUES ($1, $2, $3, $4)",
        )
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
            sqlx::query_scalar::<_, String>("SELECT key_hash FROM api_keys WHERE key_prefix = $1")
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
        sqlx::query("DELETE FROM api_keys WHERE id = $1")
            .bind(key_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn list_keys(&self) -> Result<Vec<ApiKeyRecord>, SentinelError> {
        use sqlx::Row;
        let rows = sqlx::query(
            "SELECT id, label, created_at::text, scope FROM api_keys ORDER BY created_at DESC, id DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| ApiKeyRecord {
                id: r.try_get("id").unwrap_or_default(),
                label: r.try_get("label").unwrap_or_default(),
                created_at: r.try_get("created_at").unwrap_or_default(),
                // Tolerant: rows read before the 0005 migration ran report
                // the historical fully-privileged scope.
                scope: r
                    .try_get("scope")
                    .unwrap_or_else(|_| KeyScope::Admin.as_str().to_string()),
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
    ) -> Result<(), SentinelError> {
        let prefix = &raw_key[..raw_key.len().min(8)];
        sqlx::query(
            "INSERT INTO api_keys (id, key_hash, key_prefix, label, scope) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(key_id)
        .bind(key_hash)
        .bind(prefix)
        .bind(label)
        .bind(scope.as_str())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn verify_raw_key_scoped(
        &self,
        raw_key: &str,
    ) -> Result<Option<VerifiedKey>, SentinelError> {
        let prefix = &raw_key[..raw_key.len().min(8)];
        let candidates = sqlx::query_as::<_, (String, String, String)>(
            "SELECT id, key_hash, scope FROM api_keys WHERE key_prefix = $1",
        )
        .bind(prefix)
        .fetch_all(&self.pool)
        .await?;

        for (id, stored_hash, scope) in &candidates {
            if crate::auth::api_keys::verify_key(raw_key, stored_hash) {
                return Ok(Some(VerifiedKey {
                    key_id: Some(id.clone()),
                    scope: KeyScope::from_db(scope),
                }));
            }
        }
        Ok(None)
    }
}

// ── TenantStore ──

#[async_trait]
impl TenantStore for PostgresStorage {
    async fn create_tenant(&self, tenant: &Tenant) -> Result<(), SentinelError> {
        let metadata = tenant
            .metadata
            .as_ref()
            .map(|m| serde_json::to_string(m).unwrap_or_default());
        sqlx::query(
            "INSERT INTO tenants (tenant_id, name, enabled, metadata, created_at) VALUES ($1, $2, $3, $4::jsonb, $5)",
        )
        .bind(&tenant.tenant_id)
        .bind(&tenant.name)
        .bind(tenant.enabled)
        .bind(&metadata)
        .bind(&tenant.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_tenant(&self, tenant_id: &str) -> Result<Tenant, SentinelError> {
        use sqlx::Row;
        let row = sqlx::query(
            "SELECT tenant_id, name, enabled, metadata::text, created_at::text FROM tenants WHERE tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| SentinelError::Storage(format!("Tenant not found: {tenant_id}")))?;

        let metadata_str: Option<String> = row.try_get("metadata").unwrap_or(None);
        Ok(Tenant {
            tenant_id: row.try_get("tenant_id")?,
            name: row.try_get("name")?,
            enabled: row.try_get::<bool, _>("enabled").unwrap_or(true),
            created_at: row.try_get("created_at")?,
            metadata: metadata_str.and_then(|s| parse_json_opt_or_warn(&s, "tenants.metadata")),
        })
    }

    async fn list_tenants(&self) -> Result<Vec<Tenant>, SentinelError> {
        use sqlx::Row;
        let rows = sqlx::query(
            "SELECT tenant_id, name, enabled, metadata::text, created_at::text FROM tenants ORDER BY created_at, tenant_id",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut tenants = Vec::new();
        for row in &rows {
            let metadata_str: Option<String> = row.try_get("metadata").unwrap_or(None);
            tenants.push(Tenant {
                tenant_id: row.try_get("tenant_id")?,
                name: row.try_get("name")?,
                enabled: row.try_get::<bool, _>("enabled").unwrap_or(true),
                created_at: row.try_get("created_at")?,
                metadata: metadata_str.and_then(|s| parse_json_opt_or_warn(&s, "tenants.metadata")),
            });
        }
        Ok(tenants)
    }

    async fn delete_tenant(&self, tenant_id: &str) -> Result<(), SentinelError> {
        sqlx::query("DELETE FROM tenants WHERE tenant_id = $1")
            .bind(tenant_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

// ── Helper functions ──

fn pg_row_to_audit(row: &sqlx::postgres::PgRow) -> StoredAuditEvent {
    use sqlx::Row;
    StoredAuditEvent {
        event_id: row.try_get("event_id").unwrap_or_default(),
        agent_id: row.try_get("agent_id").unwrap_or_default(),
        tenant_id: row.try_get("tenant_id").unwrap_or(None),
        framework: row.try_get("framework").unwrap_or_default(),
        action_type: {
            let s: String = row.try_get("action_type").unwrap_or_default();
            serde_json::from_value(serde_json::Value::String(s)).unwrap_or(ActionType::Custom)
        },
        tool_name: row.try_get("tool_name").unwrap_or_default(),
        // Not persisted as a column; only meaningful at receipt-creation time.
        input_sha256: String::new(),
        decision: {
            let s: String = row.try_get("decision").unwrap_or_default();
            serde_json::from_value(serde_json::Value::String(s))
                .unwrap_or(GovernanceDecision::Block)
        },
        // i32, NOT i64. These columns are declared INTEGER (int4) and sqlx's
        // Postgres type check is strict equality against INT8, so an i64 read is
        // REJECTED at decode time and `unwrap_or` silently substitutes the
        // constant. Measured effect: every row reported riskScore 0.
        risk_score: {
            let v: i32 = row.try_get("risk_score").unwrap_or_else(|e| {
                tracing::warn!(error = %e, "risk_score did not decode as i32");
                0
            });
            v as u32
        },
        review_status: {
            let s: String = row.try_get("review_status").unwrap_or_default();
            serde_json::from_value(serde_json::Value::String(s))
                .unwrap_or(ReviewStatus::NotRequired)
        },
        reasons: {
            let s: String = row.try_get("reasons").unwrap_or_default();
            parse_json_or_warn(&s, "audit_events.reasons")
        },
        timestamp: row.try_get("timestamp").unwrap_or_default(),
        usage: {
            let s: Option<String> = row.try_get("usage_json").unwrap_or(None);
            s.and_then(|s| parse_json_opt_or_warn(&s, "audit_events.usage_json"))
        },
        // Not persisted as a column: receipt run grouping uses the in-memory
        // event at request time, and the chain lives in the receipts table.
        session_id: None,
    }
}

fn pg_row_to_review(row: &sqlx::postgres::PgRow) -> ReviewRequest {
    use sqlx::Row;
    ReviewRequest {
        id: row.try_get("id").unwrap_or_default(),
        agent_id: row.try_get("agent_id").unwrap_or_default(),
        workspace_id: row.try_get("workspace_id").unwrap_or_default(),
        tool_name: row.try_get("tool_name").unwrap_or_default(),
        decision: {
            let s: String = row.try_get("decision").unwrap_or_default();
            serde_json::from_value(serde_json::Value::String(s))
                .unwrap_or(GovernanceDecision::Review)
        },
        status: row.try_get("status").unwrap_or_default(),
        // i32, NOT i64. These columns are declared INTEGER (int4) and sqlx's
        // Postgres type check is strict equality against INT8, so an i64 read is
        // REJECTED at decode time and `unwrap_or` silently substitutes the
        // constant. Measured effect: every row reported riskScore 0.
        risk_score: {
            let v: i32 = row.try_get("risk_score").unwrap_or_else(|e| {
                tracing::warn!(error = %e, "risk_score did not decode as i32");
                0
            });
            v as u32
        },
        reasons: {
            let s: String = row.try_get("reasons").unwrap_or_default();
            parse_json_or_warn(&s, "review_requests.reasons")
        },
        created_at: row.try_get("created_at").unwrap_or_default(),
        updated_at: row.try_get("updated_at").unwrap_or_default(),
    }
}

fn pg_row_to_profile(row: &sqlx::postgres::PgRow) -> AgentProfile {
    use sqlx::Row;
    AgentProfile {
        agent_id: row.try_get("agent_id").unwrap_or_default(),
        tenant_id: row.try_get("tenant_id").unwrap_or(None),
        workspace_id: row.try_get("workspace_id").unwrap_or_default(),
        framework: row.try_get("framework").unwrap_or_default(),
        role: {
            let s: String = row.try_get("role").unwrap_or_default();
            serde_json::from_value(serde_json::Value::String(s)).unwrap_or(AgentRole::Builder)
        },
        approved_tools: {
            let s: String = row.try_get("approved_tools").unwrap_or_default();
            parse_json_or_warn(&s, "agent_profiles.approved_tools")
        },
        approved_secrets: {
            let s: String = row.try_get("approved_secrets").unwrap_or_default();
            parse_json_or_warn(&s, "agent_profiles.approved_secrets")
        },
        baseline_action_types: {
            let s: String = row.try_get("baseline_action_types").unwrap_or_default();
            parse_json_or_warn(&s, "agent_profiles.baseline_action_types")
        },
        // Databases created before migration 0007 have no column; the fallback
        // is the same 0.7 those rows were already being scored with.
        tool_trust: row.try_get("tool_trust").unwrap_or(0.7),
    }
}

fn pg_row_to_workspace(row: &sqlx::postgres::PgRow) -> WorkspacePolicy {
    use sqlx::Row;
    WorkspacePolicy {
        workspace_id: row.try_get("workspace_id").unwrap_or_default(),
        tenant_id: row.try_get("tenant_id").unwrap_or(None),
        allowed_protocols: {
            let s: String = row.try_get("allowed_protocols").unwrap_or_default();
            parse_json_or_warn(&s, "workspace_policies.allowed_protocols")
        },
        allowed_domains: {
            let s: String = row.try_get("allowed_domains").unwrap_or_default();
            parse_json_or_warn(&s, "workspace_policies.allowed_domains")
        },
        tools: {
            let s: String = row.try_get("tools").unwrap_or_default();
            parse_json_or_warn(&s, "workspace_policies.tools")
        },
        // The pair that mattered most: both columns are INTEGER, so the i64
        // read was rejected and EVERY workspace governed at the fallback 70/35
        // regardless of what it had configured. These feed the verdict
        // comparisons AND `workspace_policy_hash`, which is bound into every
        // signed receipt.
        threshold_block: {
            let v: i32 = row.try_get("threshold_block").unwrap_or_else(|e| {
                tracing::warn!(error = %e, "threshold_block did not decode as i32");
                70
            });
            v as u32
        },
        threshold_review: {
            let v: i32 = row.try_get("threshold_review").unwrap_or_else(|e| {
                tracing::warn!(error = %e, "threshold_review did not decode as i32");
                35
            });
            v as u32
        },
    }
}

fn pg_row_to_policy_rule(row: &sqlx::postgres::PgRow) -> Result<PolicyRule, SentinelError> {
    use sqlx::Row;

    let match_criteria: String = row.try_get("match_criteria").unwrap_or_default();
    let conditions: String = row.try_get("conditions").unwrap_or_default();
    let decision: String = row.try_get("decision").unwrap_or_default();

    Ok(PolicyRule {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        priority: row.try_get("priority").unwrap_or(0),
        match_criteria: parse_json_or_warn(&match_criteria, "workspace_rules.match_criteria"),
        conditions: parse_json_or_warn(&conditions, "workspace_rules.conditions"),
        decision: serde_json::from_value(serde_json::Value::String(decision))
            .unwrap_or(GovernanceDecision::Review),
        reason: row.try_get("reason").unwrap_or(None),
        enabled: row.try_get("enabled").unwrap_or(true),
    })
}

// ═══════════════════════════════════════════════════════════════
// v0.4.0, Durable State Storage Implementations
// ═══════════════════════════════════════════════════════════════

use crate::modules::fingerprint::behavioral::AgentFingerprint;
use crate::modules::nhi::crypto_identity::{AgentIdentity, PendingChallenge};
use crate::modules::session_graph::session_dag::{FSAState, SessionDAG};
use std::collections::HashSet;

// ── NhiStore ──

#[async_trait]
impl NhiStore for PostgresStorage {
    async fn store_identity(
        &self,
        identity: &AgentIdentity,
        secret_key_hex: &str,
    ) -> Result<(), SentinelError> {
        let capabilities = serde_json::to_string(&identity.capabilities).unwrap_or_default();

        sqlx::query(
            "INSERT INTO nhi_identities (agent_id, spiffe_id, public_key_hex, secret_key_hex, attestation_status, trust_score, capabilities, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, NOW(), NOW())
             ON CONFLICT(agent_id) DO UPDATE SET
                spiffe_id = EXCLUDED.spiffe_id,
                public_key_hex = EXCLUDED.public_key_hex,
                secret_key_hex = EXCLUDED.secret_key_hex,
                attestation_status = EXCLUDED.attestation_status,
                trust_score = EXCLUDED.trust_score,
                capabilities = EXCLUDED.capabilities,
                updated_at = NOW()"
        )
        .bind(&identity.agent_id)
        .bind(&identity.spiffe_id)
        .bind(&identity.key_commitment)
        .bind(secret_key_hex)
        .bind(&identity.attestation_status)
        .bind(identity.trust_score)
        .bind(&capabilities)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_identity(&self, agent_id: &str) -> Result<Option<AgentIdentity>, SentinelError> {
        use sqlx::Row;

        let row = sqlx::query(
            "SELECT agent_id, spiffe_id, public_key_hex, attestation_status, trust_score, capabilities::text, created_at::text
             FROM nhi_identities WHERE agent_id = $1"
        )
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| {
            let caps_str: String = r.try_get("capabilities").unwrap_or_default();
            AgentIdentity {
                agent_id: r.try_get("agent_id").unwrap_or_default(),
                spiffe_id: r.try_get("spiffe_id").unwrap_or_default(),
                key_commitment: r.try_get("public_key_hex").unwrap_or_default(),
                created_at: r.try_get("created_at").unwrap_or_default(),
                attestation_status: r.try_get("attestation_status").unwrap_or_default(),
                trust_score: r.try_get("trust_score").unwrap_or(0.0),
                capabilities: parse_json_or_warn(&caps_str, "nhi_identities.capabilities"),
            }
        }))
    }

    async fn get_secret_key_hex(&self, agent_id: &str) -> Result<Option<String>, SentinelError> {
        let row = sqlx::query_scalar::<_, String>(
            "SELECT secret_key_hex FROM nhi_identities WHERE agent_id = $1",
        )
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    async fn list_identities(&self) -> Result<Vec<AgentIdentity>, SentinelError> {
        use sqlx::Row;

        let rows = sqlx::query(
            "SELECT agent_id, spiffe_id, public_key_hex, attestation_status, trust_score, capabilities::text, created_at::text
             FROM nhi_identities ORDER BY created_at, agent_id"
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .iter()
            .map(|r| {
                let caps_str: String = r.try_get("capabilities").unwrap_or_default();
                AgentIdentity {
                    agent_id: r.try_get("agent_id").unwrap_or_default(),
                    spiffe_id: r.try_get("spiffe_id").unwrap_or_default(),
                    key_commitment: r.try_get("public_key_hex").unwrap_or_default(),
                    created_at: r.try_get("created_at").unwrap_or_default(),
                    attestation_status: r.try_get("attestation_status").unwrap_or_default(),
                    trust_score: r.try_get("trust_score").unwrap_or(0.0),
                    capabilities: parse_json_or_warn(&caps_str, "nhi_identities.capabilities"),
                }
            })
            .collect())
    }

    async fn update_trust(&self, agent_id: &str, trust_score: f64) -> Result<(), SentinelError> {
        sqlx::query(
            "UPDATE nhi_identities SET trust_score = $1, updated_at = NOW() WHERE agent_id = $2",
        )
        .bind(trust_score)
        .bind(agent_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn store_challenge(&self, challenge: &PendingChallenge) -> Result<(), SentinelError> {
        sqlx::query(
            "INSERT INTO nhi_challenges (challenge_id, agent_id, nonce, expires_at, created_at)
             VALUES ($1, $2, $3, $4, NOW())
             ON CONFLICT(challenge_id) DO UPDATE SET
                agent_id = EXCLUDED.agent_id,
                nonce = EXCLUDED.nonce,
                expires_at = EXCLUDED.expires_at,
                created_at = NOW()",
        )
        .bind(&challenge.challenge_id)
        .bind(&challenge.agent_id)
        .bind(&challenge.nonce)
        .bind(&challenge.expires_at)
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
            "SELECT challenge_id, agent_id, nonce, expires_at
             FROM nhi_challenges WHERE challenge_id = $1",
        )
        .bind(challenge_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| PendingChallenge {
            challenge_id: r.try_get("challenge_id").unwrap_or_default(),
            agent_id: r.try_get("agent_id").unwrap_or_default(),
            nonce: r.try_get("nonce").unwrap_or_default(),
            expires_at: r.try_get("expires_at").unwrap_or_default(),
        }))
    }

    async fn delete_challenge(&self, challenge_id: &str) -> Result<(), SentinelError> {
        sqlx::query("DELETE FROM nhi_challenges WHERE challenge_id = $1")
            .bind(challenge_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn prune_expired_challenges(&self) -> Result<usize, SentinelError> {
        // `expires_at` is TEXT written from `to_rfc3339()` ("...T...+00:00");
        // `NOW()::text` renders Postgres ISO style ("... ...+00"). Once the date
        // parts match, the comparison turns on 'T' (0x54) vs ' ' (0x20) and the
        // row survives its own 60-second TTL until the DATE advances. It also
        // renders in the session TimeZone. Format in Rust and bind, as the
        // SQLite twin already does.
        let now = chrono::Utc::now().to_rfc3339();
        let result = sqlx::query("DELETE FROM nhi_challenges WHERE expires_at < $1")
            .bind(&now)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() as usize)
    }
}

// ── SessionStore ──

#[async_trait]
impl SessionStore for PostgresStorage {
    async fn store_session(&self, session: &SessionDAG) -> Result<(), SentinelError> {
        let nodes_json = serde_json::to_string(&session.nodes).unwrap_or_default();
        let edges_json = serde_json::to_string(&session.edges).unwrap_or_default();
        let state_str = serde_json::to_value(session.state)
            .unwrap_or_default()
            .as_str()
            .unwrap_or("idle")
            .to_string();

        sqlx::query(
            "INSERT INTO session_graphs (session_id, agent_id, state, blocked, block_reason, blocked_at, block_count, nodes_json, edges_json, created_at, last_activity)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb, $10, $11)
             ON CONFLICT(session_id) DO UPDATE SET
                agent_id = EXCLUDED.agent_id,
                state = EXCLUDED.state,
                blocked = EXCLUDED.blocked,
                block_reason = EXCLUDED.block_reason,
                blocked_at = EXCLUDED.blocked_at,
                block_count = EXCLUDED.block_count,
                nodes_json = EXCLUDED.nodes_json,
                edges_json = EXCLUDED.edges_json,
                last_activity = EXCLUDED.last_activity"
        )
        .bind(&session.session_id)
        .bind(&session.agent_id)
        .bind(&state_str)
        .bind(session.blocked)
        .bind(&session.block_reason)
        .bind(session.blocked_at as i64)
        .bind(session.block_count as i32)
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
            "SELECT session_id, agent_id, state, blocked, block_reason, blocked_at, block_count, nodes_json::text, edges_json::text, created_at, last_activity
             FROM session_graphs WHERE session_id = $1"
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| pg_row_to_session(&r)))
    }

    async fn list_sessions(&self) -> Result<Vec<SessionDAG>, SentinelError> {
        let rows = sqlx::query(
            "SELECT session_id, agent_id, state, blocked, block_reason, blocked_at, block_count, nodes_json::text, edges_json::text, created_at, last_activity
             FROM session_graphs ORDER BY last_activity DESC"
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(pg_row_to_session).collect())
    }

    async fn delete_session(&self, session_id: &str) -> Result<(), SentinelError> {
        sqlx::query("DELETE FROM session_graphs WHERE session_id = $1")
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

        let result = sqlx::query("DELETE FROM session_graphs WHERE last_activity < $1")
            .bind(cutoff)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() as usize)
    }
}

// ── TaintStore ──

#[async_trait]
impl TaintStore for PostgresStorage {
    async fn get_session_taint(&self, session_id: &str) -> Result<HashSet<String>, SentinelError> {
        use sqlx::Row;

        let row = sqlx::query("SELECT labels_json::text FROM taint_sessions WHERE session_id = $1")
            .bind(session_id)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(r) => {
                let json_str: String = r.try_get("labels_json").unwrap_or_default();
                Ok(parse_json_or_warn(&json_str, "taint_sessions.labels_json"))
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

        sqlx::query(
            "INSERT INTO taint_sessions (session_id, labels_json, updated_at)
             VALUES ($1, $2::jsonb, NOW())
             ON CONFLICT(session_id) DO UPDATE SET
                labels_json = EXCLUDED.labels_json,
                updated_at = NOW()",
        )
        .bind(session_id)
        .bind(&labels_json)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn prune_stale_sessions(&self, max_age_secs: u64) -> Result<usize, SentinelError> {
        let result = sqlx::query(
            "DELETE FROM taint_sessions WHERE updated_at < NOW() - ($1 || ' seconds')::interval",
        )
        .bind(max_age_secs.to_string())
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() as usize)
    }
}

// ── FingerprintStore ──

#[async_trait]
impl FingerprintStore for PostgresStorage {
    async fn get_fingerprint(
        &self,
        agent_id: &str,
    ) -> Result<Option<AgentFingerprint>, SentinelError> {
        let row = sqlx::query(
            "SELECT agent_id, total_requests, tool_usage::text, action_types::text, avg_risk_score, peak_risk_score, hourly_pattern::text, anomaly_score, first_seen, last_seen, flags::text
             FROM fingerprints WHERE agent_id = $1"
        )
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| pg_row_to_fingerprint(&r)))
    }

    async fn upsert_fingerprint(&self, fp: &AgentFingerprint) -> Result<(), SentinelError> {
        let tool_usage = serde_json::to_string(&fp.tool_usage).unwrap_or_default();
        let action_types = serde_json::to_string(&fp.action_types).unwrap_or_default();
        let hourly_pattern = serde_json::to_string(&fp.hourly_pattern).unwrap_or_default();
        let flags = serde_json::to_string(&fp.flags).unwrap_or_default();

        sqlx::query(
            "INSERT INTO fingerprints (agent_id, total_requests, tool_usage, action_types, avg_risk_score, peak_risk_score, hourly_pattern, anomaly_score, first_seen, last_seen, flags, updated_at)
             VALUES ($1, $2, $3::jsonb, $4::jsonb, $5, $6, $7::jsonb, $8, $9, $10, $11::jsonb, NOW())
             ON CONFLICT(agent_id) DO UPDATE SET
                total_requests = EXCLUDED.total_requests,
                tool_usage = EXCLUDED.tool_usage,
                action_types = EXCLUDED.action_types,
                avg_risk_score = EXCLUDED.avg_risk_score,
                peak_risk_score = EXCLUDED.peak_risk_score,
                hourly_pattern = EXCLUDED.hourly_pattern,
                anomaly_score = EXCLUDED.anomaly_score,
                first_seen = EXCLUDED.first_seen,
                last_seen = EXCLUDED.last_seen,
                flags = EXCLUDED.flags,
                updated_at = NOW()"
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
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn list_fingerprints(&self) -> Result<Vec<AgentFingerprint>, SentinelError> {
        let rows = sqlx::query(
            "SELECT agent_id, total_requests, tool_usage::text, action_types::text, avg_risk_score, peak_risk_score, hourly_pattern::text, anomaly_score, first_seen, last_seen, flags::text
             FROM fingerprints ORDER BY last_seen DESC"
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(pg_row_to_fingerprint).collect())
    }

    async fn delete_fingerprint(&self, agent_id: &str) -> Result<(), SentinelError> {
        sqlx::query("DELETE FROM fingerprints WHERE agent_id = $1")
            .bind(agent_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}

// ── RateLimitStore ──

#[async_trait]
impl RateLimitStore for PostgresStorage {
    async fn load_config(&self) -> Result<Option<RateLimitConfig>, SentinelError> {
        use sqlx::Row;

        let row = sqlx::query(
            "SELECT max_per_minute, max_per_hour, burst_limit FROM rate_limit_config WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| {
            let mpm: i32 = r.try_get("max_per_minute").unwrap_or(60);
            let mph: i32 = r.try_get("max_per_hour").unwrap_or(600);
            let bl: i32 = r.try_get("burst_limit").unwrap_or(10);
            RateLimitConfig {
                max_per_minute: mpm as u32,
                max_per_hour: mph as u32,
                burst_limit: bl as u32,
            }
        }))
    }

    async fn save_config(&self, config: &RateLimitConfig) -> Result<(), SentinelError> {
        sqlx::query(
            "INSERT INTO rate_limit_config (id, max_per_minute, max_per_hour, burst_limit, updated_at)
             VALUES (1, $1, $2, $3, NOW())
             ON CONFLICT(id) DO UPDATE SET
                max_per_minute = EXCLUDED.max_per_minute,
                max_per_hour = EXCLUDED.max_per_hour,
                burst_limit = EXCLUDED.burst_limit,
                updated_at = NOW()"
        )
        .bind(config.max_per_minute as i32)
        .bind(config.max_per_hour as i32)
        .bind(config.burst_limit as i32)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

// ── v0.4.0 Helper functions ──

fn pg_row_to_session(row: &sqlx::postgres::PgRow) -> SessionDAG {
    use sqlx::Row;

    let state_str: String = row.try_get("state").unwrap_or_default();
    let state: FSAState =
        serde_json::from_value(serde_json::Value::String(state_str)).unwrap_or(FSAState::Idle);

    let nodes_str: String = row.try_get("nodes_json").unwrap_or_default();
    let edges_str: String = row.try_get("edges_json").unwrap_or_default();

    SessionDAG {
        session_id: row.try_get("session_id").unwrap_or_default(),
        agent_id: row.try_get("agent_id").unwrap_or_default(),
        nodes: parse_json_or_warn(&nodes_str, "sessions.nodes_json"),
        edges: parse_json_or_warn(&edges_str, "sessions.edges_json"),
        created_at: {
            let v: i64 = row.try_get("created_at").unwrap_or(0);
            v as u64
        },
        last_activity: {
            let v: i64 = row.try_get("last_activity").unwrap_or(0);
            v as u64
        },
        state,
        blocked: row.try_get("blocked").unwrap_or(false),
        block_reason: row.try_get("block_reason").unwrap_or(None),
        blocked_at: {
            let v: i64 = row.try_get("blocked_at").unwrap_or(0);
            v as u64
        },
        block_count: {
            let v: i32 = row.try_get("block_count").unwrap_or(0);
            v as u32
        },
    }
}

fn pg_row_to_fingerprint(row: &sqlx::postgres::PgRow) -> AgentFingerprint {
    use sqlx::Row;

    let tool_usage_str: String = row.try_get("tool_usage").unwrap_or_default();
    let action_types_str: String = row.try_get("action_types").unwrap_or_default();
    let hourly_str: String = row.try_get("hourly_pattern").unwrap_or_default();
    let flags_str: String = row.try_get("flags").unwrap_or_default();

    let hourly_vec: Vec<u64> = serde_json::from_str(&hourly_str).unwrap_or_else(|_| vec![0; 24]);
    let mut hourly_pattern = [0u64; 24];
    for (i, v) in hourly_vec.iter().take(24).enumerate() {
        hourly_pattern[i] = *v;
    }

    AgentFingerprint {
        agent_id: row.try_get("agent_id").unwrap_or_default(),
        total_requests: {
            let v: i64 = row.try_get("total_requests").unwrap_or(0);
            v as u64
        },
        tool_usage: parse_json_or_warn(&tool_usage_str, "fingerprints.tool_usage"),
        action_types: parse_json_or_warn(&action_types_str, "fingerprints.action_types"),
        avg_risk_score: row.try_get("avg_risk_score").unwrap_or(0.0),
        peak_risk_score: row.try_get("peak_risk_score").unwrap_or(0.0),
        hourly_pattern,
        anomaly_score: row.try_get("anomaly_score").unwrap_or(0.0),
        first_seen: row.try_get("first_seen").unwrap_or_default(),
        last_seen: row.try_get("last_seen").unwrap_or_default(),
        flags: parse_json_or_warn(&flags_str, "fingerprints.flags"),
    }
}
