use crate::core::errors::SentinelError;

#[cfg(feature = "postgres")]
static POSTGRES_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/postgres");
#[cfg(feature = "sqlite")]
static SQLITE_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/sqlite");

#[cfg(feature = "sqlite")]
pub async fn run_sqlite_migrations(pool: &sqlx::SqlitePool) -> Result<(), SentinelError> {
    SQLITE_MIGRATOR
        .run(pool)
        .await
        .map_err(|e| SentinelError::Storage(format!("Failed to run SQLite migrations: {e}")))?;

    // Keep old community databases bootable by backfilling columns that predate v0.2/v3.
    for (table, column, definition) in [
        (
            "workspace_policies",
            "threshold_block",
            "INTEGER NOT NULL DEFAULT 70",
        ),
        (
            "workspace_policies",
            "threshold_review",
            "INTEGER NOT NULL DEFAULT 35",
        ),
        ("audit_events", "tenant_id", "TEXT DEFAULT NULL"),
        ("review_requests", "tenant_id", "TEXT DEFAULT NULL"),
        ("agent_profiles", "tenant_id", "TEXT DEFAULT NULL"),
        ("workspace_policies", "tenant_id", "TEXT DEFAULT NULL"),
        ("api_keys", "tenant_id", "TEXT DEFAULT NULL"),
        // 1.5 cost-control columns (idempotent backfill for older community DBs)
        ("audit_events", "usage_json", "TEXT DEFAULT NULL"),
        ("audit_events", "cost_usd", "REAL DEFAULT NULL"),
        ("audit_events", "savings_usd", "REAL DEFAULT NULL"),
        ("audit_events", "total_tokens", "INTEGER DEFAULT NULL"),
        ("audit_events", "cache_hit", "INTEGER DEFAULT NULL"),
        ("audit_events", "provider", "TEXT DEFAULT NULL"),
        ("audit_events", "model", "TEXT DEFAULT NULL"),
        // 1.5.2 API key scope (idempotent backfill for older community DBs)
        ("api_keys", "scope", "TEXT NOT NULL DEFAULT 'admin'"),
        // 2.0.1 audit: persisted tool_trust (idempotent backfill for older
        // community DBs). 0.7 is the value those rows were already being scored
        // with while the column did not exist, so backfilling changes no verdict.
        ("agent_profiles", "tool_trust", "REAL NOT NULL DEFAULT 0.7"),
    ] {
        ensure_sqlite_column(pool, table, column, definition).await?;
    }

    Ok(())
}

#[cfg(feature = "sqlite")]
async fn ensure_sqlite_column(
    pool: &sqlx::SqlitePool,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<(), SentinelError> {
    let exists_sql = format!("SELECT 1 FROM pragma_table_info('{table}') WHERE name = ? LIMIT 1");
    let exists = sqlx::query_scalar::<_, i64>(&exists_sql)
        .bind(column)
        .fetch_optional(pool)
        .await?
        .is_some();

    if !exists {
        let alter_sql = format!("ALTER TABLE {table} ADD COLUMN {column} {definition}");
        sqlx::query(&alter_sql).execute(pool).await?;
    }

    Ok(())
}

#[cfg(feature = "postgres")]
pub async fn run_postgres_migrations(pool: &sqlx::PgPool) -> Result<(), SentinelError> {
    POSTGRES_MIGRATOR
        .run(pool)
        .await
        .map_err(|e| SentinelError::Storage(format!("Failed to run PostgreSQL migrations: {e}")))?;

    for ddl in [
        "ALTER TABLE IF EXISTS workspace_policies ADD COLUMN IF NOT EXISTS threshold_block INTEGER NOT NULL DEFAULT 70",
        "ALTER TABLE IF EXISTS workspace_policies ADD COLUMN IF NOT EXISTS threshold_review INTEGER NOT NULL DEFAULT 35",
        "ALTER TABLE IF EXISTS audit_events ADD COLUMN IF NOT EXISTS tenant_id TEXT REFERENCES tenants(tenant_id) ON DELETE CASCADE",
        "ALTER TABLE IF EXISTS review_requests ADD COLUMN IF NOT EXISTS tenant_id TEXT REFERENCES tenants(tenant_id) ON DELETE CASCADE",
        "ALTER TABLE IF EXISTS agent_profiles ADD COLUMN IF NOT EXISTS tenant_id TEXT REFERENCES tenants(tenant_id) ON DELETE CASCADE",
        "ALTER TABLE IF EXISTS workspace_policies ADD COLUMN IF NOT EXISTS tenant_id TEXT REFERENCES tenants(tenant_id) ON DELETE CASCADE",
        "ALTER TABLE IF EXISTS api_keys ADD COLUMN IF NOT EXISTS tenant_id TEXT REFERENCES tenants(tenant_id) ON DELETE CASCADE",
        // 1.5 cost-control columns (idempotent backfill for older community DBs)
        "ALTER TABLE IF EXISTS audit_events ADD COLUMN IF NOT EXISTS usage_json TEXT DEFAULT NULL",
        "ALTER TABLE IF EXISTS audit_events ADD COLUMN IF NOT EXISTS cost_usd DOUBLE PRECISION DEFAULT NULL",
        "ALTER TABLE IF EXISTS audit_events ADD COLUMN IF NOT EXISTS savings_usd DOUBLE PRECISION DEFAULT NULL",
        "ALTER TABLE IF EXISTS audit_events ADD COLUMN IF NOT EXISTS total_tokens BIGINT DEFAULT NULL",
        "ALTER TABLE IF EXISTS audit_events ADD COLUMN IF NOT EXISTS cache_hit BOOLEAN DEFAULT NULL",
        "ALTER TABLE IF EXISTS audit_events ADD COLUMN IF NOT EXISTS provider TEXT DEFAULT NULL",
        "ALTER TABLE IF EXISTS audit_events ADD COLUMN IF NOT EXISTS model TEXT DEFAULT NULL",
        // 1.5.2 API key scope (idempotent backfill for older community DBs)
        "ALTER TABLE IF EXISTS api_keys ADD COLUMN IF NOT EXISTS scope TEXT NOT NULL DEFAULT 'admin'",
        // 2.0.1 audit: persisted tool_trust (idempotent backfill for older
        // community DBs). 0.7 is the value those rows were already being scored
        // with while the column did not exist, so backfilling changes no verdict.
        "ALTER TABLE IF EXISTS agent_profiles ADD COLUMN IF NOT EXISTS tool_trust DOUBLE PRECISION NOT NULL DEFAULT 0.7",
    ] {
        sqlx::query(ddl).execute(pool).await?;
    }

    Ok(())
}
