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
        // Every entry above originates in `0001_initial.sql` and is reachable:
        // a database created before those columns existed already has 0001's row
        // in `_sqlx_migrations`, so sqlx will not re-run it and
        // `CREATE TABLE IF NOT EXISTS` is a no-op. This loop is the only path
        // that can add them.
        //
        // Nine more entries used to follow, backfilling the 1.5 cost columns,
        // the 1.5.2 `api_keys.scope` and the 2.0.1 `agent_profiles.tool_trust`.
        // All nine were unreachable by construction: `SQLITE_MIGRATOR.run` above
        // completes with `?` BEFORE this loop starts, so any database that gets
        // here has 0004/0005/0006 applied and `ensure_sqlite_column`'s
        // `pragma_table_info` probe always found the column and skipped.
        //
        // They could not even rescue the case they were written for. A legacy DB
        // that already had the cost columns but no `_sqlx_migrations` row for
        // 0004 makes sqlx run 0004's plain `ALTER TABLE ... ADD COLUMN` (SQLite
        // has no `IF NOT EXISTS` there), which fails with "duplicate column
        // name" and returns Err before this loop is reached.
    ] {
        ensure_sqlite_column(pool, table, column, definition).await?;
    }

    warn_about_unbound_agent_keys(
        sqlx::query_scalar::<_, i64>(UNBOUND_AGENT_KEYS)
            .fetch_one(pool)
            .await
            .unwrap_or(0),
    );

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
        // The nine cost / scope / tool_trust backfills that used to follow
        // are gone: `POSTGRES_MIGRATOR.run` above completes with `?` before
        // this loop, so 0004/0005/0006 are always applied by the time it
        // runs, and `ADD COLUMN IF NOT EXISTS` made each one a server-side
        // no-op. The seven above stay -- they originate in 0001, which sqlx
        // will not re-run on an existing database.
    ] {
        sqlx::query(ddl).execute(pool).await?;
    }

    warn_about_unbound_agent_keys(
        sqlx::query_scalar::<_, i64>(UNBOUND_AGENT_KEYS)
            .fetch_one(pool)
            .await
            .unwrap_or(0),
    );

    Ok(())
}

/// Agent-scoped keys that `0009` left with no identity binding.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
const UNBOUND_AGENT_KEYS: &str =
    "SELECT COUNT(*) FROM api_keys WHERE scope = 'agent' AND agent_id IS NULL";

/// Say out loud what `0009` just did to the keys already in this database.
///
/// The schema change is additive; the authorization change is not. Every
/// agent-scoped key minted before this migration has a null binding and starts
/// answering `403 agent_key_unbound`, which is deliberate and fail-closed — but
/// the product knew the exact count at migration time and said nothing at the
/// default log level, so the first signal an operator got was a 403 in a
/// caller's face. Worse for anything that fails OPEN on an unexpected status:
/// the Claude Code hook's default turns that 403 into `allow`, so an upgrade
/// disarms it silently. One line, only when the count is nonzero.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
fn warn_about_unbound_agent_keys(count: i64) {
    if count > 0 {
        tracing::warn!(
            unbound_agent_keys = count,
            "migration 0009: {count} agent-scoped API key(s) predate identity binding and now \
             fail closed with 403 agent_key_unbound. Rotate them: \
             `iaga gen-key --scope agent --agent-id <id>`, then delete the old keys."
        );
    }
}
