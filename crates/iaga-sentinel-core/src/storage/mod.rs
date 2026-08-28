pub mod migrations;
#[cfg(feature = "postgres")]
pub mod postgres;
#[cfg(feature = "sqlite")]
pub mod sqlite;
pub mod traits;

/// Ceiling on `/v1/audit/export?limit=`.
///
/// The caller's `u32` went straight into `LIMIT`, so `?limit=4294967295`
/// materialized the whole `audit_events` table into a `Vec` and, for
/// `format=csv`, concatenated it into one in-process `String`. The route is
/// `RequireAdmin`, so this is an admin footgun rather than a reachable DoS --
/// but the audit log is the store that is expected to grow without bound, and
/// nothing signalled the cost. `docs/openapi.yaml` carries the matching
/// `maximum:`.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) const MAX_AUDIT_EXPORT_ROWS: u32 = 50_000;

/// Normalize one end of an `/v1/audit/export` date range to a comparable key.
///
/// `audit_events.timestamp` is TEXT on BOTH backends, and the filter bound the
/// caller's raw query-string value straight into `timestamp >= ?`. That is a
/// lexical compare, so it only ever worked for input spelled exactly the way
/// the writer spells it. Measured on a live 2.1.0 server over the same one-hour
/// window: `12:00:00+00:00` returned 34 rows, the identical instant written
/// `14:00:00+02:00` returned 0, `08:00:00-04:00` returned 0, and the literal
/// string `yesterday` also returned 0 — every one of them `200 OK`. A filter
/// that silently answers "no events" is worse than one that errors: the caller
/// concludes nothing happened.
///
/// Two things fix it. The value is parsed and converted to UTC, so any RFC3339
/// offset names the instant it actually names; and the comparison is made on
/// the first 19 characters (`YYYY-MM-DDTHH:MM:SS`), which sidesteps the stored
/// fractional part being 0, 3, 6 or 9 digits long — with variable-width
/// fractions a lexical compare on the full string mis-orders values that differ
/// only in precision. Second resolution is all an export range needs.
///
/// A bare `YYYY-MM-DD` is accepted because it is the obvious thing to type;
/// `end_of_day` makes `to_date=2026-08-22` mean the end of that day rather than
/// its midnight, which would otherwise exclude the whole day the caller asked
/// for. Anything unparseable is refused rather than silently matching nothing.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) fn normalize_audit_boundary(
    raw: &str,
    field: &str,
    end_of_day: bool,
) -> Result<String, crate::core::errors::SentinelError> {
    const KEY: &str = "%Y-%m-%dT%H:%M:%S";
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(trimmed) {
        return Ok(dt.with_timezone(&chrono::Utc).format(KEY).to_string());
    }
    if let Ok(date) = chrono::NaiveDate::parse_from_str(trimmed, "%Y-%m-%d") {
        let time = if end_of_day { (23, 59, 59) } else { (0, 0, 0) };
        if let Some(naive) = date.and_hms_opt(time.0, time.1, time.2) {
            return Ok(naive.format(KEY).to_string());
        }
    }
    Err(crate::core::errors::SentinelError::InvalidRequest(format!(
        "{field} must be an RFC3339 timestamp or a YYYY-MM-DD date, got {trimmed:?}"
    )))
}

/// One agent's aggregate row: `(agent_id, total, avg_risk, last_activity)`.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) type AgentTotalsRow = (String, u64, f64, String);

/// A grouped count keyed by agent: `(agent_id, key, count)`.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) type AgentCountRow = (String, String, u64);

/// Number of tools reported per agent by `agent_analytics`.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) const TOP_TOOLS: usize = 5;

/// Assemble `AgentAnalytics` from three already-grouped result sets.
///
/// Dialect-free on purpose, so it can be shared: the two backends differ in
/// their SQL (`$N` vs `?`, `::double precision` vs bare `AVG`), not in how the
/// rows are folded. Only the pure-Rust half lives here.
///
/// This replaces a per-agent `STRING_AGG(tool_name, ',')` / `GROUP_CONCAT` whose
/// output was split back apart in Rust. That was wrong three ways: it
/// materialized one CSV entry per audit event (megabytes for a top-5 list, and
/// it eventually hits the 1 GB aggregate ceiling), a tool whose own name
/// contained a comma was counted as two phantom tools, and the top-5 cut was
/// decided by a `HashMap` iteration plus a count-only sort, so which of several
/// tied tools survived changed run to run and between backends. Ties now break
/// on `tool_name ASC`, the same rule `stats().top_agents` already uses.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) fn fold_agent_analytics(
    totals: Vec<AgentTotalsRow>,
    decisions: Vec<AgentCountRow>,
    tools: Vec<AgentCountRow>,
) -> Vec<crate::core::types::AgentAnalytics> {
    use std::collections::HashMap;

    let mut by_agent_decisions: HashMap<String, HashMap<String, u64>> = HashMap::new();
    for (agent_id, decision, count) in decisions {
        by_agent_decisions
            .entry(agent_id)
            .or_default()
            .insert(decision, count);
    }

    let mut by_agent_tools: HashMap<String, Vec<(String, u64)>> = HashMap::new();
    for (agent_id, tool_name, count) in tools {
        by_agent_tools
            .entry(agent_id)
            .or_default()
            .push((tool_name, count));
    }

    totals
        .into_iter()
        .map(|(agent_id, total, avg_risk, last_activity)| {
            let mut top_tools = by_agent_tools.remove(&agent_id).unwrap_or_default();
            // Deterministic: count first, then name. The SQL already orders this
            // way, but the tie-break is re-applied here so the guarantee does not
            // depend on which backend produced the rows.
            top_tools.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            top_tools.truncate(TOP_TOOLS);

            let trust_score = crate::modules::nhi::crypto_identity::get_agent_trust(&agent_id);
            crate::core::types::AgentAnalytics {
                decisions: by_agent_decisions.remove(&agent_id).unwrap_or_default(),
                total_requests: total,
                avg_risk_score: avg_risk,
                top_tools,
                last_activity,
                trust_score,
                agent_id,
            }
        })
        .collect()
}

/// Parse JSON persisted in a storage column, falling back to `T::default()`.
///
/// Same fallback the backends always used, but corrupt rows are no longer
/// silently swallowed: each one logs a warning naming the column so operators
/// can spot data corruption instead of seeing fields quietly reset (1.5.2).
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) fn parse_json_or_warn<T: serde::de::DeserializeOwned + Default>(
    raw: &str,
    context: &'static str,
) -> T {
    match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(context, error = %e, "corrupt stored JSON; substituting default");
            T::default()
        }
    }
}

/// Like [`parse_json_or_warn`] for optional columns: corrupt JSON becomes
/// `None` (the historical behavior) plus a warning.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) fn parse_json_opt_or_warn<T: serde::de::DeserializeOwned>(
    raw: &str,
    context: &'static str,
) -> Option<T> {
    match serde_json::from_str(raw) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!(context, error = %e, "corrupt stored JSON; dropping value");
            None
        }
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod audit_boundary_tests {
    use super::normalize_audit_boundary;

    /// The measured defect: the same instant in three spellings must produce
    /// the same key. Before the fix the raw strings were bound straight into a
    /// lexical compare, so two of these three returned zero rows.
    #[test]
    fn the_same_instant_in_any_offset_normalizes_to_one_key() {
        let utc =
            normalize_audit_boundary("2026-08-22T12:00:00+00:00", "from_date", false).unwrap();
        let zulu = normalize_audit_boundary("2026-08-22T12:00:00Z", "from_date", false).unwrap();
        let cest =
            normalize_audit_boundary("2026-08-22T14:00:00+02:00", "from_date", false).unwrap();
        let est =
            normalize_audit_boundary("2026-08-22T08:00:00-04:00", "from_date", false).unwrap();
        assert_eq!(utc, "2026-08-22T12:00:00");
        assert_eq!(zulu, utc);
        assert_eq!(cest, utc);
        assert_eq!(est, utc);
    }

    /// Fractional seconds are dropped: the key is second resolution, which is
    /// what makes the comparison safe against the stored 0/3/6/9-digit fraction.
    #[test]
    fn fractional_seconds_are_truncated_to_the_second() {
        for input in [
            "2026-08-22T12:00:00.1+00:00",
            "2026-08-22T12:00:00.123456+00:00",
            "2026-08-22T12:00:00.123456789+00:00",
        ] {
            assert_eq!(
                normalize_audit_boundary(input, "from_date", false).unwrap(),
                "2026-08-22T12:00:00",
                "{input}"
            );
        }
    }

    /// A bare date is accepted, and `to_date` covers the whole day rather than
    /// stopping at its midnight — otherwise asking for "up to the 22nd" silently
    /// excludes everything that happened on the 22nd.
    #[test]
    fn a_bare_date_spans_the_whole_day_on_the_to_side() {
        assert_eq!(
            normalize_audit_boundary("2026-08-22", "from_date", false).unwrap(),
            "2026-08-22T00:00:00"
        );
        assert_eq!(
            normalize_audit_boundary("2026-08-22", "to_date", true).unwrap(),
            "2026-08-22T23:59:59"
        );
    }

    /// Empty means "no bound", which the SQL reads as the filter being off.
    #[test]
    fn an_empty_boundary_stays_empty() {
        assert_eq!(
            normalize_audit_boundary("", "from_date", false).unwrap(),
            ""
        );
        assert_eq!(
            normalize_audit_boundary("   ", "to_date", true).unwrap(),
            ""
        );
    }

    /// Unparseable input is refused instead of silently matching nothing.
    #[test]
    fn garbage_is_an_error_not_an_empty_result() {
        for bad in [
            "yesterday",
            "2026-13-45T99:99:99Z",
            "22/08/2026",
            "1755864000",
        ] {
            let err = normalize_audit_boundary(bad, "from_date", false)
                .expect_err(&format!("{bad} must be refused"));
            let msg = err.to_string();
            assert!(
                msg.contains("from_date"),
                "the error names the field: {msg}"
            );
        }
    }

    /// The keys order the way the SQL compare needs them to.
    #[test]
    fn keys_compare_in_chronological_order() {
        let a = normalize_audit_boundary("2026-08-22T12:00:00Z", "from_date", false).unwrap();
        let b = normalize_audit_boundary("2026-08-22T13:00:00Z", "to_date", false).unwrap();
        let c = normalize_audit_boundary("2026-09-01T00:00:00Z", "to_date", false).unwrap();
        assert!(a < b && b < c, "{a} < {b} < {c}");
    }
}
