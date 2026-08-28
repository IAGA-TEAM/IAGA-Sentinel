//! LAYER 5, Deterministic Sandbox Execution
//!
//! High-risk tool calls get dry-run analysis before execution.
//! Shows impact ("would delete 4,382 rows") and waits for approval.

use std::collections::HashMap;
use std::sync::Mutex;

use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use uuid::Uuid;

// ── Types ──

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxResult {
    pub execution_id: String,
    pub tool_name: String,
    pub status: String,
    pub impact: ImpactAnalysis,
    pub captured_network: Vec<NetworkCapture>,
    pub db_operations: Vec<DbOperation>,
    pub duration_ms: u64,
    pub requires_approval: bool,
    pub approval_status: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImpactAnalysis {
    pub severity: String,
    pub summary: String,
    pub details: Vec<String>,
    pub estimated_rows_affected: Option<u64>,
    pub reversible: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkCapture {
    pub method: String,
    pub url: String,
    pub body_size: usize,
    pub blocked: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DbOperation {
    pub op_type: String,
    pub table: String,
    pub estimated_rows: u64,
    pub reversible: bool,
}

// ── Store ──

static PENDING: Lazy<Mutex<HashMap<String, SandboxResult>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

// Bounded, like every comparable process-global in this codebase
// (`session_dag`'s MAX_SESSIONS + SESSION_TTL_MS, `taint_tracker`'s
// `prune_stale_agents`). PENDING only ever shrank when an admin called
// approve/reject, so an agent that keeps tripping `should_sandbox` grew it by
// one full `SandboxResult` per call, forever, with no operator action short of
// a restart able to bound it. Same env-var + TTL shape as its siblings; the
// defaults are deliberately generous, since evicting a genuine approval request
// loses an operator's queue entry.
static MAX_PENDING: Lazy<usize> =
    Lazy::new(|| crate::config::env::env_parse("IAGA_SENTINEL_MAX_SANDBOX_PENDING", 1_000usize));
static PENDING_TTL_MS: Lazy<u64> = Lazy::new(|| {
    crate::config::env::env_parse(
        "IAGA_SENTINEL_SANDBOX_PENDING_TTL_MS",
        24 * 60 * 60 * 1000u64,
    )
});

/// Drop approval requests older than `ttl_ms`. Returns how many went.
///
/// `SandboxResult::timestamp` is already ms-since-epoch, so no new field is
/// needed. Called from the periodic cleanup task, which pruned taint, session
/// DAGs, NHI challenges and the rate limiter but never this map.
pub fn prune_stale_pending(ttl_ms: u64) -> usize {
    let mut pending = PENDING.lock().unwrap_or_else(|e| e.into_inner());
    let now = now_ms();
    let before = pending.len();
    // saturating: `timestamp` is wall-clock and can sit in the future after a
    // clock step, which must not evict a live entry (or panic in debug).
    pending.retain(|_, r| now.saturating_sub(r.timestamp) < ttl_ms);
    before - pending.len()
}

/// The TTL the cleanup task should use when the operator has not set one.
pub fn pending_ttl_ms() -> u64 {
    *PENDING_TTL_MS
}

// ponytail: a `COMPLETED` map used to sit here. `get_sandbox_result` was its
// only reader and had no call sites, so removing that function left an
// unbounded process-global map that was written on every completed, approved
// and rejected sandbox and read by nothing, with no eviction - a pure leak.
// Nothing is lost: `approve_sandbox`/`reject_sandbox` already RETURN the result
// to their caller, which is how the HTTP handlers serve it.

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ── Analyzers ──

struct ShellCheck {
    regex: Regex,
    severity: &'static str,
    description: &'static str,
    reversible: bool,
}

static SHELL_CHECKS: Lazy<Vec<ShellCheck>> = Lazy::new(|| {
    let defs: Vec<(&str, &str, &str, bool)> = vec![
        (
            r"rm\s+(-rf?|--recursive)",
            "critical",
            "Recursive file deletion",
            false,
        ),
        (
            r"mkfs|format|fdisk",
            "critical",
            "Disk formatting operation",
            false,
        ),
        (
            r"chmod\s+777",
            "high",
            "Setting world-writable permissions",
            true,
        ),
        (r"kill\s+(-9\s+)?", "high", "Process termination", true),
        (
            r"systemctl\s+(stop|restart|disable)",
            "high",
            "Service management",
            true,
        ),
        (
            r"curl.*\|.*sh|wget.*\|.*sh",
            "critical",
            "Remote code execution via pipe",
            false,
        ),
        (r"dd\s+", "critical", "Low-level disk copy", false),
        (
            r"iptables|firewall",
            "high",
            "Firewall rule modification",
            true,
        ),
    ];
    defs.into_iter()
        .filter_map(|(pat, sev, desc, rev)| {
            Regex::new(pat).ok().map(|re| ShellCheck {
                regex: re,
                severity: sev,
                description: desc,
                reversible: rev,
            })
        })
        .collect()
});

fn analyze_shell(command: &str) -> ImpactAnalysis {
    let mut details = Vec::new();
    let mut severity = "low".to_string();
    let mut reversible = true;

    for check in SHELL_CHECKS.iter() {
        if check.regex.is_match(command) {
            severity = check.severity.to_string();
            details.push(check.description.to_string());
            if !check.reversible {
                reversible = false;
            }
        }
    }

    ImpactAnalysis {
        severity,
        summary: if details.is_empty() {
            "Standard shell command".into()
        } else {
            details.join("; ")
        },
        details,
        estimated_rows_affected: None,
        reversible,
    }
}

/// Word-boundary matchers for the four mutating statements.
///
/// Substring matching on the uppercased query read `deleted_at`, `dropbox_url`,
/// `updated_at` and `alternate_id` as DELETE/DROP/UPDATE/ALTER, so an ordinary
/// `SELECT ... WHERE deleted_at IS NULL` was reported as a critical,
/// irreversible DELETE. That changes no verdict, score or receipt byte -- the
/// composite risk formula has no sandbox term (`layer_roles`) -- but it decides
/// `requires_approval`, so it filled the human approval queue and the console
/// with destructive-looking entries for read-only reads.
///
/// Built like `SHELL_CHECKS` above, with `filter_map` so an unparseable pattern
/// is dropped rather than panicking at first use. `(?i)` here because these are
/// matched against the raw query, not the uppercased copy.
static DB_STATEMENTS: Lazy<Vec<(&'static str, Regex)>> = Lazy::new(|| {
    [
        ("DELETE", r"(?i)\bDELETE\b"),
        ("DROP", r"(?i)\bDROP\b"),
        ("UPDATE", r"(?i)\bUPDATE\b"),
        ("ALTER", r"(?i)\bALTER\b"),
    ]
    .into_iter()
    .filter_map(|(name, pat)| Regex::new(pat).ok().map(|re| (name, re)))
    .collect()
});

static DB_WHERE: Lazy<Option<Regex>> = Lazy::new(|| Regex::new(r"(?i)\bWHERE\b").ok());

/// Whether `query` contains `statement` as a whole SQL keyword.
fn has_statement(query: &str, statement: &str) -> bool {
    DB_STATEMENTS
        .iter()
        .find(|(name, _)| *name == statement)
        .is_some_and(|(_, re)| re.is_match(query))
}

fn has_where(query: &str) -> bool {
    DB_WHERE.as_ref().is_some_and(|re| re.is_match(query))
}

fn analyze_db(query: &str) -> (ImpactAnalysis, Vec<DbOperation>) {
    let mut ops = Vec::new();
    let mut details = Vec::new();
    let mut severity = "low".to_string();
    let mut reversible = true;
    let mut total_rows: u64 = 0;

    if has_statement(query, "DELETE") {
        let rows = if has_where(query) { 100 } else { 10000 };
        total_rows += rows;
        severity = if rows > 100 {
            "critical".into()
        } else {
            "high".into()
        };
        reversible = false;
        details.push(format!("DELETE: ~{} rows affected", rows));
        ops.push(DbOperation {
            op_type: "DELETE".into(),
            table: "unknown".into(),
            estimated_rows: rows,
            reversible: false,
        });
    }
    if has_statement(query, "DROP") {
        severity = "critical".into();
        reversible = false;
        details.push("DROP TABLE: entire table destroyed".into());
        ops.push(DbOperation {
            op_type: "DROP".into(),
            table: "unknown".into(),
            estimated_rows: 0,
            reversible: false,
        });
    }
    if has_statement(query, "UPDATE") {
        let rows = if has_where(query) { 100 } else { 10000 };
        total_rows += rows;
        severity = if rows > 1000 {
            "high".into()
        } else {
            "medium".into()
        };
        details.push(format!("UPDATE: ~{} rows", rows));
        ops.push(DbOperation {
            op_type: "UPDATE".into(),
            table: "unknown".into(),
            estimated_rows: rows,
            reversible: true,
        });
    }
    if has_statement(query, "ALTER") {
        severity = "high".into();
        reversible = false;
        details.push("ALTER TABLE: schema modification".into());
        ops.push(DbOperation {
            op_type: "ALTER".into(),
            table: "unknown".into(),
            estimated_rows: 0,
            reversible: false,
        });
    }

    let impact = ImpactAnalysis {
        severity,
        summary: if details.is_empty() {
            "Read-only query".into()
        } else {
            details.join("; ")
        },
        details,
        estimated_rows_affected: if total_rows > 0 {
            Some(total_rows)
        } else {
            None
        },
        reversible,
    };
    (impact, ops)
}

fn analyze_http(payload: &serde_json::Value) -> (ImpactAnalysis, Vec<NetworkCapture>) {
    let url = payload
        .get("url")
        .or(payload.get("endpoint"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let method = payload
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("GET")
        .to_uppercase();
    let body = payload.get("body").or(payload.get("data"));
    let body_size = body
        .map(|b| serde_json::to_string(b).unwrap_or_default().len())
        .unwrap_or(0);

    let mut severity = "low".to_string();
    let mut details = Vec::new();
    let mut blocked = false;
    let mut reason = None;

    if ["POST", "PUT", "PATCH", "DELETE"].contains(&method.as_str()) {
        severity = "medium".into();
        details.push(format!("{} request to {}", method, url));
    }

    static RE_SUSPICIOUS: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?i)ngrok|pastebin|webhook\.site|requestbin|pipedream")
            .expect("hardcoded regex is valid")
    });
    let suspicious = &*RE_SUSPICIOUS;
    if suspicious.is_match(&url) {
        severity = "high".into();
        details.push("Request to known data exfiltration service".into());
        blocked = true;
        reason = Some("suspicious destination".into());
    }

    if body_size > 10000 {
        severity = "high".into();
        details.push(format!(
            "Large payload ({} bytes), potential exfiltration",
            body_size
        ));
    }

    let impact = ImpactAnalysis {
        severity,
        summary: if details.is_empty() {
            format!("{} {}", method, url)
        } else {
            details.join("; ")
        },
        details,
        estimated_rows_affected: None,
        reversible: method == "GET",
    };

    let capture = vec![NetworkCapture {
        method,
        url,
        body_size,
        blocked,
        reason,
    }];
    (impact, capture)
}

// ── Main ──

pub fn sandbox_execute(
    tool_name: &str,
    action_type: &str,
    payload: &serde_json::Value,
    risk_score: u32,
) -> SandboxResult {
    let start = now_ms();
    let execution_id = Uuid::new_v4().to_string();
    let (impact, network, db_ops) = match action_type {
        "shell" => {
            let cmd = payload
                .get("command")
                .or(payload.get("cmd"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            (analyze_shell(cmd), Vec::new(), Vec::new())
        }
        "db_query" => {
            let q = payload
                .get("query")
                .or(payload.get("sql"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let (imp, ops) = analyze_db(q);
            (imp, Vec::new(), ops)
        }
        "http" => {
            let (imp, net) = analyze_http(payload);
            (imp, net, Vec::new())
        }
        "email" => {
            let to = payload
                .get("to")
                .or(payload.get("recipient"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let imp = ImpactAnalysis {
                severity: "medium".into(),
                summary: format!("Email to {}", to),
                details: vec![format!("Would send email to {}", to)],
                estimated_rows_affected: None,
                reversible: false,
            };
            (imp, Vec::new(), Vec::new())
        }
        _ => {
            let imp = ImpactAnalysis {
                severity: "low".into(),
                summary: format!("{} on {}", action_type, tool_name),
                details: Vec::new(),
                estimated_rows_affected: None,
                reversible: true,
            };
            (imp, Vec::new(), Vec::new())
        }
    };

    let requires_approval =
        impact.severity == "high" || impact.severity == "critical" || risk_score >= 65;

    let result = SandboxResult {
        execution_id: execution_id.clone(),
        tool_name: tool_name.to_string(),
        status: "completed".into(),
        impact,
        captured_network: network,
        db_operations: db_ops,
        duration_ms: now_ms() - start,
        requires_approval,
        approval_status: if requires_approval {
            "pending".into()
        } else {
            "not_required".into()
        },
        timestamp: now_ms(),
    };

    // Only work awaiting a human is retained; a completed sandbox is returned
    // to the caller and not stored (see the note on the removed COMPLETED map).
    if requires_approval {
        let mut pending = PENDING.lock().unwrap_or_else(|e| e.into_inner());
        // Evict expired entries before enforcing the cap, so a full map does not
        // start refusing new approval requests while holding stale ones.
        if pending.len() >= *MAX_PENDING {
            let now = now_ms();
            pending.retain(|_, r| now.saturating_sub(r.timestamp) < *PENDING_TTL_MS);
        }
        // Still full: drop the OLDEST rather than refuse the newest, so the
        // queue keeps tracking what the agent is doing now. Logged, because
        // silently discarding something a human was meant to see is exactly the
        // failure this map exists to prevent.
        if pending.len() >= *MAX_PENDING {
            if let Some(oldest) = pending
                .values()
                .min_by_key(|r| r.timestamp)
                .map(|r| r.execution_id.clone())
            {
                tracing::warn!(
                    max_pending = *MAX_PENDING,
                    evicted = %oldest,
                    "sandbox approval queue is full; evicting the oldest entry. \
                     Raise IAGA_SENTINEL_MAX_SANDBOX_PENDING or drain the queue."
                );
                pending.remove(&oldest);
            }
        }
        pending.insert(execution_id, result.clone());
    }

    result
}

pub fn should_sandbox(action_type: &str, risk_score: u32) -> bool {
    let always = ["shell", "db_query", "email"];
    if always.contains(&action_type) && risk_score >= 50 {
        return true;
    }
    if risk_score >= 65 {
        return true;
    }
    if action_type == "file_write" && risk_score >= 40 {
        return true;
    }
    false
}

pub fn approve_sandbox(id: &str) -> Option<SandboxResult> {
    let mut pending = PENDING.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(mut r) = pending.remove(id) {
        r.approval_status = "approved".into();
        Some(r)
    } else {
        None
    }
}

pub fn reject_sandbox(id: &str) -> Option<SandboxResult> {
    let mut pending = PENDING.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(mut r) = pending.remove(id) {
        r.approval_status = "rejected".into();
        r.status = "blocked".into();
        Some(r)
    } else {
        None
    }
}

pub fn list_pending() -> Vec<SandboxResult> {
    PENDING
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .values()
        .cloned()
        .collect()
}

// ponytail: `get_sandbox_result(id)` used to live here. It was the only reader
// of the COMPLETED map and had zero call sites anywhere in crates/, sdks/ or
// plug-ins/ - no route, no CLI path, no test.
