//! LAYER 2, Taint Tracking for Data Flow
//!
//! Every piece of data gets tagged with a taint label at its source.
//! Taint propagates through the flow. When tainted data reaches a
//! sensitive sink → exfiltration detected → block.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use once_cell::sync::Lazy;
use serde::Serialize;

// ── Taint Labels ──

pub const UNTRUSTED_USER: &str = "untrusted_user";
pub const EXTERNAL_TOOL: &str = "external_tool";
pub const LOCAL_FS: &str = "local_fs";
pub const SECRET: &str = "secret";
pub const INTERNAL_API: &str = "internal_api";
pub const SHELL_OUTPUT: &str = "shell_output";
pub const DB_RESULT: &str = "db_result";
pub const NETWORK_RESPONSE: &str = "network_response";

// ── Sink Types ──

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkType {
    NetworkEgress,
    FileWrite,
    ShellExec,
    DbWrite,
    EmailSend,
    LogOutput,
}

impl std::fmt::Display for SinkType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SinkType::NetworkEgress => write!(f, "network_egress"),
            SinkType::FileWrite => write!(f, "file_write"),
            SinkType::ShellExec => write!(f, "shell_exec"),
            SinkType::DbWrite => write!(f, "db_write"),
            SinkType::EmailSend => write!(f, "email_send"),
            SinkType::LogOutput => write!(f, "log_output"),
        }
    }
}

// ── Taint Policy ──

struct TaintPolicy {
    sink: SinkType,
    forbidden: &'static [&'static str],
    severity: &'static str,
    description: &'static str,
}

fn default_policies() -> Vec<TaintPolicy> {
    vec![
        TaintPolicy {
            sink: SinkType::NetworkEgress,
            forbidden: &[LOCAL_FS, SECRET, INTERNAL_API, DB_RESULT],
            severity: "critical",
            description: "Sensitive data must not flow to external network",
        },
        TaintPolicy {
            sink: SinkType::EmailSend,
            forbidden: &[SECRET, INTERNAL_API],
            severity: "critical",
            description: "Secrets and internal data must not be sent via email",
        },
        TaintPolicy {
            sink: SinkType::ShellExec,
            forbidden: &[UNTRUSTED_USER, EXTERNAL_TOOL],
            severity: "high",
            description: "Untrusted input must not be used in shell commands",
        },
        TaintPolicy {
            sink: SinkType::DbWrite,
            forbidden: &[UNTRUSTED_USER],
            severity: "high",
            description: "Untrusted user input must not flow to database writes",
        },
        TaintPolicy {
            sink: SinkType::FileWrite,
            forbidden: &[UNTRUSTED_USER],
            severity: "medium",
            description: "Untrusted user input in file writes requires sanitization",
        },
        TaintPolicy {
            sink: SinkType::LogOutput,
            forbidden: &[SECRET],
            severity: "high",
            description: "Secrets must never appear in log output",
        },
    ]
}

// ── Taint Violation ──

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaintViolation {
    pub description: String,
    pub severity: String,
    pub violating_taints: Vec<String>,
    pub blocked: bool,
}

// ── Analysis Result ──

/// Serialize a label set in a stable order.
///
/// `HashSet` iterates in an order that depends on the hasher's per-process
/// random seed, so the same verdict serialized twice produced the same SET in a
/// different ORDER — measured as 45 differing array positions across two
/// identical runs of the same 42 actions. The set never reached `reasons` or any
/// receipt field, so no signed byte moved; what it did was make the verdict
/// payload impossible to compare byte-for-byte, one code change away from a
/// nondeterministic receipt.
fn sorted_labels<S: serde::Serializer>(v: &HashSet<String>, s: S) -> Result<S::Ok, S::Error> {
    let mut labels: Vec<&String> = v.iter().collect();
    labels.sort();
    s.collect_seq(labels)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaintAnalysisResult {
    pub source_taints: Vec<String>,
    pub sink_type: Option<String>,
    #[serde(serialize_with = "sorted_labels")]
    pub accumulated_labels: HashSet<String>,
    pub violations: Vec<TaintViolation>,
    pub blocked: bool,
    pub exfiltration_detected: bool,
    pub summary: String,
}

// ── Session Taint Store ──

struct TimestampedTaint {
    labels: HashSet<String>,
    last_updated: std::time::Instant,
}

static SESSION_TAINTS: Lazy<Mutex<HashMap<String, TimestampedTaint>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub fn get_session_taint(session_id: &str) -> HashSet<String> {
    let store = SESSION_TAINTS.lock().unwrap_or_else(|e| e.into_inner());
    store
        .get(session_id)
        .map(|t| t.labels.clone())
        .unwrap_or_default()
}

/// Clear the process-global per-session taint accumulation. Exposed so
/// deterministic tests can reset the shared `SESSION_TAINTS` map between runs.
pub fn reset_sessions() {
    SESSION_TAINTS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
}

pub fn update_session_taint(session_id: &str, labels: &HashSet<String>) {
    let mut store = SESSION_TAINTS.lock().unwrap_or_else(|e| e.into_inner());
    let entry = store
        .entry(session_id.to_string())
        .or_insert_with(|| TimestampedTaint {
            labels: HashSet::new(),
            last_updated: std::time::Instant::now(),
        });
    for l in labels {
        entry.labels.insert(l.clone());
    }
    entry.last_updated = std::time::Instant::now();
}

/// Prune taint data older than the given TTL. Call periodically to prevent unbounded memory growth.
pub fn prune_stale_sessions(ttl: std::time::Duration) -> usize {
    let mut store = SESSION_TAINTS.lock().unwrap_or_else(|e| e.into_inner());
    let now = std::time::Instant::now();
    let before = store.len();
    store.retain(|_, v| now.duration_since(v.last_updated) < ttl);
    before - store.len()
}

/// Hydrate taint labels into the in-memory store (used on startup to load from DB).
pub fn hydrate_session_taint(session_id: &str, labels: HashSet<String>) {
    let mut store = SESSION_TAINTS.lock().unwrap_or_else(|e| e.into_inner());
    store.insert(
        session_id.to_string(),
        TimestampedTaint {
            labels,
            last_updated: std::time::Instant::now(),
        },
    );
}

// ── Source Classification ──

fn is_secret_path(text: &str) -> bool {
    let patterns = [
        ".env",
        ".ssh",
        ".aws",
        "credentials",
        ".gnupg",
        ".npmrc",
        ".pypirc",
        ".netrc",
        "secret",
        "token",
        "passwd",
        "shadow",
        ".pem",
        ".key",
        ".p12",
        "vault",
        ".kube/config",
    ];
    let lower = text.to_lowercase();
    patterns.iter().any(|p| lower.contains(p))
}

fn has_secret_content(text: &str) -> bool {
    let lower = text.to_lowercase();
    let patterns = [
        "api_key",
        "api-key",
        "api_secret",
        "access_token",
        "access-token",
        "private_key",
        "private-key",
        "-----begin",
        "secretref://",
        "bearer ",
        "ghp_",
        "aws_secret",
        "password",
    ];
    patterns.iter().any(|p| lower.contains(p)) || contains_openai_like_key(&lower)
}

fn contains_openai_like_key(text: &str) -> bool {
    text.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '-'))
        .any(|token| token.starts_with("sk-") && token.len() >= 20)
}

fn is_internal_url(text: &str) -> bool {
    let lower = text.to_lowercase();
    let patterns = [
        "localhost",
        "127.0.0.1",
        "10.",
        "192.168.",
        ".internal",
        ".local",
        ".corp",
    ];
    patterns.iter().any(|p| lower.contains(p))
}

pub fn classify_source(action_type: &str, _tool_name: &str, payload_str: &str) -> Vec<String> {
    let mut labels = Vec::new();

    match action_type {
        "file_read" => {
            labels.push(LOCAL_FS.into());
            if is_secret_path(payload_str) {
                labels.push(SECRET.into());
            }
        }
        "db_query" => labels.push(DB_RESULT.into()),
        "http" => {
            labels.push(NETWORK_RESPONSE.into());
            if is_internal_url(payload_str) {
                labels.push(INTERNAL_API.into());
            } else {
                labels.push(EXTERNAL_TOOL.into());
            }
        }
        "shell" => labels.push(SHELL_OUTPUT.into()),
        "custom" => labels.push(EXTERNAL_TOOL.into()),
        _ => {}
    }

    if has_secret_content(payload_str) && !labels.contains(&SECRET.to_string()) {
        labels.push(SECRET.into());
    }

    labels
}

pub fn classify_sink(action_type: &str, tool_name: &str) -> Option<SinkType> {
    match action_type {
        "http" => Some(SinkType::NetworkEgress),
        "email" => Some(SinkType::EmailSend),
        "file_write" => Some(SinkType::FileWrite),
        "shell" => Some(SinkType::ShellExec),
        "db_query" => {
            let lower = tool_name.to_lowercase();
            if ["write", "insert", "update", "delete", "drop", "alter"]
                .iter()
                .any(|k| lower.contains(k))
            {
                Some(SinkType::DbWrite)
            } else {
                None
            }
        }
        _ => None,
    }
}

// ── Main Taint Analysis ──

pub fn analyze_taint(
    action_type: &str,
    tool_name: &str,
    payload_str: &str,
    inherited_taints: &HashSet<String>,
) -> TaintAnalysisResult {
    // 1. Source taints
    let source_taints = classify_source(action_type, tool_name, payload_str);

    // 2. Accumulated (inherited + new)
    let mut accumulated: HashSet<String> = inherited_taints.clone();
    for t in &source_taints {
        accumulated.insert(t.clone());
    }

    // 3. Sink classification
    let sink = classify_sink(action_type, tool_name);

    // 4. Check violations
    let mut violations = Vec::new();
    if let Some(ref sink_type) = sink {
        for policy in default_policies() {
            if policy.sink != *sink_type {
                continue;
            }
            let violating: Vec<String> = policy
                .forbidden
                .iter()
                .filter(|t| accumulated.contains(**t))
                .map(|t| t.to_string())
                .collect();

            if !violating.is_empty() {
                let blocked = policy.severity == "critical" || policy.severity == "high";
                violations.push(TaintViolation {
                    description: policy.description.to_string(),
                    severity: policy.severity.to_string(),
                    violating_taints: violating,
                    blocked,
                });
            }
        }
    }

    let blocked = violations.iter().any(|v| v.blocked);
    let exfiltration_detected = violations
        .iter()
        .any(|v| v.description.contains("network") || v.description.contains("email"));

    let sink_str = sink.map(|s| s.to_string());
    // DET-TAINT-1: `accumulated` is a HashSet, so its iteration order is
    // process-randomized. This `summary` is pushed into the signed receipt
    // reasons (notably on the Block/exfiltration path), so sort the labels for a
    // deterministic, reproducible signed string.
    let mut labels_str: Vec<String> = accumulated.iter().cloned().collect();
    labels_str.sort();
    let mut summary = format!("taints: [{}]", labels_str.join(", "));
    if let Some(ref s) = sink_str {
        summary.push_str(&format!(" → sink: {}", s));
    }
    if !violations.is_empty() {
        summary.push_str(&format!(" | {} violation(s)", violations.len()));
    }
    if blocked {
        summary.push_str(" | BLOCKED");
    }
    if exfiltration_detected {
        summary.push_str(" | EXFILTRATION DETECTED");
    }

    TaintAnalysisResult {
        source_taints,
        sink_type: sink_str,
        accumulated_labels: accumulated,
        violations,
        blocked,
        exfiltration_detected,
        summary,
    }
}
