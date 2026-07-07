//! LAYER 1, Session Graph Analysis
//!
//! Models every agent session as a DAG (Directed Acyclic Graph).
//! Nodes = tool calls. Edges = data flow.
//! FSA (Finite State Automaton) per session enforces allowed transitions.
//! Pattern matching on the DAG detects multi-step attack chains.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use once_cell::sync::Lazy;
use serde::Serialize;
use sha2::{Digest, Sha256};

// ── Types ──

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolCallNode {
    pub id: String,
    pub tool_name: String,
    pub action_type: String,
    pub timestamp: u64,
    pub taint_labels: HashSet<String>,
    pub risk_score: u32,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataFlowEdge {
    pub from: String,
    pub to: String,
    pub data_keys: Vec<String>,
    pub taint_propagated: HashSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FSAState {
    Idle,
    Reading,
    Processing,
    Writing,
    NetworkEgress,
    Blocked,
}

impl std::fmt::Display for FSAState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FSAState::Idle => write!(f, "idle"),
            FSAState::Reading => write!(f, "reading"),
            FSAState::Processing => write!(f, "processing"),
            FSAState::Writing => write!(f, "writing"),
            FSAState::NetworkEgress => write!(f, "network_egress"),
            FSAState::Blocked => write!(f, "blocked"),
        }
    }
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionDAG {
    pub session_id: String,
    pub agent_id: String,
    pub nodes: Vec<ToolCallNode>,
    pub edges: Vec<DataFlowEdge>,
    pub created_at: u64,
    pub last_activity: u64,
    pub state: FSAState,
    pub blocked: bool,
    pub block_reason: Option<String>,
    /// Timestamp (ms since epoch) when the session was last blocked.
    pub blocked_at: u64,
    /// How many times this session has been blocked (resets are free until MAX_BLOCK_COUNT).
    pub block_count: u32,
}

// ── Attack Signatures ──

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttackSignature {
    pub name: String,
    pub description: String,
    pub severity: String,
    pub pattern: Vec<String>,
    pub required_taints: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttackMatch {
    pub name: String,
    pub severity: String,
    pub confidence: f64,
    pub matched_nodes: Vec<String>,
}

fn attack_signatures() -> Vec<AttackSignature> {
    vec![
        AttackSignature {
            name: "data_exfiltration".into(),
            description: "Read local/secret data then send to external network".into(),
            severity: "critical".into(),
            pattern: vec!["file_read".into(), "http".into()],
            required_taints: Some(vec!["local_fs".into(), "secret".into()]),
        },
        AttackSignature {
            name: "secret_exfiltration_email".into(),
            description: "Access secrets then exfiltrate via email".into(),
            severity: "critical".into(),
            pattern: vec!["file_read".into(), "email".into()],
            required_taints: Some(vec!["secret".into()]),
        },
        AttackSignature {
            name: "reverse_shell_setup".into(),
            description: "HTTP fetch followed by shell execution".into(),
            severity: "critical".into(),
            pattern: vec!["http".into(), "shell".into()],
            required_taints: None,
        },
        AttackSignature {
            name: "lateral_movement".into(),
            description: "Read internal data, query DB, then network egress".into(),
            severity: "high".into(),
            pattern: vec!["db_query".into(), "http".into()],
            required_taints: Some(vec!["internal_api".into()]),
        },
        AttackSignature {
            name: "db_dump_exfiltration".into(),
            description: "Database query followed by file write and network send".into(),
            severity: "critical".into(),
            pattern: vec!["db_query".into(), "file_write".into(), "http".into()],
            required_taints: None,
        },
        AttackSignature {
            name: "privilege_escalation_chain".into(),
            description: "Shell commands that modify then read protected files".into(),
            severity: "high".into(),
            pattern: vec!["shell".into(), "file_read".into(), "shell".into()],
            required_taints: None,
        },
    ]
}

// ── FSA Transitions ──

struct Transition {
    from: FSAState,
    action: &'static str,
    to: FSAState,
}

fn default_transitions() -> Vec<Transition> {
    vec![
        Transition {
            from: FSAState::Idle,
            action: "file_read",
            to: FSAState::Reading,
        },
        Transition {
            from: FSAState::Idle,
            action: "db_query",
            to: FSAState::Reading,
        },
        Transition {
            from: FSAState::Idle,
            action: "http",
            to: FSAState::NetworkEgress,
        },
        Transition {
            from: FSAState::Idle,
            action: "shell",
            to: FSAState::Processing,
        },
        Transition {
            from: FSAState::Idle,
            action: "custom",
            to: FSAState::Processing,
        },
        Transition {
            from: FSAState::Idle,
            action: "email",
            to: FSAState::NetworkEgress,
        },
        Transition {
            from: FSAState::Idle,
            action: "file_write",
            to: FSAState::Writing,
        },
        Transition {
            from: FSAState::Reading,
            action: "file_read",
            to: FSAState::Reading,
        },
        Transition {
            from: FSAState::Reading,
            action: "db_query",
            to: FSAState::Reading,
        },
        Transition {
            from: FSAState::Reading,
            action: "custom",
            to: FSAState::Processing,
        },
        Transition {
            from: FSAState::Reading,
            action: "shell",
            to: FSAState::Processing,
        },
        Transition {
            from: FSAState::Reading,
            action: "file_write",
            to: FSAState::Writing,
        },
        Transition {
            from: FSAState::Processing,
            action: "file_read",
            to: FSAState::Reading,
        },
        Transition {
            from: FSAState::Processing,
            action: "file_write",
            to: FSAState::Writing,
        },
        Transition {
            from: FSAState::Processing,
            action: "custom",
            to: FSAState::Processing,
        },
        Transition {
            from: FSAState::Processing,
            action: "shell",
            to: FSAState::Processing,
        },
        Transition {
            from: FSAState::Processing,
            action: "db_query",
            to: FSAState::Reading,
        },
        Transition {
            from: FSAState::Processing,
            action: "http",
            to: FSAState::NetworkEgress,
        },
        Transition {
            from: FSAState::Writing,
            action: "file_read",
            to: FSAState::Reading,
        },
        Transition {
            from: FSAState::Writing,
            action: "custom",
            to: FSAState::Processing,
        },
        Transition {
            from: FSAState::Writing,
            action: "file_write",
            to: FSAState::Writing,
        },
        Transition {
            from: FSAState::NetworkEgress,
            action: "file_read",
            to: FSAState::Reading,
        },
        Transition {
            from: FSAState::NetworkEgress,
            action: "custom",
            to: FSAState::Processing,
        },
        Transition {
            from: FSAState::NetworkEgress,
            action: "http",
            to: FSAState::NetworkEgress,
        },
    ]
}

// ── Session Store ──

static SESSIONS: Lazy<Mutex<HashMap<String, SessionDAG>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

// Tunables below are read from the environment once, at first use (not
// hot-reloadable); the defaults are the pre-1.5.2 hardcoded values.
static MAX_SESSIONS: Lazy<usize> =
    Lazy::new(|| crate::config::env::env_parse("IAGA_SENTINEL_MAX_SESSIONS", 10_000usize));
static SESSION_TTL_MS: Lazy<u64> =
    Lazy::new(|| crate::config::env::env_parse("IAGA_SENTINEL_SESSION_TTL_MS", 30 * 60 * 1000u64));
/// How long a blocked session stays blocked before decaying to a
/// "cooldown" state where new requests are evaluated with elevated
/// scrutiny but not auto-rejected. 60 seconds by default.
static BLOCK_COOLDOWN_MS: Lazy<u64> =
    Lazy::new(|| crate::config::env::env_parse("IAGA_SENTINEL_BLOCK_COOLDOWN_MS", 60_000u64));
/// Maximum number of times a session can be blocked before it becomes
/// permanently blocked (no more cooldown recovery).
static MAX_BLOCK_COUNT: Lazy<u32> =
    Lazy::new(|| crate::config::env::env_parse("IAGA_SENTINEL_MAX_BLOCK_COUNT", 3u32));

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Retrieve a session DAG by ID from the in-memory store.
pub fn get_session(session_id: &str) -> Option<SessionDAG> {
    let store = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    store.get(session_id).cloned()
}

/// Hydrate a session into the in-memory store (used on startup to load from DB).
pub fn hydrate_session(session: SessionDAG) {
    let mut store = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    store.insert(session.session_id.clone(), session);
}

/// Clear the in-memory session store (process-global). Exposed so deterministic
/// tests can reset the shared `SESSIONS` map between runs; the durable session
/// store is unaffected.
pub fn reset_sessions() {
    let mut store = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    store.clear();
}

// ── Analysis Result ──

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionAnalysisResult {
    pub node_id: String,
    pub session_id: String,
    pub transition_allowed: bool,
    pub previous_state: String,
    pub new_state: String,
    pub attacks_detected: Vec<AttackMatch>,
    /// SIGNED structural anomaly score (tool diversity, taint accumulation,
    /// depth, multi-step arcs). Feeds `layer_risks.session_graph`.
    pub anomaly_score: u32,
    pub anomaly_reasons: Vec<String>,
    /// ADVISORY anomaly score (prior-block history + wall-clock burst).
    /// Surfaced for dashboards/alerts; NOT folded into the signed verdict.
    #[serde(default)]
    pub advisory_score: u32,
    #[serde(default)]
    pub advisory_reasons: Vec<String>,
    #[serde(skip_serializing)]
    pub session_call_count: u32,
    #[serde(skip_serializing)]
    pub recent_call_timestamps: Vec<u64>,
}

// ── Core Engine ──

/// Derive a stable, content-addressed node id (DET-SESSION-UUID-1). The session
/// id makes it unique across sessions; the position makes it unique within a
/// session even when the same tool is called twice; the call content ties the
/// id to what the node represents. Deterministic — no RNG.
fn derive_node_id(session_id: &str, index: usize, tool_name: &str, action_type: &str) -> String {
    let mut h = Sha256::new();
    h.update(session_id.as_bytes());
    h.update([0x1f]);
    h.update((index as u64).to_le_bytes());
    h.update([0x1f]);
    h.update(tool_name.as_bytes());
    h.update([0x1f]);
    h.update(action_type.as_bytes());
    hex::encode(h.finalize())
}

pub fn add_tool_call_to_session(
    session_id: &str,
    agent_id: &str,
    tool_name: &str,
    action_type: &str,
    taint_labels: HashSet<String>,
) -> SessionAnalysisResult {
    let mut store = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());

    // Evict stale sessions when at capacity before inserting a new entry.
    if !store.contains_key(session_id) && store.len() >= *MAX_SESSIONS {
        let now = now_ms();
        store.retain(|_, s| now - s.last_activity < *SESSION_TTL_MS);
    }

    let session = store
        .entry(session_id.to_string())
        .or_insert_with(|| SessionDAG {
            session_id: session_id.to_string(),
            agent_id: agent_id.to_string(),
            nodes: Vec::new(),
            edges: Vec::new(),
            created_at: now_ms(),
            last_activity: now_ms(),
            state: FSAState::Idle,
            blocked: false,
            block_reason: None,
            blocked_at: 0,
            block_count: 0,
        });
    session.last_activity = now_ms();

    // ── Cooldown/decay: blocked sessions can recover after BLOCK_COOLDOWN_MS ──
    if session.blocked {
        let now = now_ms();
        let elapsed = now.saturating_sub(session.blocked_at);

        // Permanently blocked after MAX_BLOCK_COUNT strikes
        if session.block_count >= *MAX_BLOCK_COUNT {
            return SessionAnalysisResult {
                node_id: String::new(),
                session_id: session_id.to_string(),
                transition_allowed: false,
                previous_state: session.state.to_string(),
                new_state: "blocked".to_string(),
                attacks_detected: Vec::new(),
                anomaly_score: 100,
                anomaly_reasons: vec![format!(
                    "session permanently blocked after {} strikes: {}",
                    session.block_count,
                    session.block_reason.as_deref().unwrap_or("unknown")
                )],
                advisory_score: 0,
                advisory_reasons: Vec::new(),
                session_call_count: session.nodes.len() as u32,
                recent_call_timestamps: collect_recent_timestamps(session, 16),
            };
        }

        // Still within cooldown window, remain blocked
        if elapsed < *BLOCK_COOLDOWN_MS {
            return SessionAnalysisResult {
                node_id: String::new(),
                session_id: session_id.to_string(),
                transition_allowed: false,
                previous_state: session.state.to_string(),
                new_state: "blocked".to_string(),
                attacks_detected: Vec::new(),
                anomaly_score: 80,
                anomaly_reasons: vec![format!(
                    "session in cooldown ({:.0}s remaining): {}",
                    (*BLOCK_COOLDOWN_MS - elapsed) as f64 / 1000.0,
                    session.block_reason.as_deref().unwrap_or("unknown")
                )],
                advisory_score: 0,
                advisory_reasons: Vec::new(),
                session_call_count: session.nodes.len() as u32,
                recent_call_timestamps: collect_recent_timestamps(session, 16),
            };
        }

        // Cooldown expired, transition to elevated-scrutiny state.
        // Reset blocked flag but keep elevated anomaly via block_count.
        session.blocked = false;
        session.block_reason = None;
        session.state = FSAState::Processing; // restart from Processing, not Idle
    }

    // Create node. DET-SESSION-UUID-1: derive a stable, content-addressed id
    // from the session + position + call content instead of a random UUID, so
    // the persisted/returned session graph is reproducible. (Node ids are not in
    // the signed receipt today; this closes the latent non-determinism before
    // any future capture extends to the session graph.)
    let mut node_taints = taint_labels;
    let node_id = derive_node_id(session_id, session.nodes.len(), tool_name, action_type);

    // Propagate taints from the previous node and record the sequence edge with
    // the real target id directly (no placeholder fix-up needed).
    if let Some(prev) = session.nodes.last() {
        let prev_id = prev.id.clone();
        let prev_taints = prev.taint_labels.clone();
        for t in &prev_taints {
            node_taints.insert(t.clone());
        }
        session.edges.push(DataFlowEdge {
            from: prev_id,
            to: node_id.clone(),
            data_keys: vec!["implicit_sequence".into()],
            taint_propagated: prev_taints,
        });
    }

    let node = ToolCallNode {
        id: node_id,
        tool_name: tool_name.to_string(),
        action_type: action_type.to_string(),
        timestamp: now_ms(),
        taint_labels: node_taints.clone(),
        risk_score: 0,
    };

    session.nodes.push(node.clone());

    // FSA transition
    let previous_state = session.state;
    let (allowed, next_state) = check_transition(session.state, action_type, &node_taints);

    let mut transition_allowed = true;
    let new_state;

    if !allowed {
        transition_allowed = false;
        new_state = FSAState::Blocked;
        session.blocked = true;
        session.blocked_at = now_ms();
        session.block_count += 1;
        session.block_reason = Some(format!(
            "unauthorized FSA transition: {} → {}",
            previous_state, action_type
        ));
    } else {
        new_state = next_state;
    }
    session.state = new_state;

    // Attack signature matching
    let attacks = match_attack_signatures(session);

    if attacks.iter().any(|a| a.severity == "critical") {
        if !session.blocked {
            session.block_count += 1;
        }
        session.blocked = true;
        session.blocked_at = now_ms();
        session.block_reason = Some(format!(
            "attack pattern: {}",
            attacks
                .iter()
                .map(|a| a.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
        session.state = FSAState::Blocked;
        transition_allowed = false;
    }

    // Anomaly detection: structural signals are signed; block-history + burst
    // are advisory (DET-SESSION-2).
    let (anomaly_score, anomaly_reasons, advisory_score, advisory_reasons) =
        detect_anomalies(session);

    SessionAnalysisResult {
        node_id: node.id,
        session_id: session_id.to_string(),
        transition_allowed,
        previous_state: previous_state.to_string(),
        new_state: session.state.to_string(),
        attacks_detected: attacks,
        anomaly_score,
        anomaly_reasons,
        advisory_score,
        advisory_reasons,
        session_call_count: session.nodes.len() as u32,
        recent_call_timestamps: collect_recent_timestamps(session, 16),
    }
}

fn check_transition(
    current: FSAState,
    action_type: &str,
    taints: &HashSet<String>,
) -> (bool, FSAState) {
    if current == FSAState::Blocked {
        return (false, FSAState::Blocked);
    }

    // Special: reading → network requires no sensitive taints
    let sensitive = ["local_fs", "secret", "internal_api"];
    if current == FSAState::Reading && (action_type == "http" || action_type == "email") {
        if taints.iter().any(|t| sensitive.contains(&t.as_str())) {
            return (false, FSAState::Blocked);
        }
        return (true, FSAState::NetworkEgress);
    }

    for t in default_transitions() {
        if t.from == current && t.action == action_type {
            return (true, t.to);
        }
    }

    (false, FSAState::Blocked)
}

fn match_attack_signatures(session: &SessionDAG) -> Vec<AttackMatch> {
    let mut matches = Vec::new();

    for sig in attack_signatures() {
        if session.nodes.len() < sig.pattern.len() {
            continue;
        }

        // Subsequence matching
        for start in 0..=session.nodes.len().saturating_sub(sig.pattern.len()) {
            let mut pat_idx = 0;
            let mut matched_nodes = Vec::new();
            let mut all_taints = HashSet::new();

            for i in start..session.nodes.len() {
                if pat_idx >= sig.pattern.len() {
                    break;
                }
                if session.nodes[i].action_type == sig.pattern[pat_idx] {
                    matched_nodes.push(session.nodes[i].id.clone());
                    for t in &session.nodes[i].taint_labels {
                        all_taints.insert(t.clone());
                    }
                    pat_idx += 1;
                }
            }

            if pat_idx != sig.pattern.len() {
                continue;
            }

            // Check required taints
            if let Some(ref req) = sig.required_taints {
                if !req.iter().any(|t| all_taints.contains(t)) {
                    continue;
                }
            }

            let confidence = 0.7 + if sig.severity == "critical" { 0.2 } else { 0.1 };
            matches.push(AttackMatch {
                name: sig.name.clone(),
                severity: sig.severity.clone(),
                confidence,
                matched_nodes,
            });
            break; // One match per signature
        }
    }

    matches
}

fn collect_recent_timestamps(session: &SessionDAG, limit: usize) -> Vec<u64> {
    let start = session.nodes.len().saturating_sub(limit);
    session.nodes[start..]
        .iter()
        .map(|node| node.timestamp)
        .collect()
}

fn is_read_action(action_type: &str) -> bool {
    matches!(action_type, "file_read" | "db_query")
}

fn is_egress_action(action_type: &str) -> bool {
    matches!(action_type, "http" | "email")
}

fn is_staging_action(action_type: &str) -> bool {
    matches!(action_type, "shell" | "custom" | "file_write")
}

/// Returns `(structural_score, structural_reasons, advisory_score, advisory_reasons)`.
///
/// **Structural** signals (tool diversity, taint accumulation, depth, multi-step
/// arcs) are a deterministic function of the session sequence and never read the
/// clock, so they stay in the SIGNED `anomaly_score` (DET-SESSION-2). The
/// **advisory** signals — prior-block history (process-global `block_count`) and
/// the wall-clock burst — are surfaced for dashboards/alerts but EXCLUDED from
/// the signed verdict, so the receipt stays reproducible from its recorded
/// inputs without capturing session state (capture is Enterprise, ADR 0010).
fn detect_anomalies(session: &SessionDAG) -> (u32, Vec<String>, u32, Vec<String>) {
    let mut score: u32 = 0;
    let mut reasons = Vec::new();
    let mut advisory_score: u32 = 0;
    let mut advisory_reasons: Vec<String> = Vec::new();
    let now = now_ms();

    // ADVISORY: prior-block history (process-global, not bound in the receipt).
    if session.block_count > 0 {
        let history_penalty = (session.block_count * 15).min(45);
        advisory_score += history_penalty;
        advisory_reasons.push(format!(
            "prior block history: {} strike(s) (+{})",
            session.block_count, history_penalty
        ));
    }

    // ADVISORY: burst (wall-clock vs session timestamps). DET-7: saturating_sub.
    let recent = session
        .nodes
        .iter()
        .filter(|n| now.saturating_sub(n.timestamp) < 10_000)
        .count();
    if recent > 15 {
        advisory_score += 30;
        advisory_reasons.push(format!("burst: {} calls in 10s", recent));
    } else if recent > 8 {
        advisory_score += 15;
        advisory_reasons.push(format!("elevated frequency: {} calls in 10s", recent));
    }

    // ── STRUCTURAL (signed): deterministic given the session sequence ──

    // Tool diversity
    let unique_tools: HashSet<_> = session.nodes.iter().map(|n| &n.tool_name).collect();
    if unique_tools.len() > 10 {
        score += 20;
        reasons.push(format!(
            "high tool diversity: {} distinct tools",
            unique_tools.len()
        ));
    }

    // Taint accumulation
    let mut all_taints = HashSet::new();
    for n in &session.nodes {
        for t in &n.taint_labels {
            all_taints.insert(t.clone());
        }
    }
    if all_taints.len() >= 4 {
        score += 25;
        // DET-SESSION-1: sort the HashSet labels before joining; this reason is
        // signed into the receipt, so its order must be reproducible.
        let mut labels: Vec<String> = all_taints.into_iter().collect();
        labels.sort();
        reasons.push(format!("high taint accumulation: {}", labels.join(", ")));
    }

    // Depth
    if session.nodes.len() > 50 {
        score += 30;
        reasons.push(format!(
            "extremely deep session: {} calls",
            session.nodes.len()
        ));
    } else if session.nodes.len() > 25 {
        score += 15;
        reasons.push(format!("deep session: {} calls", session.nodes.len()));
    }

    // Recent multi-step arcs: low-risk individual calls can still form a dangerous chain.
    if let Some(last_node) = session.nodes.last() {
        let recent_window: Vec<&ToolCallNode> = session.nodes.iter().rev().take(5).collect();
        let prior_nodes = recent_window.iter().skip(1).copied().collect::<Vec<_>>();

        if is_egress_action(&last_node.action_type) {
            let read_steps = prior_nodes
                .iter()
                .filter(|node| is_read_action(&node.action_type))
                .count();
            let distinct_read_tools: HashSet<&str> = prior_nodes
                .iter()
                .filter(|node| is_read_action(&node.action_type))
                .map(|node| node.tool_name.as_str())
                .collect();
            let staged_processing = prior_nodes
                .iter()
                .any(|node| is_staging_action(&node.action_type));

            if read_steps >= 2 {
                score += 35;
                reasons.push(format!(
                    "multi-step collection → egress arc: {} read steps before {}",
                    read_steps, last_node.action_type
                ));
            }

            if distinct_read_tools.len() >= 2 {
                score += 15;
                reasons.push(format!(
                    "fan-in before egress: {} distinct read tools",
                    distinct_read_tools.len()
                ));
            }

            if read_steps >= 1 && staged_processing {
                score += 20;
                reasons.push(format!(
                    "staged processing before egress: read/transform/{} chain",
                    last_node.action_type
                ));
            }
        }

        if last_node.action_type == "shell"
            && prior_nodes.iter().any(|node| node.action_type == "http")
        {
            score += 25;
            reasons.push("network-delivered execution arc: recent http followed by shell".into());
        }
    }

    (
        score.min(100),
        reasons,
        advisory_score.min(100),
        advisory_reasons,
    )
}

// ── Public Queries ──

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInfo {
    pub session_id: String,
    pub agent_id: String,
    pub node_count: usize,
    pub state: FSAState,
}

pub fn list_active_sessions() -> Vec<SessionInfo> {
    let store = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    store
        .values()
        .map(|s| SessionInfo {
            session_id: s.session_id.clone(),
            agent_id: s.agent_id.clone(),
            node_count: s.nodes.len(),
            state: s.state,
        })
        .collect()
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionMetrics {
    pub node_count: usize,
    pub edge_count: usize,
    pub state: FSAState,
    pub taint_labels: Vec<String>,
    pub duration_ms: u64,
}

pub fn get_session_metrics(session_id: &str) -> Option<SessionMetrics> {
    let store = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    let s = store.get(session_id)?;
    let mut taints = HashSet::new();
    for n in &s.nodes {
        for t in &n.taint_labels {
            taints.insert(t.clone());
        }
    }
    Some(SessionMetrics {
        node_count: s.nodes.len(),
        edge_count: s.edges.len(),
        state: s.state,
        taint_labels: taints.into_iter().collect(),
        duration_ms: s.last_activity - s.created_at,
    })
}

/// Prune sessions inactive for longer than `ttl_ms` milliseconds.
/// Returns the number of sessions pruned.
pub fn prune_stale_sessions(ttl_ms: u64) -> usize {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let mut store = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    let before = store.len();
    store.retain(|_, s| now.saturating_sub(s.last_activity) < ttl_ms);
    before - store.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ponytail: each test uses a unique session_id, so it starts from a clean
    // DAG without touching shared state. The old `clear_sessions()` helper wiped
    // the WHOLE global SESSIONS map, which raced parallel sibling tests (one
    // test's clear nuked another's in-flight nodes) — removed.

    #[test]
    fn detects_multi_step_collection_to_egress_arc() {
        let session_id = "session-arc-egress";

        let _ = add_tool_call_to_session(
            session_id,
            "agent-seq",
            "fs.readme",
            "file_read",
            HashSet::new(),
        );
        let _ = add_tool_call_to_session(
            session_id,
            "agent-seq",
            "db.lookup",
            "db_query",
            HashSet::from(["local_fs".to_string()]),
        );
        let result = add_tool_call_to_session(
            session_id,
            "agent-seq",
            "http.fetch",
            "http",
            HashSet::from(["local_fs".to_string(), "db_result".to_string()]),
        );

        assert!(
            result
                .anomaly_reasons
                .iter()
                .any(|reason| reason.contains("multi-step collection")),
            "expected sequence anomaly, got {:?}",
            result.anomaly_reasons
        );
        assert!(result.anomaly_score >= 35);
    }

    #[test]
    fn returns_real_session_context_for_pipeline() {
        let session_id = "session-context";

        let _ = add_tool_call_to_session(
            session_id,
            "agent-seq",
            "fs.config",
            "file_read",
            HashSet::new(),
        );
        let result = add_tool_call_to_session(
            session_id,
            "agent-seq",
            "shell.grep",
            "shell",
            HashSet::from(["local_fs".to_string()]),
        );

        assert_eq!(result.session_call_count, 2);
        assert_eq!(result.recent_call_timestamps.len(), 2);
        assert!(result.recent_call_timestamps[0] <= result.recent_call_timestamps[1]);
    }
}
