use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use once_cell::sync::Lazy;
use regex::Regex;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::core::errors::SentinelError;
use crate::core::types::*;
use crate::modules::injection_firewall::prompt_firewall;
use crate::modules::nhi::crypto_identity;
use crate::modules::policy::evaluate_policy::evaluate_policy;
use crate::modules::policy::formal_verify;
use crate::modules::policy::rules_engine::evaluate_rules;
use crate::modules::policy::tool_risk::{score_tool_risk_with_thresholds, LayerRiskContributions};
use crate::modules::protocol::detect_protocol::detect_protocol;
use crate::modules::protocol::protocol_envelope::{
    normalize_protocol_payload, validate_protocol_payload,
};
use crate::modules::risk::adaptive_scorer::{self, AdaptiveScoreInput};
use crate::modules::sandbox::sandbox_executor;
use crate::modules::secrets::secret_references::plan_secret_injection;
use crate::modules::session_graph::session_dag;
use crate::modules::taint::taint_tracker;
use crate::modules::telemetry::otel_emitter;
use crate::plugins::PluginInspectRequest;
use crate::server::app_state::AppState;

fn action_type_str(at: ActionType) -> &'static str {
    match at {
        ActionType::Shell => "shell",
        ActionType::FileRead => "file_read",
        ActionType::FileWrite => "file_write",
        ActionType::Http => "http",
        ActionType::DbQuery => "db_query",
        ActionType::Email => "email",
        ActionType::Custom => "custom",
    }
}

fn protocol_name(protocol: ProtocolKind) -> &'static str {
    match protocol {
        ProtocolKind::Mcp => "mcp",
        ProtocolKind::Acp => "acp",
        ProtocolKind::A2a => "a2a",
        ProtocolKind::HttpFunction => "http-function",
        ProtocolKind::Unknown => "unknown",
    }
}

pub async fn execute_pipeline(
    input: &InspectRequest,
    state: &Arc<AppState>,
) -> Result<GovernanceResult, SentinelError> {
    execute_pipeline_at(input, state, Utc::now()).await
}

/// Pipeline core with an injectable decision time. `decision_time` is the
/// single wall-clock reading for the whole evaluation: it stamps the receipt
/// and feeds every time-based *signed* signal (off-hours), so the signed
/// verdict is a pure function of (request + resolved policy + decision_time +
/// ML digest) and is reproducible on replay (DET-CLOCK-1 / DET-SESSION-2 /
/// DET-BEHAVIORAL-2). Tests pin it to assert bit-exact replay; the public
/// `execute_pipeline` wrapper passes `Utc::now()`.
pub async fn execute_pipeline_at(
    input: &InspectRequest,
    state: &Arc<AppState>,
    decision_time: chrono::DateTime<Utc>,
) -> Result<GovernanceResult, SentinelError> {
    let pipeline_start = std::time::Instant::now();
    let trace_id = Uuid::new_v4().to_string();
    // The one timestamp for this evaluation: receipt + every signed time
    // signal read from it, never from a fresh `Utc::now()`.
    let decision_ts = decision_time.to_rfc3339();

    tracing::debug!(
        trace_id = %trace_id,
        agent_id = %input.agent_id,
        tool_name = %input.action.tool_name,
        "governance pipeline started"
    );

    let profile = state
        .policy_store
        .get_agent_profile(&input.agent_id)
        .await?;
    // SCOPE-DERIVE-1: the governance scope is derived from the agent profile,
    // never from the request body. Until 1.9 a client-supplied `workspaceId`
    // took precedence over the profile, so an authenticated caller could have
    // its action evaluated against another workspace's thresholds, egress
    // allowlist and tool policy — and get a receipt signed with that
    // workspace's `policy_hash`. The field is still accepted, but only as an
    // assertion that must agree with the server's view.
    //
    // Empty string is treated as absent: the Python SDK serializes "no opinion"
    // that way (sdks/python/iaga_sentinel/types.py).
    if let Some(claimed) = input.workspace_id.as_deref().filter(|s| !s.is_empty()) {
        if claimed != profile.workspace_id {
            return Err(SentinelError::WorkspaceScopeMismatch {
                agent_id: input.agent_id.clone(),
                expected: profile.workspace_id.clone(),
                claimed: claimed.to_string(),
            });
        }
    }
    let workspace_id = profile.workspace_id.as_str();
    let workspace_policy = state
        .policy_store
        .get_workspace_policy(workspace_id)
        .await?;
    // `tenantId` from the request is ignored, not rejected: it feeds the audit
    // event, so honouring a client value would let a caller mislabel its own
    // evidence, but the field was documented as a request-level input and a
    // hard 403 would break callers with no deprecation window. Ignoring closes
    // the hole just as completely — an ignored value never reaches the row.
    let tenant_id = profile
        .tenant_id
        .clone()
        .or_else(|| workspace_policy.tenant_id.clone());

    // CRYPTO-POLICYHASH-7a: digest the real resolved workspace policy so every
    // receipt binds the YAML that decided the verdict (was a constant
    // placeholder). Computed once, before `workspace_policy` is moved into the
    // result; the receipt logger uses it unless a Dictum overlay is loaded.
    let workspace_policy_hash =
        crate::pipeline::policy_hash::workspace_policy_hash(&workspace_policy);
    // DET-THREAT-1: digest of the active threat-intel feed that contributes to
    // the signed score, so the verdict is reproducible against the exact feed.
    let threat_feed_hash = state.threat_feed.feed_hash();

    // Serialize the action payload ONCE (PERF-PAYLOAD-3X-1) and bind its
    // digest into the receipt (PROOF-INPUTHASH-BIND-3). `payload_str` is
    // reused by the firewall, threat-intel, reasoning and tool-risk layers;
    // `input_sha256` is hashed over the canonical (serde_json sorts object
    // keys with preserve_order off) form, so it is stable regardless of the
    // request's key order. Hoisted above the rate-limit gate so the fast-path
    // receipt binds the payload too.
    let payload_json = serde_json::Value::Object(
        input
            .action
            .payload
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    );
    let payload_str = serde_json::to_string(&payload_json).unwrap_or_default();
    let input_sha256 = hex::encode(Sha256::digest(payload_str.as_bytes()));

    // ═══════════════════════════════════════════════════════════════
    // RATE LIMIT CHECK, runs before all security layers
    // ═══════════════════════════════════════════════════════════════
    let rate_result = state
        .rate_limiter
        .check_rate(&input.agent_id, Some(&input.action.tool_name))
        .await;

    if !rate_result.allowed {
        let now = decision_ts.clone();
        let event_id = Uuid::new_v4().to_string();
        let finding = format!(
            "Rate limit exceeded (remaining={}, retry_after={}s)",
            rate_result.remaining,
            rate_result.retry_after_secs.unwrap_or(0)
        );
        // DET-RATELIMIT-1: this verdict depends on `Instant::now()` and an
        // in-memory sliding window, so its receipt cannot be reproduced by
        // replay. Mark it so the signed receipt honestly declares its own
        // non-replayability instead of looking like a deterministic verdict.
        let reasons = vec![finding.clone(), "non-replayable:rate-limit".to_string()];

        let risk = RiskScore {
            score: 0,
            decision: GovernanceDecision::Block,
            reasons: reasons.clone(),
        };

        let audit_event = AuditEvent {
            event_id: event_id.clone(),
            agent_id: input.agent_id.clone(),
            framework: input.framework.clone(),
            action_type: input.action.action_type,
            tool_name: input.action.tool_name.clone(),
            decision: GovernanceDecision::Block,
            timestamp: now.clone(),
            reasons: reasons.clone(),
        };

        let stored = StoredAuditEvent {
            event_id: audit_event.event_id.clone(),
            agent_id: audit_event.agent_id.clone(),
            tenant_id: tenant_id.clone(),
            framework: audit_event.framework.clone(),
            action_type: audit_event.action_type,
            tool_name: audit_event.tool_name.clone(),
            input_sha256: input_sha256.clone(),
            decision: GovernanceDecision::Block,
            timestamp: audit_event.timestamp.clone(),
            reasons: audit_event.reasons.clone(),
            review_status: ReviewStatus::NotRequired,
            risk_score: 0,
            usage: None,
            session_id: input
                .metadata
                .as_ref()
                .and_then(|m| m.get("sessionId"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string()),
        };
        if let Err(e) = state.audit_store.append(&stored).await {
            tracing::error!(event_id = %stored.event_id, error = %e, "Failed to persist audit event");
        }
        if let Some(rl) = state.receipts.as_ref() {
            // Fast-path block: no ML evidence or usage at this stage. The rate
            // limiter short-circuits before the Dictum overlay, so bind the
            // resolved workspace policy + threat-feed hashes and no Dictum trace.
            rl.record(
                &stored,
                None,
                None,
                crate::pipeline::receipts::ReceiptContext {
                    policy_hash: Some(&workspace_policy_hash),
                    threat_feed_hash: Some(&threat_feed_hash),
                    dictum_trace: None,
                },
            )
            .await?;
        }

        return Ok(GovernanceResult {
            trace_id,
            protocol: detect_protocol(input),
            normalized_payload: input.action.payload.clone(),
            decision: GovernanceDecision::Block,
            review_status: ReviewStatus::NotRequired,
            risk,
            secret_plan: SecretInjectionPlan {
                approved: vec![],
                denied: vec![],
            },
            audit_event,
            profile,
            workspace_policy,
            policy_findings: vec![finding],
            schema_validation: SchemaValidation {
                tool_name: input.action.tool_name.clone(),
                valid: true,
                findings: vec![],
            },
            review_request_id: None,
            session_graph: None,
            // No `correlationScope` here, deliberately. This return fires before
            // any layer runs, so no multi-step correlation was performed — and
            // the verdict is Block, which nobody can over-read as evidence that
            // a chain was examined and found clean. The disclosure exists for
            // the `allow` path, where the absence of a finding looks like a
            // finding of absence. Attaching a scope to a null taint block would
            // report a correlation basis for an analysis that never happened.
            taint_analysis: None,
            adaptive_risk: None,
            sandbox_result: None,
            injection_firewall: None,
            policy_verification: None,
            telemetry_span: None,
            behavioral_fingerprint: None,
            threat_intel: None,
            plugin_results: None,
            advisory: None,
            layer_roles: crate::core::types::layer_roles(),
        });
    }

    let protocol = detect_protocol(input);

    let normalized_payload = normalize_protocol_payload(input, protocol);

    let schema_validation = validate_protocol_payload(input, protocol);

    let action_type_s = action_type_str(input.action.action_type);
    // `payload_json` / `payload_str` / `input_sha256` were computed once above
    // the rate-limit gate (PERF-PAYLOAD-3X-1).

    // ═══════════════════════════════════════════════════════════════
    // LAYER 7, Prompt Injection Firewall (runs FIRST, fastest gate)
    // ═══════════════════════════════════════════════════════════════
    let firewall_result = prompt_firewall::scan_prompt(&payload_str);
    let firewall_json = serde_json::to_value(&firewall_result).ok();

    // ═══════════════════════════════════════════════════════════════
    // THREAT INTELLIGENCE, check payload against known IOCs
    // ═══════════════════════════════════════════════════════════════
    let threat_matches = state.threat_feed.check_threats(&payload_str);
    let threat_intel_json = if threat_matches.is_empty() {
        None
    } else {
        serde_json::to_value(serde_json::json!({
            "matches": threat_matches,
            "count": threat_matches.len(),
        }))
        .ok()
    };

    // ═══════════════════════════════════════════════════════════════
    // LAYER 1, Session Graph Analysis
    // ═══════════════════════════════════════════════════════════════
    // Session key: prefer an explicit `sessionId` from metadata. When the caller
    // omits it we fall back to `agent_id`, which groups every session-less call
    // from the same agent into ONE long-lived DAG (session_dag::SESSIONS, 30-min
    // TTL refreshed per call). Attack-signature matching is a subsequence scan
    // over the whole uncapped node history, so a busy agent that never sets a
    // sessionId can eventually match multi-step signatures across unrelated
    // operations (false positives; fail-safe toward Review/Block, not a bypass).
    // For precise per-task correlation, pass a stable `metadata.sessionId` per
    // logical session (all SDK adapters expose it).
    let declared_session_id = input
        .metadata
        .as_ref()
        .and_then(|m| m.get("sessionId"))
        .and_then(|v| v.as_str());
    let session_id = declared_session_id.unwrap_or(&input.agent_id);

    // We need inherited taints for session graph too, so get them first.
    //
    // The session key above is whatever the CLIENT said it was, so rotating it
    // between two beats erases the link between them. When the operator has set
    // a window, labels this AGENT accumulated in its other sessions are folded
    // in as well. Off by default: see `taint_tracker::agent_taint_window` for
    // why the cost of having it on is a certainty rather than a risk.
    let agent_window = taint_tracker::agent_taint_window();
    let correlation_scope =
        taint_tracker::TaintCorrelationScope::describe(declared_session_id.is_some(), agent_window);
    let mut inherited_taints = taint_tracker::get_session_taint(session_id);
    if let Some(window) = agent_window {
        // Not the agent's whole label set: `cross_session_inheritable` keeps
        // only `secret`, and only when this request actually carries a body.
        // Folding everything in blocked a non-secret read followed by an
        // allowlisted GET — measured, 2 false positives in 43 benign controls.
        let agent_labels = taint_tracker::get_agent_taint(&input.agent_id, window);
        inherited_taints.extend(taint_tracker::cross_session_inheritable(
            &agent_labels,
            &input.action.payload,
        ));
    }

    let session_result = session_dag::add_tool_call_to_session(
        session_id,
        &input.agent_id,
        &input.action.tool_name,
        action_type_s,
        inherited_taints.clone(),
    );
    let session_json = serde_json::to_value(&session_result).ok();

    // v0.4.0, persist session graph to durable storage (write-behind)
    if let Some(session) = session_dag::get_session(session_id) {
        let session_store = state.session_store.clone();
        let session_owned = session;
        tokio::spawn(async move {
            if let Err(e) = session_store.store_session(&session_owned).await {
                tracing::warn!(error = %e, "failed to persist session graph");
            }
        });
    }

    // ═══════════════════════════════════════════════════════════════
    // LAYER 2, Taint Tracking
    // ═══════════════════════════════════════════════════════════════
    let taint_result = taint_tracker::analyze_taint(
        action_type_s,
        &input.action.tool_name,
        &payload_str,
        &inherited_taints,
    );
    taint_tracker::update_session_taint(session_id, &taint_result.accumulated_labels);
    // Recorded unconditionally, so enabling the window later does not begin from
    // an empty store and report a misleadingly quiet first window.
    taint_tracker::update_agent_taint(&input.agent_id, &taint_result.accumulated_labels);
    let taint_json = serde_json::to_value(&taint_result).ok().map(|mut v| {
        // Attach the correlation basis to the taint block itself: the reader who
        // is judging a multi-step verdict is looking here, not at a sibling key.
        if let (Some(obj), Ok(scope)) =
            (v.as_object_mut(), serde_json::to_value(&correlation_scope))
        {
            obj.insert("correlationScope".to_string(), scope);
        }
        v
    });

    // v0.4.0, persist taint labels to durable storage (write-behind)
    {
        let taint_store = state.taint_store.clone();
        let sid = session_id.to_string();
        let labels = taint_result.accumulated_labels.clone();
        tokio::spawn(async move {
            if let Err(e) = taint_store.update_session_taint(&sid, &labels).await {
                tracing::warn!(error = %e, "failed to persist taint labels");
            }
        });
    }

    // ═══════════════════════════════════════════════════════════════
    // LAYER 3, Crypto NHI (ensure agent identity exists)
    // ═══════════════════════════════════════════════════════════════
    if crypto_identity::get_identity(&input.agent_id).is_none() {
        let identity = crypto_identity::register_identity(
            &input.agent_id,
            Some(workspace_id),
            profile.approved_tools.clone(),
        );
        // v0.4.0, persist new NHI identity to durable storage
        let secret_hex = crypto_identity::get_secret_key_hex(&input.agent_id).unwrap_or_default();
        let nhi_store = state.nhi_store.clone();
        let identity_owned = identity;
        tokio::spawn(async move {
            if let Err(e) = nhi_store.store_identity(&identity_owned, &secret_hex).await {
                tracing::warn!(error = %e, "failed to persist NHI identity");
            }
        });
    }
    let agent_trust = crypto_identity::get_agent_trust(&input.agent_id);

    // ═══════════════════════════════════════════════════════════════
    // LAYER 4, Adaptive Risk Scoring (5-signal ensemble)
    // ═══════════════════════════════════════════════════════════════
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let session_call_count = session_result.session_call_count.max(1);
    let call_timestamps = if session_result.recent_call_timestamps.is_empty() {
        vec![now_ms]
    } else {
        session_result.recent_call_timestamps.clone()
    };

    let adaptive_input = AdaptiveScoreInput {
        agent_id: &input.agent_id,
        action_type: action_type_s,
        tool_name: &input.action.tool_name,
        payload_str: &payload_str,
        taint_result: Some(&taint_result),
        session_call_count,
        call_timestamps: &call_timestamps,
        agent_trust,
        tool_trust: profile.tool_trust,
    };
    let adaptive_result = adaptive_scorer::calculate_adaptive_risk(&adaptive_input, decision_time);
    let adaptive_json = serde_json::to_value(&adaptive_result).ok();

    // Update baseline for future behavioral analysis
    adaptive_scorer::update_baseline(
        &input.agent_id,
        &input.action.tool_name,
        action_type_s,
        session_call_count,
    );

    // ═══════════════════════════════════════════════════════════════
    // Behavioral Fingerprinting, record action & detect anomalies
    // ═══════════════════════════════════════════════════════════════
    state.behavioral_engine.record_action(
        &input.agent_id,
        &input.action.tool_name,
        action_type_s,
        adaptive_result.total_score as f64,
    );
    let fingerprint_anomalies = state.behavioral_engine.detect_anomalies(
        &input.agent_id,
        &input.action.tool_name,
        adaptive_result.total_score as f64,
    );

    // v0.4.0, persist behavioral fingerprint to durable storage (write-behind)
    if let Some(fp) = state.behavioral_engine.get_fingerprint(&input.agent_id) {
        let fp_store = state.fingerprint_store.clone();
        tokio::spawn(async move {
            if let Err(e) = fp_store.upsert_fingerprint(&fp).await {
                tracing::warn!(error = %e, "failed to persist behavioral fingerprint");
            }
        });
    }

    // LAYER 5, Sandbox Execution, used to sit here. It now runs after the
    // composite score exists — see "LAYER 5, deferred" below for why.

    // ═══════════════════════════════════════════════════════════════
    // LAYER 6, Formal Policy Verification
    // ═══════════════════════════════════════════════════════════════
    let verification = formal_verify::verify_policy(&workspace_policy);
    let verification_json = serde_json::to_value(&verification).ok();

    let plugin_evaluation = state.plugin_registry.evaluate(&PluginInspectRequest {
        agent_id: input.agent_id.clone(),
        tool_name: input.action.tool_name.clone(),
        action_type: action_type_s.to_string(),
        framework: input.framework.clone(),
        // ponytail: last use of payload_json, move it in instead of cloning the
        // whole payload Value a second time (the build above is the only clone).
        payload: payload_json,
        risk_score: adaptive_result.total_score,
    });

    // ═══════════════════════════════════════════════════════════════
    // Original policy evaluation + risk scoring
    // ═══════════════════════════════════════════════════════════════
    let policy_eval = evaluate_policy(input, &profile, &workspace_policy, protocol);
    let workspace_rules = state
        .policy_store
        .list_workspace_rules(workspace_id)
        .await?;
    let matched_workspace_rule = evaluate_rules(
        &workspace_rules,
        input,
        profile.role,
        Some(adaptive_result.total_score),
        decision_time,
    );
    let secret_plan = plan_secret_injection(input, &profile);
    let secret_denied = !secret_plan.denied.is_empty();

    let mut policy_findings = policy_eval.findings;

    if let Some(rule_match) = &matched_workspace_rule {
        policy_findings.push(format!(
            "policy rule [{}]: {}",
            rule_match.rule_name, rule_match.reason
        ));
    }

    if secret_denied {
        policy_findings
            .push("one or more requested secrets were denied by vault policy".to_string());
    }
    if !schema_validation.valid {
        policy_findings.push(format!(
            "{} protocol schema validation failed",
            protocol_name(protocol)
        ));
    }
    for error in &plugin_evaluation.errors {
        policy_findings.push(format!("plugin runtime: {}", error));
    }

    // ═══════════════════════════════════════════════════════════════
    // Integrate 8-layer signals into decision + layer risk scores
    // ═══════════════════════════════════════════════════════════════
    let mut minimum_decision = policy_eval.minimum_decision;

    if let Some(rule_match) = &matched_workspace_rule {
        match rule_match.decision {
            GovernanceDecision::Block => minimum_decision = GovernanceDecision::Block,
            GovernanceDecision::Review => {
                if minimum_decision != GovernanceDecision::Block {
                    minimum_decision = GovernanceDecision::Review;
                }
            }
            GovernanceDecision::Allow => {
                if minimum_decision == GovernanceDecision::Review {
                    minimum_decision = GovernanceDecision::Allow;
                }
            }
        }
    }

    let mut layer_risks = LayerRiskContributions {
        firewall: firewall_result.risk_score,
        ..Default::default()
    };

    // ── Firewall ──
    if firewall_result.blocked {
        minimum_decision = GovernanceDecision::Block;
        policy_findings.push(format!("injection firewall: {}", firewall_result.summary));
    }

    // ── Threat Intelligence ──
    if !threat_matches.is_empty() {
        for tm in &threat_matches {
            policy_findings.push(format!(
                "threat intel [{}]: {} (severity={})",
                tm.indicator_type, tm.description, tm.severity
            ));
        }
        let has_critical = threat_matches.iter().any(|m| m.severity == "critical");
        let has_high = threat_matches.iter().any(|m| m.severity == "high");
        layer_risks.threat_intel = if has_critical {
            95
        } else if has_high {
            75
        } else {
            50
        };
        if has_critical {
            minimum_decision = GovernanceDecision::Block;
        } else if has_high && minimum_decision != GovernanceDecision::Block {
            minimum_decision = GovernanceDecision::Review;
        }
    }

    // ── Taint ──
    if taint_result.exfiltration_detected {
        layer_risks.taint = 100;
    } else if taint_result.blocked {
        layer_risks.taint = 90;
    } else if !taint_result.violations.is_empty() {
        layer_risks.taint = 60 + (taint_result.violations.len() as u32 * 10).min(30);
    }
    if taint_result.blocked {
        minimum_decision = GovernanceDecision::Block;
        policy_findings.push(format!("taint tracking: {}", taint_result.summary));
    }

    // ── Plugins ──
    if !plugin_evaluation.outputs.is_empty() {
        layer_risks.plugins = plugin_evaluation
            .outputs
            .iter()
            .map(|output| output.result.risk_score)
            .max()
            .unwrap_or(0);

        for output in &plugin_evaluation.outputs {
            for finding in &output.result.findings {
                policy_findings.push(format!("plugin [{}]: {}", output.plugin_name, finding));
            }

            if let Some(hint) = output.result.decision_hint.as_deref() {
                match hint.to_ascii_lowercase().as_str() {
                    "block" => {
                        minimum_decision = GovernanceDecision::Block;
                        policy_findings.push(format!(
                            "plugin [{}]: decision hint -> block",
                            output.plugin_name
                        ));
                    }
                    "review" | "human_review" => {
                        if minimum_decision != GovernanceDecision::Block {
                            minimum_decision = GovernanceDecision::Review;
                        }
                        policy_findings.push(format!(
                            "plugin [{}]: decision hint -> review",
                            output.plugin_name
                        ));
                    }
                    _ => {}
                }
            }
        }

        if layer_risks.plugins >= workspace_policy.threshold_block {
            minimum_decision = GovernanceDecision::Block;
            policy_findings.push(format!(
                "plugin risk: score={} → block",
                layer_risks.plugins
            ));
        } else if layer_risks.plugins >= workspace_policy.threshold_review
            && minimum_decision != GovernanceDecision::Block
        {
            minimum_decision = GovernanceDecision::Review;
            policy_findings.push(format!(
                "plugin risk: score={} → review",
                layer_risks.plugins
            ));
        }
    } else if !plugin_evaluation.errors.is_empty() && minimum_decision != GovernanceDecision::Block
    {
        minimum_decision = GovernanceDecision::Review;
    }

    // ── Session Graph ──
    layer_risks.session_graph = session_result.anomaly_score;
    if !session_result.attacks_detected.is_empty() || session_result.anomaly_score >= 50 {
        if minimum_decision != GovernanceDecision::Block {
            minimum_decision = GovernanceDecision::Review;
        }
        for attack in &session_result.attacks_detected {
            policy_findings.push(format!("session graph attack: {}", attack.name));
        }
        for reason in &session_result.anomaly_reasons {
            policy_findings.push(format!("session graph: {}", reason));
        }
    }
    if !session_result.transition_allowed {
        minimum_decision = GovernanceDecision::Block;
        layer_risks.session_graph = layer_risks.session_graph.max(90);
        policy_findings.push("session graph: state transition blocked".into());
    }

    // ── Adaptive Risk ──
    layer_risks.adaptive = adaptive_result.total_score;
    if adaptive_result.decision == "block" {
        minimum_decision = GovernanceDecision::Block;
        policy_findings.push(format!(
            "adaptive risk: score={} → block",
            adaptive_result.total_score
        ));
    } else if adaptive_result.decision == "human_review"
        && minimum_decision != GovernanceDecision::Block
    {
        minimum_decision = GovernanceDecision::Review;
        policy_findings.push(format!(
            "adaptive risk: score={} → review",
            adaptive_result.total_score
        ));
    }

    // ── Behavioral Fingerprint (ADVISORY) ──
    // DET-BEHAVIORAL-2: the fingerprint anomalies are derived from process-global
    // accumulated state that the receipt does not capture, so they no longer feed
    // `layer_risks.behavioral` nor escalate `minimum_decision`. They are surfaced
    // in `GovernanceResult.advisory` (and the behavioralFingerprint JSON) for
    // dashboards/alerts instead. `layer_risks.behavioral` stays 0.

    // ── Policy ──
    // Score based on how many policy violations were found
    let policy_violation_count = policy_findings
        .iter()
        .filter(|f| {
            f.contains("not approved")
                || f.contains("outside baseline")
                || f.contains("requires human review")
                || f.contains("action type")
        })
        .count();
    if policy_violation_count > 0 {
        layer_risks.policy = (30 + policy_violation_count as u32 * 20).min(100);
    }

    // ── Secrets ──
    if secret_denied {
        layer_risks.secrets = 90;
        minimum_decision = GovernanceDecision::Block;
        policy_findings.push("unauthorized secret access denied by vault policy".into());
    }
    if !schema_validation.valid && minimum_decision != GovernanceDecision::Block {
        minimum_decision = GovernanceDecision::Block;
        policy_findings.push(if schema_validation.findings.is_empty() {
            "schema validation failed".to_string()
        } else {
            format!(
                "schema validation failed: {}",
                schema_validation.findings.join("; ")
            )
        });
    }

    // 1.0 M3.5: optional probabilistic reasoning. Produces evidence
    // consumed by the receipt logger; never fails the pipeline.
    let ml_outcome = match state.reasoning.as_ref() {
        Some(eng) => Some(
            eng.evaluate_json(
                &input.agent_id,
                &input.action.tool_name,
                action_type_str(input.action.action_type),
                &payload_str,
            )
            .await,
        ),
        None => None,
    };

    let risk = score_tool_risk_with_thresholds(
        input,
        minimum_decision,
        &policy_findings,
        &layer_risks,
        &payload_str,
        workspace_policy.threshold_block,
        workspace_policy.threshold_review,
    );

    // ═══════════════════════════════════════════════════════════════
    // LAYER 5, deferred: Sandbox Execution (dry-run for high-risk)
    // ═══════════════════════════════════════════════════════════════
    //
    // This ran before the composite score existed and was therefore fed
    // `adaptive_result.total_score`, while its thresholds (40 / 50 / 65) are on
    // the composite's scale — the same scale as `threshold_review` 35 and
    // `threshold_block` 70. The two scales do not overlap where it matters:
    // measured across 42 actions the adaptive score spans 9..40 (mean 23.6)
    // while the composite spans 2..84, so NOTHING reached any of the three
    // thresholds and the layer produced a result 0 times out of 42 — including
    // `curl | sh`, which scores 84 and blocks while charging adaptive 30. A
    // containment layer that reports itself present and never runs is worse
    // than one that is absent.
    //
    // Nothing between the old position and this one reads `sandbox_json`, and
    // the layer is advisory — `sandbox_result` is not part of the signed
    // receipt and feeds no term of the composite (tool_risk.rs weights adaptive,
    // firewall, policy/behavioral, taint/threat-intel, secrets, plugins,
    // pattern, session graph — there is no sandbox term). So this changes which
    // actions carry a `sandboxResult` in the API response, and changes no
    // verdict, score, reason or signed byte.
    // ponytail: `payload_json` was moved into the plugin request above, back
    // when this layer ran before it. Rather than downgrade that move to a clone
    // on EVERY request, rebuild the value from `payload_str` — the string it was
    // serialized from — inside the branch that actually sandboxes. The common
    // path pays nothing; the rare one pays a single parse. `sandbox_execute`
    // only does `.get("command")`-style lookups, so key order does not matter.
    let sandbox_json = if sandbox_executor::should_sandbox(action_type_s, risk.score) {
        let payload = serde_json::from_str::<serde_json::Value>(&payload_str)
            .unwrap_or(serde_json::Value::Null);
        let sb = sandbox_executor::sandbox_execute(
            &input.action.tool_name,
            action_type_s,
            &payload,
            risk.score,
        );
        serde_json::to_value(&sb).ok()
    } else {
        None
    };

    // Build audit event
    let mut reasons = risk.reasons.clone();
    reasons.push(format!("agent-role:{:?}", profile.role).to_lowercase());

    // Causes that arrive AFTER the risk score is settled: a Dictum policy
    // firing, and the cost-control budget refusing. Pushed whenever they fire,
    // not only when they move the verdict — an `allow` policy that fires is
    // still why this action was judged the way it was, and the audit event has
    // always recorded it that way.
    //
    // They used to be pushed onto `reasons` only — the audit clone — so an
    // action refused by nothing else came back to the caller as
    // `"reasons": ["no high-risk rule matched"]` next to `"decision": "block"`,
    // and the SDKs' `PermissionError`, `demo_run`'s "Why:" and the review queue
    // all repeated that. Collected here and given to BOTH the audit event and
    // the caller's `risk.reasons`; the clone above already happened, so neither
    // gets them twice.
    //
    // Not every surface follows: the dashboard Live feed renders `reasons[0]`
    // only, and these are appended last, so a policy-driven refusal still shows
    // a baseline reason there. The cost cause never reaches the review queue
    // either — a budget refusal sets Block, and the queue is only written on
    // Review. `agent-role:` stays out of this vec on purpose: it is a tag about
    // the caller, not a reason the action was judged.
    #[cfg_attr(
        not(any(feature = "dictum", feature = "cost-control")),
        allow(unused_mut)
    )]
    let mut decision_causes: Vec<String> = Vec::new();

    // 1.5 cost-control: cumulative session spend so far + the configured budget,
    // injected into the Dictum context and enforced by the non-Dictum fallback below.
    #[cfg(feature = "cost-control")]
    let (cost_session_usd, cost_budget_usd) = {
        let key = crate::modules::cost::spend_store::SpendKey::from_request(input);
        (
            Some(crate::modules::cost::spend_store::session_spend_usd(&key)),
            crate::pipeline::cost::session_budget_usd(),
        )
    };
    #[cfg(not(feature = "cost-control"))]
    let (cost_session_usd, cost_budget_usd): (Option<f64>, Option<f64>) = (None, None);

    // 1.0 M6: Dictum live overlay. If a policy bundle is loaded on the
    // host, run it after the YAML risk score and merge stricter-wins.
    // Dictum can tighten the verdict; it never relaxes it.
    let mut decision = risk.decision;
    // Real Dictum evaluation summary for the receipt (PIP-DICTUM-UNBOUND);
    // stays `None` when no overlay is loaded / the feature is off.
    #[cfg_attr(not(feature = "dictum"), allow(unused_mut))]
    let mut dictum_trace: Option<crate::pipeline::receipts::DictumTraceData> = None;
    #[cfg(feature = "dictum")]
    if let Some(overlay) = state.dictum_overlay.as_ref() {
        let ml_scores = ml_outcome.as_ref().map(|o| &o.scores);
        let ctx = crate::pipeline::dictum_overlay::build_overlay_context(
            input,
            risk.score,
            risk.decision,
            Some(&workspace_policy.workspace_id),
            &workspace_policy.allowed_domains,
            ml_scores,
            cost_session_usd,
            cost_budget_usd,
        );
        // Fail-closed overlay: a Block/Review policy whose `when` errors still
        // tightens (PIP-DICTUM-FAILOPEN); the trace records what ran/fired.
        let trace = overlay.evaluate(&ctx);
        if let Some(fired) = trace.fired.as_ref() {
            let merged =
                crate::pipeline::dictum_overlay::merge_decisions(decision, fired.verdict.clone());
            let reason_str = fired.reason.clone().unwrap_or_else(|| "fired".to_string());
            decision_causes.push(format!("dictum[{}]: {}", fired.policy_name, reason_str));
            decision = merged;
        }
        dictum_trace = Some(crate::pipeline::receipts::DictumTraceData {
            policies_evaluated: trace.policies_evaluated,
            policies_fired: trace.policies_fired.clone(),
            evidence_sha256: trace
                .fired
                .as_ref()
                .and_then(|f| f.evidence.as_ref())
                .map(crate::pipeline::dictum_overlay::evidence_sha256),
        });
    }

    // 1.5 cost-control: enforce the session budget even without a Dictum policy.
    // check_and_add does the limit check and the cost increment atomically under
    // a single write lock, eliminating the TOCTOU between a separate read and a
    // later add. Stricter-wins: this can only tighten the verdict.
    #[cfg(feature = "cost-control")]
    {
        let spend_key = crate::modules::cost::spend_store::SpendKey::from_request(input);
        let micros = crate::pipeline::cost::resolve_for_request(input)
            .as_ref()
            .map_or(0, |u| u.cost_micros);
        if !crate::modules::cost::spend_store::check_and_add(&spend_key, cost_budget_usd, micros) {
            decision = GovernanceDecision::Block;
            if let Some(limit) = cost_budget_usd {
                decision_causes.push(format!(
                    "cost: session spend ${:.4} exceeds budget ${limit:.4}",
                    cost_session_usd.unwrap_or(0.0)
                ));
            }
        }
    }

    reasons.extend(decision_causes.iter().cloned());

    let audit_event = AuditEvent {
        event_id: Uuid::new_v4().to_string(),
        agent_id: input.agent_id.clone(),
        framework: input.framework.clone(),
        action_type: input.action.action_type,
        tool_name: input.action.tool_name.clone(),
        decision,
        timestamp: decision_ts.clone(),
        reasons,
    };

    let review_status = if decision == GovernanceDecision::Review {
        ReviewStatus::Pending
    } else {
        ReviewStatus::NotRequired
    };

    // ═══════════════════════════════════════════════════════════════
    // LAYER 8, Telemetry
    // ═══════════════════════════════════════════════════════════════
    let duration_ms = pipeline_start.elapsed().as_millis() as u64;
    // After M6: use the merged `decision` (YAML + Dictum stricter-wins) so
    // telemetry reflects the actual final verdict.
    let decision_str = format!("{:?}", decision).to_lowercase();

    let mut layer_attrs = HashMap::new();
    layer_attrs.insert(
        "session_graph".into(),
        serde_json::json!(session_result.new_state),
    );
    layer_attrs.insert(
        "taint_blocked".into(),
        serde_json::json!(taint_result.blocked),
    );
    layer_attrs.insert(
        "firewall_score".into(),
        serde_json::json!(firewall_result.risk_score),
    );
    layer_attrs.insert(
        "adaptive_score".into(),
        serde_json::json!(adaptive_result.total_score),
    );

    let telemetry_span = otel_emitter::emit_governance_span(
        &input.agent_id,
        &input.action.tool_name,
        action_type_s,
        &decision_str,
        risk.score,
        duration_ms,
        layer_attrs,
    );
    otel_emitter::emit_pipeline_metrics(&decision_str, risk.score, duration_ms, action_type_s);
    let telemetry_json = serde_json::to_value(&telemetry_span).ok();

    // Update NHI trust based on outcome (severity-aware)
    let new_trust =
        crypto_identity::update_trust_from_decision(&input.agent_id, &decision_str, risk.score);

    // v0.4.0, persist updated trust score to durable storage (write-behind)
    if let Some(trust) = new_trust {
        let nhi_store = state.nhi_store.clone();
        let aid = input.agent_id.clone();
        tokio::spawn(async move {
            if let Err(e) = nhi_store.update_trust(&aid, trust).await {
                tracing::warn!(error = %e, "failed to persist NHI trust update");
            }
        });
    }

    // Collect advisory signals — derived from process-global mutable state and
    // EXCLUDED from the signed verdict above (D1) — into a single field for
    // dashboards/alerts. `None` when nothing fired, so the response stays
    // byte-identical for the common case.
    let advisory = {
        let adaptive_adv: Vec<&adaptive_scorer::RiskSignal> = adaptive_result
            .advisory
            .iter()
            .filter(|s| s.score > 0)
            .collect();
        let has_session_adv = session_result.advisory_score > 0;
        let has_fingerprint = !fingerprint_anomalies.is_empty();
        if adaptive_adv.is_empty() && !has_session_adv && !has_fingerprint {
            None
        } else {
            Some(serde_json::json!({
                "adaptive": adaptive_adv,
                "session": {
                    "score": session_result.advisory_score,
                    "reasons": session_result.advisory_reasons,
                },
                "behavioralFingerprint": fingerprint_anomalies,
            }))
        }
    };

    let mut result = GovernanceResult {
        trace_id: trace_id.clone(),
        protocol,
        normalized_payload,
        decision,
        review_status,
        risk,
        secret_plan,
        audit_event,
        profile,
        workspace_policy,
        policy_findings,
        schema_validation,
        review_request_id: None,
        // 8-layer results
        session_graph: session_json,
        taint_analysis: taint_json,
        adaptive_risk: adaptive_json,
        sandbox_result: sandbox_json,
        injection_firewall: firewall_json,
        policy_verification: verification_json,
        telemetry_span: telemetry_json,
        behavioral_fingerprint: state
            .behavioral_engine
            .get_fingerprint(&input.agent_id)
            .and_then(|fp| serde_json::to_value(fp).ok()),
        threat_intel: threat_intel_json,
        plugin_results: (!plugin_evaluation.outputs.is_empty())
            .then_some(plugin_evaluation.outputs.clone()),
        advisory,
        layer_roles: crate::core::types::layer_roles(),
    };

    // The caller gets the same causes the audit event records. Appended after
    // the struct is built so the receipt path is untouched: the signed body
    // takes `event.reasons` (`pipeline::receipts`), never `risk.reasons`, so
    // the frozen wire format does not move.
    result.risk.reasons.extend(decision_causes);

    // 1.5 cost-control: resolve any caller-reported usage into the canonical
    // cost ledger (priced locally; a caller-supplied cost wins). No-op (None)
    // when the feature is off, keeping the default build byte-identical.
    #[cfg(feature = "cost-control")]
    let captured_usage = crate::pipeline::cost::resolve_for_request(input);
    #[cfg(not(feature = "cost-control"))]
    let captured_usage: Option<iaga_sentinel_cost::UsageData> = None;

    // Persist audit event
    let stored = StoredAuditEvent {
        event_id: result.audit_event.event_id.clone(),
        agent_id: result.audit_event.agent_id.clone(),
        tenant_id,
        framework: result.audit_event.framework.clone(),
        action_type: result.audit_event.action_type,
        tool_name: result.audit_event.tool_name.clone(),
        input_sha256: input_sha256.clone(),
        decision: result.audit_event.decision,
        timestamp: result.audit_event.timestamp.clone(),
        reasons: result.audit_event.reasons.clone(),
        review_status: result.review_status,
        risk_score: result.risk.score,
        usage: captured_usage,
        // Receipt run grouping: use the EXPLICIT metadata.sessionId only (never
        // the agent_id fallback from `session_id` above — that would chain
        // unrelated session-less calls together). Absent -> None -> receipt
        // logger falls back to event_id, preserving byte-equality.
        session_id: input
            .metadata
            .as_ref()
            .and_then(|m| m.get("sessionId"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string()),
    };
    state.audit_store.append(&stored).await?;
    if let Some(rl) = state.receipts.as_ref() {
        // With a Dictum overlay live the logger already binds the compiled
        // bundle digest; otherwise bind the resolved workspace policy hash
        // (CRYPTO-POLICYHASH-7a).
        let overlay_active = {
            #[cfg(feature = "dictum")]
            {
                state.dictum_overlay.is_some()
            }
            #[cfg(not(feature = "dictum"))]
            {
                false
            }
        };
        let policy_hash_override = if overlay_active {
            None
        } else {
            Some(workspace_policy_hash.as_str())
        };
        rl.record(
            &stored,
            ml_outcome.as_ref(),
            stored.usage.as_ref(),
            crate::pipeline::receipts::ReceiptContext {
                policy_hash: policy_hash_override,
                threat_feed_hash: Some(&threat_feed_hash),
                dictum_trace: dictum_trace.as_ref(),
            },
        )
        .await?;
    }

    // Create review request if needed
    if result.decision == GovernanceDecision::Review {
        let now = decision_ts.clone();
        let mut review_reasons = result.policy_findings.clone();
        // `risk.reasons` now carries the overlay attribution (see
        // `decision_causes` above), so the human deciding this request sees the
        // rule that opened it. It used to reach them as "no high-risk rule
        // matched" with nothing naming the rule, because the attribution was
        // pushed only onto the audit clone.
        //
        // Sourced from here rather than from `audit_event.reasons`, which is a
        // superset: that one also carries `agent-role:<role>`, a tag about the
        // caller rather than a reason to refuse, and the queue is the one place
        // where every extra line costs a human's attention.
        review_reasons.extend(result.risk.reasons.clone());

        let review = ReviewRequest {
            id: Uuid::new_v4().to_string(),
            agent_id: result.profile.agent_id.clone(),
            workspace_id: result.profile.workspace_id.clone(),
            tool_name: result.audit_event.tool_name.clone(),
            decision: result.decision,
            status: "pending".to_string(),
            risk_score: result.risk.score,
            reasons: review_reasons,
            created_at: now.clone(),
            updated_at: now,
        };

        state.review_store.create(&review).await?;
        result.review_request_id = Some(review.id);
        result.review_status = ReviewStatus::Pending;
    }

    tracing::info!(
        trace_id = %trace_id,
        agent_id = %result.audit_event.agent_id,
        tool_name = %result.audit_event.tool_name,
        decision = ?result.decision,
        risk_score = result.risk.score,
        duration_ms,
        "governance pipeline completed"
    );

    Ok(result)
}

// ═══════════════════════════════════════════════════════════════
// Response-Side Scanning
// ═══════════════════════════════════════════════════════════════

struct SensitivePatternDef {
    name: &'static str,
    description: &'static str,
    category: &'static str,
    regex: &'static str,
    redact_with: &'static str,
}

const SENSITIVE_PATTERNS: &[SensitivePatternDef] = &[
    SensitivePatternDef {
        name: "ssn",
        description: "US Social Security Number",
        category: "pii",
        regex: r"\b\d{3}-\d{2}-\d{4}\b",
        redact_with: "[REDACTED-SSN]",
    },
    SensitivePatternDef {
        name: "credit_card",
        description: "Credit card number (Visa, MC, Amex, Discover)",
        category: "financial",
        regex: r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{0,4}\b",
        redact_with: "[REDACTED-CC]",
    },
    SensitivePatternDef {
        name: "aws_access_key",
        description: "AWS Access Key ID",
        category: "credential",
        regex: r"\bAKIA[0-9A-Z]{16}\b",
        redact_with: "[REDACTED-AWS-KEY]",
    },
    SensitivePatternDef {
        name: "aws_secret_key",
        description: "AWS Secret Access Key",
        category: "credential",
        regex: r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}",
        redact_with: "[REDACTED-AWS-SECRET]",
    },
    SensitivePatternDef {
        name: "github_token",
        description: "GitHub personal access token",
        category: "credential",
        regex: r"\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b",
        redact_with: "[REDACTED-GH-TOKEN]",
    },
    SensitivePatternDef {
        name: "openai_api_key",
        description: "OpenAI API key",
        category: "credential",
        regex: r"\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b",
        redact_with: "[REDACTED-OPENAI-KEY]",
    },
    SensitivePatternDef {
        name: "generic_api_key",
        description: "Generic API key in assignment",
        category: "credential",
        regex: r#"(?i)(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token)\s*[=:]\s*['"]?[A-Za-z0-9_\-]{20,}['"]?"#,
        redact_with: "[REDACTED-API-KEY]",
    },
    SensitivePatternDef {
        name: "password_assignment",
        description: "Password in assignment or config",
        category: "credential",
        regex: r#"(?i)(password|passwd|pwd)\s*[=:]\s*['"]?[^\s'"]{8,}['"]?"#,
        redact_with: "[REDACTED-PASSWORD]",
    },
    SensitivePatternDef {
        name: "private_key_block",
        description: "PEM private key block",
        category: "credential",
        regex: r"-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE KEY-----",
        redact_with: "[REDACTED-PRIVATE-KEY]",
    },
    SensitivePatternDef {
        name: "bearer_token",
        description: "Bearer authentication token",
        category: "credential",
        regex: r"(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}",
        redact_with: "[REDACTED-BEARER]",
    },
    SensitivePatternDef {
        name: "connection_string",
        description: "Database connection string with credentials",
        category: "credential",
        regex: r"(?i)(mongodb|postgres|mysql|redis|amqp)://[^\s@]+:[^\s@]+@",
        redact_with: "[REDACTED-CONN-STRING]",
    },
];

/// Build compiled regex patterns (cached via Lazy).
static COMPILED_PATTERNS: Lazy<Vec<(Regex, &'static SensitivePatternDef)>> = Lazy::new(|| {
    SENSITIVE_PATTERNS
        .iter()
        .filter_map(|p| Regex::new(p.regex).ok().map(|re| (re, p)))
        .collect()
});

/// Return the list of sensitive patterns being checked.
pub fn get_sensitive_patterns() -> Vec<SensitivePattern> {
    SENSITIVE_PATTERNS
        .iter()
        .map(|p| SensitivePattern {
            name: p.name.to_string(),
            description: p.description.to_string(),
            category: p.category.to_string(),
        })
        .collect()
}

/// Scan a tool response for prompt injection, taint leaks, and sensitive data.
pub fn scan_response(input: &ResponseScanRequest) -> ResponseScanResult {
    let payload_str = serde_json::to_string(&input.response_payload).unwrap_or_default();
    let mut findings: Vec<String> = Vec::new();
    let mut risk_score: u32 = 0;

    // ── Check 1: Injection firewall on response content ──
    let firewall_result = prompt_firewall::scan_prompt(&payload_str);
    if firewall_result.blocked {
        findings.push(format!("injection firewall: {}", firewall_result.summary));
    }
    if firewall_result.risk_score > risk_score {
        risk_score = firewall_result.risk_score;
    }

    // ── Check 2: Taint tracking (detect secret/credential leaks) ──
    let inherited_taints = input
        .metadata
        .as_ref()
        .and_then(|m| m.get("sessionId"))
        .and_then(|v| v.as_str())
        .map(taint_tracker::get_session_taint)
        .unwrap_or_default();

    let taint_result = taint_tracker::analyze_taint(
        "http", // response is coming back from a tool, treat as network data
        &input.tool_name,
        &payload_str,
        &inherited_taints,
    );
    if taint_result.blocked {
        findings.push(format!("taint tracking: {}", taint_result.summary));
        if risk_score < 80 {
            risk_score = 80;
        }
    }
    if taint_result.exfiltration_detected {
        findings.push("taint: potential data exfiltration in response".to_string());
    }

    // ── Check 3: Sensitive pattern matching with redaction ──
    let mut redacted = payload_str.clone();
    let mut has_sensitive = false;

    for (re, pat) in COMPILED_PATTERNS.iter() {
        if re.is_match(&redacted) {
            has_sensitive = true;
            let count = re.find_iter(&redacted).count();
            findings.push(format!(
                "sensitive pattern: {} ({} occurrence{})",
                pat.name,
                count,
                if count > 1 { "s" } else { "" }
            ));
            // Each pattern category carries different weight
            let pattern_score = match pat.category {
                "credential" => 70,
                "financial" => 75,
                "pii" => 65,
                _ => 50,
            };
            if pattern_score > risk_score {
                risk_score = pattern_score;
            }
            redacted = re.replace_all(&redacted, pat.redact_with).to_string();
        }
    }

    // ── Build decision ──
    let decision = if risk_score >= 80 {
        ResponseDecision::Block
    } else if risk_score >= 40 {
        ResponseDecision::Review
    } else {
        ResponseDecision::Allow
    };

    let redacted_payload = if has_sensitive {
        serde_json::from_str::<serde_json::Value>(&redacted)
            .ok()
            .or(Some(serde_json::Value::String(redacted)))
    } else {
        None
    };

    ResponseScanResult {
        request_id: input.request_id.clone(),
        decision,
        risk_score,
        findings,
        redacted_payload,
    }
}
