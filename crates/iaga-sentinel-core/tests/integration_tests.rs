use std::collections::HashMap;
use std::sync::Arc;

#[cfg(feature = "plugins")]
#[path = "support/plugin_test_support.rs"]
mod plugin_test_support;

use iaga_sentinel::config::env::{AppEnv, NodeEnv, ServiceMode};
use iaga_sentinel::core::errors::SentinelError;
use iaga_sentinel::core::types::RateLimitConfig;
use iaga_sentinel::core::types::*;
use iaga_sentinel::demo::scenarios::{demo_profiles, demo_scenarios, demo_workspace_policies};
use iaga_sentinel::events::bus::EventBus;
use iaga_sentinel::events::webhooks::{DeadLetterQueue, WebhookManager};
use iaga_sentinel::modules::fingerprint::behavioral::BehavioralEngine;
use iaga_sentinel::modules::policy::rules_engine::{ConditionSet, MatchCriteria, PolicyRule};
use iaga_sentinel::modules::rate_limit::limiter::RateLimiter;
use iaga_sentinel::modules::threat_intel::feed::ThreatFeed;
use iaga_sentinel::pipeline::execute_pipeline::execute_pipeline;
use iaga_sentinel::plugins::PluginRegistry;
use iaga_sentinel::server::app_state::AppState;
use iaga_sentinel::storage::sqlite::SqliteStorage;
use iaga_sentinel::storage::traits::{PolicyStore, StorageBackend};

/// Build a fully-wired AppState backed by an in-memory SQLite database,
/// with demo profiles and workspace policies seeded.
async fn build_test_state() -> Arc<AppState> {
    build_test_state_with_plugin_registry(Arc::new(PluginRegistry::default())).await
}

async fn build_test_state_with_plugin_registry(
    plugin_registry: Arc<PluginRegistry>,
) -> Arc<AppState> {
    let storage = SqliteStorage::new("sqlite::memory:")
        .await
        .expect("failed to create in-memory SQLite");

    let storage = Arc::new(storage);

    // Seed demo profiles
    for profile in demo_profiles() {
        storage
            .upsert_profile(&profile)
            .await
            .expect("failed to seed profile");
    }

    // Seed demo workspace policies
    for policy in demo_workspace_policies() {
        storage
            .upsert_workspace(&policy)
            .await
            .expect("failed to seed workspace policy");
    }

    let event_bus = EventBus::new(64);
    let webhook_manager = Arc::new(WebhookManager::new(Arc::new(DeadLetterQueue::new())));

    let env = AppEnv {
        port: 4010,
        host: "127.0.0.1".to_string(),
        node_env: NodeEnv::Test,
        default_mode: ServiceMode::Gateway,
        cors_origins: None,
    };

    Arc::new(AppState {
        audit_store: storage.clone(),
        review_store: storage.clone(),
        policy_store: storage.clone(),
        api_key_store: storage.clone(),
        tenant_store: storage.clone(),
        nhi_store: storage.clone(),
        session_store: storage.clone(),
        taint_store: storage.clone(),
        fingerprint_store: storage.clone(),
        rate_limit_store: storage.clone(),
        event_bus,
        webhook_manager,
        behavioral_engine: Arc::new(BehavioralEngine::new()),
        rate_limiter: Arc::new(RateLimiter::new(RateLimitConfig::default())),
        threat_feed: Arc::new(ThreatFeed::with_builtin_indicators()),
        plugin_registry,
        storage_backend: StorageBackend::Sqlite,
        env,
        auth_cache: iaga_sentinel::auth::cache::AuthCache::from_env(),
        receipts: None,
        reasoning: None,
        #[cfg(feature = "dictum")]
        dictum_overlay: None,
    })
}

fn payload(pairs: &[(&str, serde_json::Value)]) -> HashMap<String, serde_json::Value> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

fn session_metadata(session_id: &str) -> Option<HashMap<String, serde_json::Value>> {
    Some(HashMap::from([(
        "sessionId".to_string(),
        serde_json::json!(session_id),
    )]))
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1: Safe file read should be allowed
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_safe_file_read_is_allowed() {
    let state = build_test_state().await;

    let request = InspectRequest {
        agent_id: "openclaw-builder-01".into(),
        tenant_id: None,
        workspace_id: Some("ws-demo".into()),
        framework: "openclaw".into(),
        protocol: Some(ProtocolKind::Mcp),
        action: ActionDetail {
            action_type: ActionType::FileRead,
            tool_name: "filesystem.read".into(),
            payload: payload(&[
                ("path", serde_json::json!("src/config.json")),
                ("intent", serde_json::json!("read configuration")),
            ]),
        },
        requested_secrets: None,
        // Unique sessionId so this test's session DAG is isolated from other
        // tests in the shared process-global session store (session_dag::SESSIONS).
        metadata: session_metadata("it-safe-file-read"),
        usage: None,
    };

    let result = execute_pipeline(&request, &state)
        .await
        .expect("pipeline should succeed");

    assert_eq!(
        result.decision,
        GovernanceDecision::Allow,
        "safe file read should be allowed, got {:?} with findings: {:?}",
        result.decision,
        result.policy_findings
    );
    assert!(
        !result.trace_id.is_empty(),
        "governance result should include a trace_id"
    );
}

#[cfg(feature = "plugins")]
#[tokio::test]
async fn test_wasm_plugin_registry_populates_governance_results() {
    let plugin_dir = plugin_test_support::TempPluginDir::new("integration");
    let plugin_path = plugin_dir.write_review_plugin();
    let plugin_registry = Arc::new(PluginRegistry::new(plugin_dir.path().to_path_buf()));
    let snapshot = plugin_registry.reload();

    assert_eq!(
        snapshot.loaded_count, 1,
        "expected one real WASM plugin to load, got snapshot {snapshot:?}"
    );
    assert_eq!(snapshot.plugins[0].name, plugin_test_support::PLUGIN_NAME);
    assert_eq!(
        snapshot.plugins[0].version,
        plugin_test_support::PLUGIN_VERSION
    );
    assert_eq!(snapshot.plugins[0].path, plugin_path.display().to_string());
    assert!(
        snapshot.load_errors.is_empty(),
        "unexpected plugin load errors: {:?}",
        snapshot.load_errors
    );

    let state = build_test_state_with_plugin_registry(plugin_registry).await;
    let request = InspectRequest {
        agent_id: "openclaw-builder-01".into(),
        tenant_id: None,
        workspace_id: Some("ws-demo".into()),
        framework: "openclaw".into(),
        protocol: Some(ProtocolKind::Mcp),
        action: ActionDetail {
            action_type: ActionType::FileRead,
            tool_name: "filesystem.read".into(),
            payload: payload(&[
                ("path", serde_json::json!("README.md")),
                ("intent", serde_json::json!("inspect repository docs")),
            ]),
        },
        requested_secrets: None,
        metadata: session_metadata("it-wasm-plugin"),
        usage: None,
    };

    let result = execute_pipeline(&request, &state)
        .await
        .expect("pipeline with WASM plugin should succeed");

    assert_eq!(
        result.decision,
        GovernanceDecision::Review,
        "plugin review signal should elevate the decision, got {:?} with findings {:?}",
        result.decision,
        result.policy_findings
    );

    let plugin_results = result
        .plugin_results
        .as_ref()
        .expect("governance result should include plugin outputs");
    assert_eq!(plugin_results.len(), 1);

    let plugin_output = &plugin_results[0];
    assert_eq!(plugin_output.plugin_name, plugin_test_support::PLUGIN_NAME);
    assert_eq!(
        plugin_output.plugin_version,
        plugin_test_support::PLUGIN_VERSION
    );
    assert_eq!(
        plugin_output.result.risk_score,
        plugin_test_support::PLUGIN_RISK_SCORE
    );
    assert_eq!(
        plugin_output.result.decision_hint.as_deref(),
        Some(plugin_test_support::PLUGIN_DECISION_HINT)
    );
    assert!(
        plugin_output
            .result
            .findings
            .iter()
            .any(|finding| finding == plugin_test_support::PLUGIN_FINDING),
        "expected concrete plugin finding, got {:?}",
        plugin_output.result.findings
    );
    assert!(
        result
            .policy_findings
            .iter()
            .any(|finding| finding.contains(plugin_test_support::PLUGIN_FINDING)),
        "pipeline should merge plugin findings into policy findings, got {:?}",
        result.policy_findings
    );
    assert!(
        result
            .policy_findings
            .iter()
            .any(|finding| finding.contains("decision hint -> review")),
        "pipeline should surface the plugin decision hint, got {:?}",
        result.policy_findings
    );
}

#[tokio::test]
async fn test_workspace_allow_rule_can_lower_review_to_allow() {
    let state = build_test_state().await;

    state
        .policy_store
        .upsert_profile(&AgentProfile {
            agent_id: "rule-allow-agent".into(),
            tenant_id: None,
            workspace_id: "ws-rule-allow".into(),
            framework: "openclaw".into(),
            role: AgentRole::Builder,
            approved_tools: vec!["terminal.exec".into()],
            approved_secrets: vec![],
            baseline_action_types: vec![ActionType::Shell],
            tool_trust: 0.9,
        })
        .await
        .expect("failed to seed rule-allow profile");

    state
        .policy_store
        .upsert_workspace(&WorkspacePolicy {
            workspace_id: "ws-rule-allow".into(),
            tenant_id: None,
            allowed_protocols: vec![ProtocolKind::Mcp],
            tools: vec![ToolPolicy {
                tool_name: "terminal.exec".into(),
                allowed_action_types: vec![ActionType::Shell],
                max_decision: GovernanceDecision::Review,
                requires_human_review: false,
            }],
            allowed_domains: vec![],
            threshold_block: 70,
            threshold_review: 35,
        })
        .await
        .expect("failed to seed rule-allow workspace");

    state
        .policy_store
        .upsert_workspace_rule(
            "ws-rule-allow",
            &PolicyRule {
                id: "allow-safe-shell".into(),
                name: "allow-safe-shell".into(),
                priority: 1,
                match_criteria: MatchCriteria {
                    action_type: vec![ActionType::Shell],
                    tool_name: vec!["terminal.exec".into()],
                    ..Default::default()
                },
                conditions: ConditionSet {
                    max_risk_score: Some(35),
                    payload_contains: vec!["echo hello".into()],
                    ..Default::default()
                },
                decision: GovernanceDecision::Allow,
                reason: Some("Known-safe shell command is auto-allowed".into()),
                enabled: true,
            },
        )
        .await
        .expect("failed to persist workspace rule");

    let request = InspectRequest {
        agent_id: "rule-allow-agent".into(),
        tenant_id: None,
        workspace_id: Some("ws-rule-allow".into()),
        framework: "openclaw".into(),
        protocol: Some(ProtocolKind::Mcp),
        action: ActionDetail {
            action_type: ActionType::Shell,
            tool_name: "terminal.exec".into(),
            payload: payload(&[
                ("command", serde_json::json!("echo hello")),
                ("intent", serde_json::json!("print a greeting")),
            ]),
        },
        requested_secrets: None,
        metadata: session_metadata("it-workspace-allow-rule"),
        usage: None,
    };

    let result = execute_pipeline(&request, &state)
        .await
        .expect("pipeline with allow rule should succeed");

    assert_eq!(
        result.decision,
        GovernanceDecision::Allow,
        "allow rule should lower the base review decision, got {:?} with findings {:?}",
        result.decision,
        result.policy_findings
    );
    assert!(
        result
            .policy_findings
            .iter()
            .any(|finding| finding.contains("Known-safe shell command is auto-allowed")),
        "expected rule reason in policy findings, got {:?}",
        result.policy_findings
    );
}

#[tokio::test]
async fn test_double_call_same_session_read_then_http_is_blocked() {
    let state = build_test_state().await;
    let session_id = "integration-sequence-double-1";

    let read_request = InspectRequest {
        agent_id: "openclaw-builder-01".into(),
        tenant_id: None,
        workspace_id: Some("ws-demo".into()),
        framework: "openclaw".into(),
        protocol: Some(ProtocolKind::Mcp),
        action: ActionDetail {
            action_type: ActionType::FileRead,
            tool_name: "filesystem.read".into(),
            payload: payload(&[
                ("path", serde_json::json!("README.md")),
                ("intent", serde_json::json!("inspect repository docs")),
            ]),
        },
        requested_secrets: None,
        metadata: session_metadata(session_id),
        usage: None,
    };

    let first = execute_pipeline(&read_request, &state)
        .await
        .expect("first pipeline call should succeed");
    assert_eq!(first.decision, GovernanceDecision::Allow);

    let http_request = InspectRequest {
        agent_id: "openclaw-builder-01".into(),
        tenant_id: None,
        workspace_id: Some("ws-demo".into()),
        framework: "openclaw".into(),
        protocol: Some(ProtocolKind::Mcp),
        action: ActionDetail {
            action_type: ActionType::Http,
            tool_name: "http.fetch".into(),
            payload: payload(&[
                ("method", serde_json::json!("POST")),
                ("destination", serde_json::json!("api.github.com")),
                ("intent", serde_json::json!("send repository summary")),
            ]),
        },
        requested_secrets: None,
        metadata: session_metadata(session_id),
        usage: None,
    };

    let second = execute_pipeline(&http_request, &state)
        .await
        .expect("second pipeline call should succeed");

    assert_eq!(
        second.decision,
        GovernanceDecision::Block,
        "same-session read -> http should be blocked, got {:?} with findings {:?}",
        second.decision,
        second.policy_findings
    );
    assert!(
        second.risk.score >= 70,
        "same-session exfil chain should be high risk, got {}",
        second.risk.score
    );
    assert!(
        second
            .policy_findings
            .iter()
            .any(|finding| finding.contains("session graph") || finding.contains("taint tracking")),
        "expected session/taint correlation findings, got {:?}",
        second.policy_findings
    );

    let session_graph = second
        .session_graph
        .as_ref()
        .expect("response should include session graph details");
    assert_eq!(session_graph["transitionAllowed"], false);
    assert!(
        session_graph["attacksDetected"]
            .as_array()
            .is_some_and(|attacks| attacks
                .iter()
                .any(|attack| attack["name"] == "data_exfiltration")),
        "expected data_exfiltration attack in session graph, got {:?}",
        session_graph
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2: Shell command referencing .env should trigger Review or Block
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_shell_with_env_secret_triggers_review_or_block() {
    let state = build_test_state().await;

    let request = InspectRequest {
        agent_id: "openclaw-builder-01".into(),
        tenant_id: None,
        workspace_id: Some("ws-demo".into()),
        framework: "openclaw".into(),
        protocol: Some(ProtocolKind::Mcp),
        action: ActionDetail {
            action_type: ActionType::Shell,
            tool_name: "terminal.exec".into(),
            payload: payload(&[
                ("command", serde_json::json!("cat .env && source .env")),
                ("intent", serde_json::json!("load environment")),
            ]),
        },
        requested_secrets: None,
        metadata: session_metadata("it-shell-env-secret"),
        usage: None,
    };

    let result = execute_pipeline(&request, &state)
        .await
        .expect("pipeline should succeed");

    assert!(
        result.decision == GovernanceDecision::Review
            || result.decision == GovernanceDecision::Block,
        "shell referencing .env should be Review or Block, got {:?} with findings: {:?}",
        result.decision,
        result.policy_findings
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3: Destructive rm -rf / should be blocked
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_destructive_command_is_blocked() {
    let state = build_test_state().await;

    let request = InspectRequest {
        agent_id: "openclaw-builder-01".into(),
        tenant_id: None,
        workspace_id: Some("ws-demo".into()),
        framework: "openclaw".into(),
        protocol: Some(ProtocolKind::Mcp),
        action: ActionDetail {
            action_type: ActionType::Shell,
            tool_name: "terminal.exec".into(),
            payload: payload(&[
                ("command", serde_json::json!("rm -rf /")),
                ("intent", serde_json::json!("cleanup old data")),
            ]),
        },
        requested_secrets: None,
        metadata: session_metadata("it-destructive-cmd"),
        usage: None,
    };

    let result = execute_pipeline(&request, &state)
        .await
        .expect("pipeline should succeed");

    assert_eq!(
        result.decision,
        GovernanceDecision::Block,
        "destructive rm -rf / should be blocked, got {:?} with findings: {:?}",
        result.decision,
        result.policy_findings
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4: Researcher requesting unknown secret should trigger Review
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_unknown_secret_triggers_review() {
    let state = build_test_state().await;

    let request = InspectRequest {
        agent_id: "openclaw-research-01".into(),
        tenant_id: None,
        workspace_id: Some("ws-demo".into()),
        framework: "openclaw".into(),
        protocol: Some(ProtocolKind::Mcp),
        action: ActionDetail {
            action_type: ActionType::Http,
            tool_name: "http.fetch".into(),
            payload: payload(&[
                ("method", serde_json::json!("POST")),
                ("destination", serde_json::json!("hooks.slack.com")),
                ("intent", serde_json::json!("send external summary")),
            ]),
        },
        requested_secrets: Some(vec!["secretref://prod/root/aws-admin".into()]),
        metadata: session_metadata("it-unknown-secret"),
        usage: None,
    };

    let result = execute_pipeline(&request, &state)
        .await
        .expect("pipeline should succeed");

    assert!(
        result.decision == GovernanceDecision::Review
            || result.decision == GovernanceDecision::Block,
        "unknown secret request should be Review or Block, got {:?} with findings: {:?}",
        result.decision,
        result.policy_findings
    );

    // Verify the secret was denied in the plan
    assert!(
        result
            .secret_plan
            .denied
            .contains(&"secretref://prod/root/aws-admin".to_string()),
        "aws-admin secret should be in denied list, got approved: {:?}, denied: {:?}",
        result.secret_plan.approved,
        result.secret_plan.denied
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 5: Verify demo scenarios execute without errors
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_all_demo_scenarios_execute_successfully() {
    let state = build_test_state().await;

    let scenarios = demo_scenarios();
    assert!(
        !scenarios.is_empty(),
        "demo scenarios should not be empty (ensure 'demo' feature is enabled)"
    );

    for scenario in &scenarios {
        let result = execute_pipeline(&scenario.request, &state).await;
        assert!(
            result.is_ok(),
            "scenario '{}' ({}) should not return an error, got: {:?}",
            scenario.title,
            scenario.step,
            result.err()
        );
    }
}

#[tokio::test]
async fn test_a2a_payload_flows_through_pipeline() {
    let state = build_test_state().await;

    state
        .policy_store
        .upsert_profile(&AgentProfile {
            agent_id: "a2a-agent".into(),
            tenant_id: None,
            workspace_id: "ws-a2a".into(),
            framework: "a2a".into(),
            role: AgentRole::Builder,
            approved_tools: vec!["a2a.message.send".into()],
            approved_secrets: vec![],
            baseline_action_types: vec![ActionType::Http],
            tool_trust: 0.7,
        })
        .await
        .expect("failed to seed a2a profile");

    state
        .policy_store
        .upsert_workspace(&WorkspacePolicy {
            workspace_id: "ws-a2a".into(),
            tenant_id: None,
            allowed_protocols: vec![ProtocolKind::A2a],
            tools: vec![ToolPolicy {
                tool_name: "a2a.message.send".into(),
                allowed_action_types: vec![ActionType::Http],
                max_decision: GovernanceDecision::Allow,
                requires_human_review: false,
            }],
            allowed_domains: vec![],
            threshold_block: 70,
            threshold_review: 35,
        })
        .await
        .expect("failed to seed a2a workspace");

    let request = InspectRequest {
        agent_id: "a2a-agent".into(),
        tenant_id: None,
        workspace_id: Some("ws-a2a".into()),
        framework: "a2a".into(),
        protocol: None,
        action: ActionDetail {
            action_type: ActionType::Http,
            tool_name: "a2a.message.send".into(),
            payload: payload(&[
                ("jsonrpc", serde_json::json!("2.0")),
                ("method", serde_json::json!("SendMessage")),
                (
                    "params",
                    serde_json::json!({
                        "message": {
                            "messageId": "msg-1",
                            "taskId": "task-123",
                            "role": "ROLE_USER",
                            "parts": [{ "text": "hello from a2a" }]
                        }
                    }),
                ),
            ]),
        },
        requested_secrets: None,
        metadata: None,
        usage: None,
    };

    let result = execute_pipeline(&request, &state)
        .await
        .expect("A2A pipeline should succeed");

    assert_eq!(result.protocol, ProtocolKind::A2a);
    assert!(result.schema_validation.valid, "A2A schema should be valid");
    assert_eq!(
        result.decision,
        GovernanceDecision::Allow,
        "A2A request should be allowed, got {:?} with findings: {:?}",
        result.decision,
        result.policy_findings
    );
    assert_eq!(
        result.normalized_payload.get("messageText"),
        Some(&serde_json::json!("hello from a2a"))
    );
}

#[tokio::test]
async fn test_acp_payload_flows_through_pipeline() {
    let state = build_test_state().await;

    state
        .policy_store
        .upsert_profile(&AgentProfile {
            agent_id: "acp-agent".into(),
            tenant_id: None,
            workspace_id: "ws-acp".into(),
            framework: "acp".into(),
            role: AgentRole::Builder,
            approved_tools: vec!["acp.run.create".into()],
            approved_secrets: vec![],
            baseline_action_types: vec![ActionType::Http],
            tool_trust: 0.7,
        })
        .await
        .expect("failed to seed acp profile");

    state
        .policy_store
        .upsert_workspace(&WorkspacePolicy {
            workspace_id: "ws-acp".into(),
            tenant_id: None,
            allowed_protocols: vec![ProtocolKind::Acp],
            tools: vec![ToolPolicy {
                tool_name: "acp.run.create".into(),
                allowed_action_types: vec![ActionType::Http],
                max_decision: GovernanceDecision::Allow,
                requires_human_review: false,
            }],
            allowed_domains: vec![],
            threshold_block: 70,
            threshold_review: 35,
        })
        .await
        .expect("failed to seed acp workspace");

    let request = InspectRequest {
        agent_id: "acp-agent".into(),
        tenant_id: None,
        workspace_id: Some("ws-acp".into()),
        framework: "acp".into(),
        protocol: None,
        action: ActionDetail {
            action_type: ActionType::Http,
            tool_name: "acp.run.create".into(),
            payload: payload(&[
                ("agent_name", serde_json::json!("planner")),
                ("mode", serde_json::json!("sync")),
                (
                    "session_id",
                    serde_json::json!("123e4567-e89b-12d3-a456-426614174000"),
                ),
                (
                    "input",
                    serde_json::json!([
                        {
                            "role": "user",
                            "parts": [{ "content_type": "text/plain", "content": "hello from acp" }]
                        }
                    ]),
                ),
            ]),
        },
        requested_secrets: None,
        metadata: None,
        usage: None,
    };

    let result = execute_pipeline(&request, &state)
        .await
        .expect("ACP pipeline should succeed");

    assert_eq!(result.protocol, ProtocolKind::Acp);
    assert!(result.schema_validation.valid, "ACP schema should be valid");
    assert_eq!(
        result.decision,
        GovernanceDecision::Allow,
        "ACP request should be allowed, got {:?} with findings: {:?}",
        result.decision,
        result.policy_findings
    );
    assert_eq!(
        result.normalized_payload.get("agentName"),
        Some(&serde_json::json!("planner"))
    );
}

/// SCOPE-DERIVE-1: the governance scope comes from the agent profile, not the
/// request body. A caller that asserts a workspace it does not belong to is
/// refused instead of being silently evaluated against that workspace's policy.
#[tokio::test]
async fn test_pipeline_rejects_foreign_workspace_id() {
    let state = build_test_state().await;

    let request = InspectRequest {
        agent_id: "openclaw-builder-01".into(),
        tenant_id: None,
        // The seeded profile lives in ws-demo; ws-cli is a real, different
        // workspace, which is what makes this a confused-deputy attempt rather
        // than a typo.
        workspace_id: Some("ws-cli".into()),
        framework: "openclaw".into(),
        protocol: Some(ProtocolKind::Mcp),
        action: ActionDetail {
            action_type: ActionType::FileRead,
            tool_name: "filesystem.read".into(),
            payload: payload(&[("path", serde_json::json!("README.md"))]),
        },
        requested_secrets: None,
        metadata: session_metadata("it-scope-foreign-ws"),
        usage: None,
    };

    let err = execute_pipeline(&request, &state)
        .await
        .expect_err("a foreign workspaceId must not be honoured");
    assert!(
        matches!(err, SentinelError::WorkspaceScopeMismatch { .. }),
        "expected a scope mismatch, got {err:?}"
    );
}

/// The same request without the field is unaffected: scope falls back to the
/// profile, which is what every shipped SDK and adapter actually sends.
#[tokio::test]
async fn test_pipeline_derives_workspace_when_absent() {
    let state = build_test_state().await;

    let request = InspectRequest {
        agent_id: "openclaw-builder-01".into(),
        tenant_id: None,
        workspace_id: None,
        framework: "openclaw".into(),
        protocol: Some(ProtocolKind::Mcp),
        action: ActionDetail {
            action_type: ActionType::FileRead,
            tool_name: "filesystem.read".into(),
            payload: payload(&[("path", serde_json::json!("README.md"))]),
        },
        requested_secrets: None,
        metadata: session_metadata("it-scope-derived-ws"),
        usage: None,
    };

    let result = execute_pipeline(&request, &state)
        .await
        .expect("an absent workspaceId must still resolve from the profile");
    assert_eq!(result.profile.workspace_id, "ws-demo");
}
