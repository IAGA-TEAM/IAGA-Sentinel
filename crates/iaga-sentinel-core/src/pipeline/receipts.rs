//! Integration point between the governance pipeline and `iaga-sentinel-receipts`.
//!
//! Design (M2, dual-write transition):
//! - The pipeline keeps writing to `audit_store` exactly as in 0.4.0.
//! - In addition, if a `ReceiptLogger` is configured on `AppState`, every
//!   stored verdict is translated into a signed `Receipt` appended to the
//!   Merkle chain of the corresponding `run_id` (mapped from `trace_id` /
//!   `event_id`). A failure in the receipt path must never fail the
//!   governance decision, errors are logged at warn level and swallowed.
//! - The trait is defined here so callers can remain feature-agnostic:
//!   `state.receipts: Option<Arc<dyn ReceiptLogger>>` is `None` when the
//!   `receipts` cargo feature is disabled and the concrete impl is absent.
//!
//! The concrete `SignedReceiptLogger` (feature `receipts`) lives at the
//! bottom of this file and is gated so the core still compiles without
//! the `iaga-sentinel-receipts` crate in the dependency graph.

use async_trait::async_trait;

use crate::core::types::StoredAuditEvent;
use crate::pipeline::reasoning::ReasoningOutcome;

/// Real Dictum evaluation summary threaded from the pipeline into the receipt
/// (PIP-DICTUM-UNBOUND / CRYPTO-POLICYHASH-7c): which policies ran, which
/// fired, and a digest of the fired policy's evidence. Replaces the formerly
/// hardcoded `0/[]` capture. Populated only when a Dictum overlay is active.
#[derive(Debug, Clone, Default)]
pub struct DictumTraceData {
    pub policies_evaluated: u32,
    pub policies_fired: Vec<String>,
    pub evidence_sha256: Option<String>,
}

/// Per-request context bound into the signed receipt. Grouped into one struct
/// (with named fields) so the two same-typed digests can never be passed in the
/// wrong positional order — a swap would silently bind the wrong hash into the
/// proof.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReceiptContext<'a> {
    /// Digest of the resolved policy that decided. `Some(workspace YAML digest)`
    /// when no Dictum overlay is loaded; `None` keeps the logger's configured
    /// hash (the compiled Dictum bundle digest) — CRYPTO-POLICYHASH-7a.
    pub policy_hash: Option<&'a str>,
    /// Digest of the active threat-intel feed that contributed to the verdict
    /// (DET-THREAT-1).
    pub threat_feed_hash: Option<&'a str>,
    /// Real per-request Dictum evaluation summary (capture mode only); `None`
    /// when no overlay ran.
    pub dictum_trace: Option<&'a DictumTraceData>,
}

#[async_trait]
pub trait ReceiptLogger: Send + Sync {
    /// Append a signed receipt for the given audit event. Must not panic
    /// and must not propagate errors into the hot path: implementations
    /// log internally and return. The optional `evidence` carries ML
    /// scores and model digests from the reasoning plane (M3.5); when
    /// `None`, the receipt body records empty `model_digests` and
    /// `ml_scores: None` (legacy M2 behavior).
    /// `usage` carries the optional cost/token ledger for this verdict
    /// (1.5 cost-control); `None` when cost tracking is off, which leaves the
    /// receipt byte-identical to a pre-1.5 receipt.
    /// `ctx` carries the per-request signed bindings (resolved policy digest,
    /// threat-feed digest, Dictum trace).
    async fn record(
        &self,
        event: &StoredAuditEvent,
        evidence: Option<&ReasoningOutcome>,
        usage: Option<&iaga_sentinel_cost::UsageData>,
        ctx: ReceiptContext<'_>,
    );

    /// 1.0 read surface for the dashboard / HTTP API. Implementations
    /// return JSON-shaped data; defaults return empty so non-receipt
    /// loggers (the `receipts` feature off path) still satisfy the
    /// trait without forcing JSON construction.
    async fn list_runs_json(&self, _limit: u32) -> serde_json::Value {
        serde_json::Value::Array(Vec::new())
    }

    async fn get_run_json(&self, _run_id: &str) -> serde_json::Value {
        serde_json::json!({ "receipts": [], "verify": null, "receiptDropped": false })
    }

    fn signer_key_id(&self) -> Option<String> {
        None
    }

    fn policy_hash(&self) -> Option<String> {
        None
    }
}

/// Best-effort construction of a signed receipt logger. Returns `None` when:
/// - the `receipts` feature is disabled at compile time, or
/// - the host cannot resolve a signer key path (e.g. no `HOME` on a
///   restricted environment), or
/// - the SQLite/Postgres receipt store fails to open (errors are
///   logged and swallowed, receipts must never break the pipeline
///   startup path).
///
/// `policy_hash` is the SHA-256 hex digest of the active policy
/// bundle. When the host has a Dictum overlay loaded (M6) it should
/// pass `Some(overlay.policy_hash().to_string())` so receipts can
/// be replayed against the exact policy that produced them. Pass
/// `None` for the default placeholder (M2 behavior preserved).
pub async fn try_build_receipt_logger(
    database_url: &str,
    policy_hash: Option<String>,
) -> Option<std::sync::Arc<dyn ReceiptLogger>> {
    #[cfg(feature = "receipts")]
    {
        signed::try_build(database_url, policy_hash).await
    }
    #[cfg(not(feature = "receipts"))]
    {
        let _ = database_url;
        let _ = policy_hash;
        None
    }
}

#[cfg(feature = "receipts")]
pub use signed::SignedReceiptLogger;

#[cfg(feature = "receipts")]
mod signed {
    use std::sync::Arc;

    use async_trait::async_trait;
    use iaga_sentinel_receipts::{
        chain_link, DictumEvalTrace, LocalDiskSigner, MlInferenceInputs, MlScoreBundle,
        MlTokenDigest, PipelineInputsCapture, ReceiptBody, ReceiptError, ReceiptStore, Signer,
        Verdict,
    };
    use sha2::{Digest, Sha256};
    use tokio::sync::Mutex;
    use tracing::{error, warn};

    use super::ReceiptLogger;
    use crate::core::types::{GovernanceDecision, StoredAuditEvent};

    /// Concrete `ReceiptLogger` that signs and appends receipts via an
    /// `iaga_sentinel_receipts::ReceiptStore`.
    ///
    /// Head tracking is delegated to the store (`store.head(run_id)`),
    /// avoiding drift from an in-memory cache that could get out of sync
    /// across process restarts.
    pub struct SignedReceiptLogger {
        store: Arc<dyn ReceiptStore>,
        signer: Arc<dyn Signer>,
        policy_hash: String,
        /// Serializes append operations so concurrent writes to the same
        /// run_id can't race on `head()`/`append()`. A per-run_id mutex map
        /// would be lower contention; a single global lock is simpler and
        /// adequate for M2 throughput.
        append_guard: Mutex<()>,
        /// OBS-RECEIPT-DROP / issue #23: per-run count of receipts lost to an
        /// append error or retry exhaustion. A drop diverges the SQL audit trail
        /// from the signed chain; recording it per `run_id` lets the read API
        /// (`GET /v1/receipts/{run_id}`) surface the gap instead of leaving it
        /// only in the `error!` log and the `receipts.dropped` counter. In-memory
        /// (process lifetime); the durable operator signals stay the log + metric.
        dropped_runs: std::sync::Mutex<std::collections::HashMap<String, u32>>,
    }

    impl SignedReceiptLogger {
        pub fn new(
            store: Arc<dyn ReceiptStore>,
            signer: Arc<dyn Signer>,
            policy_hash: String,
        ) -> Self {
            Self {
                store,
                signer,
                policy_hash,
                append_guard: Mutex::new(()),
                dropped_runs: std::sync::Mutex::new(std::collections::HashMap::new()),
            }
        }

        fn input_hash(event: &StoredAuditEvent) -> String {
            // PROOF-INPUTHASH-BIND-3: bind the action *content*, not the random
            // `event_id`. `input_sha256` is the SHA-256 of the canonical payload
            // (computed once in the pipeline). Folding it in with agent + tool
            // makes the receipt's `input_hash` both content-binding (`rm -rf /`
            // and `ls` now differ) and reproducible on replay (no random UUID).
            // The raw payload stays out of the receipt for privacy; only the
            // digest is bound. NB: this changes the signed bytes of *new*
            // receipts (see CHANGELOG); old receipts verify unchanged.
            let mut hasher = Sha256::new();
            hasher.update(event.agent_id.as_bytes());
            hasher.update(event.tool_name.as_bytes());
            hasher.update(event.input_sha256.as_bytes());
            hex::encode(hasher.finalize())
        }

        fn map_verdict(d: GovernanceDecision) -> Verdict {
            match d {
                GovernanceDecision::Allow => Verdict::Allow,
                GovernanceDecision::Review => Verdict::Review,
                GovernanceDecision::Block => Verdict::Block,
            }
        }

        fn run_id(event: &StoredAuditEvent) -> String {
            // Group a logical session into ONE hash-chained run: when the caller
            // supplied an explicit `metadata.sessionId`, every action in that
            // session shares a run_id, so receipts chain seq 0,1,2... with
            // parent_hash links.
            //
            // PIP-RUNID-COLLISION: qualify the run_id with the agent so two
            // principals choosing the same `sessionId` ("session-1") can't
            // interleave into one chain that `verify_chain` would report Valid.
            // `run_id` is part of the signed bytes and the verifier checks it is
            // consistent across the chain, so this binds the principal into the
            // proof with no new field. Tenant-scoped isolation (multi-tenant DB
            // separation) stays Enterprise; agent qualification is a different,
            // single-tenant axis and does not move that boundary.
            //
            // When no session is supplied we fall back to `event_id` (one
            // receipt per run), which keeps the body byte-identical to earlier
            // releases for session-less callers.
            match event.session_id.as_deref().filter(|s| !s.is_empty()) {
                Some(session) => format!("{}:{}", event.agent_id, session),
                None => event.event_id.clone(),
            }
        }
    }

    #[async_trait]
    impl ReceiptLogger for SignedReceiptLogger {
        async fn record(
            &self,
            event: &StoredAuditEvent,
            evidence: Option<&super::ReasoningOutcome>,
            usage: Option<&iaga_sentinel_cost::UsageData>,
            ctx: super::ReceiptContext<'_>,
        ) {
            let run_id = Self::run_id(event);
            let input_hash = Self::input_hash(event);
            // CRYPTO-POLICYHASH-7a: when the host has no Dictum overlay, the
            // caller passes the digest of the resolved workspace policy so the
            // receipt binds the YAML that actually decided. With an overlay
            // loaded the override is `None` and we keep the compiled bundle
            // digest configured at construction.
            let policy_hash = ctx.policy_hash.unwrap_or(&self.policy_hash);
            let dictum_trace = ctx.dictum_trace;

            // M3.5: lift ML evidence (model digests + scores) into the
            // receipt body. Empty / None when no reasoning engine is
            // wired or the engine produced no evidence, receipt stays
            // bit-identical to M2 in that case. Head-independent: computed
            // once and reused across retries.
            let (model_digests, ml_scores) = match evidence {
                Some(ev)
                    if !ev.model_digests.is_empty()
                        || ev
                            .scores
                            .as_object()
                            .map(|o| !o.is_empty())
                            .unwrap_or(false) =>
                {
                    let digests: Vec<iaga_sentinel_receipts::ModelDigest> = ev
                        .model_digests
                        .iter()
                        .map(|(name, sha)| iaga_sentinel_receipts::ModelDigest {
                            name: name.clone(),
                            sha256: sha.clone(),
                        })
                        .collect();
                    (digests, Some(MlScoreBundle(ev.scores.clone())))
                }
                _ => (vec![], None::<MlScoreBundle>),
            };

            // 1.2: optional drift-replay capture, gated by env. When
            // unset (default), all three fields stay `None` and are
            // elided from signing_bytes, 1.1 byte-equality preserved.
            let (pipeline_inputs_capture, apl_eval_trace, ml_inference_inputs) =
                if capture_enabled() {
                    let request_json =
                        serde_json::to_value(event).unwrap_or(serde_json::Value::Null);
                    let capture = PipelineInputsCapture {
                        request_json,
                        framework: "iaga-sentinel-core".into(),
                        payload_sha256: input_hash.clone(),
                    };
                    // PIP-DICTUM-UNBOUND / CRYPTO-POLICYHASH-7c: populate the
                    // real evaluation summary (was hardcoded 0/[]), and mirror
                    // the resolved policy hash.
                    let dictum_eval_trace = DictumEvalTrace {
                        policy_hash: policy_hash.to_string(),
                        policies_evaluated: dictum_trace.map(|d| d.policies_evaluated).unwrap_or(0),
                        policies_fired: dictum_trace
                            .map(|d| d.policies_fired.clone())
                            .unwrap_or_default(),
                        evidence_sha256: dictum_trace.and_then(|d| d.evidence_sha256.clone()),
                    };
                    let ml_inputs = evidence.map(|ev| MlInferenceInputs {
                        tokenized_digests: ev
                            .model_digests
                            .iter()
                            .map(|(name, sha)| MlTokenDigest {
                                model_name: name.clone(),
                                tokenized_sha256: sha.clone(),
                            })
                            .collect(),
                    });
                    (Some(capture), Some(dictum_eval_trace), ml_inputs)
                } else {
                    (None, None, None)
                };

            // Serialize append within this logger instance.
            let _guard = self.append_guard.lock().await;

            // SND-APPEND-DROP / SND-APPEND-RACE / OBS-RECEIPT-DROP: re-read the
            // head, rebuild the link, re-sign and re-append on a lost-head race
            // (DuplicateSeq / ChainViolation from a concurrent writer on the
            // same DB) instead of silently dropping the receipt. On success
            // emit `receipts.signed`; on a terminal error or retry exhaustion
            // emit `receipts.dropped` + error! so the operator has a signal
            // that the audit trail and the signed chain diverged.
            const MAX_ATTEMPTS: usize = 5;
            for attempt in 0..MAX_ATTEMPTS {
                let head = match self.store.head(&run_id).await {
                    Ok(h) => h,
                    Err(e) => {
                        warn!(run_id = %run_id, error = %e, "receipt head lookup failed");
                        break;
                    }
                };
                let (parent_hash, seq) = match chain_link(head.as_ref()) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(run_id = %run_id, error = %e, "receipt chain_link failed");
                        break;
                    }
                };

                let body = ReceiptBody {
                    run_id: run_id.clone(),
                    seq,
                    parent_hash,
                    input_hash: input_hash.clone(),
                    policy_hash: policy_hash.to_string(),
                    threat_feed_hash: ctx.threat_feed_hash.map(str::to_string),
                    plugin_digests: vec![],
                    model_digests: model_digests.clone(),
                    ml_scores: ml_scores.clone(),
                    verdict: Self::map_verdict(event.decision),
                    reasons: event.reasons.clone(),
                    risk_score: event.risk_score,
                    timestamp: event.timestamp.clone(),
                    signer_key_id: self.signer.key_id().to_string(),
                    pipeline_inputs_capture: pipeline_inputs_capture.clone(),
                    apl_eval_trace: apl_eval_trace.clone(),
                    ml_inference_inputs: ml_inference_inputs.clone(),
                    // 1.3.1: OSS enforcement is soft (no authoritative kernel
                    // ships in the community build), so every OSS receipt
                    // honestly records is_authoritative = false.
                    is_authoritative: Some(false),
                    // 1.5 cost-control: the resolved usage/cost ledger when the
                    // host reported usage for this action; `None` otherwise,
                    // which keeps the receipt byte-identical to pre-1.5.
                    usage: usage.cloned(),
                };

                let receipt = match self.signer.sign_body(body).await {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(run_id = %run_id, error = %e, "receipt signing failed");
                        break;
                    }
                };

                // Additive, opt-in: surface the receipt in the OpenTelemetry feed.
                #[cfg(feature = "otel-receipts")]
                crate::modules::telemetry::otel_emitter::emit_receipt_span(&receipt);

                match self.store.append(&receipt).await {
                    Ok(()) => {
                        emit_receipt_metric("iaga_sentinel.receipts.signed");
                        return;
                    }
                    Err(ReceiptError::DuplicateSeq { .. })
                    | Err(ReceiptError::ChainViolation { .. }) => {
                        warn!(
                            run_id = %run_id,
                            seq,
                            attempt,
                            "receipt append lost the head race; retrying"
                        );
                        continue;
                    }
                    Err(e) => {
                        warn!(run_id = %run_id, error = %e, "receipt append failed");
                        break;
                    }
                }
            }

            error!(
                run_id = %run_id,
                "receipt dropped (append error or retries exhausted); audit trail and signed chain may diverge"
            );
            // issue #23: record the divergence per run so the read API can surface
            // it. A compliance inspector comparing audit-event count to chain
            // length would otherwise see an unexplained gap in the signed material.
            if let Ok(mut dropped) = self.dropped_runs.lock() {
                *dropped.entry(run_id.clone()).or_insert(0) += 1;
            }
            emit_receipt_metric("iaga_sentinel.receipts.dropped");
        }

        async fn list_runs_json(&self, limit: u32) -> serde_json::Value {
            match self.store.list_runs(limit).await {
                Ok(runs) => serde_json::to_value(&runs).unwrap_or(serde_json::Value::Null),
                Err(e) => {
                    warn!(error = %e, "receipt list_runs failed");
                    serde_json::json!({ "error": e.to_string() })
                }
            }
        }

        async fn get_run_json(&self, run_id: &str) -> serde_json::Value {
            let receipts = match self.store.get_run(run_id).await {
                Ok(r) => r,
                Err(e) => {
                    return serde_json::json!({
                        "error": e.to_string(),
                        "receipts": [],
                        "verify": null,
                    });
                }
            };
            let verify = match self.store.verify_chain(run_id).await {
                Ok(status) => serde_json::to_value(&status).unwrap_or(serde_json::Value::Null),
                Err(e) => serde_json::json!({ "error": e.to_string() }),
            };
            // issue #23: a signed receipt lost for this run means the SQL audit
            // trail and the signed chain diverge. `verify` above only reflects the
            // receipts that ARE present, so it can report Valid despite the gap;
            // this flag is the missing API-visible signal of the divergence.
            let dropped_receipts = self
                .dropped_runs
                .lock()
                .map(|d| d.get(run_id).copied().unwrap_or(0))
                .unwrap_or(0);
            serde_json::json!({
                "runId": run_id,
                "receipts": serde_json::to_value(&receipts).unwrap_or(serde_json::Value::Null),
                "verify": verify,
                "receiptDropped": dropped_receipts > 0,
                "droppedReceipts": dropped_receipts,
                "signerKeyId": self.signer.key_id(),
                "policyHash": self.policy_hash,
            })
        }

        fn signer_key_id(&self) -> Option<String> {
            Some(self.signer.key_id().to_string())
        }

        fn policy_hash(&self) -> Option<String> {
            Some(self.policy_hash.clone())
        }
    }

    /// Emit a receipt-outcome counter into the OTel feed. `signed` on a
    /// successful append, `dropped` when the receipt was lost (append error
    /// or retry exhaustion). Kept attribute-free to avoid run_id cardinality
    /// blowup; the `error!` log carries the run_id for the dropped case.
    fn emit_receipt_metric(name: &str) {
        crate::modules::telemetry::otel_emitter::emit_counter(
            name,
            "IAGA Sentinel signed-receipt append outcome",
            1.0,
            std::collections::HashMap::new(),
        );
    }

    /// 1.2: opt-in trigger for the drift-replay capture. Default off.
    /// Accepts `1`, `true`, or `yes` (case-sensitive); anything else
    /// keeps the receipt bit-identical to 1.1.
    fn capture_enabled() -> bool {
        matches!(
            std::env::var("IAGA_SENTINEL_RECEIPT_CAPTURE").as_deref(),
            Ok("1") | Ok("true") | Ok("yes")
        )
    }

    /// Default policy hash placeholder for M2. In M3 Dictum will replace this
    /// with the SHA-256 of the compiled policy bundle.
    pub fn default_policy_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"iaga-sentinel-policy-v0");
        hex::encode(hasher.finalize())
    }

    /// Resolve the signer key path: env override `IAGA_SENTINEL_SIGNER_KEY_PATH`
    /// wins; otherwise `<HOME>/.iaga-sentinel/keys/receipt_signer.ed25519`.
    fn signer_key_path() -> Option<std::path::PathBuf> {
        if let Ok(p) = std::env::var("IAGA_SENTINEL_SIGNER_KEY_PATH") {
            return Some(std::path::PathBuf::from(p));
        }
        let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
        let mut p = std::path::PathBuf::from(home);
        p.push(".iaga-sentinel");
        p.push("keys");
        p.push("receipt_signer.ed25519");
        Some(p)
    }

    /// Public helper called from `pipeline::receipts::try_build_receipt_logger`.
    /// M5: supports `sqlite:` and `postgres://`/`postgresql://` URLs.
    /// M6: accepts an optional `policy_hash` override so Dictum-loaded
    /// hosts can embed the bundle digest in every receipt body.
    pub(super) async fn try_build(
        database_url: &str,
        policy_hash: Option<String>,
    ) -> Option<Arc<dyn super::ReceiptLogger>> {
        let key_path = match signer_key_path() {
            Some(p) => p,
            None => {
                tracing::warn!("receipts: cannot resolve signer key path; receipts disabled");
                return None;
            }
        };
        let signer = match LocalDiskSigner::load_or_create(&key_path) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, path = %key_path.display(), "receipts: signer load failed; receipts disabled");
                return None;
            }
        };
        let signer: Arc<dyn Signer> = Arc::new(signer);

        let store: Arc<dyn ReceiptStore> = if database_url.starts_with("sqlite:") {
            #[cfg(feature = "sqlite")]
            {
                use iaga_sentinel_receipts::SqliteReceiptStore;
                match SqliteReceiptStore::new(database_url, signer.verifying_key()).await {
                    Ok(s) => Arc::new(s) as Arc<dyn ReceiptStore>,
                    Err(e) => {
                        tracing::warn!(error = %e, "receipts: sqlite store open failed; receipts disabled");
                        return None;
                    }
                }
            }
            #[cfg(not(feature = "sqlite"))]
            {
                tracing::info!("receipts: sqlite URL but core built without `sqlite` feature; receipts disabled");
                return None;
            }
        } else if database_url.starts_with("postgres://")
            || database_url.starts_with("postgresql://")
        {
            #[cfg(feature = "postgres")]
            {
                use iaga_sentinel_receipts::PgReceiptStore;
                match PgReceiptStore::new(database_url, signer.verifying_key()).await {
                    Ok(s) => Arc::new(s) as Arc<dyn ReceiptStore>,
                    Err(e) => {
                        tracing::warn!(error = %e, "receipts: postgres store open failed; receipts disabled");
                        return None;
                    }
                }
            }
            #[cfg(not(feature = "postgres"))]
            {
                tracing::info!("receipts: postgres URL but core built without `postgres` feature; receipts disabled");
                return None;
            }
        } else {
            tracing::info!("receipts: unrecognized database_url scheme; receipts disabled");
            return None;
        };

        let resolved_policy_hash = policy_hash.unwrap_or_else(default_policy_hash);
        tracing::info!(
            key_id = signer.key_id(),
            path = %key_path.display(),
            policy_hash = %resolved_policy_hash,
            "receipts: signed action receipts enabled"
        );
        let logger = SignedReceiptLogger::new(store, signer, resolved_policy_hash);
        Some(Arc::new(logger) as Arc<dyn super::ReceiptLogger>)
    }

    #[cfg(test)]
    mod run_id_tests {
        use super::SignedReceiptLogger;
        use crate::core::types::{ActionType, GovernanceDecision, ReviewStatus, StoredAuditEvent};
        use crate::pipeline::receipts::{ReceiptContext, ReceiptLogger};
        use async_trait::async_trait;
        use iaga_sentinel_receipts::{
            ChainStatus, LocalDiskSigner, Receipt, ReceiptError, ReceiptStore, RunSummary, Signer,
        };
        use std::sync::Arc;

        fn event(session_id: Option<&str>) -> StoredAuditEvent {
            StoredAuditEvent {
                event_id: "evt-123".into(),
                agent_id: "a".into(),
                tenant_id: None,
                framework: "test".into(),
                action_type: ActionType::Http,
                tool_name: "t".into(),
                input_sha256: "deadbeef".into(),
                decision: GovernanceDecision::Allow,
                timestamp: "2026-06-13T00:00:00Z".into(),
                reasons: vec![],
                review_status: ReviewStatus::NotRequired,
                risk_score: 0,
                usage: None,
                session_id: session_id.map(|s| s.to_string()),
            }
        }

        #[test]
        fn run_id_qualifies_session_with_agent_then_falls_back_to_event_id() {
            // Explicit session -> all actions in it share one run_id (chained),
            // qualified by the agent so two principals can't collide on the same
            // session id (PIP-RUNID-COLLISION). The test event's agent_id is "a".
            assert_eq!(
                SignedReceiptLogger::run_id(&event(Some("sess-42"))),
                "a:sess-42"
            );
            // No session -> event_id (one receipt per run; byte-equality preserved).
            assert_eq!(SignedReceiptLogger::run_id(&event(None)), "evt-123");
            // An empty session string is treated as absent.
            assert_eq!(SignedReceiptLogger::run_id(&event(Some(""))), "evt-123");
        }

        /// A store whose `append` always fails, forcing the retry loop to exhaust
        /// and drop the receipt (issue #23).
        struct FailingStore;

        #[async_trait]
        impl ReceiptStore for FailingStore {
            async fn append(&self, _r: &Receipt) -> Result<(), ReceiptError> {
                Err(ReceiptError::ChainViolation {
                    seq: 0,
                    reason: "test: append always fails".into(),
                })
            }
            async fn head(&self, _run_id: &str) -> Result<Option<Receipt>, ReceiptError> {
                Ok(None)
            }
            async fn get_run(&self, _run_id: &str) -> Result<Vec<Receipt>, ReceiptError> {
                Ok(vec![])
            }
            async fn verify_chain(&self, _run_id: &str) -> Result<ChainStatus, ReceiptError> {
                Ok(ChainStatus::Empty)
            }
            async fn list_runs(&self, _limit: u32) -> Result<Vec<RunSummary>, ReceiptError> {
                Ok(vec![])
            }
        }

        #[tokio::test]
        async fn dropped_receipt_is_surfaced_on_get_run_json() {
            // issue #23: when a receipt is lost (append fails after retries) the
            // SQL audit row still exists but the signed chain has a gap. The read
            // API must expose that divergence, not just the log/metric.
            let logger = SignedReceiptLogger::new(
                Arc::new(FailingStore) as Arc<dyn ReceiptStore>,
                Arc::new(LocalDiskSigner::generate()) as Arc<dyn Signer>,
                "policy-test".to_string(),
            );
            // Session-less event -> run_id == event_id ("evt-123").
            logger
                .record(&event(None), None, None, ReceiptContext::default())
                .await;

            let run = logger.get_run_json("evt-123").await;
            assert_eq!(
                run["receiptDropped"],
                serde_json::json!(true),
                "a dropped receipt must be visible on GET /v1/receipts/{{run_id}}"
            );
            assert_eq!(run["droppedReceipts"], serde_json::json!(1));

            // A run that never dropped reports false.
            let clean = logger.get_run_json("some-other-run").await;
            assert_eq!(clean["receiptDropped"], serde_json::json!(false));
            assert_eq!(clean["droppedReceipts"], serde_json::json!(0));
        }
    }
}
