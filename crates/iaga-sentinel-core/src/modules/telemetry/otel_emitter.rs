//! LAYER 8, OpenTelemetry-Compatible Telemetry
//!
//! Emits OTEL-compatible spans & metrics in OTLP JSON format.
//! Zero external OTEL dependency, pure Rust structs matching the spec.

use std::collections::HashMap;
use std::sync::Mutex;

use once_cell::sync::Lazy;
use serde::Serialize;
// uuid used for trace/span IDs via rand

// ── Time ──

fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ── OTEL Span ──

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OtelSpan {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub name: String,
    pub kind: String,
    pub start_time_unix_nano: u64,
    pub end_time_unix_nano: u64,
    pub attributes: HashMap<String, serde_json::Value>,
    pub status: SpanStatus,
    pub events: Vec<SpanEvent>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpanStatus {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpanEvent {
    pub name: String,
    pub time_unix_nano: u64,
    pub attributes: HashMap<String, serde_json::Value>,
}

// ── OTEL Metric ──

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OtelMetric {
    pub name: String,
    pub description: String,
    pub unit: String,
    pub metric_type: String,
    pub value: f64,
    pub attributes: HashMap<String, serde_json::Value>,
    pub timestamp: u64,
}

// ── Telemetry Record ──

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TelemetryRecord {
    pub kind: String, // "span" or "metric"
    pub span: Option<OtelSpan>,
    pub metric: Option<OtelMetric>,
    pub timestamp: u64,
}

// ── Stores ──

static SPANS: Lazy<Mutex<Vec<OtelSpan>>> = Lazy::new(|| Mutex::new(Vec::new()));
static METRICS: Lazy<Mutex<Vec<OtelMetric>>> = Lazy::new(|| Mutex::new(Vec::new()));

const MAX_BUFFER: usize = 10_000;

fn store_span(span: &OtelSpan) {
    let mut buf = SPANS.lock().unwrap_or_else(|e| e.into_inner());
    if buf.len() >= MAX_BUFFER {
        let half = buf.len() / 2;
        buf.drain(0..half);
    }
    buf.push(span.clone());
}

fn store_metric(metric: &OtelMetric) {
    let mut buf = METRICS.lock().unwrap_or_else(|e| e.into_inner());
    if buf.len() >= MAX_BUFFER {
        let half = buf.len() / 2;
        buf.drain(0..half);
    }
    buf.push(metric.clone());
}

// ── ID Generation ──

fn trace_id() -> String {
    format!("{:032x}", rand::random::<u128>())
}

fn span_id() -> String {
    format!("{:016x}", rand::random::<u64>())
}

// ── Span Builder ──

pub struct SpanBuilder {
    trace_id: String,
    parent_span_id: Option<String>,
    name: String,
    kind: String,
    start: u64,
    attributes: HashMap<String, serde_json::Value>,
    events: Vec<SpanEvent>,
}

impl SpanBuilder {
    pub fn new(name: &str) -> Self {
        SpanBuilder {
            trace_id: trace_id(),
            parent_span_id: None,
            name: name.to_string(),
            kind: "INTERNAL".into(),
            start: now_ns(),
            attributes: HashMap::new(),
            events: Vec::new(),
        }
    }

    // ponytail: `with_trace_id` and `with_parent` used to sit here, both with
    // zero call sites - the trace id is always the one minted in `new` and no
    // caller ever builds a child span. The FIELDS stay: `trace_id` and
    // `parent_span_id` are serialized into `GovernanceResult.telemetry_span`
    // and served by GET /v1/telemetry/spans.

    pub fn with_kind(mut self, kind: &str) -> Self {
        self.kind = kind.to_string();
        self
    }

    pub fn attr(mut self, key: &str, value: serde_json::Value) -> Self {
        self.attributes.insert(key.to_string(), value);
        self
    }

    /// Bulk-set attributes, extending (and overriding on key collision) the
    /// builder's current set. Lets callers pass a fully-populated attribute
    /// map (e.g. the governance decision + every layer detail) instead of
    /// chaining one `.attr()` per key.
    pub fn attrs(mut self, attrs: HashMap<String, serde_json::Value>) -> Self {
        self.attributes.extend(attrs);
        self
    }

    pub fn event(mut self, name: &str, attrs: HashMap<String, serde_json::Value>) -> Self {
        self.events.push(SpanEvent {
            name: name.to_string(),
            time_unix_nano: now_ns(),
            attributes: attrs,
        });
        self
    }

    pub fn finish(self, status_code: &str, message: &str) -> OtelSpan {
        let span = OtelSpan {
            trace_id: self.trace_id,
            span_id: span_id(),
            parent_span_id: self.parent_span_id,
            name: self.name,
            kind: self.kind,
            start_time_unix_nano: self.start,
            end_time_unix_nano: now_ns(),
            attributes: self.attributes,
            status: SpanStatus {
                code: status_code.to_string(),
                message: message.to_string(),
            },
            events: self.events,
        };
        store_span(&span);
        span
    }
}

// ── Metric Helpers ──

pub fn emit_counter(
    name: &str,
    description: &str,
    value: f64,
    attrs: HashMap<String, serde_json::Value>,
) -> OtelMetric {
    let m = OtelMetric {
        name: name.to_string(),
        description: description.to_string(),
        unit: "1".into(),
        metric_type: "counter".into(),
        value,
        attributes: attrs,
        timestamp: now_ms(),
    };
    store_metric(&m);
    m
}

// ponytail: `emit_gauge` used to sit here, never called by anything. The
// "gauge" metric_type is still reachable through OtelMetric if a caller ever
// needs it; the emitter helper was speculative.

pub fn emit_histogram(
    name: &str,
    description: &str,
    value: f64,
    unit: &str,
    attrs: HashMap<String, serde_json::Value>,
) -> OtelMetric {
    let m = OtelMetric {
        name: name.to_string(),
        description: description.to_string(),
        unit: unit.to_string(),
        metric_type: "histogram".into(),
        value,
        attributes: attrs,
        timestamp: now_ms(),
    };
    store_metric(&m);
    m
}

// ── Pipeline Telemetry ──

pub fn emit_governance_span(
    agent_id: &str,
    tool_name: &str,
    action_type: &str,
    decision: &str,
    risk_score: u32,
    duration_ms: u64,
    layers_detail: HashMap<String, serde_json::Value>,
) -> OtelSpan {
    let mut attrs = HashMap::new();
    attrs.insert("agent.id".into(), serde_json::json!(agent_id));
    attrs.insert("tool.name".into(), serde_json::json!(tool_name));
    attrs.insert("action.type".into(), serde_json::json!(action_type));
    attrs.insert("governance.decision".into(), serde_json::json!(decision));
    attrs.insert("risk.score".into(), serde_json::json!(risk_score));
    attrs.insert(
        "pipeline.duration_ms".into(),
        serde_json::json!(duration_ms),
    );
    attrs.insert("service.name".into(), serde_json::json!("iaga-sentinel"));
    attrs.insert(
        "service.version".into(),
        serde_json::json!(env!("CARGO_PKG_VERSION")),
    );

    for (k, v) in layers_detail {
        attrs.insert(format!("layer.{}", k), v);
    }

    let status = match decision {
        "block" => ("ERROR", "Action blocked by governance"),
        "human_review" => ("OK", "Action requires human review"),
        _ => ("OK", "Action allowed"),
    };

    SpanBuilder::new("iaga_sentinel.governance")
        .with_kind("SERVER")
        .attrs(attrs)
        .finish(status.0, status.1)
}

pub fn emit_pipeline_metrics(decision: &str, risk_score: u32, duration_ms: u64, action_type: &str) {
    let mut attrs = HashMap::new();
    attrs.insert("decision".into(), serde_json::json!(decision));
    attrs.insert("action_type".into(), serde_json::json!(action_type));

    emit_counter(
        "iaga_sentinel.requests.total",
        "Total governance requests",
        1.0,
        attrs.clone(),
    );

    if decision == "block" {
        emit_counter(
            "iaga_sentinel.blocks.total",
            "Total blocked actions",
            1.0,
            attrs.clone(),
        );
    }

    emit_histogram(
        "iaga_sentinel.risk_score",
        "Risk score distribution",
        risk_score as f64,
        "score",
        attrs.clone(),
    );

    emit_histogram(
        "iaga_sentinel.pipeline.duration",
        "Pipeline execution time",
        duration_ms as f64,
        "ms",
        attrs,
    );
}

// ── Receipt Telemetry ──

/// Emit a signed governance receipt as an OpenTelemetry span into the
/// in-process telemetry feed, so it surfaces on `/v1/telemetry/spans` and
/// `/v1/telemetry/export` and any OTel backend that scrapes them. Additive
/// and feature-gated (`otel-receipts`). It does not push to a remote OTLP
/// collector; that is a later step.
#[cfg(feature = "otel-receipts")]
pub fn emit_receipt_span(receipt: &iaga_sentinel_receipts::Receipt) -> OtelSpan {
    use iaga_sentinel_receipts::Verdict;
    let b = &receipt.body;
    let verdict = match b.verdict {
        Verdict::Allow => "allow",
        Verdict::Review => "review",
        Verdict::Block => "block",
    };
    let status = match b.verdict {
        Verdict::Block => ("ERROR", "receipt: blocked"),
        _ => ("OK", "receipt recorded"),
    };
    let sig_prefix: String = receipt.signature.chars().take(16).collect();
    // 1.3.1: roadmap-named attribute keys. `iaga.receipt.id` is the stable
    // (run_id, seq) identity; `iaga.chain.head` is this receipt's body hash
    // (the new chain head after append); `iaga.policy.verdict` is the
    // decision. The existing `receipt.*` keys are kept as back-compat aliases.
    //
    // This span describes a governance *verdict*, not an LLM call: it carries
    // `iaga.*` keys, not the OpenTelemetry `gen_ai.*` semantic conventions,
    // which model prompts/tokens/model-ids that the verdict surface does not
    // own. Emitting `gen_ai.*` here would misattribute conventions IAGA can't
    // populate honestly, so it is deliberately not done (the earlier
    // "lands in 1.4" plan is dropped).
    let receipt_id = format!("{}:{}", b.run_id, b.seq);
    let chain_head = b.body_hash().map(hex::encode).unwrap_or_default();
    SpanBuilder::new("iaga_sentinel.receipt")
        .with_kind("INTERNAL")
        .attr("service.name", serde_json::json!("iaga-sentinel"))
        .attr(
            "service.version",
            serde_json::json!(env!("CARGO_PKG_VERSION")),
        )
        .attr("iaga.receipt.id", serde_json::json!(receipt_id))
        .attr("iaga.chain.head", serde_json::json!(chain_head))
        .attr("iaga.policy.verdict", serde_json::json!(verdict))
        .attr(
            "iaga.is_authoritative",
            serde_json::json!(b.is_authoritative),
        )
        .attr("receipt.runId", serde_json::json!(b.run_id))
        .attr("receipt.seq", serde_json::json!(b.seq))
        .attr("receipt.verdict", serde_json::json!(verdict))
        .attr("receipt.inputHash", serde_json::json!(b.input_hash))
        .attr("receipt.policyHash", serde_json::json!(b.policy_hash))
        .attr("receipt.riskScore", serde_json::json!(b.risk_score))
        .attr("receipt.signerKeyId", serde_json::json!(b.signer_key_id))
        .attr("receipt.parentHash", serde_json::json!(b.parent_hash))
        .attr("receipt.timestamp", serde_json::json!(b.timestamp))
        .attr("receipt.signaturePrefix", serde_json::json!(sig_prefix))
        .finish(status.0, status.1)
}

// ── Export ──

pub fn export_otlp_json(limit: usize) -> Vec<TelemetryRecord> {
    let spans = SPANS.lock().unwrap_or_else(|e| e.into_inner());
    let metrics = METRICS.lock().unwrap_or_else(|e| e.into_inner());
    let mut records = Vec::new();

    for span in spans.iter().rev().take(limit) {
        records.push(TelemetryRecord {
            kind: "span".into(),
            span: Some(span.clone()),
            metric: None,
            timestamp: span.end_time_unix_nano / 1_000_000,
        });
    }

    for metric in metrics.iter().rev().take(limit) {
        records.push(TelemetryRecord {
            kind: "metric".into(),
            span: None,
            metric: Some(metric.clone()),
            timestamp: metric.timestamp,
        });
    }

    records.sort_by_key(|r| std::cmp::Reverse(r.timestamp));
    records.truncate(limit);
    records
}

pub fn get_recent_spans(limit: usize) -> Vec<OtelSpan> {
    let spans = SPANS.lock().unwrap_or_else(|e| e.into_inner());
    spans.iter().rev().take(limit).cloned().collect()
}

pub fn get_recent_metrics(limit: usize) -> Vec<OtelMetric> {
    let metrics = METRICS.lock().unwrap_or_else(|e| e.into_inner());
    metrics.iter().rev().take(limit).cloned().collect()
}

// ponytail: `clear_telemetry()` used to sit here with no callers - not even a
// test. Both maps are already bounded by `store_span`/`store_metric`.

#[cfg(all(test, feature = "otel-receipts"))]
mod receipt_span_tests {
    use super::*;
    use iaga_sentinel_receipts::{ReceiptBody, ReceiptSigner, Verdict};

    #[test]
    fn receipt_span_carries_receipt_attributes() {
        let signer = ReceiptSigner::generate();
        let body = ReceiptBody {
            run_id: "otel-test-run-xyz".into(),
            seq: 0,
            parent_hash: None,
            input_hash: "a".repeat(64),
            policy_hash: "b".repeat(64),
            threat_feed_hash: None,
            plugin_digests: vec![],
            model_digests: vec![],
            ml_scores: None,
            verdict: Verdict::Block,
            reasons: vec!["nope".into()],
            risk_score: 88,
            timestamp: "2026-06-06T00:00:00Z".into(),
            signer_key_id: signer.key_id().into(),
            pipeline_inputs_capture: None,
            apl_eval_trace: None,
            ml_inference_inputs: None,
            is_authoritative: None,
            usage: None,
        };
        let receipt = signer.sign(body).expect("sign ok");
        emit_receipt_span(&receipt);

        // Global span buffer is shared across tests, so locate ours by run id.
        let spans = get_recent_spans(500);
        let span = spans
            .iter()
            .find(|s| {
                s.name == "iaga_sentinel.receipt"
                    && s.attributes.get("receipt.runId")
                        == Some(&serde_json::json!("otel-test-run-xyz"))
            })
            .expect("receipt span present");
        assert_eq!(
            span.attributes.get("receipt.verdict"),
            Some(&serde_json::json!("block"))
        );
        assert_eq!(
            span.attributes.get("receipt.seq"),
            Some(&serde_json::json!(0))
        );
        assert_eq!(
            span.attributes.get("receipt.riskScore"),
            Some(&serde_json::json!(88))
        );
        assert_eq!(
            span.attributes.get("receipt.signerKeyId"),
            Some(&serde_json::json!(signer.key_id()))
        );
        // 1.3.1: roadmap-named keys present alongside the `receipt.*` aliases.
        assert_eq!(
            span.attributes.get("iaga.receipt.id"),
            Some(&serde_json::json!("otel-test-run-xyz:0"))
        );
        assert_eq!(
            span.attributes.get("iaga.policy.verdict"),
            Some(&serde_json::json!("block"))
        );
        let chain_head = span
            .attributes
            .get("iaga.chain.head")
            .and_then(|v| v.as_str())
            .expect("iaga.chain.head present");
        assert_eq!(chain_head.len(), 64, "chain head is a hex SHA-256");
    }
}

#[cfg(test)]
mod governance_span_tests {
    use super::*;

    /// OBS-OTEL-SPAN-1: the governance span must carry the full decision
    /// context, not just `agent.id`. Before the fix it dropped every
    /// attribute except the agent id.
    #[test]
    fn governance_span_carries_decision_and_layers() {
        let mut layers = HashMap::new();
        layers.insert("adaptive".into(), serde_json::json!(42));
        let span = emit_governance_span("agent-xyz", "bash", "shell", "block", 91, 7, layers);
        assert_eq!(
            span.attributes.get("governance.decision"),
            Some(&serde_json::json!("block"))
        );
        assert_eq!(
            span.attributes.get("risk.score"),
            Some(&serde_json::json!(91))
        );
        assert_eq!(
            span.attributes.get("agent.id"),
            Some(&serde_json::json!("agent-xyz"))
        );
        assert_eq!(
            span.attributes.get("layer.adaptive"),
            Some(&serde_json::json!(42))
        );
    }
}
