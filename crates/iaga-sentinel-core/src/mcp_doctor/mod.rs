//! `iaga mcp-doctor` — OSS health-check for an MCP endpoint.
//!
//! Spawns a target MCP server over stdio (the only MCP transport this build
//! speaks, same as `proxy` / `mcp-server`), drives the `initialize` +
//! `tools/list` handshake as a *client* — the proxy is the only other place we
//! talk MCP and it only *relays*, so this is the first real MCP client driver in
//! the tree — checks each advertised tool's `inputSchema`, optionally probes one
//! named tool, and runs every listed tool through the **same** governance
//! interception the `proxy` uses, so the report shows which calls the policy
//! engine would allow / review / block.
//!
//! It is a cooperative diagnostic. Nothing here is authoritative enforcement and
//! [`DoctorReport::authoritative`] is always `false`, mirroring the
//! `is_authoritative:false` posture of every OSS receipt.
//!
//! Side effect: the governance step runs the real pipeline, which writes a
//! signed receipt per listed tool, the same as any governed call. `mcp-doctor`
//! is therefore *not* a pure read against the receipt store — that is
//! intentional (it proves each `tools/call` is encapsulable in a receipt) and is
//! noted in the subcommand `--help`.

use std::sync::Arc;

use serde::Serialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

use crate::core::errors::SentinelError;
use crate::mcp_proxy::protocol::{JsonRpcRequest, JsonRpcResponse, McpToolCallParams, McpToolInfo};
use crate::mcp_proxy::tool_interceptor::{intercept_tool_call, InterceptResult};
use crate::server::app_state::AppState;

/// What [`run_doctor`] needs to probe one endpoint.
pub struct DoctorConfig {
    /// Agent the governance checks are attributed to.
    pub agent_id: String,
    /// Program to launch as the downstream MCP server.
    pub command: String,
    /// Arguments for the downstream command.
    pub args: Vec<String>,
    /// If set, actually call this one tool with empty arguments.
    pub probe_tool: Option<String>,
}

/// Structured result of a doctor run. `camelCase` so `--format json` matches the
/// rest of the wire surface.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DoctorReport {
    pub server_command: String,
    pub initialized: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
    pub tools_listed: usize,
    pub tools: Vec<ToolCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub probe: Option<ProbeResult>,
    /// Always `false`: OSS governance is cooperative, never authoritative.
    pub authoritative: bool,
    /// Set when the handshake itself failed; the run stops early.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Per-tool check: schema shape + what governance would decide.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolCheck {
    pub name: String,
    pub schema_present: bool,
    pub schema_well_formed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_reason: Option<String>,
    /// `allow` | `review` | `block`.
    pub governance_decision: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub governance_reasons: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeResult {
    pub tool: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A minimal stdio MCP **client**: spawn the server, write one JSON-RPC line,
/// read one back. Mirrors the proxy's `forward_and_relay`, minus governance.
struct McpClient {
    child: Child,
    writer: ChildStdin,
    reader: tokio::io::Lines<BufReader<ChildStdout>>,
}

impl McpClient {
    fn spawn(command: &str, args: &[String]) -> Result<Self, SentinelError> {
        let mut cmd = Command::new(command);
        cmd.args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit());
        let mut child = cmd.spawn().map_err(|e| {
            SentinelError::Proxy(format!("failed to spawn MCP server '{command}': {e}"))
        })?;
        let writer = child
            .stdin
            .take()
            .ok_or_else(|| SentinelError::Proxy("failed to capture MCP server stdin".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| SentinelError::Proxy("failed to capture MCP server stdout".into()))?;
        let reader = BufReader::new(stdout).lines();
        Ok(Self {
            child,
            writer,
            reader,
        })
    }

    /// Send one request and read one response line.
    async fn call(
        &mut self,
        id: i64,
        method: &str,
        params: serde_json::Value,
    ) -> Result<JsonRpcResponse, SentinelError> {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(serde_json::json!(id)),
            method: method.to_string(),
            params,
        };
        self.write_line(&req, method).await?;
        // Read until a JSON-RPC object: a well-behaved MCP server keeps stdout
        // pure JSON-RPC, but some print a startup banner or stray log line, so
        // skip anything that isn't an object rather than failing the handshake.
        loop {
            match self
                .reader
                .next_line()
                .await
                .map_err(|e| SentinelError::Proxy(format!("read {method}: {e}")))?
            {
                Some(line) => {
                    if !line.trim_start().starts_with('{') {
                        continue;
                    }
                    return serde_json::from_str(&line).map_err(|e| {
                        SentinelError::Proxy(format!("bad JSON-RPC for {method}: {e}"))
                    });
                }
                None => {
                    return Err(SentinelError::Proxy(format!(
                        "MCP server closed before responding to {method}"
                    )))
                }
            }
        }
    }

    /// Send a notification (no id, no response expected).
    async fn notify(
        &mut self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<(), SentinelError> {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: None,
            method: method.to_string(),
            params,
        };
        self.write_line(&req, method).await
    }

    async fn write_line(
        &mut self,
        req: &JsonRpcRequest,
        method: &str,
    ) -> Result<(), SentinelError> {
        let line = serde_json::to_string(req)
            .map_err(|e| SentinelError::Proxy(format!("serialize {method}: {e}")))?;
        self.writer
            .write_all(line.as_bytes())
            .await
            .map_err(|e| SentinelError::Proxy(format!("write {method}: {e}")))?;
        self.writer
            .write_all(b"\n")
            .await
            .map_err(|e| SentinelError::Proxy(format!("write {method}: {e}")))?;
        self.writer
            .flush()
            .await
            .map_err(|e| SentinelError::Proxy(format!("flush {method}: {e}")))?;
        Ok(())
    }

    async fn close(&mut self) {
        let _ = self.child.kill().await;
    }
}

fn initialize_params() -> serde_json::Value {
    serde_json::json!({
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": { "name": "iaga-mcp-doctor", "version": env!("CARGO_PKG_VERSION") }
    })
}

/// Minimal `inputSchema` well-formedness: present, a JSON object, and shaped like
/// an object schema (`"type":"object"` or a `properties` object). Returns
/// `(present, well_formed, reason_when_not_ok)`. This is a *shape* check, not a
/// full JSON-Schema validator — that distinction is stated in the CHANGELOG and
/// `--help` so the report can't be read as a conformance certificate.
fn check_schema(schema: &Option<serde_json::Value>) -> (bool, bool, Option<String>) {
    match schema {
        None => (false, false, Some("no inputSchema advertised".into())),
        Some(v) => match v.as_object() {
            None => (true, false, Some("inputSchema is not a JSON object".into())),
            Some(obj) => {
                let type_is_object = obj.get("type").and_then(|t| t.as_str()) == Some("object");
                let has_properties = obj
                    .get("properties")
                    .map(|p| p.is_object())
                    .unwrap_or(false);
                if type_is_object || has_properties {
                    (true, true, None)
                } else {
                    (
                        true,
                        false,
                        Some(
                            "inputSchema is a JSON object but not an object schema (no \"type\":\"object\" or \"properties\")"
                                .into(),
                        ),
                    )
                }
            }
        },
    }
}

/// Drive the full doctor flow against one endpoint. Never panics; any transport
/// failure is captured in [`DoctorReport::error`] and the run stops early.
pub async fn run_doctor(state: &Arc<AppState>, config: DoctorConfig) -> DoctorReport {
    let server_command = format!("{} {}", config.command, config.args.join(" "))
        .trim()
        .to_string();
    let mut report = DoctorReport {
        server_command,
        initialized: false,
        server_name: None,
        server_version: None,
        protocol_version: None,
        tools_listed: 0,
        tools: Vec::new(),
        probe: None,
        authoritative: false,
        error: None,
    };

    let mut client = match McpClient::spawn(&config.command, &config.args) {
        Ok(c) => c,
        Err(e) => {
            report.error = Some(e.to_string());
            return report;
        }
    };

    // 1. initialize
    match client.call(1, "initialize", initialize_params()).await {
        Ok(resp) => {
            if let Some(err) = resp.error {
                report.error = Some(format!("initialize returned error: {}", err.message));
                client.close().await;
                return report;
            }
            let result = resp.result.unwrap_or_default();
            report.initialized = true;
            report.protocol_version = result
                .get("protocolVersion")
                .and_then(|v| v.as_str())
                .map(String::from);
            report.server_name = result
                .pointer("/serverInfo/name")
                .and_then(|v| v.as_str())
                .map(String::from);
            report.server_version = result
                .pointer("/serverInfo/version")
                .and_then(|v| v.as_str())
                .map(String::from);
        }
        Err(e) => {
            report.error = Some(format!("initialize failed: {e}"));
            client.close().await;
            return report;
        }
    }

    // 2. notifications/initialized (best-effort; servers that ignore it are fine)
    let _ = client
        .notify("notifications/initialized", serde_json::json!({}))
        .await;

    // 3. tools/list
    let tools: Vec<McpToolInfo> = match client.call(2, "tools/list", serde_json::json!({})).await {
        Ok(resp) => {
            if let Some(err) = resp.error {
                report.error = Some(format!("tools/list returned error: {}", err.message));
                client.close().await;
                return report;
            }
            resp.result
                .and_then(|r| r.get("tools").cloned())
                .and_then(|t| serde_json::from_value(t).ok())
                .unwrap_or_default()
        }
        Err(e) => {
            report.error = Some(format!("tools/list failed: {e}"));
            client.close().await;
            return report;
        }
    };
    report.tools_listed = tools.len();

    // 4. per-tool: schema shape + governance encapsulability (real pipeline run)
    // One doctor invocation gets one run identity; without it, its N governed
    // checks were N unrelated one-receipt runs.
    let session_id = format!("mcp-doctor-{}", uuid::Uuid::new_v4());
    for tool in &tools {
        let (schema_present, schema_well_formed, schema_reason) = check_schema(&tool.input_schema);
        let params = McpToolCallParams {
            name: tool.name.clone(),
            arguments: Default::default(),
        };
        let (decision, reasons) =
            match intercept_tool_call(state, &config.agent_id, &session_id, &params).await {
                InterceptResult::Allow => ("allow".to_string(), Vec::new()),
                InterceptResult::Review { risk_score, .. } => (
                    "review".to_string(),
                    vec![format!("risk score {risk_score}")],
                ),
                InterceptResult::Block { reasons, .. } => ("block".to_string(), reasons),
            };
        report.tools.push(ToolCheck {
            name: tool.name.clone(),
            schema_present,
            schema_well_formed,
            schema_reason,
            governance_decision: decision,
            governance_reasons: reasons,
        });
    }

    // 5. optional probe (actually calls the tool)
    if let Some(probe_tool) = &config.probe_tool {
        let params = serde_json::json!({ "name": probe_tool, "arguments": {} });
        let probe = match client.call(99, "tools/call", params).await {
            Ok(resp) => match resp.error {
                Some(err) => ProbeResult {
                    tool: probe_tool.clone(),
                    ok: false,
                    error: Some(err.message),
                },
                None => ProbeResult {
                    tool: probe_tool.clone(),
                    ok: true,
                    error: None,
                },
            },
            Err(e) => ProbeResult {
                tool: probe_tool.clone(),
                ok: false,
                error: Some(e.to_string()),
            },
        };
        report.probe = Some(probe);
    }

    client.close().await;
    report
}

impl DoctorReport {
    /// Exit code: 0 = healthy, 1 = handshake failed, a tool schema is not
    /// well-formed, or an explicitly requested probe failed. Lets `mcp-doctor`
    /// slot into CI as a gate.
    ///
    /// The probe used to be excluded, so `--probe-tool X` reported
    /// `probe: FAILED` in its own output and still exited 0 — the one flag whose
    /// entire purpose is "does calling this actually work" could not gate the
    /// CI job it exists for. A probe is only run when the operator asks for it
    /// by name, so failing on it cannot surprise anyone who did not.
    pub fn exit_code(&self) -> i32 {
        if !self.initialized || self.error.is_some() {
            return 1;
        }
        if self.tools.iter().any(|t| !t.schema_well_formed) {
            return 1;
        }
        if self.probe.as_ref().is_some_and(|p| !p.ok) {
            return 1;
        }
        0
    }

    /// Human-readable table for `--format table`.
    pub fn render_table(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("MCP endpoint: {}\n", self.server_command));
        if let Some(err) = &self.error {
            out.push_str(&format!("  handshake: FAILED — {err}\n"));
            return out;
        }
        let server = match (&self.server_name, &self.server_version) {
            (Some(n), Some(v)) => format!("{n} {v}"),
            (Some(n), None) => n.clone(),
            _ => "<unknown>".to_string(),
        };
        out.push_str(&format!(
            "  initialize: OK  (server={server}, protocol={})\n",
            self.protocol_version.as_deref().unwrap_or("<unknown>")
        ));
        out.push_str(&format!("  tools/list: {} tool(s)\n", self.tools_listed));
        out.push_str("  authoritative: false  (cooperative diagnostics; not enforcement)\n");
        for t in &self.tools {
            let schema = if t.schema_well_formed {
                "schema OK".to_string()
            } else {
                format!(
                    "schema BAD ({})",
                    t.schema_reason.as_deref().unwrap_or("malformed")
                )
            };
            let gov = if t.governance_reasons.is_empty() {
                t.governance_decision.clone()
            } else {
                format!(
                    "{} [{}]",
                    t.governance_decision,
                    t.governance_reasons.join("; ")
                )
            };
            out.push_str(&format!(
                "    - {:<28} {schema:<26} governance={gov}\n",
                t.name
            ));
        }
        if let Some(p) = &self.probe {
            let status = if p.ok {
                "OK".to_string()
            } else {
                format!("FAILED — {}", p.error.as_deref().unwrap_or("error"))
            };
            out.push_str(&format!("  probe {}: {status}\n", p.tool));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_present_object_is_well_formed() {
        let s = Some(serde_json::json!({ "type": "object", "properties": {} }));
        let (present, ok, reason) = check_schema(&s);
        assert!(present && ok && reason.is_none());
    }

    #[test]
    fn schema_properties_only_is_well_formed() {
        let s = Some(serde_json::json!({ "properties": { "x": { "type": "string" } } }));
        let (present, ok, _) = check_schema(&s);
        assert!(present && ok);
    }

    #[test]
    fn schema_missing_is_flagged() {
        let (present, ok, reason) = check_schema(&None);
        assert!(!present && !ok && reason.is_some());
    }

    #[test]
    fn schema_non_object_is_flagged() {
        let s = Some(serde_json::json!("not-a-schema"));
        let (present, ok, reason) = check_schema(&s);
        assert!(present && !ok && reason.is_some());
    }

    #[test]
    fn schema_object_without_object_shape_is_flagged() {
        let s = Some(serde_json::json!({ "type": "string" }));
        let (present, ok, reason) = check_schema(&s);
        assert!(present && !ok && reason.is_some());
    }

    #[test]
    fn exit_code_is_one_on_handshake_failure() {
        let mut r = DoctorReport {
            server_command: "x".into(),
            initialized: false,
            server_name: None,
            server_version: None,
            protocol_version: None,
            tools_listed: 0,
            tools: Vec::new(),
            probe: None,
            authoritative: false,
            error: Some("boom".into()),
        };
        assert_eq!(r.exit_code(), 1);
        r.initialized = true;
        r.error = None;
        assert_eq!(r.exit_code(), 0);
    }

    #[test]
    fn report_is_never_authoritative() {
        let r = DoctorReport {
            server_command: "x".into(),
            initialized: true,
            server_name: None,
            server_version: None,
            protocol_version: None,
            tools_listed: 0,
            tools: Vec::new(),
            probe: None,
            authoritative: false,
            error: None,
        };
        assert!(!r.authoritative);
    }
}

#[cfg(test)]
mod exit_code_tests {
    use super::{DoctorReport, ProbeResult};

    fn healthy() -> DoctorReport {
        DoctorReport {
            server_command: "iaga mcp-server".into(),
            initialized: true,
            server_name: Some("iaga".into()),
            server_version: Some("2.1.0".into()),
            protocol_version: Some("2024-11-05".into()),
            tools_listed: 0,
            tools: Vec::new(),
            probe: None,
            authoritative: false,
            error: None,
        }
    }

    #[test]
    fn a_healthy_report_with_no_probe_exits_zero() {
        assert_eq!(healthy().exit_code(), 0);
    }

    #[test]
    fn a_failed_handshake_exits_one() {
        let mut r = healthy();
        r.initialized = false;
        assert_eq!(r.exit_code(), 1);
    }

    /// The measured defect: `--probe-tool` printed `FAILED` and exited 0, so the
    /// one flag whose purpose is "does calling this work" could not gate CI.
    #[test]
    fn a_failed_probe_exits_one() {
        let mut r = healthy();
        r.probe = Some(ProbeResult {
            tool: "search".into(),
            ok: false,
            error: Some("downstream refused".into()),
        });
        assert_eq!(
            r.exit_code(),
            1,
            "a probe the operator explicitly asked for must gate the exit code"
        );
    }

    #[test]
    fn a_successful_probe_still_exits_zero() {
        let mut r = healthy();
        r.probe = Some(ProbeResult {
            tool: "search".into(),
            ok: true,
            error: None,
        });
        assert_eq!(r.exit_code(), 0);
    }
}
