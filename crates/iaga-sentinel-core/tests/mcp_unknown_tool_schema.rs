//! A tool this build has no schema for is not a schema VIOLATION.
//!
//! `validate_schema` knows four names — `filesystem.read`, `filesystem.write`,
//! `terminal.exec`, `http.fetch` — and answered `(false, "no MCP schema
//! registered for tool X")` for everything else. `execute_pipeline` then turns
//! any `!valid` into an unconditional `minimum_decision = Block`.
//!
//! Together that made `iaga proxy` useless against every real MCP server:
//! measured end to end, a fully registered agent, a workspace policy listing the
//! downstream tool at `maxDecision: allow`, and a harmless read still came back
//! `block` on 100% of tool calls. No configuration could allow one, because the
//! refusal happened before policy was consulted. A governance layer that denies
//! everything is not strict, it is broken — operators turn it off.
//!
//! "I have no schema for this" and "this payload is malformed" are different
//! statements and only the second is a finding that should gate. The unknown
//! case is now advisory: it is recorded in the evidence, and the layers that DO
//! know the tool — the workspace tool registry, the domain allowlist, taint,
//! the firewall — decide the verdict. An unregistered tool is still refused by
//! `approvedTools`; it is simply refused by the layer that actually knows.

use std::collections::HashMap;

use iaga_sentinel::modules::protocol::mcp_tool_schemas::validate_schema;
use serde_json::{json, Value};

fn payload(pairs: &[(&str, Value)]) -> HashMap<String, Value> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), v.clone()))
        .collect()
}

/// Tool names taken from real MCP servers. None of them can be a hard failure.
#[test]
fn a_tool_with_no_registered_schema_is_valid_but_recorded() {
    for tool in [
        "search",
        "read_file",
        "github.create_issue",
        "brave_web_search",
        "sqlite.query",
        "everything.echo",
    ] {
        let (valid, findings) = validate_schema(tool, &payload(&[("q", json!("hello"))]));
        assert!(
            valid,
            "{tool}: an unknown tool must not be a schema violation — that is what \
             blocked 100% of proxied calls. findings: {findings:?}"
        );
        assert!(
            findings.iter().any(|f| f.contains(tool)),
            "{tool}: the gap must still be recorded in the evidence, findings: {findings:?}"
        );
    }
}

/// The four known schemas keep gating: a malformed payload is still invalid.
#[test]
fn a_known_tool_with_a_malformed_payload_is_still_a_violation() {
    let (valid, findings) = validate_schema("filesystem.read", &payload(&[]));
    assert!(
        !valid,
        "a read with no path must fail, findings: {findings:?}"
    );

    let (valid, findings) = validate_schema("http.fetch", &payload(&[("method", json!("GET"))]));
    assert!(
        !valid,
        "an http.fetch with no destination must fail, findings: {findings:?}"
    );

    let (valid, findings) = validate_schema(
        "http.fetch",
        &payload(&[("method", json!("TRACE")), ("url", json!("https://x/y"))]),
    );
    assert!(
        !valid,
        "an unsupported method must fail, findings: {findings:?}"
    );
}

/// And a well-formed payload for a known tool still passes.
#[test]
fn a_known_tool_with_a_good_payload_still_passes() {
    let (valid, _) = validate_schema(
        "http.fetch",
        &payload(&[
            ("method", json!("GET")),
            ("url", json!("https://api.github.com/repos")),
            ("intent", json!("read the repo list")),
        ]),
    );
    assert!(valid, "a well-formed http.fetch must pass");
}
