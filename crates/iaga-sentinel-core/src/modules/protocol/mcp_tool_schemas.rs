use serde_json::Value;
use std::collections::HashMap;

/// Validates payload fields against known MCP tool schemas.
/// Returns `(valid, findings)`.
///
/// `valid` reflects only the *structural* requirements a tool cannot act without
/// (a read needs a `path`, an HTTP call needs a `method` + `destination`, …).
/// `intent` is advisory everywhere: it enriches the evidence trail but is not a
/// security control, so a missing/short intent produces a soft finding and never
/// fails validation. Forcing a benign, well-formed action to Block merely because
/// it omitted an `intent` string was a footgun for MCP self-connecting agents.
pub fn validate_schema(tool_name: &str, payload: &HashMap<String, Value>) -> (bool, Vec<String>) {
    match tool_name {
        "filesystem.read" => validate_filesystem_read(payload),
        "filesystem.write" => validate_filesystem_write(payload),
        "terminal.exec" => validate_terminal_exec(payload),
        "http.fetch" => validate_http_fetch(payload),
        // ADVISORY, not a violation. "I have no schema for this tool" and "this
        // payload is malformed" are different statements, and only the second
        // should gate.
        //
        // Returning `false` here made `iaga proxy` unusable against every real
        // MCP server: `execute_pipeline` turns any `!valid` into an
        // unconditional `minimum_decision = Block`, so a fully registered agent
        // with a workspace policy listing the downstream tool at
        // `maxDecision: allow` still got `block` on 100% of tool calls — the
        // refusal landed before policy was ever consulted, and no configuration
        // could lift it. Four hardcoded names cannot be the allowlist for an
        // open protocol.
        //
        // Nothing is smuggled through: an unregistered tool is still refused by
        // the workspace tool registry (`approvedTools`), and the domain
        // allowlist, taint tracker and injection firewall all still run. The
        // gap is recorded in the findings so the evidence says plainly that no
        // structural check was available for this tool.
        _ => (
            true,
            vec![format!(
                "schema: advisory — no MCP schema registered for tool {tool_name}; \
                 structural validation skipped, policy layers still applied"
            )],
        ),
    }
}

/// `intent` is advisory context for the receipt, not a gate. Record a soft
/// finding when it is missing/short/non-string, but never fail validation on it.
fn check_intent_advisory(payload: &HashMap<String, Value>, advisory: &mut Vec<String>) {
    match payload.get("intent") {
        Some(Value::String(s)) if s.len() >= 3 => {}
        Some(Value::String(_)) => advisory.push(
            "intent: advisory — provide at least 3 characters for clearer evidence".to_string(),
        ),
        Some(_) => advisory.push("intent: advisory — expected a string".to_string()),
        None => {
            advisory.push("intent: advisory — omitted; include it for clearer evidence".to_string())
        }
    }
}

/// Combine hard (validity-affecting) findings with soft advisories into the
/// `(valid, findings)` contract. When everything hard passes, the action is valid
/// regardless of advisories; a clean payload still reports the canonical match
/// message so existing callers see unchanged output.
fn finalize(hard: Vec<String>, mut advisory: Vec<String>) -> (bool, Vec<String>) {
    if hard.is_empty() {
        if advisory.is_empty() {
            (true, vec!["payload matched MCP tool schema".to_string()])
        } else {
            (true, advisory)
        }
    } else {
        let mut findings = hard;
        findings.append(&mut advisory);
        (false, findings)
    }
}

fn validate_filesystem_read(payload: &HashMap<String, Value>) -> (bool, Vec<String>) {
    let mut hard = Vec::new();
    match payload.get("path") {
        Some(Value::String(s)) if !s.is_empty() => {}
        _ => hard.push("path: Required".to_string()),
    }
    let mut advisory = Vec::new();
    check_intent_advisory(payload, &mut advisory);
    finalize(hard, advisory)
}

fn validate_filesystem_write(payload: &HashMap<String, Value>) -> (bool, Vec<String>) {
    let mut hard = Vec::new();
    match payload.get("path") {
        Some(Value::String(s)) if !s.is_empty() => {}
        _ => hard.push("path: Required".to_string()),
    }
    // `content` is what gets written; accept any non-null JSON (an empty string is
    // a legitimate truncating write) but it cannot be absent or null.
    match payload.get("content") {
        Some(v) if !v.is_null() => {}
        _ => hard.push("content: Required".to_string()),
    }
    let mut advisory = Vec::new();
    check_intent_advisory(payload, &mut advisory);
    finalize(hard, advisory)
}

fn validate_terminal_exec(payload: &HashMap<String, Value>) -> (bool, Vec<String>) {
    let mut hard = Vec::new();
    match payload.get("command") {
        Some(Value::String(s)) if !s.is_empty() => {}
        _ => hard.push("command: Required".to_string()),
    }
    // destination is optional, but must be a string when present
    if let Some(val) = payload.get("destination") {
        if !val.is_string() {
            hard.push("destination: Expected string".to_string());
        }
    }
    let mut advisory = Vec::new();
    check_intent_advisory(payload, &mut advisory);
    finalize(hard, advisory)
}

fn validate_http_fetch(payload: &HashMap<String, Value>) -> (bool, Vec<String>) {
    let mut hard = Vec::new();
    match payload.get("method") {
        Some(Value::String(s))
            if matches!(s.as_str(), "GET" | "POST" | "PUT" | "PATCH" | "DELETE") => {}
        _ => hard.push("method: Expected one of GET, POST, PUT, PATCH, DELETE".to_string()),
    }
    // Any of the names the egress layer recognises, not `destination` alone.
    //
    // The policy layer host-checks `url`, `uri`, `endpoint`, `href` and `target`
    // as well (`DEFAULT_EGRESS_DESTINATION_FIELDS`), so requiring exactly
    // `destination` here made the two disagree: under `ProtocolKind::Mcp` a
    // `{method, url}` call — which the policy layer checks correctly against the
    // domain allowlist — was refused by schema validation before it got there.
    // Two layers with different ideas of what names a destination is how a
    // caller ends up choosing the name that neither one checks.
    let has_destination = crate::core::types::DEFAULT_EGRESS_DESTINATION_FIELDS
        .iter()
        .any(|k| matches!(payload.get(*k), Some(Value::String(s)) if !s.trim().is_empty()));
    if !has_destination {
        hard.push(format!(
            "destination: Required (one of {})",
            crate::core::types::DEFAULT_EGRESS_DESTINATION_FIELDS.join(", ")
        ));
    }
    let mut advisory = Vec::new();
    check_intent_advisory(payload, &mut advisory);
    finalize(hard, advisory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn payload(pairs: &[(&str, Value)]) -> HashMap<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn filesystem_read_valid_with_path_and_intent() {
        let (valid, findings) = validate_schema(
            "filesystem.read",
            &payload(&[
                ("path", json!("/workspace/README.md")),
                ("intent", json!("read docs")),
            ]),
        );
        assert!(valid);
        assert_eq!(
            findings,
            vec!["payload matched MCP tool schema".to_string()]
        );
    }

    #[test]
    fn intent_is_advisory_not_blocking() {
        // Missing intent must NOT invalidate an otherwise well-formed read — this
        // is the regression that force-blocked benign MCP self-connect calls.
        let (valid, findings) = validate_schema(
            "filesystem.read",
            &payload(&[("path", json!("/workspace/README.md"))]),
        );
        assert!(valid, "missing intent must stay valid (advisory only)");
        assert!(findings.iter().any(|f| f.contains("intent: advisory")));
    }

    #[test]
    fn filesystem_read_invalid_without_path() {
        let (valid, findings) =
            validate_schema("filesystem.read", &payload(&[("intent", json!("read"))]));
        assert!(!valid);
        assert!(findings.iter().any(|f| f.contains("path: Required")));
    }

    #[test]
    fn filesystem_write_is_registered_and_needs_path_and_content() {
        let (valid, _) = validate_schema(
            "filesystem.write",
            &payload(&[
                ("path", json!("/workspace/notes.md")),
                ("content", json!("hello")),
            ]),
        );
        assert!(
            valid,
            "filesystem.write with path+content must be schema-valid"
        );

        let (valid, findings) = validate_schema(
            "filesystem.write",
            &payload(&[("path", json!("/workspace/notes.md"))]),
        );
        assert!(!valid, "a write without content is malformed");
        assert!(findings.iter().any(|f| f.contains("content: Required")));
    }

    /// `http.fetch` had NO schema test at all, which is how the widening below
    /// shipped uncovered.
    #[test]
    fn http_fetch_accepts_any_declared_destination_name() {
        for key in [
            "destination",
            "url",
            "uri",
            "endpoint",
            "href",
            "target",
            "webhook",
        ] {
            let (valid, findings) = validate_schema(
                "http.fetch",
                &payload(&[
                    ("method", json!("GET")),
                    (key, json!("https://example.com/x")),
                ]),
            );
            assert!(
                valid,
                "`{key}` is one of DEFAULT_EGRESS_DESTINATION_FIELDS and must be \
                 accepted, or the schema refuses calls the policy layer checks \
                 correctly: {findings:?}"
            );
        }
    }

    /// The widening is what makes the tier-3 bare-host exception necessary:
    /// three of the seven names accepted here are NOT read by the legacy
    /// tier-2 probe (`destination`/`url`/`endpoint`/`href`).
    #[test]
    fn http_fetch_accepts_names_the_legacy_egress_probe_does_not_read() {
        let legacy = ["destination", "url", "endpoint", "href"];
        let beyond: Vec<&str> = crate::core::types::DEFAULT_EGRESS_DESTINATION_FIELDS
            .iter()
            .copied()
            .filter(|k| !legacy.contains(k))
            .collect();
        assert_eq!(
            beyond,
            vec!["uri", "target", "webhook"],
            "the set of schema-accepted names outside the legacy probe changed; \
             the tier-3 bare-host exception in evaluate_policy.rs is scoped to it"
        );
    }

    #[test]
    fn http_fetch_without_any_destination_is_invalid() {
        let (valid, findings) = validate_schema(
            "http.fetch",
            &payload(&[("method", json!("GET")), ("data", json!("cGF5bG9hZA=="))]),
        );
        assert!(!valid, "a fetch with no destination at all is malformed");
        assert!(
            findings.iter().any(|f| f.contains("destination: Required")),
            "{findings:?}"
        );
    }

    #[test]
    fn http_fetch_rejects_a_blank_destination() {
        let (valid, _) = validate_schema(
            "http.fetch",
            &payload(&[("method", json!("GET")), ("url", json!("   "))]),
        );
        assert!(!valid, "a whitespace-only destination must not satisfy it");
    }

    /// An unregistered tool is a GAP in this build's knowledge, not a defect in
    /// the caller's payload — so it is advisory, not a validation failure.
    ///
    /// This test previously asserted the opposite (`assert!(!valid)`), which is
    /// how the behaviour survived: `execute_pipeline` turns any `!valid` into an
    /// unconditional Block, so every tool of every real MCP server was refused
    /// before policy was consulted, and `iaga proxy` blocked 100% of calls with
    /// no configuration able to lift it. Four hardcoded names cannot be the
    /// allowlist for an open protocol.
    ///
    /// The finding is still emitted, so the evidence records that no structural
    /// check was available, and the layers that DO know the tool — the workspace
    /// tool registry, the domain allowlist, taint, the firewall — still decide.
    #[test]
    fn unknown_tool_is_advisory_not_invalid() {
        let (valid, findings) = validate_schema("totally.unknown", &payload(&[]));
        assert!(
            valid,
            "an unknown tool must not gate the verdict: {findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.contains("no MCP schema registered") && f.contains("totally.unknown")),
            "the gap must be named in the evidence: {findings:?}"
        );
    }
}
