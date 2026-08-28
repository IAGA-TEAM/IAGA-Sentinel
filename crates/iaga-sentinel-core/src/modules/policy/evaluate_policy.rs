use crate::core::types::{
    ActionType, AgentProfile, GovernanceDecision, InspectRequest, ProtocolKind, WorkspacePolicy,
};

pub struct PolicyEvaluation {
    pub findings: Vec<String>,
    pub minimum_decision: GovernanceDecision,
}

pub fn evaluate_policy(
    input: &InspectRequest,
    profile: &AgentProfile,
    workspace_policy: &WorkspacePolicy,
    protocol: ProtocolKind,
) -> PolicyEvaluation {
    let mut findings: Vec<String> = Vec::new();
    let mut minimum_decision = GovernanceDecision::Allow;

    // Check protocol allowed
    if !workspace_policy.allowed_protocols.contains(&protocol) {
        findings.push(format!(
            "protocol {:?} is not allowed for workspace {}",
            protocol, workspace_policy.workspace_id
        ));
        minimum_decision = GovernanceDecision::Block;
    }

    // Check tool policy
    let tool_policy = workspace_policy
        .tools
        .iter()
        .find(|t| t.tool_name == input.action.tool_name);

    match tool_policy {
        None => {
            findings.push(format!(
                "tool {} is not registered in workspace policy",
                input.action.tool_name
            ));
            minimum_decision = GovernanceDecision::Block;
        }
        Some(tp) => {
            if !tp.allowed_action_types.contains(&input.action.action_type) {
                findings.push(format!(
                    "tool {} cannot run action type {:?}",
                    input.action.tool_name, input.action.action_type
                ));
                minimum_decision = GovernanceDecision::Block;
            }

            if tp.requires_human_review && minimum_decision != GovernanceDecision::Block {
                findings.push(format!(
                    "tool {} requires human review",
                    input.action.tool_name
                ));
                minimum_decision = GovernanceDecision::Review;
            }

            // `max_decision` is implemented as a FLOOR, not a ceiling: the arm
            // below RAISES Allow to Review. `Block` had no arm at all, so a tool
            // pinned to `maxDecision: block` was governed exactly as if it had
            // said `allow` and the verdict fell through to the risk score alone.
            //
            // Meanwhile `formal_verify` reads the same field the other way:
            // :151 calls an all-Block tool's `allowedActionTypes` "meaningless"
            // and :257 reports an all-Block policy as a CRITICAL deny-all, which
            // `iaga validate` prints as an error (main.rs:1418). So a policy that
            // permitted everything was being reported to the operator as one that
            // denied everything. `types.rs:225` makes Block the Default and calls
            // it "the safe end of the scale", which is only true if Block denies.
            //
            // `GovernanceDecision` is Ord (Allow < Review < Block), so one
            // monotone merge covers both arms and can never soften a stricter
            // decision an earlier arm already reached.
            if tp.max_decision > minimum_decision {
                findings.push(if tp.max_decision == GovernanceDecision::Block {
                    format!(
                        "tool {} is pinned to block in workspace policy",
                        input.action.tool_name
                    )
                } else {
                    format!(
                        "tool {} is capped at review in workspace policy",
                        input.action.tool_name
                    )
                });
                minimum_decision = tp.max_decision;
            }
        }
    }

    // Check agent approved for tool
    if !profile.approved_tools.contains(&input.action.tool_name) {
        findings.push(format!(
            "agent {} is not approved for tool {}",
            profile.agent_id, input.action.tool_name
        ));
        minimum_decision = GovernanceDecision::Block;
    }

    // Check baseline action types
    if !profile
        .baseline_action_types
        .contains(&input.action.action_type)
    {
        findings.push(format!(
            "action type {:?} is outside baseline for agent {}",
            input.action.action_type, profile.agent_id
        ));
        if minimum_decision == GovernanceDecision::Allow {
            minimum_decision = GovernanceDecision::Review;
        }
    }

    // Check destination domain. Host-aware: a full URL like
    // `https://api.github.com/x` is normalized to its host before being matched
    // (case-insensitively) against the bare-host allowlist, so structured URLs
    // are no longer spuriously blocked. Mirrors the Dictum `url_host()` builtin.
    //
    // Three tiers, in descending order of confidence:
    //
    //  1. The tool DECLARES which keys carry its destination -> read only those,
    //     and fail CLOSED if none is present. A declaration is an assertion that
    //     this tool's destination is caller-controlled, so a payload hiding it
    //     is evasive, not merely unusual.
    //  2. The tool declares nothing -> legacy fixed-key probe. Unchanged, which
    //     is what keeps `openai.chat.completions.create` (an `Http` action with
    //     no payload URL at all) working; fail-closing on that shape is exactly
    //     what `fe52454` did and `ad51406` had to revert.
    //  3. Nothing found by (2) on an `Http` action -> sweep the remaining
    //     top-level strings for a scheme-qualified URL and escalate to REVIEW,
    //     never to Block. This is the residual net for a workspace that has not
    //     adopted (1) yet, priced as a human decision rather than a refusal.
    let declared = tool_policy
        .map(|tp| tp.destination_fields.as_slice())
        .unwrap_or(&[]);

    // EVERY present destination, not the first one found.
    //
    // This walked the DECLARED list and stopped at the first hit, so a caller
    // who put an allowed URL under an early-declared name and the real target
    // under a later one was host-checked on the decoy and never on the target.
    // Payload order was irrelevant — the walk is over the declaration — so it
    // was a stable bypass, not a race, and it is the same class of defect (#20)
    // that `destinationFields` exists to close. Measured on a workspace
    // allowing only `api.github.com`:
    //     {target: attacker}              -> block 70
    //     {url: github, target: attacker} -> ALLOW 2
    let destinations: Vec<String> = if declared.is_empty() {
        extract_destination(&input.action.payload)
            .into_iter()
            .collect()
    } else {
        present_keys(&input.action.payload, declared.iter().map(String::as_str))
    };

    let mut offending: Vec<(String, String)> = Vec::new();
    for destination in &destinations {
        let host = host_of(destination);
        if !host_is_allowed(&host, workspace_policy) {
            offending.push((destination.clone(), host));
        }
    }

    for (destination, host) in &offending {
        findings.push(format!(
            "destination {destination} (host {host}) is outside allowed workspace domains"
        ));
    }
    if !offending.is_empty() {
        minimum_decision = GovernanceDecision::Block;
    }

    if destinations.is_empty() && !declared.is_empty() {
        // Tier 1 fail-closed. Scoped to tools that opted in, so it cannot
        // repeat the 1.9.2 regression.
        findings.push(format!(
            "tool {} declares its egress destination in {:?} but the payload exposes none of \
             them, so the workspace domain allowlist cannot be applied",
            input.action.tool_name, declared
        ));
        minimum_decision = GovernanceDecision::Block;
    }

    // Tier 3 escalation, on EVERY HTTP action.
    //
    // It used to run only when the tool declared nothing AND the legacy probe
    // found nothing, which left two holes of the same shape. A hostile URL rode
    // along beside an allowlisted `destination` on an undeclared tool; and on a
    // DECLARING tool it was invisible whenever it sat under a name outside the
    // declaration — the shipped example declares six of the seven default names,
    // so `webhook` was exactly that gap. Tier 1 was satisfied by the declared
    // keys, tier 3 never ran, and the request was allowed at risk 2.
    //
    // Still Review, never Block: a key the tool did not declare is a weaker
    // signal than one it did, and the tier-1 refusal above already covers the
    // strong case. Stricter-wins, so a tier-1 Block is never softened by this.
    //
    // The DECLARED keys are excluded, because tier 1 already reported them
    // correctly. Without that, this re-found the key tier 1 had just refused
    // and pushed a second finding saying it was undeclared and being escalated
    // for review — both false, and both signed into the receipt via
    // `risk.reasons`.
    if input.action.action_type == ActionType::Http {
        if let Some((field, host)) = scan_undeclared_hosts(&input.action.payload, declared, |h| {
            host_is_allowed(h, workspace_policy)
        }) {
            // Only claim an escalation when this is the arm that caused one.
            let escalating = minimum_decision == GovernanceDecision::Allow;
            findings.push(format!(
                "payload key `{field}` carries host {host}, which is outside allowed \
                 workspace domains and is not among this tool's declared destinationFields{}",
                if escalating {
                    " — escalating for human review; declare it to have it enforced as a refusal"
                } else {
                    ""
                }
            ));
            if escalating {
                minimum_decision = GovernanceDecision::Review;
            }
        }
    }

    if findings.is_empty() {
        findings.push("request matched registered tool and workspace policy".to_string());
    }

    PolicyEvaluation {
        findings,
        minimum_decision,
    }
}

/// Legacy fixed-key probe, used when a tool declares no `destination_fields`.
///
/// Callers name the target differently (`url`, `endpoint`, `href`); checking
/// only `destination` let a URL in any other field slip past the domain
/// allowlist (issue #20). Widening the list from one name to four did not fix
/// the shape of the defect, only its reach: any name outside the list is still
/// invisible here, and finding nothing skips the allowlist entirely rather than
/// failing closed. `ToolPolicy::destination_fields` is the actual fix; this
/// remains the compatible default for policies that have not adopted it.
fn extract_destination(
    payload: &std::collections::HashMap<String, serde_json::Value>,
) -> Option<String> {
    first_present_key(
        payload,
        ["destination", "url", "endpoint", "href"].into_iter(),
    )
}

/// First key in `keys` (priority order) whose value is a string.
///
/// Still first-match, and only for the LEGACY probe: a workspace that has not
/// adopted `destinationFields` is deliberately priced at Review rather than
/// Block, and the tier-3 sweep — which now runs even when this found an allowed
/// destination — is what catches a second, hostile URL there.
fn first_present_key<'a>(
    payload: &std::collections::HashMap<String, serde_json::Value>,
    keys: impl Iterator<Item = &'a str>,
) -> Option<String> {
    let mut keys = keys;
    keys.find_map(|k| payload.get(k).and_then(|v| v.as_str()))
        .map(|s| s.to_string())
}

/// EVERY declared key the payload actually carries, in declaration order.
///
/// Returning only the first was a bypass: the allowlist was applied to whichever
/// declared name happened to come first, and a second declared key carrying the
/// real destination went unchecked. A tool that declares N names is asserting
/// that any of them may be its destination, so all of them have to clear the
/// allowlist.
fn present_keys<'a>(
    payload: &std::collections::HashMap<String, serde_json::Value>,
    keys: impl Iterator<Item = &'a str>,
) -> Vec<String> {
    keys.filter_map(|k| payload.get(k).and_then(|v| v.as_str()))
        .map(|s| s.to_string())
        .collect()
}

/// Sweep top-level string values for a scheme-qualified URL whose host fails
/// `is_allowed`, returning the offending `(key, host)`.
///
/// Deliberately narrow on three axes, because a broad version of this is a
/// false-positive generator rather than a control:
///
///  * **Scheme-qualified only, EXCEPT under a destination name.** A bare
///    `evil.com` inside prose is not treated as a destination; requiring `://`
///    keeps ordinary text out. But a key literally called `uri`, `target` or
///    `webhook` is a destination by its own name, and the MCP schema now
///    ACCEPTS all seven of those names for `http.fetch` where it used to demand
///    `destination`. The legacy tier-2 probe reads only four of the seven, so
///    without this exception a bare host under the other three cleared every
///    tier: schema-valid, unread by tier 2, and skipped here for want of a
///    scheme. Those keys are still held to [`looks_like_a_host`] so prose in a
///    `target` field is not mistaken for one.
///  * **Top level only.** Nested structures are where request/response BODIES
///    live, and a URL inside a body is content, not a destination. The skill
///    gate encodes the same rule from the other side, nesting raw tool input
///    under `raw` so it can never be read as one.
///  * **Callers restrict it to `Http` actions.** A URL in a file being written
///    or in a SQL literal is content by construction; sweeping those is how a
///    scan-everything implementation starts blocking documentation.
///  * **Content-bearing keys are skipped.** See [`CONTENT_KEYS`].
fn scan_undeclared_hosts(
    payload: &std::collections::HashMap<String, serde_json::Value>,
    declared: &[String],
    is_allowed: impl Fn(&str) -> bool,
) -> Option<(String, String)> {
    // Deterministic across runs: HashMap iteration order is seeded per process,
    // and this string reaches `findings`, which reaches the audit record.
    let mut keys: Vec<&String> = payload.keys().collect();
    keys.sort();
    for key in keys {
        if CONTENT_KEYS.contains(&key.to_ascii_lowercase().as_str()) {
            continue;
        }
        // Tier 1 owns the declared keys and has already host-checked every one
        // of them; re-reporting here is what made the finding lie about them.
        if declared.iter().any(|d| d.eq_ignore_ascii_case(key)) {
            continue;
        }
        let Some(value) = payload.get(key).and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(scheme_at) = value.find("://") else {
            // No scheme. Only a key that NAMES a destination gets read anyway,
            // and only when the value is shaped like a host.
            let named_destination = crate::core::types::DEFAULT_EGRESS_DESTINATION_FIELDS
                .iter()
                .any(|k| k.eq_ignore_ascii_case(key));
            if named_destination && looks_like_a_host(value) {
                let host = host_of(value);
                if !host.is_empty() && !is_allowed(&host) {
                    return Some((key.clone(), host));
                }
            }
            continue;
        };
        // Rewind over the scheme so `host_of` sees a whole URL, not a tail.
        //
        // Step by the matched char's OWN width, not by 1: `is_whitespace` is
        // the Unicode property, so it matches multi-byte spaces (U+00A0,
        // U+2000..U+200A, U+3000), and `i + 1` then lands inside the character
        // and panics the slice below.
        let start = value[..scheme_at]
            .char_indices()
            .rev()
            .find(|(_, c)| c.is_whitespace() || *c == '"' || *c == '\'')
            .map(|(i, c)| i + c.len_utf8())
            .unwrap_or(0);
        let candidate = value[start..].split_whitespace().next().unwrap_or_default();
        let host = host_of(candidate);
        if !host.is_empty() && !is_allowed(&host) {
            return Some((key.clone(), host));
        }
    }
    None
}

/// Is this bare (scheme-less) string shaped like a host rather than prose?
///
/// Only consulted for keys that already NAME a destination, so it does not have
/// to separate hosts from arbitrary text — only from the plausible non-URL
/// values such a key carries in practice (`target: "production"`,
/// `webhook: "disabled"`). A host has no whitespace and at least one dot;
/// `localhost` and bare IPv6 are the accepted exceptions.
fn looks_like_a_host(value: &str) -> bool {
    let candidate = value.split(['/', '?', '#']).next().unwrap_or("");
    let candidate = candidate.rsplit_once('@').map_or(candidate, |(_, h)| h);
    let bare = candidate.split_once(':').map_or(candidate, |(h, _)| h);
    if bare.is_empty() || value.split_whitespace().count() != 1 {
        return false;
    }
    bare.eq_ignore_ascii_case("localhost")
        || candidate.starts_with('[')
        || (bare.contains('.')
            && !bare.starts_with('.')
            && !bare.ends_with('.')
            && bare
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-'))
}

/// Top-level keys that carry CONTENT, never a destination.
///
/// The "top level only" rule keeps the sweep out of request bodies when the
/// caller nests them, but plenty of callers do not nest: an SDK that forwards
/// `input="summarise https://example.com/article"` puts a URL in a top-level
/// string on an `Http` action, and the sweep would read it as an egress target
/// and queue a human review for an ordinary prompt.
///
/// A missing name here costs a spurious Review, never a bypass — the enforcing
/// arm is the declared extraction, and this sweep only escalates. That asymmetry
/// is why a name list is acceptable here and was not acceptable as the
/// extraction itself.
const CONTENT_KEYS: [&str; 12] = [
    "body", "content", "data", "form", "input", "json", "message", "messages", "note", "prompt",
    "query", "text",
];

fn host_is_allowed(host: &str, workspace_policy: &WorkspacePolicy) -> bool {
    workspace_policy
        .allowed_domains
        .iter()
        .any(|d| d.eq_ignore_ascii_case(host))
}

/// Extract the lowercased host from a URL or bare-host string.
///
/// Pure mirror of `iaga_sentinel_dictum::extract_host`. It is duplicated here on
/// purpose: `iaga-sentinel-dictum` is an *optional* dependency (behind the default
/// `dictum` feature) and this module compiles in every feature configuration, so
/// it cannot import the Dictum one. Strips scheme, userinfo, port, and
/// path/query/fragment; preserves a bracketed IPv6 literal. A bare host is
/// returned unchanged (lowercased), so existing bare-host allowlists keep
/// working; unparseable input yields "" (matches no allowlist entry).
pub(crate) fn host_of(s: &str) -> String {
    let after_scheme = s.split_once("://").map(|(_, r)| r).unwrap_or(s);
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    let host = if let Some(rest) = hostport.strip_prefix('[') {
        match rest.split_once(']') {
            Some((h6, _)) => format!("[{h6}]"),
            None => hostport.to_string(),
        }
    } else {
        hostport
            .split_once(':')
            .map(|(h, _)| h)
            .unwrap_or(hostport)
            .to_string()
    };
    host.to_ascii_lowercase()
}

#[cfg(test)]
mod egress_tests {
    use super::*;
    use crate::core::types::{ActionDetail, AgentRole, ToolPolicy};
    use std::collections::HashMap;

    fn payload(pairs: &[(&str, &str)]) -> HashMap<String, serde_json::Value> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), serde_json::json!(v)))
            .collect()
    }

    fn request(tool: &str, payload: HashMap<String, serde_json::Value>) -> InspectRequest {
        request_of(ActionType::Http, tool, payload)
    }

    /// The action type is the guard that keeps the tier-3 sweep away from
    /// content, so it has to be a parameter somewhere or it never gets tested.
    fn request_of(
        action_type: ActionType,
        tool: &str,
        payload: HashMap<String, serde_json::Value>,
    ) -> InspectRequest {
        InspectRequest {
            agent_id: "a".into(),
            tenant_id: None,
            workspace_id: Some("ws".into()),
            framework: "test".into(),
            protocol: Some(ProtocolKind::HttpFunction),
            action: ActionDetail {
                action_type,
                tool_name: tool.into(),
                payload,
            },
            requested_secrets: None,
            metadata: None,
            usage: None,
        }
    }

    fn profile(tool: &str) -> AgentProfile {
        profile_for(tool, vec![ActionType::Http])
    }

    fn profile_for(tool: &str, types: Vec<ActionType>) -> AgentProfile {
        AgentProfile {
            agent_id: "a".into(),
            tenant_id: None,
            workspace_id: "ws".into(),
            framework: "test".into(),
            role: AgentRole::Builder,
            approved_tools: vec![tool.into()],
            approved_secrets: vec![],
            baseline_action_types: types,
            tool_trust: 0.7,
        }
    }

    fn workspace(tool: ToolPolicy) -> WorkspacePolicy {
        WorkspacePolicy {
            workspace_id: "ws".into(),
            tenant_id: None,
            allowed_protocols: vec![ProtocolKind::HttpFunction],
            tools: vec![tool],
            allowed_domains: vec!["api.github.com".into()],
            threshold_block: 70,
            threshold_review: 35,
        }
    }

    fn declaring(tool: &str) -> ToolPolicy {
        ToolPolicy {
            tool_name: tool.into(),
            allowed_action_types: vec![ActionType::Http],
            max_decision: GovernanceDecision::Allow,
            requires_human_review: false,
            destination_fields: ToolPolicy::default_egress_fields(),
        }
    }

    fn silent(tool: &str) -> ToolPolicy {
        ToolPolicy {
            tool_name: tool.into(),
            allowed_action_types: vec![ActionType::Http],
            max_decision: GovernanceDecision::Allow,
            requires_human_review: false,
            ..Default::default()
        }
    }

    /// One allowlisted key must not shadow a hostile one.
    ///
    /// `first_present_key` walked the DECLARED list and returned on the first
    /// hit, so a caller who put an allowed URL under an early-declared name and
    /// the real destination under a later one was host-checked on the decoy and
    /// never on the target. Order in the payload is irrelevant — the walk is
    /// over the declaration — so this is not a race, it is a stable bypass, and
    /// it is exactly the class of defect (#20) `destinationFields` exists to
    /// close.
    ///
    /// Measured live before the fix, on a workspace allowing only
    /// `api.github.com`:
    ///   `{target: attacker}`             -> block 70
    ///   `{url: github, target: attacker}` -> ALLOW 2
    #[test]
    fn a_benign_declared_key_cannot_shadow_a_hostile_one() {
        for pairs in [
            // `url` is declared before `target`; the decoy is found first.
            &[
                ("method", "POST"),
                ("url", "https://api.github.com/x"),
                ("target", "https://attacker.example/collect"),
            ][..],
            // ...and the other way round, to show payload order is not the axis.
            &[
                ("method", "POST"),
                ("target", "https://attacker.example/collect"),
                ("url", "https://api.github.com/x"),
            ][..],
            // Three keys, hostile one last in the declaration order.
            &[
                ("destination", "https://api.github.com/a"),
                ("url", "https://api.github.com/b"),
                ("webhook", "https://attacker.example/collect"),
            ][..],
        ] {
            let req = request("http.fetch", payload(pairs));
            assert_eq!(
                decide(declaring("http.fetch"), &req),
                GovernanceDecision::Block,
                "an off-allowlist host under ANY declared key must block, even \
                 when another declared key carries an allowed one: {pairs:?}"
            );
        }
    }

    /// A declaring tool does not get a free pass on names it did NOT declare.
    ///
    /// The shipped `iaga-sentinel.example.yaml` declares six of the seven
    /// default names — `webhook` is missing — so this is the real shape, not a
    /// contrived one. Tier 1 was satisfied by the declared keys and the tier-3
    /// sweep was gated on "the tool declared nothing", so the hostile URL was
    /// checked by neither: measured live, `allow` at risk 2.
    #[test]
    fn a_declaring_tool_is_still_swept_for_hosts_under_names_it_did_not_declare() {
        let mut tool = declaring("http.fetch");
        tool.destination_fields = ["destination", "url", "uri", "endpoint", "href", "target"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();

        let req = request(
            "http.fetch",
            payload(&[
                ("destination", "https://api.github.com/a"),
                ("webhook", "https://attacker.example/collect"),
            ]),
        );
        assert_eq!(
            decide(tool, &req),
            GovernanceDecision::Review,
            "an off-allowlist host under a name the tool did not declare must \
             still escalate; only a DECLARED name earns the tier-1 refusal"
        );
    }

    /// The all-allowed case must stay allowed, or the fix above is just a
    /// blanket refusal of multi-key payloads.
    #[test]
    fn several_declared_keys_all_on_the_allowlist_still_pass() {
        let req = request(
            "http.fetch",
            payload(&[
                ("method", "GET"),
                ("url", "https://api.github.com/a"),
                ("target", "https://api.github.com/b"),
            ]),
        );
        assert_eq!(
            decide(declaring("http.fetch"), &req),
            GovernanceDecision::Allow
        );
    }

    /// The same shadowing on the tier-3 path: the legacy probe found an
    /// allowlisted `destination`, so the sweep never ran and a hostile URL under
    /// an undeclared key rode along. Measured before the fix:
    ///   `{callback: attacker}`                 -> review
    ///   `{destination: github, callback: attacker}` -> ALLOW
    #[test]
    fn an_allowed_legacy_destination_does_not_suppress_the_tier_three_sweep() {
        let req = request(
            "http.fetch",
            payload(&[
                ("method", "POST"),
                ("destination", "https://api.github.com/x"),
                ("callback", "https://attacker.example/collect"),
            ]),
        );
        assert_eq!(
            decide(silent("http.fetch"), &req),
            GovernanceDecision::Review,
            "a hostile host under an undeclared key must still escalate even \
             when the legacy probe found an allowed destination"
        );
    }

    fn decide(tool: ToolPolicy, req: &InspectRequest) -> GovernanceDecision {
        let name = tool.tool_name.clone();
        evaluate_policy(
            req,
            &profile(&name),
            &workspace(tool),
            ProtocolKind::HttpFunction,
        )
        .minimum_decision
    }

    /// The case study's `A17`: the URL under `target`, a name the legacy fixed
    /// probe does not know. Declared extraction host-checks it like any other.
    #[test]
    fn a_declared_alias_is_host_checked() {
        let req = request(
            "http.fetch",
            payload(&[
                ("method", "POST"),
                ("target", "https://attacker.example/collect"),
            ]),
        );
        assert_eq!(
            decide(declaring("http.fetch"), &req),
            GovernanceDecision::Block
        );
    }

    /// Same declaration, allowlisted host: still allowed. A fail-closed rule
    /// that blocks the legitimate case is not a control, it is an outage.
    #[test]
    fn a_declared_alias_on_an_allowlisted_host_is_allowed() {
        let req = request(
            "http.fetch",
            payload(&[
                ("method", "GET"),
                ("uri", "https://api.github.com/rate_limit"),
            ]),
        );
        assert_eq!(
            decide(declaring("http.fetch"), &req),
            GovernanceDecision::Allow
        );
    }

    /// The fail-closed branch: the tool declared where its destination lives and
    /// the payload exposes none of those keys.
    #[test]
    fn a_declaring_tool_with_no_destination_fails_closed() {
        let req = request(
            "http.fetch",
            payload(&[("method", "POST"), ("data", "cGF5bG9hZA==")]),
        );
        assert_eq!(
            decide(declaring("http.fetch"), &req),
            GovernanceDecision::Block
        );
    }

    /// THE regression guard for `ad51406`.
    ///
    /// `openai.chat.completions.create` is an `Http` action whose destination is
    /// the provider baked into the SDK, not a payload field. `fe52454` fail-closed
    /// on exactly this shape and broke the OpenAI adapter smoke; the revert is
    /// why the fail-closed is scoped to tools that DECLARE. A tool that declares
    /// nothing must keep the legacy behaviour.
    #[test]
    fn an_llm_sdk_call_that_declares_nothing_is_not_blocked() {
        let req = request(
            "openai.chat.completions.create",
            payload(&[
                ("model", "gpt-4o-mini"),
                ("messages", r#"[{"role":"user","content":"hello"}]"#),
            ]),
        );
        assert_eq!(
            decide(silent("openai.chat.completions.create"), &req),
            GovernanceDecision::Allow,
            "fail-closed must stay scoped to tools that declared a destination \
             field, or this is fe52454 again"
        );
    }

    /// The MCP schema accepts seven destination names; this probe checks four.
    ///
    /// `validate_http_fetch` was relaxed to accept ANY of
    /// `DEFAULT_EGRESS_DESTINATION_FIELDS`, so a `{method, target}` MCP call is
    /// now schema-VALID where it used to be a hard `Block`
    /// (`execute_pipeline`: schema invalid => Block). But for a tool that
    /// declares nothing, tier 2 probes only the legacy four
    /// (`destination`/`url`/`endpoint`/`href`) and tier 3 requires `://`. So a
    /// BARE host under `uri`, `target` or `webhook` clears all three tiers.
    ///
    /// Those three names are exactly the gap between the seven the schema now
    /// admits and the four this probe reads.
    #[test]
    fn a_bare_host_under_a_schema_accepted_name_is_not_waved_through() {
        for key in ["uri", "target", "webhook"] {
            let req = request(
                "http.fetch",
                payload(&[("method", "GET"), (key, "attacker.example")]),
            );
            assert_ne!(
                decide(silent("http.fetch"), &req),
                GovernanceDecision::Allow,
                "a bare off-allowlist host under `{key}` — a name the MCP \
                 schema now accepts as a destination — was allowed outright: \
                 tier 2 does not read that key and tier 3 requires a scheme"
            );
        }
    }

    /// The tier-3 finding is signed into the receipt, so it has to be true.
    ///
    /// The sweep is named for the declaration but never received it, so on a
    /// DECLARING tool it re-found the very key tier 1 had just refused and
    /// pushed a second finding asserting two false things about it: that the
    /// key "is not among this tool's declared destinationFields" (it is), and
    /// that the request is "escalating for human review" (it is a Block —
    /// tier 3 only upgrades from Allow). `tool_risk` copies policy findings
    /// into `risk.reasons`, which `execute_pipeline` clones into
    /// `auditEvent.reasons` and signs, so a conformity receipt carried a reason
    /// line contradicting its own verdict.
    #[test]
    fn a_declared_destination_is_not_also_reported_as_undeclared() {
        for value in ["https://attacker.example/collect", "attacker.example"] {
            let req = request(
                "http.fetch",
                payload(&[("method", "POST"), ("target", value)]),
            );
            let out = evaluate_policy(
                &req,
                &profile("http.fetch"),
                &workspace(declaring("http.fetch")),
                ProtocolKind::HttpFunction,
            );

            assert_eq!(
                out.minimum_decision,
                GovernanceDecision::Block,
                "a declared off-allowlist destination is a tier-1 refusal"
            );
            let undeclared: Vec<&String> = out
                .findings
                .iter()
                .filter(|f| f.contains("is not among this tool's declared"))
                .collect();
            assert!(
                undeclared.is_empty(),
                "`target` IS declared and the verdict is Block, but a finding \
                 signed into the receipt says it is undeclared and that the \
                 request is being escalated for review: {:#?}",
                out.findings
            );
        }
    }

    /// The cost side of the exception above, and the reason it is guarded.
    ///
    /// Reading a scheme-less value as a destination is only safe if ordinary
    /// non-URL contents of those keys stay out of it. `target: "production"` is
    /// a deployment target, not a host; sweeping it would put every such call
    /// in the review queue.
    #[test]
    fn a_benign_non_host_under_a_destination_name_is_left_alone() {
        for (key, value) in [
            ("target", "production"),
            ("webhook", "disabled"),
            ("uri", "urn:ietf:rfc:2648"),
            ("target", "the build server"),
        ] {
            let req = request("http.fetch", payload(&[("method", "GET"), (key, value)]));
            assert_eq!(
                decide(silent("http.fetch"), &req),
                GovernanceDecision::Allow,
                "`{key}: {value}` is not a host and must not be swept as one"
            );
        }
    }

    /// A bare host that IS on the allowlist must not be escalated either.
    #[test]
    fn a_bare_allowlisted_host_under_a_destination_name_is_allowed() {
        let req = request(
            "http.fetch",
            payload(&[("method", "GET"), ("target", "api.github.com")]),
        );
        assert_eq!(
            decide(silent("http.fetch"), &req),
            GovernanceDecision::Allow
        );
    }

    /// Tier 3: an un-migrated workspace still gets a net, priced as a human
    /// decision rather than a refusal.
    #[test]
    fn an_undeclared_host_in_an_unknown_key_escalates_to_review_not_block() {
        let req = request(
            "http.fetch",
            payload(&[
                ("method", "POST"),
                ("callback", "https://attacker.example/collect"),
            ]),
        );
        assert_eq!(
            decide(silent("http.fetch"), &req),
            GovernanceDecision::Review
        );
    }

    /// The sweep must not fire on an allowlisted host, or every ordinary call
    /// through an un-migrated policy lands in the review queue.
    #[test]
    fn the_sweep_ignores_allowlisted_hosts() {
        let req = request(
            "http.fetch",
            payload(&[
                ("method", "GET"),
                ("callback", "https://api.github.com/hook"),
            ]),
        );
        assert_eq!(
            decide(silent("http.fetch"), &req),
            GovernanceDecision::Allow
        );
    }

    /// A bare host in prose is not a destination. Requiring `://` is what keeps
    /// the sweep from reading documentation as egress.
    #[test]
    fn the_sweep_ignores_bare_hosts_in_prose() {
        let req = request(
            "http.fetch",
            payload(&[("method", "GET"), ("note", "mirrors evil.example are down")]),
        );
        assert_eq!(
            decide(silent("http.fetch"), &req),
            GovernanceDecision::Allow
        );
    }

    /// A non-ASCII space before the scheme must not panic the sweep.
    ///
    /// `rfind` yields the BYTE index of the matched char, and `+ 1` is a char
    /// boundary only when that char is one byte wide. `U+00A0` is
    /// `White_Space`, so it matched the predicate and the next slice cut it in
    /// half. The sweep runs on every `Http` action and reads top-level strings,
    /// so this was a payload any caller of `/v1/inspect` could send: the task
    /// panicked, the connection closed with no response, and no audit event was
    /// written — an ungoverned action that leaves no evidence it happened.
    #[test]
    fn a_multibyte_space_before_the_scheme_does_not_panic() {
        let req = request(
            "http.fetch",
            payload(&[
                ("method", "GET"),
                ("callback", "x\u{00a0}https://attacker.example/y"),
            ]),
        );
        assert_eq!(
            decide(silent("http.fetch"), &req),
            GovernanceDecision::Review
        );
    }

    // ── The guards that keep content from becoming a destination ──
    //
    // These are the tests the sweep did not have. Every case above builds an
    // `Http` request, so the ACTION-TYPE gate — the comparison standing between
    // this sweep and "any URL anywhere is egress" — was never once exercised.
    //
    // Two guards overlap here, and it is worth being exact about which test
    // pins which, because a test that would pass with the guard deleted proves
    // nothing about it. Measured by deleting each:
    //
    //  * `a_url_in_a_sql_literal_is_not_a_destination` is the ACTION-TYPE
    //    gate's witness — `sql` is not a content key, so removing the gate is
    //    what turns that case into a Review.
    //  * the file-content and prompt cases survive the gate's removal, because
    //    `content` and `prompt` are in `CONTENT_KEYS`. They witness the SKIP
    //    LIST, and they are kept as the shapes a reader recognises.
    //  * `the_sweep_skips_content_bearing_keys_on_http_too` is the skip list's
    //    witness on the one action type the gate cannot help with.

    fn decide_typed(
        action_type: ActionType,
        tool: ToolPolicy,
        req: &InspectRequest,
    ) -> GovernanceDecision {
        let name = tool.tool_name.clone();
        evaluate_policy(
            req,
            &profile_for(&name, vec![action_type]),
            &workspace(tool),
            ProtocolKind::HttpFunction,
        )
        .minimum_decision
    }

    /// A URL inside a file being WRITTEN is content. This is the case the skill
    /// gate documents from the other side, in
    /// `sentinel-skill/test/gate.test.mjs`, and the reason the sweep is gated on
    /// the action type rather than on the key name alone.
    #[test]
    fn a_url_in_written_file_content_is_not_a_destination() {
        let tool = ToolPolicy {
            tool_name: "fs.write".into(),
            allowed_action_types: vec![ActionType::FileWrite],
            max_decision: GovernanceDecision::Allow,
            requires_human_review: false,
            ..Default::default()
        };
        let req = request_of(
            ActionType::FileWrite,
            "fs.write",
            payload(&[
                ("path", "/workspace/README.md"),
                ("content", "Mirror list: https://evil.example.net/pkg"),
            ]),
        );
        assert_eq!(
            decide_typed(ActionType::FileWrite, tool, &req),
            GovernanceDecision::Allow,
            "writing a document that mentions a URL is not egress"
        );
    }

    /// A URL inside a prompt is content. An agent asked to summarise a page is
    /// the single most ordinary thing this product sees.
    #[test]
    fn a_url_in_a_prompt_is_not_a_destination() {
        let tool = ToolPolicy {
            tool_name: "agent.prompt".into(),
            allowed_action_types: vec![ActionType::Custom],
            max_decision: GovernanceDecision::Allow,
            requires_human_review: false,
            ..Default::default()
        };
        let req = request_of(
            ActionType::Custom,
            "agent.prompt",
            payload(&[("prompt", "summarise https://evil.example.net/article")]),
        );
        assert_eq!(
            decide_typed(ActionType::Custom, tool, &req),
            GovernanceDecision::Allow
        );
    }

    /// A URL inside a SQL literal is content.
    #[test]
    fn a_url_in_a_sql_literal_is_not_a_destination() {
        let tool = ToolPolicy {
            tool_name: "db.select".into(),
            allowed_action_types: vec![ActionType::DbQuery],
            max_decision: GovernanceDecision::Allow,
            requires_human_review: false,
            ..Default::default()
        };
        let req = request_of(
            ActionType::DbQuery,
            "db.select",
            payload(&[(
                "sql",
                "select id from links where href = 'https://evil.example.net/x'",
            )]),
        );
        assert_eq!(
            decide_typed(ActionType::DbQuery, tool, &req),
            GovernanceDecision::Allow
        );
    }

    /// Even on an `Http` action, a URL in a content-bearing key is content. An
    /// SDK that forwards `input="… https://example.com/…"` must not queue a
    /// human review for an ordinary prompt.
    #[test]
    fn the_sweep_skips_content_bearing_keys_on_http_too() {
        let req = request(
            "http.fetch",
            payload(&[
                ("method", "POST"),
                ("input", "summarise https://evil.example.net/article"),
            ]),
        );
        assert_eq!(
            decide(silent("http.fetch"), &req),
            GovernanceDecision::Allow,
            "prompt text is not an egress destination"
        );
    }

    /// The skip list must not swallow the case the sweep exists for: a
    /// destination-shaped key alongside a content key still escalates.
    #[test]
    fn a_destination_shaped_key_still_escalates_next_to_content() {
        let req = request(
            "http.fetch",
            payload(&[
                ("method", "POST"),
                ("data", "some base64 body"),
                ("callback", "https://evil.example.net/collect"),
            ]),
        );
        assert_eq!(
            decide(silent("http.fetch"), &req),
            GovernanceDecision::Review,
            "skipping `data` must not also skip `callback`"
        );
    }
}

#[cfg(test)]
mod host_tests {
    use super::host_of;

    #[test]
    fn full_url_to_bare_host() {
        assert_eq!(
            host_of("https://api.github.com/repos/x?y=1"),
            "api.github.com"
        );
        assert_eq!(
            host_of("http://user:pass@API.GitHub.com:8443/p"),
            "api.github.com"
        );
    }

    #[test]
    fn bare_host_unchanged() {
        assert_eq!(host_of("api.github.com"), "api.github.com");
        assert_eq!(host_of("evil.com"), "evil.com");
    }

    #[test]
    fn ipv6_and_garbage() {
        assert_eq!(host_of("http://[::1]:8080/"), "[::1]");
        assert_eq!(host_of(""), "");
    }
}
