//! A shared session must not make one agent's evidence accuse another.
//!
//! The session DAG is keyed on the client-declared `metadata.sessionId`, and
//! both SDK quick starts hardcode `sessionId: "session-123"` — so two agents
//! sharing one graph is the copy-paste default, not an exotic case.
//!
//! Measured before the change: an attacker ran a 3-step escalation in session S
//! and tripped the 60-second cooldown. A DIFFERENT agent doing a benign read in
//! the SAME session came back `block`/72 carrying "session graph: session in
//! cooldown (60s remaining): attack pattern: data_exfiltration" plus
//! "session graph attack: data_exfiltration" — with nothing naming who had
//! actually done it. Those strings are copied verbatim into `reasons`, which is
//! signed into the receipt, so the innocent agent's cryptographic evidence
//! asserted that IT had exfiltrated data.
//!
//! The fix attributes at WRITE time, not read time. A cooldown reason is stored
//! once and then replayed to every later caller, so deciding "who" when it is
//! read names whoever called last — which is precisely the wrong agent. The
//! actors are known when the chain matches, so they are recorded then.
//!
//! Its own test binary: these drive the process-global `SESSIONS` map, and each
//! test uses a session id of its own rather than calling any reset helper —
//! clearing a shared map under the parallel runner is how these turn flaky.

use std::collections::HashSet;

use iaga_sentinel::modules::session_graph::session_dag::add_tool_call_to_session;

/// The discriminating case: the chain is formed by two agents, and a third
/// agent's reason must name them rather than name itself.
#[test]
fn the_block_reason_names_every_agent_in_the_chain_not_the_last_caller() {
    let session = "session-shared-chain-actors";

    // agent-a reads a secret, agent-b sends it out: that is `data_exfiltration`.
    let _ = add_tool_call_to_session(
        session,
        "agent-a",
        "fs.secrets",
        "file_read",
        HashSet::from(["secret".to_string(), "local_fs".to_string()]),
    );
    let _ = add_tool_call_to_session(session, "agent-b", "http.post", "http", HashSet::new());

    // agent-c does something entirely benign in the same declared session.
    let third =
        add_tool_call_to_session(session, "agent-c", "fs.readme", "file_read", HashSet::new());

    let joined = third.anomaly_reasons.join(" | ");
    assert!(
        !joined.is_empty(),
        "a shared blocked session must still say something to the sibling"
    );
    assert!(
        joined.contains("agent-a") || joined.contains("agent-b"),
        "the chain was formed by agent-a and agent-b, and this reason is signed \
         into agent-c's receipt — it must name them: {joined}"
    );
    assert!(
        !joined.contains("agent-c"),
        "agent-c formed no part of the chain and must not be named as an actor: {joined}"
    );
}

/// The single-agent case is unchanged: no attribution clause, nothing extra for
/// a human to read in the review queue.
#[test]
fn a_single_agent_session_reads_the_same_as_before() {
    let session = "session-single-agent-actor";

    let _ = add_tool_call_to_session(
        session,
        "solo-agent",
        "fs.secrets",
        "file_read",
        HashSet::from(["secret".to_string(), "local_fs".to_string()]),
    );
    let second =
        add_tool_call_to_session(session, "solo-agent", "http.post", "http", HashSet::new());

    let joined = second.anomaly_reasons.join(" | ");
    // The attack is still detected — the point is attribution, not detection.
    assert!(
        second
            .attacks_detected
            .iter()
            .any(|a| a.name == "data_exfiltration")
            || joined.contains("data_exfiltration"),
        "the chain must still be detected for one agent: {joined} / {:?}",
        second.attacks_detected
    );
}

/// Every matched attack carries the agents that formed it.
#[test]
fn an_attack_match_carries_its_actors() {
    let session = "session-attack-match-actors";

    let _ = add_tool_call_to_session(
        session,
        "chain-a",
        "fs.secrets",
        "file_read",
        HashSet::from(["secret".to_string(), "local_fs".to_string()]),
    );
    let second = add_tool_call_to_session(session, "chain-b", "http.post", "http", HashSet::new());

    let attack = second
        .attacks_detected
        .iter()
        .find(|a| a.name == "data_exfiltration")
        .unwrap_or_else(|| {
            panic!(
                "expected data_exfiltration, got {:?}",
                second.attacks_detected
            )
        });

    assert!(
        attack.agents.contains(&"chain-a".to_string())
            && attack.agents.contains(&"chain-b".to_string()),
        "the match must record who formed the chain: {:?}",
        attack.agents
    );
    // Sorted and deduped so the string built from it is reproducible — it ends
    // up inside a signed receipt.
    let mut sorted = attack.agents.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        attack.agents, sorted,
        "actors must be sorted and deduped for reproducibility"
    );
}
