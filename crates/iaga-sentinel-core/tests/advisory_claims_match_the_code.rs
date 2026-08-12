//! A layer the docs call "advisory" must actually be advisory.
//!
//! The session graph returns TWO scores and only one of them is excluded from
//! the verdict:
//!
//!   * `anomaly_score` — SIGNED and decisive. `execute_pipeline` assigns it to
//!     `layer_risks.session_graph` (so it is a term in the composite) and
//!     escalates to `Review` when it reaches 50 on its own, with no attack
//!     signature required. `session_dag.rs` says so itself: the structural
//!     signals "stay in the SIGNED `anomaly_score` (DET-SESSION-2)".
//!   * `advisory_score` — prior-block history and the wall-clock burst.
//!     Surfaced for dashboards, "EXCLUDED from the signed verdict".
//!
//! `layer_roles()` gets this right — it names `advisoryScore` explicitly. The
//! published prose did not: four separate documents told a reader that the
//! *anomaly* score is advisory / "never part of the verdict" / "cannot move a
//! verdict". That is the same class of defect 2.0.1 fixed in the other
//! direction ("layers that reported themselves present and were not"), and for
//! a conformity-evidence product it is the worse direction: it understates what
//! is actually inside the signed verdict.
//!
//! Nothing tied the prose to the field names, which is why four copies of one
//! sentence could all be wrong at once.

/// The published claims that must never be attached to the *anomaly* score.
const ADVISORY_CLAIMS: &[&str] = &[
    "advisory",
    "never part of the verdict",
    "cannot move a verdict",
    "cannot move the verdict",
    "cannot move a decision",
    "cannot move the decision",
    "not decisive",
];

/// Files that publish prose about which layers decide.
///
/// The SDKs count. Their copy of this sentence is what an IDE shows on hover,
/// which is the closest thing most consumers ever read to a specification.
fn published_prose() -> Vec<(&'static str, &'static str)> {
    vec![
        ("CHANGELOG.md", include_str!("../../../CHANGELOG.md")),
        (
            "docs/openapi.yaml",
            include_str!("../../../docs/openapi.yaml"),
        ),
        (
            "docs/ARCHITECTURE.md",
            include_str!("../../../docs/ARCHITECTURE.md"),
        ),
        ("src/core/types.rs", include_str!("../src/core/types.rs")),
        (
            "src/modules/policy/tool_risk.rs",
            include_str!("../src/modules/policy/tool_risk.rs"),
        ),
        (
            "sdks/python/iaga_sentinel/types.py",
            include_str!("../../../sdks/python/iaga_sentinel/types.py"),
        ),
        (
            "sdks/typescript/src/types.ts",
            include_str!("../../../sdks/typescript/src/types.ts"),
        ),
    ]
}

/// Collapse to single-spaced lowercase so a claim split across source lines is
/// still one string to search.
///
/// Line-leading comment and quote markers are dropped FIRST. Without that, a
/// sentence wrapped inside a `#`/`*`/`>` comment flattens to
/// `...session-graph anomaly # score cannot move...`, the phrase never forms,
/// and the file passes while carrying the exact claim being linted — which is
/// what `sdks/python/iaga_sentinel/types.py` did on the first cut of this test.
fn flatten(text: &str) -> String {
    const MARKERS: &[&str] = &["///", "//!", "//", "#", "*", ">"];
    let mut out = String::new();
    for line in text.lines() {
        let mut rest = line.trim();
        // A line can carry more than one, e.g. `> ## heading`.
        loop {
            let before = rest;
            for marker in MARKERS {
                if let Some(stripped) = rest.strip_prefix(marker) {
                    rest = stripped.trim_start();
                }
            }
            if rest == before {
                break;
            }
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(rest);
    }
    out.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

#[test]
fn no_document_calls_the_signed_anomaly_score_advisory() {
    let mut wrong: Vec<String> = Vec::new();

    for (name, body) in published_prose() {
        let flat = flatten(body);
        // Every mention of the anomaly score, with the words around it.
        let mut from = 0;
        while let Some(hit) = flat[from..].find("anomaly score") {
            let at = from + hit;
            let start = at.saturating_sub(160);
            let end = (at + 160).min(flat.len());
            let window = &flat[start..end];

            // `advisoryScore` flattens to "advisoryscore"; an explicit mention
            // of the advisory FIELD is the correct wording, not a violation.
            let names_the_advisory_field =
                window.contains("advisoryscore") || window.contains("advisory_score");

            if !names_the_advisory_field {
                for claim in ADVISORY_CLAIMS {
                    if window.contains(claim) {
                        wrong.push(format!("{name}: \"...{window}...\" (matched {claim:?})"));
                        break;
                    }
                }
            }
            from = at + "anomaly score".len();
        }
    }

    assert!(
        wrong.is_empty(),
        "these documents call the session graph's SIGNED `anomaly_score` \
         advisory. `execute_pipeline` assigns it to `layer_risks.session_graph` \
         and escalates to Review at >= 50 with no attack signature, so it is \
         part of the verdict. The advisory field is `advisoryScore`, which is \
         what `layer_roles()` names: {wrong:#?}"
    );
}

/// The premise of the lint above, asserted against the source it depends on.
///
/// If someone ever makes the anomaly score genuinely advisory, this fails and
/// the lint should be revisited rather than worked around.
#[test]
fn the_pipeline_still_reads_the_anomaly_score_into_the_verdict() {
    let pipeline = include_str!("../src/pipeline/execute_pipeline.rs");
    let flat = flatten(pipeline);

    assert!(
        flat.contains("layer_risks.session_graph = session_result.anomaly_score"),
        "the composite no longer takes a session-graph term from `anomaly_score`"
    );
    assert!(
        flat.contains("session_result.anomaly_score >= 50"),
        "`anomaly_score` no longer escalates on its own"
    );

    // And the field docs still draw the line where the lint assumes it is.
    let dag = flatten(include_str!("../src/modules/session_graph/session_dag.rs"));
    assert!(
        dag.contains("signed structural anomaly score"),
        "`anomaly_score` is no longer documented as the signed score"
    );
    assert!(
        dag.contains("not folded into the signed verdict"),
        "`advisory_score` is no longer documented as excluded from the verdict"
    );
}

/// The same lint in the other direction: a layer must not publish that it
/// *cannot* decide when the pipeline lets it.
///
/// `layer_roles()` told a consumer the plugin layer "cannot veto on its own".
/// `execute_pipeline` sets `minimum_decision = GovernanceDecision::Block` from
/// a plugin's `decision_hint`, and again whenever `layer_risks.plugins` reaches
/// the workspace block threshold — a comparison on the plugin's OWN scale, not
/// the composite, so the 0.10 weight the note reasons about is not what decides
/// there. Understating a layer is the defect this file exists to catch; the
/// first cut of it only looked at the session graph.
#[test]
fn the_plugin_layer_is_not_published_as_unable_to_veto() {
    use iaga_sentinel::core::types::layer_roles;

    let pipeline = flatten(include_str!("../src/pipeline/execute_pipeline.rs"));

    // Premise first: if the pipeline stops letting a plugin force a decision,
    // this test should fail loudly rather than silently police a dead claim.
    let hint_forces = pipeline.contains("decision hint -> block");
    let score_forces = pipeline.contains("layer_risks.plugins >= workspace_policy.threshold_block");
    assert!(
        hint_forces && score_forces,
        "premise gone: `execute_pipeline` no longer lets the plugin layer force \
         a decision (hint arm: {hint_forces}, threshold arm: {score_forces}). \
         Revisit the note in `layer_roles()` rather than working around this."
    );

    let roles = layer_roles();
    let note = roles["pluginResults"]["note"]
        .as_str()
        .unwrap_or_default()
        .to_lowercase();
    assert!(
        !note.contains("cannot veto"),
        "`layer_roles()` publishes that the plugin layer cannot veto, but \
         `execute_pipeline` gives it two independent arms that set \
         `minimum_decision = Block` (a `decision_hint` of \"block\", and \
         `layer_risks.plugins >= threshold_block`), plus a plugin error that \
         escalates to Review. Note as published: {note:?}"
    );
}

/// The published COUNT of layers that cannot decide must match the table.
///
/// The sentence introducing `layerRoles` tells a reader how many of the ten
/// layer blocks are inert. Getting that number low is the 2.0.1 defect
/// ("layers that reported themselves present and were not") in the direction
/// that flatters the product: it invites the reader to count more defences
/// than exist. The number therefore has to be derived from `layer_roles()`
/// rather than maintained by hand — which is exactly what went wrong when
/// `policyVerification` was reclassified as advisory and the sentence counting
/// the advisory layers was left alone.
#[test]
fn the_published_advisory_count_matches_the_table() {
    use iaga_sentinel::core::types::layer_roles;

    /// The ten layer blocks `GovernanceResult` actually carries.
    ///
    /// `advisory` and `layerRoles` are fields of the result, not layer blocks,
    /// and `sessionGraph.advisoryScore` is a sub-field of one — counting it
    /// here is what let the list name three things and still be wrong.
    const LAYER_BLOCKS: [&str; 10] = [
        "sessionGraph",
        "taintAnalysis",
        "adaptiveRisk",
        "sandboxResult",
        "injectionFirewall",
        "policyVerification",
        "telemetrySpan",
        "behavioralFingerprint",
        "threatIntel",
        "pluginResults",
    ];

    let roles = layer_roles();
    let map = roles.as_object().expect("layer_roles is an object");

    // Premise: every name above must exist in the table, or the count below is
    // measuring a table that has moved under it.
    let missing: Vec<&str> = LAYER_BLOCKS
        .iter()
        .copied()
        .filter(|k| !map.contains_key(*k))
        .collect();
    assert!(
        missing.is_empty(),
        "`layer_roles()` no longer publishes these layer blocks: {missing:?}"
    );

    let advisory: Vec<&str> = LAYER_BLOCKS
        .iter()
        .copied()
        .filter(|k| {
            map.get(*k)
                .and_then(|e| e.get("role"))
                .and_then(|r| r.as_str())
                == Some("advisory")
        })
        .collect();

    let word = match advisory.len() {
        1 => "one",
        2 => "two",
        3 => "three",
        4 => "four",
        5 => "five",
        n => panic!("no spelling on hand for {n} advisory layers; add one"),
    };
    let phrase = format!("{word} of them cannot move a verdict");

    for (name, body) in [
        ("src/core/types.rs", include_str!("../src/core/types.rs")),
        (
            "docs/openapi.yaml",
            include_str!("../../../docs/openapi.yaml"),
        ),
    ] {
        assert!(
            flatten(body).contains(&phrase),
            "{name} does not say {phrase:?}. `layer_roles()` marks {} of the ten \
             layer blocks advisory ({advisory:?}), so that is the number the \
             published prose has to carry.",
            advisory.len()
        );
    }
}
