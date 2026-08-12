//! The agent panel must not put two different metrics under one label, and must
//! say when a number came from the behavioural fingerprint.
//!
//! `Avg / peak risk` rendered its two halves from two different sources: the
//! average from `/v1/analytics/agents` (the FINAL governance risk score) and the
//! peak from the fingerprint, which records `adaptive_result.total_score` — the
//! adaptive layer's intermediate composite, not the verdict's score
//! (`execute_pipeline.rs`, `record_action`).
//!
//! Measured on one agent with seven real actions, risks `[2, 40, 86, 2, 81, 40, 2]`:
//!
//! | source | avg | peak |
//! |---|---|---|
//! | audit log (final score) | 36.1 | **86** |
//! | fingerprint (adaptive composite) | 16.0 | **26** |
//!
//! The panel showed `36,1 / 26,0` — a "peak" below its own average, and a 3.3x
//! under-report of the worst thing the agent did, on the screen an operator
//! opens to ask exactly that. Neither number is wrong for its own source; the
//! row was wrong for mixing them.
//!
//! # What "mixing" means here, precisely
//!
//! A row may read from both sources only when they are the SAME quantity —
//! `Requests` falls back to `fp.totalRequests` when analytics has no row for the
//! selected agent, and that is a fallback, not a mix.
//!
//! Matching field NAMES is not enough to decide that: `avgRiskScore` exists
//! under both sources and means the final governance score on one and the
//! adaptive composite on the other, so `${num(a.avgRiskScore??fp.avgRiskScore)}`
//! would be the original defect wearing a fallback's clothes. The pairs known to
//! measure the same thing are therefore listed explicitly below, and every other
//! cross-source row fails.
//!
//! A first version of this file missed `${num(a.totalRequests||fp.totalRequests)}`
//! entirely, because it matched the literal prefix `${num(fp.` and that row's
//! fingerprint read sits inside the `a.` interpolation. Matching is now on any
//! `a.<field>` / `fp.<field>` reference anywhere in the row.
//!
//! Scope, stated rather than implied: these read the `<div class="row">` blocks
//! of the agent-detail template only. They say nothing about the reports view,
//! the PDF export, or the overview — all of which compute their own peak.

use std::collections::BTreeSet;

use iaga_sentinel::dashboard::index_html::render_dashboard_html;

/// The agent-detail template, as its individual `<div class="row">` chunks.
fn agent_panel_rows(html: &str) -> Vec<String> {
    let start = html
        .find("function renderAgentDetail()")
        .expect("the agent panel template was not found");
    let end = html[start..]
        .find("box.innerHTML=html;")
        .map(|i| start + i)
        .expect("end of the agent panel template");

    html[start..end]
        .split("<div class=\"row\">")
        .skip(1)
        .map(|chunk| {
            let e = chunk.find("</div>`").unwrap_or(chunk.len());
            chunk[..e].to_string()
        })
        .collect()
}

/// Fields that genuinely measure the same quantity in both sources, so a row may
/// fall back from one to the other. Deliberately tiny: `avgRiskScore` is NOT
/// here, because analytics means the final score by it and the fingerprint means
/// the adaptive composite.
const SAME_QUANTITY_IN_BOTH: [&str; 1] = ["totalRequests"];

/// Every `a.<field>` / `fp.<field>` field name referenced in a row.
fn fields(row: &str, prefix: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut rest = row;
    while let Some(i) = rest.find(prefix) {
        // Only a real property access: `a.` must not match `data.` or `dec.`.
        let boundary_ok = i == 0
            || !rest[..i]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '.');
        let after = &rest[i + prefix.len()..];
        let name: String = after
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if boundary_ok && !name.is_empty() {
            out.insert(name);
        }
        rest = &rest[i + prefix.len()..];
    }
    out
}

/// Does this row show an analytics value and a fingerprint value that do not
/// measure the same thing?
fn is_cross_source_mix(row: &str) -> bool {
    let a = fields(row, "a.");
    let fp = fields(row, "fp.");
    if a.is_empty() || fp.is_empty() {
        return false; // single-source row: nothing to mix
    }
    // The one shape that is allowed: a fallback over fields that mean the same
    // quantity on both sides.
    let same_quantity_fallback = a == fp
        && a.iter()
            .all(|f| SAME_QUANTITY_IN_BOTH.contains(&f.as_str()));
    !same_quantity_fallback
}

#[test]
fn no_agent_panel_row_shows_two_different_metrics_under_one_label() {
    let html = render_dashboard_html();
    let rows = agent_panel_rows(&html);
    assert!(!rows.is_empty(), "the agent panel template was not found");

    let mixed: Vec<String> = rows
        .iter()
        .filter(|row| is_cross_source_mix(row))
        .cloned()
        .collect();

    assert!(
        mixed.is_empty(),
        "these rows put an analytics field and a DIFFERENT fingerprint field under \
         one label, which is how a `peak` came to render below its own average and \
         under-report the agent's worst action by 3.3x: {mixed:#?}"
    );
}

#[test]
fn every_row_that_can_show_a_fingerprint_number_is_marked_advisory() {
    let html = render_dashboard_html();

    let unmarked: Vec<String> = agent_panel_rows(&html)
        .into_iter()
        .filter(|row| !fields(row, "fp.").is_empty() && !row.contains(">adv<"))
        .collect();

    assert!(
        unmarked.is_empty(),
        "a fingerprint-derived number shown to an operator must carry the `adv` \
         chip: it is a behavioural aggregate no receipt carries, and it measures \
         a different thing from the analytics figures beside it: {unmarked:#?}"
    );
}

#[test]
fn the_field_matcher_would_actually_catch_the_original_defect() {
    // Guards the guard: the first version of these tests was structurally
    // incapable of seeing either shape below, so pin that the matcher sees both.
    let old_defect = r#"<span class="k">Avg / peak risk</span><span class="v">${num(a.avgRiskScore,1)} / ${num(fp.peakRiskScore,1)}</span>"#;
    let missed_shape = r#"<span class="k">Requests</span><span class="v">${num(a.totalRequests||fp.peakRiskScore)}</span>"#;
    // Same NAME, different meaning: the defect wearing a fallback's clothes.
    let same_name_different_metric = r#"<span class="k">Avg risk</span><span class="v">${num(a.avgRiskScore??fp.avgRiskScore)}</span>"#;
    let legitimate_fallback = r#"<span class="k">Requests</span><span class="v">${num(a.totalRequests??fp.totalRequests)}</span>"#;

    for bad in [old_defect, missed_shape, same_name_different_metric] {
        assert!(is_cross_source_mix(bad), "not caught: {bad}");
    }
    assert!(
        !is_cross_source_mix(legitimate_fallback),
        "a fallback over a field that means the same thing in both sources must \
         NOT be flagged"
    );
}
