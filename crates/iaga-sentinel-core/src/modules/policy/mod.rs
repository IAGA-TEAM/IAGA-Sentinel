// ponytail: `hierarchy.rs` used to sit here — 205 lines implementing `extends:`
// policy inheritance. `WorkspacePolicy` has no such field, no migration adds the
// column, and it had zero callers; four in-file tests kept it green and therefore
// invisible. Deleted in 2.1.0. `templates.rs` stays: `get_builtin_template` is
// still served by `/v1/policy/templates`.
pub mod evaluate_policy;
pub mod formal_verify;
pub mod rules_engine;
pub mod templates;
pub mod time_window;
pub mod tool_risk;
