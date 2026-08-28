// ponytail: `load_config.rs` used to sit here. Both its functions had zero callers.
// The three inline config readers in `main.rs` are deliberately NOT folded into a
// shared helper: they scan a different filename set (three names, not six) and have
// three different failure contracts on purpose — see AGENTS.md §12 and the comment
// at the `auto_import_config` site. Deleted in 2.1.0.
pub mod env;
