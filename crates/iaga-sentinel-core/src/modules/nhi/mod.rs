pub mod crypto_identity;

// ponytail: `pub mod registry;` used to sit here. Its only item,
// `build_audit_event`, had zero callers anywhere in the workspace - the
// pipeline builds its audit events in `pipeline::receipts`. It was also a
// latent determinism hazard: it stamped `Utc::now()` where the pipeline uses
// the injected `decision_ts` (DET-CLOCK-1).
