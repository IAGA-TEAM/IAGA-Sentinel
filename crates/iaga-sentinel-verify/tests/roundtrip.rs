//! End to end: build a signed chain, wrap it in a ChainExport, verify it offline.

use iaga_sentinel_receipts::{
    chain_link, ChainExport, ChainStatus, Receipt, ReceiptBody, ReceiptSigner, Verdict,
};
use iaga_sentinel_verify::{verify_export, KeySource};

fn build_chain(signer: &ReceiptSigner, len: u64) -> Vec<Receipt> {
    let mut chain = Vec::with_capacity(len as usize);
    let mut head: Option<Receipt> = None;
    for i in 0..len {
        let (parent_hash, seq) = chain_link(head.as_ref()).expect("link ok");
        let body = ReceiptBody {
            run_id: "run-verify".into(),
            seq,
            parent_hash,
            input_hash: format!("{:064x}", i),
            policy_hash: "p".repeat(64),
            threat_feed_hash: None,
            plugin_digests: vec![],
            model_digests: vec![],
            ml_scores: None,
            verdict: Verdict::Allow,
            reasons: vec![format!("step {}", i)],
            risk_score: i as u32,
            timestamp: format!("2026-06-06T12:00:{:02}Z", i % 60),
            signer_key_id: signer.key_id().into(),
            pipeline_inputs_capture: None,
            apl_eval_trace: None,
            ml_inference_inputs: None,
            is_authoritative: None,
            usage: None,
        };
        let r = signer.sign(body).expect("sign ok");
        head = Some(r.clone());
        chain.push(r);
    }
    chain
}

fn export_for(signer: &ReceiptSigner, chain: Vec<Receipt>) -> ChainExport {
    ChainExport {
        run_id: "run-verify".into(),
        signer_key_id: signer.key_id().into(),
        signer_verifying_key: hex::encode(signer.verifying_key().to_bytes()),
        receipts: chain,
    }
}

#[test]
fn valid_chain_verifies_with_embedded_key() {
    let signer = ReceiptSigner::generate();
    let export = export_for(&signer, build_chain(&signer, 10));
    let (status, source) = verify_export(&export, None).expect("verify ok");
    assert_eq!(status, ChainStatus::Valid { receipt_count: 10 });
    assert_eq!(source, KeySource::Embedded);
}

#[test]
fn valid_chain_verifies_with_pinned_key() {
    let signer = ReceiptSigner::generate();
    let key_hex = hex::encode(signer.verifying_key().to_bytes());
    let export = export_for(&signer, build_chain(&signer, 5));
    let (status, source) = verify_export(&export, Some(&key_hex)).expect("verify ok");
    assert_eq!(status, ChainStatus::Valid { receipt_count: 5 });
    assert_eq!(source, KeySource::Pinned);
}

#[test]
fn tampered_chain_is_broken() {
    let signer = ReceiptSigner::generate();
    let mut chain = build_chain(&signer, 8);
    chain[4].body.reasons.push("tampered".into());
    let export = export_for(&signer, chain);
    let (status, _) = verify_export(&export, None).expect("verify returns");
    assert!(matches!(status, ChainStatus::Broken { .. }));
}

#[test]
fn wrong_pinned_key_is_rejected() {
    let signer = ReceiptSigner::generate();
    let attacker = ReceiptSigner::generate();
    let export = export_for(&signer, build_chain(&signer, 3));
    let wrong = hex::encode(attacker.verifying_key().to_bytes());
    let (status, _) = verify_export(&export, Some(&wrong)).expect("verify returns");
    assert!(matches!(status, ChainStatus::Broken { .. }));
}

#[test]
fn json_roundtrip_preserves_chain() {
    let signer = ReceiptSigner::generate();
    let export = export_for(&signer, build_chain(&signer, 4));
    let json = serde_json::to_string(&export).expect("serialize");
    let parsed: ChainExport = serde_json::from_str(&json).expect("parse");
    let (status, _) = verify_export(&parsed, None).expect("verify ok");
    assert_eq!(status, ChainStatus::Valid { receipt_count: 4 });
}

#[test]
fn lying_export_signer_id_is_rejected() {
    // PROOF-VERIFY-SIGNERID-4: an attacker signs a self-consistent chain with
    // their OWN key and embeds their own verifying key, but advertises a different
    // `signer_key_id` (a victim's). Every signature verifies, yet the printed
    // `signer=` would be a lie. `verify_export` must bind the claimed id to the
    // key that actually verifies and reject the mismatch.
    let attacker = ReceiptSigner::generate();
    let chain = build_chain(&attacker, 3);
    let mut export = export_for(&attacker, chain);
    export.signer_key_id = "ed25519-0000000000000000".into(); // a lie, not the attacker's id
    let (status, _) = verify_export(&export, None).expect("verify returns");
    match status {
        ChainStatus::Broken { reason, .. } => {
            assert!(
                reason.contains("signer_key_id mismatch"),
                "expected a signer mismatch, got: {reason}"
            );
        }
        other => panic!("expected Broken, got {other:?}"),
    }
}

#[test]
fn bad_key_hex_errors() {
    let signer = ReceiptSigner::generate();
    let export = export_for(&signer, build_chain(&signer, 2));
    let err = verify_export(&export, Some("not-hex")).unwrap_err();
    assert!(err.to_string().contains("invalid public key"));
}

#[test]
fn relabelled_export_run_id_is_rejected() {
    // The envelope's `run_id` is not covered by any signature, so a chain of
    // genuinely signed receipts can be relabelled to a run that never happened.
    // Every signature still verifies and every hash link still holds; only the
    // story the export tells about itself is false.
    //
    // This is not hypothetical drift. Measured live during the 2.1.0 user test:
    // this verifier printed `CHAIN OK run_id=run-that-never-happened:INVENTED`
    // and exited 0 on a file that the Python and Node verifiers both refused
    // with exit 1 — breaking the one promise sdks/conformance/README.md makes,
    // that all three reach the same verdict with the same exit codes. Nothing
    // caught it because nothing asserted it.
    let signer = ReceiptSigner::generate();
    let chain = build_chain(&signer, 3);
    let mut export = export_for(&signer, chain);
    export.run_id = "run-that-never-happened:INVENTED".into();
    let (status, _) = verify_export(&export, None).expect("verify returns");
    match status {
        ChainStatus::Broken { reason, .. } => {
            assert!(
                reason.contains("run_id mismatch"),
                "expected a run_id mismatch, got: {reason}"
            );
        }
        other => panic!("expected Broken, got {other:?}"),
    }
}
