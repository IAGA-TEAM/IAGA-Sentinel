//! Smoke tests for the `iaga-verify` binary (1.5.2).
//!
//! The library path was covered by `tests/roundtrip.rs`, but the CLI itself
//! (argument parsing, exit codes, output) had no test at all. Exit codes are
//! documented in `src/main.rs`: 0 valid, 1 broken/empty, 2 usage error,
//! 3 IO/parse error — these are part of the public contract (scripts and CI
//! pipelines branch on them), so each one is pinned here.
//!
//! Runs the real binary via `CARGO_BIN_EXE_iaga-verify` (same pattern as
//! `iaga-sentinel-core/tests/cli_plugin_tests.rs`); fixtures are generated
//! in-test with `ReceiptSigner::generate()` like `tests/roundtrip.rs`.

use std::process::Command;

use iaga_sentinel_receipts::{
    chain_link, ChainExport, Receipt, ReceiptBody, ReceiptSigner, Verdict,
};

const BIN: &str = env!("CARGO_BIN_EXE_iaga-verify");

fn build_chain(signer: &ReceiptSigner, len: u64) -> Vec<Receipt> {
    let mut chain = Vec::with_capacity(len as usize);
    let mut head: Option<Receipt> = None;
    for i in 0..len {
        let (parent_hash, seq) = chain_link(head.as_ref()).expect("link ok");
        let body = ReceiptBody {
            run_id: "run-cli".into(),
            seq,
            parent_hash,
            input_hash: format!("{:064x}", i),
            policy_hash: "p".repeat(64),
            threat_feed_hash: None,
            plugin_digests: vec![],
            model_digests: vec![],
            ml_scores: None,
            verdict: Verdict::Allow,
            reasons: vec![],
            risk_score: 0,
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

fn write_export(dir: &tempfile::TempDir, signer: &ReceiptSigner, chain: Vec<Receipt>) -> String {
    let export = ChainExport {
        run_id: "run-cli".into(),
        signer_key_id: signer.key_id().into(),
        signer_verifying_key: hex::encode(signer.verifying_key().to_bytes()),
        receipts: chain,
    };
    let path = dir.path().join("chain.json");
    std::fs::write(&path, serde_json::to_string(&export).expect("serialize"))
        .expect("write export");
    path.display().to_string()
}

#[test]
fn help_exits_zero_and_prints_usage() {
    let out = Command::new(BIN).arg("--help").output().expect("run bin");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("usage: iaga-verify"));
}

#[test]
fn no_args_is_a_usage_error_exit_2() {
    let out = Command::new(BIN).output().expect("run bin");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("usage: iaga-verify"));
}

#[test]
fn valid_chain_exits_zero_with_chain_ok() {
    let dir = tempfile::tempdir().expect("tempdir");
    let signer = ReceiptSigner::generate();
    let path = write_export(&dir, &signer, build_chain(&signer, 5));

    let out = Command::new(BIN).arg(&path).output().expect("run bin");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("CHAIN OK"));
    assert!(stdout.contains("run_id=run-cli"));
    // Without --key the verifier must disclose it trusted the embedded key.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("self-asserted"));
}

#[test]
fn pinned_key_is_accepted_and_labeled() {
    let dir = tempfile::tempdir().expect("tempdir");
    let signer = ReceiptSigner::generate();
    let key_hex = hex::encode(signer.verifying_key().to_bytes());
    let path = write_export(&dir, &signer, build_chain(&signer, 3));

    let out = Command::new(BIN)
        .args([&path, "--key", &key_hex])
        .output()
        .expect("run bin");
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("key=pinned"));
}

#[test]
fn tampered_chain_exits_one_with_chain_broken() {
    let dir = tempfile::tempdir().expect("tempdir");
    let signer = ReceiptSigner::generate();
    let mut chain = build_chain(&signer, 4);
    chain[2].body.risk_score = 99; // signature no longer matches
    let path = write_export(&dir, &signer, chain);

    let out = Command::new(BIN).arg(&path).output().expect("run bin");
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("CHAIN BROKEN"));
}

#[test]
fn missing_file_exits_three() {
    let out = Command::new(BIN)
        .arg("does/not/exist/chain.json")
        .output()
        .expect("run bin");
    assert_eq!(out.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot read"));
}

#[test]
fn malformed_json_exits_three() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("garbage.json");
    std::fs::write(&path, "{ not json").expect("write garbage");

    let out = Command::new(BIN)
        .arg(path.display().to_string())
        .output()
        .expect("run bin");
    assert_eq!(out.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not a valid chain export"));
}

#[test]
fn unexpected_extra_argument_exits_two() {
    let out = Command::new(BIN)
        .args(["a.json", "b.json"])
        .output()
        .expect("run bin");
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("unexpected argument"));
}

// ── --expect-count: the offline defence against tail truncation ──
//
// "CHAIN OK" proves the chain is a valid PREFIX. Drop the trailing receipts and
// what remains is a shorter valid chain that still exits 0 — a reader notices
// only from the printed count. `--expect-count` turns an external record of the
// true length into an exit code, without touching the frozen receipt bytes.

#[test]
fn expect_count_matching_the_chain_still_exits_zero() {
    let dir = tempfile::tempdir().expect("tempdir");
    let signer = ReceiptSigner::generate();
    let path = write_export(&dir, &signer, build_chain(&signer, 5));

    let out = Command::new(BIN)
        .args([&path, "--expect-count", "5"])
        .output()
        .expect("run bin");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("CHAIN OK"));
}

#[test]
fn a_tail_truncated_chain_fails_against_the_expected_count() {
    let dir = tempfile::tempdir().expect("tempdir");
    let signer = ReceiptSigner::generate();

    // Build five, keep the first three: a genesis-rooted valid prefix, which is
    // exactly what dropping the tail of an export produces.
    let mut chain = build_chain(&signer, 5);
    chain.truncate(3);
    let path = write_export(&dir, &signer, chain);

    // Without the anchor it passes — this is the hole.
    let silent = Command::new(BIN).arg(&path).output().expect("run bin");
    assert_eq!(
        silent.status.code(),
        Some(0),
        "a truncated-but-valid prefix verifies on its own; that is the defect \
         --expect-count exists to close"
    );

    // With the anchor it fails.
    let anchored = Command::new(BIN)
        .args([&path, "--expect-count", "5"])
        .output()
        .expect("run bin");
    assert_eq!(
        anchored.status.code(),
        Some(1),
        "a chain shorter than the anchored count must fail"
    );
    let stderr = String::from_utf8_lossy(&anchored.stderr);
    assert!(stderr.contains("CHAIN LENGTH MISMATCH"), "stderr: {stderr}");
    assert!(stderr.contains("expected=5"));
}

#[test]
fn expect_count_needs_an_integer_value_exit_2() {
    let dir = tempfile::tempdir().expect("tempdir");
    let signer = ReceiptSigner::generate();
    let path = write_export(&dir, &signer, build_chain(&signer, 2));

    let out = Command::new(BIN)
        .args([&path, "--expect-count", "two"])
        .output()
        .expect("run bin");
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("non-negative integer"));
}
