//! `iaga-verify`: verify an exported IAGA Sentinel receipt chain offline.
//!
//! Usage:
//!   iaga-verify <chain.json> [--key <hex-ed25519-pubkey>]
//!
//! Where `<chain.json>` is produced by `iaga replay <run_id> --export`.
//! Exit codes: 0 chain valid, 1 chain broken or empty, 2 usage error,
//! 3 IO or parse error.

use std::process::ExitCode;

use iaga_sentinel_receipts::{ChainExport, ChainStatus};
use iaga_sentinel_verify::{verify_export, KeySource};

const USAGE: &str = "usage: iaga-verify <chain.json> [--key <hex-ed25519-pubkey>]";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mut path: Option<String> = None;
    let mut key: Option<String> = None;

    while let Some(a) = args.next() {
        match a.as_str() {
            "--key" | "-k" => match args.next() {
                Some(k) => key = Some(k),
                None => {
                    eprintln!("iaga-verify: --key needs a hex public key");
                    return ExitCode::from(2);
                }
            },
            "-h" | "--help" => {
                println!("{USAGE}");
                println!(
                    "Verifies the Ed25519 signatures and hash-chain links of a signed receipt chain."
                );
                println!(
                    "Pass --key with the expected public key to authenticate authorship; without"
                );
                println!("it the verifier trusts the key embedded in the export (self-asserted).");
                return ExitCode::SUCCESS;
            }
            other if path.is_none() => path = Some(other.to_string()),
            other => {
                eprintln!("iaga-verify: unexpected argument: {other}");
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
        }
    }

    let path = match path {
        Some(p) => p,
        None => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };

    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("iaga-verify: cannot read {path}: {e}");
            return ExitCode::from(3);
        }
    };
    let export: ChainExport = match serde_json::from_str(&raw) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("iaga-verify: {path} is not a valid chain export: {e}");
            return ExitCode::from(3);
        }
    };

    let (status, source) = match verify_export(&export, key.as_deref()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("iaga-verify: {e}");
            return ExitCode::from(3);
        }
    };

    if source == KeySource::Embedded {
        eprintln!(
            "warning: verifying against the key embedded in the export (self-asserted). \
Pass --key with the expected public key to authenticate authorship."
        );
    }
    let key_label = match source {
        KeySource::Pinned => "pinned",
        KeySource::Embedded => "embedded",
    };

    match status {
        ChainStatus::Valid { receipt_count } => {
            // CRYPTO-EXPORT-TRUNC-7: surface the seq range so an auditor holding
            // an external expected count can spot a truncated tail. The chain is
            // genesis-rooted (verify_chain requires seq 0..N-1), so the range is
            // 0..receipt_count-1. "CHAIN OK" proves PREFIX integrity, not
            // completeness — dropping trailing receipts still verifies as a
            // shorter valid chain. Detecting tail truncation offline needs an
            // external anchor (sealed head / archival timestamp), which is
            // Enterprise (see SECURITY.md).
            let last_seq = receipt_count.saturating_sub(1);
            println!(
                "CHAIN OK  run_id={}  receipts={}  seq=0..{}  signer={}  key={}",
                export.run_id, receipt_count, last_seq, export.signer_key_id, key_label
            );
            ExitCode::SUCCESS
        }
        ChainStatus::Broken { seq, reason } => {
            eprintln!(
                "CHAIN BROKEN  run_id={}  seq={}  reason={}",
                export.run_id, seq, reason
            );
            ExitCode::from(1)
        }
        ChainStatus::Empty => {
            eprintln!("CHAIN EMPTY  run_id={}", export.run_id);
            ExitCode::from(1)
        }
    }
}
