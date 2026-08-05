//! What the CLI reports when it *refuses* (2.1.0).
//!
//! Three shipped paths answered a refusal with success, and none of them had a
//! test — in every case the library underneath was correct and tested, and the
//! thin CLI adapter on top was not:
//!
//! * `iaga run` mapped `LaunchOutcome::exit_code == None` (the child never
//!   started) to process exit 0, so `iaga run -- <blocked> && next` ran `next`.
//!   `iaga-sentinel-kernel/tests/userspace.rs` already asserts the outcome is
//!   `None`; nothing asserted what the CLI did with it.
//! * `iaga replay --export` wrote a chain file for a run with no receipts —
//!   real `signer_key_id`, real verifying key, `"receipts": []` — and exited 0.
//! * `iaga proxy` waited for a reply to a JSON-RPC *notification*, which by
//!   definition never comes. `notifications/initialized` is the mandatory third
//!   step of the MCP handshake, so every spec-compliant client wedged the proxy
//!   on its first connection.
//!
//! Exit codes follow the `iaga inspect` convention already in `main.rs`:
//! 0 allow, 1 review, 2 block, 3 error.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_iaga-sentinel")
}

/// `sqlite:` URLs want forward slashes even on Windows.
fn db_url(dir: &std::path::Path, name: &str) -> String {
    format!(
        "sqlite:{}?mode=rwc",
        dir.join(name).to_string_lossy().replace('\\', "/")
    )
}

#[cfg(feature = "receipts")]
#[test]
fn replay_export_refuses_to_write_an_empty_chain() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path().join("chain.json");

    let output = Command::new(bin())
        .args([
            "--db",
            &db_url(dir.path(), "export.db"),
            "replay",
            "no-such-run-id",
            "--export",
            out.to_str().expect("utf-8 path"),
        ])
        .output()
        .expect("replay --export should run");

    assert_eq!(
        output.status.code(),
        Some(3),
        "exporting a run with no receipts must fail, not report success; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !out.exists(),
        "no evidence file may be written for a run that has no receipts: an empty \
         chain carries a real signer key and reads as authentic"
    );
}

#[cfg(feature = "kernel")]
#[test]
fn run_reports_a_blocked_launch_with_a_nonzero_exit_code() {
    let dir = tempfile::tempdir().expect("tempdir");

    // `rm` is not an approved tool for the seeded `cli-runner`/`ws-cli` pair and
    // `rm -rf /` also trips the high-risk pattern, so the launch is refused
    // before the child is ever spawned.
    let output = Command::new(bin())
        .args([
            "--db",
            &db_url(dir.path(), "run-block.db"),
            "run",
            "--",
            "rm",
            "-rf",
            "/",
        ])
        .output()
        .expect("iaga run should run");

    assert_eq!(
        output.status.code(),
        Some(2),
        "a blocked launch must exit 2 (block), not 0; stdout: {} stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("decision: Block"),
        "the refusal should still be reported on stdout"
    );
}

#[cfg(feature = "kernel")]
#[test]
fn run_propagates_success_for_an_allowed_launch() {
    let dir = tempfile::tempdir().expect("tempdir");

    // Both are on the seeded `ws-cli` approved-tool list and exist on their
    // respective platforms, so the child really runs and really exits 0.
    let program = if cfg!(windows) { "hostname" } else { "true" };

    let output = Command::new(bin())
        .args([
            "--db",
            &db_url(dir.path(), "run-allow.db"),
            "run",
            "--",
            program,
        ])
        .output()
        .expect("iaga run should run");

    assert_eq!(
        output.status.code(),
        Some(0),
        "an allowed launch whose child exits 0 must exit 0; stdout: {} stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The MCP handshake, end to end, through the proxy: `initialize`, then the
/// `notifications/initialized` notification, then a real request. Before the
/// fix the proxy blocked forever on the notification, so this test does not
/// merely fail on a regression — it would hang. The watchdog turns that into a
/// loud failure instead of a stuck suite.
#[test]
fn proxy_survives_the_initialized_notification() {
    let dir = tempfile::tempdir().expect("tempdir");

    let mut child = Command::new(bin())
        .args([
            "--db",
            &db_url(dir.path(), "proxy.db"),
            "proxy",
            "--agent-id",
            "cli-runner",
            "--command",
            bin(),
            "--",
            "mcp-server",
        ])
        // The `--db` above governs the PROXY. The downstream `mcp-server` is a
        // separate process with its own CLI, and nothing forwards the flag to
        // it, so it falls back to `sqlite:iaga_sentinel.db?mode=rwc` — relative
        // to the CWD, which under `cargo test` is the crate directory. That made
        // this test read and write a database shared with every other run on the
        // machine: a leftover from a build that knows a later migration makes
        // the downstream refuse to start, and the failure surfaces here as
        // "Downstream server closed connection" — a red test that says nothing
        // about the proxy. Observed exactly that, twice. `DATABASE_URL` is
        // inherited by the child, so this pins it inside the tempdir.
        .env("DATABASE_URL", db_url(dir.path(), "downstream.db"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("iaga proxy should spawn");

    {
        let mut stdin = child.stdin.take().expect("proxy stdin");
        for line in [
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        ] {
            writeln!(stdin, "{line}").expect("write to proxy stdin");
        }
        // Closing stdin is what tells the proxy to shut down.
    }

    // Drain stdout on a worker so a wedged proxy cannot deadlock us on a full pipe.
    let mut pipe = child.stdout.take().expect("proxy stdout");
    let reader = std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = pipe.read_to_string(&mut buf);
        buf
    });

    // Poll rather than block, and *kill* on timeout: an orphaned proxy keeps
    // cargo's captured-output pipe open, which hangs the whole suite instead of
    // reporting this one test as failed.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut wedged = false;
    loop {
        match child.try_wait().expect("try_wait on proxy") {
            Some(_) => break,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                wedged = true;
                break;
            }
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    }
    let stdout = reader.join().expect("stdout reader thread");

    assert!(
        !wedged,
        "the proxy never terminated: it is blocked waiting for a reply to a \
         JSON-RPC notification, which by definition never gets one"
    );

    assert!(
        !stdout.contains("Downstream server closed connection"),
        "the notification must not tear down the downstream server; got:\n{stdout}"
    );

    let responses: Vec<serde_json::Value> = stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("proxy must emit valid JSON-RPC"))
        .collect();

    // Exactly two: one per request. A notification gets no response at all.
    assert_eq!(
        responses.len(),
        2,
        "a notification must not produce a response line; got:\n{stdout}"
    );
    assert_eq!(responses[0]["id"], 1, "first response answers initialize");
    assert_eq!(
        responses[1]["id"], 2,
        "second response answers tools/list, not the notification"
    );
    assert!(
        responses[1]["result"]["tools"].is_array(),
        "tools/list must succeed after the handshake completes; got:\n{stdout}"
    );
}
