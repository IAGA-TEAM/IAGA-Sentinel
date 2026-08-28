#![cfg(feature = "receipts")]

//! End-to-end witness for the proxy surface.
//! ponytail: `mcp-doctor` shares the required interceptor parameter and is
//! compile-covered here; duplicating this process harness would test no new path.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_iaga-sentinel")
}

fn db_url(dir: &std::path::Path, name: &str) -> String {
    format!(
        "sqlite:{}?mode=rwc",
        dir.join(name).to_string_lossy().replace('\\', "/")
    )
}

#[test]
fn one_proxy_process_forwards_calls_into_one_receipt_chain() {
    let dir = tempfile::tempdir().expect("tempdir");
    let proxy_db = db_url(dir.path(), "proxy.db");
    let signer = dir.path().join("signer.ed25519");

    let mut child = Command::new(bin())
        .args([
            "--db",
            &proxy_db,
            "proxy",
            "--agent-id",
            "openclaw-builder-01",
            "--command",
            bin(),
            "--",
            "mcp-server",
        ])
        .env("DATABASE_URL", db_url(dir.path(), "downstream.db"))
        .env("IAGA_SENTINEL_SIGNER_KEY_PATH", &signer)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("iaga proxy should spawn");

    {
        let mut stdin = child.stdin.take().expect("proxy stdin");
        for line in [
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"README.md"}}}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"filesystem.read","arguments":{"path":"docs/ARCHITECTURE.md"}}}"#,
        ] {
            writeln!(stdin, "{line}").expect("write to proxy stdin");
        }
    }

    let mut pipe = child.stdout.take().expect("proxy stdout");
    let reader = std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = pipe.read_to_string(&mut buf);
        buf
    });

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match child.try_wait().expect("try_wait on proxy") {
            Some(status) => {
                assert!(status.success(), "proxy exited with {status}");
                break;
            }
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("proxy did not terminate within 30 seconds");
            }
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    }
    let stdout = reader.join().expect("stdout reader thread");
    let responses: Vec<serde_json::Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(line).expect("downstream JSON-RPC response"))
        .collect();
    assert_eq!(responses.len(), 2, "proxy responses:\n{stdout}");
    for response in &responses {
        assert_eq!(
            response["error"]["code"], -32601,
            "an allowed call must reach the downstream server, not be blocked by the proxy: {response}"
        );
        assert!(
            response["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("Unknown IAGA Sentinel tool")),
            "unexpected downstream response: {response}"
        );
    }

    let list = Command::new(bin())
        .args(["--db", &proxy_db, "replay", "--list"])
        .env("IAGA_SENTINEL_SIGNER_KEY_PATH", &signer)
        .output()
        .expect("replay --list should run");
    assert!(
        list.status.success(),
        "replay --list failed: {}",
        String::from_utf8_lossy(&list.stderr)
    );
    let listing = String::from_utf8_lossy(&list.stdout);
    let rows: Vec<Vec<&str>> = listing
        .lines()
        .skip(1)
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.split_whitespace().collect())
        .collect();
    assert_eq!(
        rows.len(),
        1,
        "one proxy process must produce one run, not one run per call:\n{listing}"
    );
    assert!(
        rows[0][0].starts_with("openclaw-builder-01:mcp-proxy-"),
        "the run must be scoped to this proxy process:\n{listing}"
    );
    assert_eq!(
        rows[0][1], "2",
        "both calls must be in that run:\n{listing}"
    );
    assert_eq!(
        rows[0][2], "Allow",
        "the forwarded calls must be allowed:\n{listing}"
    );

    let verify = Command::new(bin())
        .args(["--db", &proxy_db, "replay", rows[0][0], "--verify-only"])
        .env("IAGA_SENTINEL_SIGNER_KEY_PATH", &signer)
        .output()
        .expect("replay --verify-only should run");
    assert!(
        verify.status.success(),
        "the two-receipt chain must verify: stdout={} stderr={}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
    assert!(
        String::from_utf8_lossy(&verify.stdout).contains("receipts=2"),
        "verification must report both receipts"
    );
}
