//! `iaga validate` must surface the policy linter it already ships.
//!
//! The product knows that an HTTP tool with no `destinationFields` gets a
//! best-effort domain allowlist — `formal_verify::verify_policy` reports it as
//! a `weak-enforcement` issue, and that is the whole point of the S1 fix. But
//! the only ways to read that report are `GET /v1/policy/verify/{ws}` (admin,
//! server must be running) and the `policyVerification` block inside every
//! `/v1/inspect` response. Neither is where an operator looks.
//!
//! Where they do look is `iaga validate`, documented as "Validate a policy
//! YAML/JSON config file without starting the server" — the pre-flight command.
//! Measured against a config whose `http.fetch` declares nothing, it printed:
//!
//!     Config is valid!
//!       2 agent profiles
//!       1 workspace policies
//!       2 tool policies
//!
//! while `/v1/policy/verify/ws-legacy` on the same config reported
//! `[medium] weak-enforcement  tools=['http.fetch']`. "Config is valid!" is
//! true about the schema and misleading about the governance.
//!
//! These lock the linter to the pre-flight command: it must warn, it must stay
//! advisory (exit 0 — a policy that has not adopted the field is legal), and it
//! must not cry wolf on a config that did adopt it.

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_iaga-sentinel")
}

const UNDECLARED: &str = r#"
profiles:
  - agentId: a-01
    workspaceId: ws-x
    framework: crewai
    role: researcher
    approvedTools: [http.fetch]
    approvedSecrets: []
    baselineActionTypes: [http]
workspaces:
  - workspaceId: ws-x
    allowedProtocols: [http-function]
    allowedDomains: ["api.github.com"]
    tools:
      - toolName: http.fetch
        allowedActionTypes: [http]
        maxDecision: allow
        requiresHumanReview: false
vault: []
"#;

const DECLARED: &str = r#"
profiles:
  - agentId: a-01
    workspaceId: ws-x
    framework: crewai
    role: researcher
    approvedTools: [http.fetch]
    approvedSecrets: []
    baselineActionTypes: [http]
workspaces:
  - workspaceId: ws-x
    allowedProtocols: [http-function]
    allowedDomains: ["api.github.com"]
    tools:
      - toolName: http.fetch
        allowedActionTypes: [http]
        maxDecision: allow
        requiresHumanReview: false
        destinationFields: [destination, url, uri, endpoint, href, target]
vault: []
"#;

fn validate(body: &str) -> (i32, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("iaga-sentinel.yaml");
    std::fs::write(&path, body).expect("write config");

    let out = Command::new(bin())
        .args(["validate", path.to_str().expect("utf-8 path")])
        .output()
        .expect("iaga validate should run");

    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn validate_warns_about_an_http_tool_that_declares_no_destination_fields() {
    let (code, stdout) = validate(UNDECLARED);

    assert!(
        stdout.contains("destinationFields"),
        "`iaga validate` must surface the weak-enforcement lint it already \
         computes for an HTTP tool with no destinationFields; an operator has \
         no other pre-flight way to see it. stdout was:\n{stdout}"
    );
    assert!(
        stdout.contains("http.fetch"),
        "the warning must name the offending tool. stdout was:\n{stdout}"
    );
    assert_eq!(
        code, 0,
        "the lint is advisory: a policy that has not adopted destinationFields \
         is still a legal policy, so validate must not start failing on it"
    );
}

/// The anti-cry-wolf control, scoped to what the fixture can actually support.
///
/// Named for what it checks: a config that adopted `destinationFields` must not
/// be warned about THAT. It says nothing about silence overall, because these
/// fixtures cover only a couple of action types and so legitimately draw an
/// `incomplete_coverage` lint — asserting an empty output would be a claim the
/// fixture cannot support, and the earlier name implied one.
#[test]
fn validate_does_not_warn_about_destination_fields_once_they_are_declared() {
    let (code, stdout) = validate(DECLARED);

    assert_eq!(code, 0, "a declaring config is valid; stdout:\n{stdout}");
    assert!(
        !stdout.contains("destinationFields"),
        "a config that adopted destinationFields must not be warned about it, or \
         the warning is noise operators learn to ignore. stdout was:\n{stdout}"
    );
    assert!(
        !stdout.contains("error ["),
        "nothing in this fixture is a contradiction, so nothing should print at \
         the `error` level. stdout was:\n{stdout}"
    );
}

/// A workspace declaring the same tool twice with conflicting `maxDecision`.
///
/// `formal_verify` classifies this `critical`: the policy does not mean one
/// thing, so there is no verdict it can be said to express.
const CONTRADICTORY: &str = r#"
profiles:
  - agentId: a-01
    workspaceId: ws-c
    framework: crewai
    role: researcher
    approvedTools: [http.fetch]
    approvedSecrets: []
    baselineActionTypes: [http]
workspaces:
  - workspaceId: ws-c
    allowedProtocols: [mcp]
    allowedDomains: ["api.example.com"]
    tools:
      - toolName: http.fetch
        allowedActionTypes: [http]
        maxDecision: allow
        destinationFields: [url]
      - toolName: http.fetch
        allowedActionTypes: [http]
        maxDecision: block
        destinationFields: [url]
"#;

/// A contradiction is not something to print under a "valid" headline.
///
/// Measured before the fix: `validate` printed `Config is valid!` as its first
/// line and `error [critical] contradiction` several lines below it, then exited
/// 0 — so a CI gate reading the exit code accepted a policy that does not mean
/// one thing, and a human reading the first line was told the opposite of the
/// truth. `iaga import` then imported it, also with exit 0.
///
/// `high`/`medium` lints stay advisory (the two tests above pin that): a policy
/// that has not adopted `destinationFields` is legal. `critical` is different —
/// it is the level `formal_verify` reserves for a policy with no single meaning.
#[test]
fn a_contradictory_policy_is_not_reported_as_valid() {
    let (code, stdout) = validate(CONTRADICTORY);

    assert!(
        stdout.contains("critical"),
        "the linter must still report the contradiction: {stdout}"
    );
    assert!(
        !stdout.contains("Config is valid!"),
        "a config with a critical contradiction must not be headlined valid: {stdout}"
    );
    assert_ne!(
        code, 0,
        "a CI gate reads the exit code; a contradiction must not pass it. stdout: {stdout}"
    );
}

/// And a clean config still says so, with exit 0.
#[test]
fn a_clean_policy_is_still_reported_as_valid_with_exit_zero() {
    let (code, stdout) = validate(DECLARED);
    assert_eq!(code, 0, "a clean config must pass: {stdout}");
    assert!(
        stdout.contains("Config is valid!"),
        "a clean config must still be headlined valid: {stdout}"
    );
}
