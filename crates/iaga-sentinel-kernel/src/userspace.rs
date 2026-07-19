//! Cross-platform userspace launcher for governed processes. Always
//! available, on every OS.
//!
//! Enforcement happens at the process boundary, and it is real:
//! - Runs the policy callback before spawning anything. If the policy
//!   says `Block`, the child never starts; on `Review` the host holds it.
//! - Spawns the child with a scoped environment (only entries explicitly
//!   listed in `ProcessSpec.env` plus a small allowlist of inherited vars:
//!   `PATH`, `HOME`, `SystemRoot` on Windows). No accidental leakage of
//!   secrets the host happens to have in its env.
//! - Scrubs a denylist of known-sensitive variables (cloud and model
//!   provider credentials, registry tokens, the receipt signing key path)
//!   from the final child environment, even when passed explicitly via
//!   `ProcessSpec.env`. Extendable via a TOML file at
//!   `IAGA_SENTINEL_ENV_DENYLIST` (1.3.1).
//! - Confines the spawned child with standard *unprivileged* process
//!   controls (1.8): no core dumps (`RLIMIT_CORE=0`, so in-memory secrets
//!   can't spill to disk), its own session/process-group (`setsid`: clean
//!   reaping, detached from the controlling tty), and — on Linux —
//!   `PR_SET_NO_NEW_PRIVS` so the child can't gain privileges through a
//!   setuid binary. The launch is reaped if the host drops it
//!   (`kill_on_drop`). These are POSIX/Linux primitives, not eBPF/LSM.
//! - Sets the working directory if specified.
//!
//! Where the boundary sits (Enterprise tier, ADR 0010): kernel-level
//! confinement — syscall filtering, network-egress mediation in the kernel,
//! and interception of arbitrary `execve` — needs an authoritative eBPF/LSM
//! backend (`BpfKernel`). That is an Enterprise implementation; this
//! userspace backend reports its posture truthfully (`is_authoritative()`
//! is `false`) and never pretends otherwise.

use std::collections::HashMap;
use std::process::Stdio;

use async_trait::async_trait;

use crate::decision::{KernelDecision, LaunchOutcome, ProcessSpec};
use crate::engine::{EnforcementKernel, PolicyCheck};
use crate::errors::{KernelError, Result};

/// Environment variables that are inherited from the parent unless the
/// `ProcessSpec.env` explicitly overrides them. Conservatively small
/// so secrets in the parent's env can't leak into the agent's child.
const INHERITED_ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "USERNAME",
    "LANG",
    "LC_ALL",
    "TZ",
    "SystemRoot",  // Windows
    "USERPROFILE", // Windows
    "TEMP",        // Windows
    "TMPDIR",      // Unix
];

/// Known-sensitive environment variables that must never reach a governed
/// child, even when explicitly placed in `ProcessSpec.env`. This is a
/// deny-by-name layer on top of `INHERITED_ENV_ALLOWLIST`: the allowlist
/// already blocks accidental inheritance, this list additionally scrubs
/// secrets the caller passes through and guards against the allowlist being
/// widened later. Extend it at runtime via a TOML file pointed to by
/// `IAGA_SENTINEL_ENV_DENYLIST` (see `load_denylist_extension`).
const SENSITIVE_ENV_DENYLIST: &[&str] = &[
    // Cloud provider credentials
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_API_KEY",
    "AZURE_CLIENT_SECRET",
    "AZURE_CLIENT_ID",
    // Model / inference provider keys
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "COHERE_API_KEY",
    "HF_TOKEN",
    "HUGGING_FACE_HUB_TOKEN",
    // Source control + package registries
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITLAB_TOKEN",
    "NPM_TOKEN",
    "PYPI_TOKEN",
    "DOCKER_PASSWORD",
    // Misc secrets
    "SLACK_TOKEN",
    "STRIPE_API_KEY",
    "VAULT_TOKEN",
    "DATABASE_URL",
    // The receipt signing key path must never leak to a governed child.
    "IAGA_SENTINEL_SIGNER_KEY_PATH",
    // Nor must the bootstrap admin credential: a governed child holding it
    // could delete API keys and drain the audit surface it is being judged by.
    "IAGA_SENTINEL_BOOTSTRAP_API_KEY",
];

/// TOML schema for the optional denylist extension file.
#[derive(serde::Deserialize)]
struct DenylistFile {
    #[serde(default)]
    deny: Vec<String>,
}

/// Load extra sensitive-var names from an optional TOML file. `path` is the
/// value of `IAGA_SENTINEL_ENV_DENYLIST`. Format:
/// ```toml
/// deny = ["MY_CUSTOM_SECRET", "INTERNAL_TOKEN"]
/// ```
/// Default (`strict = false`): unreadable or malformed files degrade to the
/// built-in list (warn only) — a bad config must never harden into a crash on
/// the launch path. With `IAGA_SENTINEL_ENV_DENYLIST_STRICT=1` the same
/// failures FAIL CLOSED instead (1.5.2): an operator who configured an
/// extension expects it to apply, and silently launching without it would
/// quietly weaken the secret-scrubbing posture.
fn load_denylist_extension(path: Option<&str>, strict: bool) -> Result<Vec<String>> {
    let path = match path {
        Some(p) if !p.is_empty() => p,
        _ => return Ok(Vec::new()),
    };
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            if strict {
                return Err(KernelError::Denied {
                    reason: format!(
                        "sensitive-env denylist TOML at `{path}` unreadable in strict mode: {e}"
                    ),
                });
            }
            tracing::warn!(path = %path, error = %e, "sensitive-env denylist TOML unreadable; using built-in list only");
            return Ok(Vec::new());
        }
    };
    match toml::from_str::<DenylistFile>(&text) {
        Ok(f) => Ok(f.deny),
        Err(e) => {
            if strict {
                return Err(KernelError::Denied {
                    reason: format!(
                        "sensitive-env denylist TOML at `{path}` malformed in strict mode: {e}"
                    ),
                });
            }
            tracing::warn!(path = %path, error = %e, "sensitive-env denylist TOML malformed; using built-in list only");
            Ok(Vec::new())
        }
    }
}

/// Effective denylist (uppercased for case-insensitive matching) given an
/// optional TOML extension path. Split from `sensitive_denylist` so it is
/// testable without mutating the process environment.
fn build_denylist(
    extra_path: Option<&str>,
    strict: bool,
) -> Result<std::collections::HashSet<String>> {
    let mut set: std::collections::HashSet<String> = SENSITIVE_ENV_DENYLIST
        .iter()
        .map(|s| s.to_ascii_uppercase())
        .collect();
    for extra in load_denylist_extension(extra_path, strict)? {
        set.insert(extra.to_ascii_uppercase());
    }
    Ok(set)
}

/// The effective sensitive-env denylist: the built-ins plus any names from
/// the TOML file at `IAGA_SENTINEL_ENV_DENYLIST`. Strict failure mode is
/// opt-in via `IAGA_SENTINEL_ENV_DENYLIST_STRICT=1`.
fn sensitive_denylist() -> Result<std::collections::HashSet<String>> {
    let extra = std::env::var("IAGA_SENTINEL_ENV_DENYLIST").ok();
    let strict = std::env::var("IAGA_SENTINEL_ENV_DENYLIST_STRICT")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);
    build_denylist(extra.as_deref(), strict)
}

/// The sensitive-env denylist resolved once, plus a stable fingerprint of the
/// scrubbed-name set so a launch can record *which* denylist was applied.
struct DenylistResolved {
    set: std::collections::HashSet<String>,
    digest: String,
}

/// Resolve the effective denylist exactly once (SOUND-KERNEL-1). On a
/// strict-mode misconfiguration the error is captured as a string and replayed
/// at every launch (fail-closed), so the constructor stays infallible.
fn resolve_denylist_once() -> std::result::Result<DenylistResolved, String> {
    match sensitive_denylist() {
        Ok(set) => {
            let digest = denylist_digest(&set);
            Ok(DenylistResolved { set, digest })
        }
        Err(e) => Err(e.to_string()),
    }
}

/// Stable FNV-1a fingerprint of the scrubbed-var-name set, so the launch log
/// records which denylist was in force without pulling a crypto dependency into
/// the kernel crate (same posture as the reasoning tokenizer hash).
fn denylist_digest(set: &std::collections::HashSet<String>) -> String {
    let mut names: Vec<&str> = set.iter().map(String::as_str).collect();
    names.sort_unstable();
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for n in names {
        for b in n.bytes() {
            hash ^= u64::from(b);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash ^= 0x1f;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

pub struct UserspaceKernel {
    policy: PolicyCheck,
    /// Resolved ONCE at construction (SOUND-KERNEL-1) instead of re-reading the
    /// env + TOML on every launch. `Err` (a strict-mode misconfiguration) is
    /// replayed as a fail-closed launch, keeping the constructor infallible.
    denylist: std::result::Result<DenylistResolved, String>,
}

impl UserspaceKernel {
    pub fn new(policy: PolicyCheck) -> Self {
        Self {
            policy,
            denylist: resolve_denylist_once(),
        }
    }

    /// Construct with a permissive default policy that always allows.
    /// Useful for tests and for hosts that intentionally want a
    /// no-op kernel (e.g. development).
    pub fn allow_all() -> Self {
        let policy: PolicyCheck = std::sync::Arc::new(|_spec: &ProcessSpec| {
            Box::pin(async { KernelDecision::Allow })
                as std::pin::Pin<Box<dyn std::future::Future<Output = KernelDecision> + Send>>
        });
        Self {
            policy,
            denylist: resolve_denylist_once(),
        }
    }

    fn build_env(&self, spec: &ProcessSpec) -> Result<HashMap<String, String>> {
        let resolved = self
            .denylist
            .as_ref()
            .map_err(|e| KernelError::Denied { reason: e.clone() })?;
        let denylist = &resolved.set;
        let mut env: HashMap<String, String> = HashMap::new();
        for key in INHERITED_ENV_ALLOWLIST {
            // Defense in depth: never inherit a known-sensitive var even if
            // the allowlist is widened to include one in a later change.
            if denylist.contains(&key.to_ascii_uppercase()) {
                continue;
            }
            if let Ok(v) = std::env::var(key) {
                env.insert((*key).to_string(), v);
            }
        }
        for (k, v) in &spec.env {
            env.insert(k.clone(), v.clone());
        }
        // Authoritative scrub: known-sensitive vars never reach a governed
        // child, even when passed explicitly via `ProcessSpec.env`. Secrets
        // must be delivered through a vetted channel, not the process env.
        env.retain(|k, _| !denylist.contains(&k.to_ascii_uppercase()));
        Ok(env)
    }

    /// Fingerprint of the resolved scrubbed-var-name set, or `None` if the
    /// denylist could not be resolved (strict-mode misconfiguration).
    fn denylist_digest(&self) -> Option<&str> {
        self.denylist.as_ref().ok().map(|r| r.digest.as_str())
    }
}

#[async_trait]
impl EnforcementKernel for UserspaceKernel {
    async fn launch(&self, spec: &ProcessSpec) -> Result<LaunchOutcome> {
        let decision = (self.policy)(spec).await;
        if matches!(decision, KernelDecision::Block) {
            return Ok(LaunchOutcome {
                decision,
                reason: Some("policy blocked launch".into()),
                pid: None,
                exit_code: None,
                backend: self.backend_name(),
            });
        }
        if matches!(decision, KernelDecision::Review) {
            // The host is responsible for surfacing the review request
            // and either approving or rejecting. The userspace kernel
            // does not hold the launch on its own.
            return Ok(LaunchOutcome {
                decision,
                reason: Some("policy held launch for human review".into()),
                pid: None,
                exit_code: None,
                backend: self.backend_name(),
            });
        }

        // Strict denylist mode fails closed: if the configured extension
        // can't be applied, the launch is blocked rather than silently run
        // with weaker secret scrubbing. The denylist is resolved once at
        // construction (SOUND-KERNEL-1); here we only replay any error.
        let env = match self.build_env(spec) {
            Ok(env) => env,
            Err(e) => {
                return Ok(LaunchOutcome {
                    decision: KernelDecision::Block,
                    reason: Some(e.to_string()),
                    pid: None,
                    exit_code: None,
                    backend: self.backend_name(),
                })
            }
        };
        // Record WHICH denylist scrubbed this launch's environment, so an
        // operator can correlate a governed run with the secret-scrubbing
        // posture in force at the time (SOUND-KERNEL-1).
        tracing::debug!(
            agent_id = %spec.agent_id,
            program = %spec.program,
            env_scrub_digest = self.denylist_digest().unwrap_or("none"),
            "governed launch environment scrubbed"
        );

        // Build a std `Command` first so we can attach the unprivileged
        // process hardening via `pre_exec` (1.8) — tokio's `Command` has no
        // such hook. Converting std -> tokio afterwards is the documented path.
        let mut std_cmd = std::process::Command::new(&spec.program);
        std_cmd.args(&spec.args);
        std_cmd.env_clear();
        for (k, v) in env {
            std_cmd.env(k, v);
        }
        if let Some(cwd) = &spec.working_dir {
            std_cmd.current_dir(cwd);
        }
        std_cmd.stdin(Stdio::null());
        std_cmd.stdout(Stdio::inherit());
        std_cmd.stderr(Stdio::inherit());
        harden_child(&mut std_cmd);

        let mut cmd = tokio::process::Command::from(std_cmd);
        // Reap the child if the host drops the launch future (cross-platform).
        cmd.kill_on_drop(true);

        let mut child = cmd.spawn().map_err(|e| KernelError::Spawn {
            program: spec.program.clone(),
            msg: e.to_string(),
        })?;
        let pid = child.id();

        // For M4 we wait synchronously on the child so the receipt
        // for the launch can record the final exit code. Long-lived
        // detached agents are an M4.1 use case (host owns the handle).
        let status = child.wait().await.map_err(|e| KernelError::Spawn {
            program: spec.program.clone(),
            msg: format!("wait failed: {}", e),
        })?;

        Ok(LaunchOutcome {
            decision,
            reason: None,
            pid,
            exit_code: status.code(),
            backend: self.backend_name(),
        })
    }

    fn backend_name(&self) -> &'static str {
        "userspace"
    }

    fn is_authoritative(&self) -> bool {
        // Stays `false` even with the 1.8 process hardening: setsid,
        // RLIMIT_CORE=0 and PR_SET_NO_NEW_PRIVS are unprivileged process
        // controls, not kernel-side enforcement. Only an authoritative
        // eBPF/LSM backend (Enterprise, ADR 0010) flips this to `true`.
        // Reporting the posture honestly is the whole point of the flag.
        false
    }
}

/// Apply standard *unprivileged* process hardening to a governed child at
/// spawn. These are POSIX/Linux process controls (not eBPF/LSM), so they stay
/// on the OSS side of the boundary (ADR 0010) and run under the host's existing
/// privileges. Best-effort by design: a step that fails (e.g. `setsid` when the
/// caller already leads a process group) must never abort an otherwise-allowed
/// launch — the posture is then simply no stronger than the pre-1.8 behaviour.
#[cfg(unix)]
#[allow(unsafe_code)] // `pre_exec` is inherently unsafe; the closure is async-signal-safe.
fn harden_child(cmd: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: `pre_exec` requires the closure to be async-signal-safe. It runs
    // in the forked child before `exec` and calls only async-signal-safe libc
    // functions with no allocation. The enclosing `unsafe` covers the closure
    // body too, so the libc calls need no further `unsafe`.
    unsafe {
        cmd.pre_exec(|| {
            // Own session/process-group: detach from the controlling tty and
            // let the host reap the whole tree.
            libc::setsid();
            // No core dumps: a core file can spill in-memory secrets to disk.
            let no_core = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            libc::setrlimit(libc::RLIMIT_CORE, &no_core);
            // Linux: the child cannot gain privileges via a setuid binary.
            #[cfg(target_os = "linux")]
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            Ok(())
        });
    }
}

/// Non-Unix hosts rely on the cross-platform `kill_on_drop` reaping path.
/// Windows Job Object resource caps are a possible future follow-up.
#[cfg(not(unix))]
fn harden_child(_cmd: &mut std::process::Command) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec_with_env(pairs: &[(&str, &str)]) -> ProcessSpec {
        ProcessSpec {
            agent_id: "test".into(),
            program: "true".into(),
            args: vec![],
            working_dir: None,
            env: pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        }
    }

    #[test]
    fn build_env_scrubs_sensitive_vars_from_spec_env() {
        let spec = spec_with_env(&[
            ("OPENAI_API_KEY", "sk-secret"),
            ("aws_secret_access_key", "lowercase-also-scrubbed"),
            ("MY_TOOL_FLAG", "1"),
        ]);
        let k = UserspaceKernel::allow_all();
        let env = k.build_env(&spec).expect("non-strict build_env");
        assert!(
            !env.contains_key("OPENAI_API_KEY"),
            "known secret must be scrubbed from the child env"
        );
        assert!(
            !env.contains_key("aws_secret_access_key"),
            "scrub is case-insensitive"
        );
        assert_eq!(
            env.get("MY_TOOL_FLAG").map(String::as_str),
            Some("1"),
            "non-sensitive explicit vars are preserved"
        );
    }

    #[test]
    fn builtin_denylist_has_24_entries() {
        assert_eq!(SENSITIVE_ENV_DENYLIST.len(), 24);
    }

    #[test]
    fn denylist_digest_is_stable_and_order_independent() {
        use std::collections::HashSet;
        let a: HashSet<String> = ["OPENAI_API_KEY", "AWS_SECRET_ACCESS_KEY"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let b: HashSet<String> = ["AWS_SECRET_ACCESS_KEY", "OPENAI_API_KEY"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        // Sorted before hashing, so insertion/iteration order does not matter.
        assert_eq!(denylist_digest(&a), denylist_digest(&b));
        assert_eq!(denylist_digest(&a).len(), 16);
        // A different set fingerprints differently.
        let c: HashSet<String> = ["OPENAI_API_KEY"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        assert_ne!(denylist_digest(&a), denylist_digest(&c));
    }

    #[test]
    fn toml_extension_adds_custom_names() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("deny.toml");
        std::fs::write(&path, "deny = [\"CUSTOM_SECRET\", \"internal_token\"]")
            .expect("write toml");
        let set = build_denylist(Some(path.to_str().unwrap()), false).expect("valid toml");
        assert!(set.contains("CUSTOM_SECRET"));
        assert!(set.contains("INTERNAL_TOKEN"), "extension is uppercased");
        // Built-ins remain present alongside the extension.
        assert!(set.contains("OPENAI_API_KEY"));
    }

    #[test]
    fn missing_toml_path_degrades_to_builtins() {
        let set = build_denylist(Some("/nonexistent/deny.toml"), false).expect("lenient mode");
        assert!(set.contains("AWS_SECRET_ACCESS_KEY"));
        assert_eq!(set.len(), SENSITIVE_ENV_DENYLIST.len());
    }

    #[test]
    fn malformed_toml_degrades_to_builtins_when_lenient() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("deny.toml");
        std::fs::write(&path, "deny = [unclosed").expect("write toml");
        let set = build_denylist(Some(path.to_str().unwrap()), false).expect("lenient mode");
        assert_eq!(set.len(), SENSITIVE_ENV_DENYLIST.len());
    }

    #[test]
    fn malformed_toml_fails_closed_in_strict_mode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("deny.toml");
        std::fs::write(&path, "deny = [unclosed").expect("write toml");
        let err = build_denylist(Some(path.to_str().unwrap()), true).expect_err("strict mode");
        assert!(matches!(err, KernelError::Denied { .. }));
        assert!(err.to_string().contains("strict mode"));
    }

    #[test]
    fn missing_toml_fails_closed_in_strict_mode() {
        let err = build_denylist(Some("/nonexistent/deny.toml"), true).expect_err("strict mode");
        assert!(matches!(err, KernelError::Denied { .. }));
    }

    #[test]
    fn strict_mode_without_extension_path_is_a_noop() {
        // Strict mode only governs the optional TOML extension; with no path
        // configured the built-in list applies as always.
        let set = build_denylist(None, true).expect("no extension configured");
        assert_eq!(set.len(), SENSITIVE_ENV_DENYLIST.len());
    }
}
