# Security

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.0.x   | Yes       |

Older lines are not patched. Receipts produced by any earlier release keep
verifying — the receipt schema has not changed since 1.3.0, and the offline
verifiers accept every chain they ever produced — so upgrading does not
invalidate evidence you have already exported.

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Please email **info@iaga.tech** with:

1. A description of the vulnerability
2. Steps to reproduce
3. Impact assessment
4. Suggested fix (optional)

We will acknowledge receipt within **48 hours** and provide an initial assessment within **5 business days**.

## In Scope

- Authentication or authorization bypass
- Injection patterns not caught by the firewall
- Data leakage through API responses or logs
- Cryptographic weaknesses in NHI identity or API key hashing
- MCP proxy bypasses allowing ungoverned tool execution

## Out of Scope

- Denial of service against the server itself
- Social engineering
- Vulnerabilities in upstream dependencies (report to respective maintainers)
- Issues requiring physical access to the host

## Disclosure

We follow responsible disclosure. Once a fix is available we will:

1. Release a patched version
2. Publish a GitHub security advisory
3. Credit the reporter (unless they prefer anonymity)

## Signing and release integrity

IAGA Sentinel uses Ed25519 signatures where applicable:

- Every governance verdict can be recorded as an Ed25519-signed receipt, appended to a
  per-run hash chain. Anyone can verify a chain offline with `iaga-verify`, with no
  database, server, or network access.
- Plugin manifests can be signed and verified with Ed25519 (opt-in, the
  `plugin-manifest-signing` feature).
- Plugin attestation can verify a Sigstore bundle and CycloneDX SBOM structurally and
  offline (opt-in, the `plugin-attestation` feature). This checks bundle structure and
  digests, not a full Rekor chain-of-trust.

Release artifacts and git tags are not signed today. If that changes it will be noted here.
Qualified eIDAS signatures are an Enterprise capability and are out of scope for this open
build.

## Secret handling for governed processes

When `iaga run` launches a child process under the kernel, the child receives a scoped
environment: an allowlist of inherited variables plus the entries the caller passes
explicitly. On top of that, IAGA Sentinel scrubs a denylist of 24 known secret-bearing
variables (cloud and model-provider credentials such as `AWS_SECRET_ACCESS_KEY` and
`OPENAI_API_KEY`, registry tokens, and the receipt signing-key path
`IAGA_SENTINEL_SIGNER_KEY_PATH`) from the final child environment, even when passed
explicitly. The scrub is authoritative: known secrets do not reach a governed agent
through the process environment, so deliver them through a vetted channel instead. Extend
the denylist at runtime with a TOML file pointed to by `IAGA_SENTINEL_ENV_DENYLIST`
(`deny = ["MY_SECRET", ...]`). Added in 1.3.1 (ADR 0018), always on, no feature flag.

For what data the software stores and where it goes, see [`DATA_HANDLING.md`](DATA_HANDLING.md).
