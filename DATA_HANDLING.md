# Data handling and security

This document describes, in technical terms, what data IAGA Sentinel writes, where it
stores it, and what leaves the machine it runs on. It exists because IAGA Sentinel is a
conformity and evidence tool: the first question a security team or a Data Protection
Officer asks is "if I run this, what ends up in the logs, and where does it go?" The
answer below is precise and matches the code, because honest data handling is part of the
product.

This is engineering documentation, not a privacy policy, and it is not legal advice. It
describes the open build (BUSL-1.1). Where behavior depends on a feature flag or an
environment variable, that is called out explicitly.

## Summary

- By default, signed receipts store hashes and decision metadata, not raw request inputs.
- Capturing raw inputs is opt-in and off by default (`IAGA_SENTINEL_RECEIPT_CAPTURE`).
- All state is self-hosted by the operator (SQLite by default, Postgres optional). There is
  no managed IAGA backend.
- Nothing calls home. The software sends no telemetry, analytics, or update checks to IAGA.
- Verification is fully offline: `iaga-verify` reads an exported chain and checks signatures
  with no database, no server, and no network.

## What a signed receipt contains

Every governance verdict can produce one Ed25519-signed receipt, appended to a per-run
hash chain. The canonical body is defined in
`crates/iaga-sentinel-receipts/src/receipt.rs` (`ReceiptBody`). Fields are serialized in a
stable order; fields that are empty or absent are omitted from the JSON.

| Field | Type | Present | Meaning |
|-------|------|---------|---------|
| `run_id` | string | always | Identifier of the run this receipt belongs to. |
| `seq` | integer | always | Position in the chain, starting at 0 and incrementing by 1. |
| `parent_hash` | string or null | always | SHA-256 of the previous receipt body, `null` at `seq` 0. |
| `input_hash` | string | always | SHA-256 binding the action content: the agent id, the tool name, and a SHA-256 digest of the canonical payload. The raw payload itself is never included (see below). |
| `policy_hash` | string | always | SHA-256 of the compiled policy bundle (or a default placeholder when no Dictum overlay is loaded). |
| `verdict` | enum | always | `allow`, `review`, or `block`. |
| `reasons` | string array | usually | Short machine reasons for the verdict; omitted when empty. |
| `risk_score` | integer | always | Numeric risk for the decision. |
| `timestamp` | string | always | RFC3339 UTC time of the verdict. |
| `signer_key_id` | string | always | Identifier of the signing key, for example `ed25519-1c81ae26...`. Not the key itself. |
| `is_authoritative` | boolean | open build (1.3.1+) | `false` on every open-build receipt: the open build enforces at the process boundary (userspace), not in the kernel, so no authoritative eBPF/LSM kernel ships here. Added in 1.3.1; absent on receipts produced before 1.3.1 and elided when unset, so old receipts verify unchanged. |
| `signature` | string | always | Hex Ed25519 signature over the canonical body (on the receipt wrapper). |
| `plugin_digests` | array | reserved | Present in the schema but not populated in this build (always empty, so omitted). |
| `model_digests` | array | conditional | Digests of ML models consulted. Present only with the `ml` feature and ML evidence; otherwise omitted. |
| `ml_scores` | object | conditional | ML score bundle. Present only with the `ml` feature and ML evidence; otherwise omitted. |
| `pipeline_inputs_capture` | object | opt-in | Raw input snapshot. Present only under drift-capture (see below); otherwise omitted. |
| `apl_eval_trace` | object | opt-in | Policy evaluation trace. Present only under drift-capture; otherwise omitted. |
| `ml_inference_inputs` | object | opt-in | Per-model tokenized-input digests (hashes, never raw tokens). Present only under drift-capture; otherwise omitted. |

`input_hash` is a hash, not the input. In the default build it is a SHA-256 over the agent
id, the tool name, and a SHA-256 digest of the canonical request payload, so it is bound to
the action's content (`rm -rf /` and `ls` produce different hashes) while the receipt still
does not carry the request body or its arguments, only the digest. `policy_hash` is likewise
a digest of the compiled policy, not the policy text.

A real default receipt, exported with `iaga replay <run_id> --export chain.json`, looks
like this. Note the absence of any raw command, path, or argument:

```json
{
  "run_id": "ff7ea492-dafd-4a25-85bc-e87960281308",
  "seq": 0,
  "parent_hash": null,
  "input_hash": "2242715af7baacff15cd7d5b87e1d75d15119888506feef88bffde8a5c66cb60",
  "policy_hash": "3f406ed201dc5a44c805f587378ffceb94766c4c2fe1f559858d0c40f247fd3f",
  "verdict": "allow",
  "reasons": ["no high-risk rule matched", "agent-role:builder"],
  "risk_score": 2,
  "timestamp": "2026-06-07T13:30:41.476975+00:00",
  "signer_key_id": "ed25519-1c81ae26e45ab1173062ea4ec12dde3f",
  "is_authoritative": false,
  "signature": "89a167550f2c982f009c51fde02d15a35db8d6c5c784949d9308401cf66f05e2..."
}
```

## PII posture

By default, receipts do not capture raw request inputs or sensitive content. They store
hashes (`input_hash`, `policy_hash`), the verdict, the risk score, short reasons, and the
signer key id. An operator can publish or share a receipt chain as evidence without
exposing the underlying request data.

Raw-input capture is opt-in. Setting the host environment variable
`IAGA_SENTINEL_RECEIPT_CAPTURE` to `1`, `true`, or `yes` turns on drift-capture, which adds
three optional, additive structures to each receipt:

- `pipeline_inputs_capture`: a JSON snapshot of the request that drove the verdict, the
  host pipeline tag, and a SHA-256 of the captured payload.
- `apl_eval_trace`: the policy hash, the number of policies evaluated, and the names of the
  policies that fired.
- `ml_inference_inputs`: per-model SHA-256 digests of the tokenized input. Digests only,
  never the raw tokens.

Capture is off by default. When it is off, these fields are `None` and are elided from the
signed bytes, so receipts stay byte-identical to a build with no capture support at all
(there is a test that asserts this byte-equality). The practical consequence: with capture
off, no request content enters the receipt store; with capture on, the
`pipeline_inputs_capture.request_json` snapshot can contain whatever the request contained,
including PII. Enabling capture is the operator's decision and the operator owns the
resulting data. Use it for forensic replay in a controlled environment, not as an
always-on default, unless the data involved is suitable for that.

## Where the data lives

All state is stored by the operator, in a backend the operator chooses:

- SQLite by default. The default connection string is
  `sqlite:iaga_sentinel.db?mode=rwc`, a local file in the working directory.
- Postgres optionally, when the build includes the `postgres` feature and `DATABASE_URL`
  is set to a `postgres://` connection string.

There is no managed IAGA backend and no cloud component. The tables created hold audit
events, the human-review queue, agent profiles and workspace policies, API key hashes (the
hash, not the raw key), non-human-identity records, session graphs, taint sessions,
behavioral fingerprints, rate-limit configuration, and the signed receipts.

The audit store records decision metadata per verdict (`StoredAuditEvent` in
`crates/iaga-sentinel-core/src/core/types.rs`): event id, agent id, optional tenant id,
framework, action type, tool name, decision, timestamp, reasons, review status, and risk
score. It does not store the raw request payload. The `reasons` strings can include a short
machine description of why a rule fired (for example a matched pattern name), so treat them
as decision metadata rather than as guaranteed free of any request fragment.

### Nothing calls home

The software sends no data to IAGA. There are no hardcoded vendor URLs, no analytics, and
no update checks. The only outbound HTTP client is for webhooks, which deliver events to
URLs the operator registers; there are no default webhook destinations.

OpenTelemetry stays local. Spans and metrics are kept in an in-process buffer and exposed
on the operator's own endpoints (`/v1/telemetry/spans`, `/v1/telemetry/metrics`,
`/v1/telemetry/export`). The `otel-receipts` feature emits signed receipts as spans into
that same in-process feed; it does not push to a remote collector in this build. Since
1.3.1 the receipt span also carries `iaga.receipt.id`, `iaga.chain.head`,
`iaga.policy.verdict`, and `iaga.is_authoritative`; all of it stays local.

### Verification is offline

`iaga-verify` is a standalone binary that reads an exported chain file and checks the
Ed25519 signatures and the hash-chain links. It opens no database, starts no server, and makes
no network call. It reuses the same `verify_chain` routine the runtime uses, so an external
auditor can confirm a chain on an air-gapped machine.

**What a `CHAIN OK` proves — and what it does not.** A `CHAIN OK` result proves the
**integrity of the prefix it was given**: every signature verifies, every `parent_hash`
links the previous body, the `seq` runs `0..N-1`, and one `run_id` owns the whole chain.
It does **not** prove **completeness**. Dropping the last *k* receipts from an export yields
a shorter chain that still verifies as `CHAIN OK` with `receipts=N-k`. There is no anchor
inside the open-build chain that records how many receipts *should* exist, so an offline
verifier cannot distinguish a complete short run from a truncated tail. `iaga-verify`
therefore prints the verified range (`seq=0..N-1`) so an auditor holding an externally
recorded expected count or head sequence can catch a truncation. A self-anchoring guarantee
— a sealed head sequence or recurring archival timestamp (eIDAS B-LTA) that makes tail
truncation detectable with no external bookkeeping — is part of IAGA Sentinel Enterprise,
not this open build.

## Governed-process environment

When `iaga run` launches a child process, the child gets a scoped environment: an allowlist
of inherited variables plus the entries passed explicitly in the launch spec. On top of
that, a denylist of 24 known secret-bearing variables (cloud and model-provider
credentials, registry tokens, and the receipt signing-key path) is stripped from the final
environment, even when passed explicitly, so a governed agent does not receive host secrets
through its process environment. The denylist is extendable at runtime with a TOML file at
`IAGA_SENTINEL_ENV_DENYLIST`. This is an open-build hardening added in 1.3.1; it is always
on, with no feature flag.

## Response scanning and redaction

The response-side scanner (`POST /v1/response/scan`) inspects tool or model output for
sensitive data before it flows onward. It detects categories including personal data (for
example government identifiers), financial data (for example card numbers), and credentials
and secrets (for example cloud access keys, provider API keys, personal access tokens,
passwords, PEM private keys, bearer tokens, and database connection strings). The live list
of patterns is available at `GET /v1/response/patterns`.

When a match is found, the scanner returns a risk-scored verdict (`allow`, `review`, or
`block`) and a redacted copy of the payload with the sensitive spans replaced by
placeholders such as `[REDACTED-AWS-KEY]`. Higher-severity matches raise the risk score
and can escalate the verdict to review or block.

## Operator responsibilities

The operator runs the software, chooses the storage backend, and decides whether
drift-capture is enabled. Because of that, the operator is the data controller for whatever
they choose to log. If you deploy IAGA Sentinel in a context subject to data-protection
rules, document this in your own records, for example your Record of Processing Activities
(RoPA) or a Data Protection Impact Assessment (DPIA): what you store, where, for how long,
and whether you enabled raw-input capture.

This file is technical guidance to help you do that. It is not legal advice, and it does
not by itself satisfy any regulatory obligation.

## Enterprise note

The compliance dossier features of IAGA Sentinel Enterprise (for example EU AI Act Annex IV
generation, RoPA and DPIA generators, and qualified eIDAS signatures that carry legal
weight in EU jurisdictions) are planned for the commercial edition, currently in
development, and are not part of this open build or this document. The open build signs with
Ed25519, an advanced signature; the qualified eIDAS seal is planned as an Enterprise capability.

IAGA Sentinel Enterprise is not yet available for purchase. To follow it and get early
access when it opens, leave your email at `info@iaga.tech` — no purchase, no commitment,
just early information.

## Quick reference: environment variables that affect data

| Variable | Default | Effect on data |
|----------|---------|----------------|
| `IAGA_SENTINEL_RECEIPT_CAPTURE` | off | When `1`/`true`/`yes`, stores raw request snapshots, policy traces, and tokenized-input digests in receipts. |
| `DATABASE_URL` | `sqlite:iaga_sentinel.db?mode=rwc` | Where all state is stored. `postgres://` requires the `postgres` feature. |
| `IAGA_SENTINEL_SIGNER_KEY_PATH` | `~/.iaga-sentinel/keys/receipt_signer.ed25519` | Path to the Ed25519 receipt signing key. Auto-generated on first use if absent. |
| `IAGA_SENTINEL_ENV_DENYLIST` | unset | Path to a TOML file (`deny = [...]`) that extends the 24-variable sensitive-env denylist scrubbed from governed child processes (1.3.1). |
| `IAGA_SENTINEL_NHI_MASTER_SEED` | random per process | Seed for non-human-identity derivation. Set it for stable identities across restarts. |
| `IAGA_SENTINEL_REASONING_MODELS` | unset | Local ONNX model paths for the `ml` feature. Models are read from local disk only. |
| `IAGA_SENTINEL_PLUGIN_DIR` | `./plugins` | Local directory WASM plugins are loaded from. |
| `IAGA_SENTINEL_OPEN_MODE` | off | When `true` and no API keys exist, disables auth on protected routes. Use only in trusted environments. |
| `IAGA_SENTINEL_BOOTSTRAP_API_KEY` | unset | An admin API key registered at startup so a fresh deployment is reachable without an interactive `iaga gen-key`. Idempotent; the value is never logged. Distinct from the client-side `IAGA_SENTINEL_API_KEY` used by the plug-ins. |
| `IAGA_SENTINEL_RECEIPT_FAIL_CLOSED` | off | When `1`/`true`/`yes`, a receipt that cannot be signed and persisted makes the governance call fail instead of returning a verdict. Off by default: receipts are advisory evidence and never fail the decision. |

See also [`SECURITY.md`](SECURITY.md) for vulnerability reporting and the signing posture.
