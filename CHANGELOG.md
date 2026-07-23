# Changelog

All notable changes to IAGA Sentinel are documented here. Format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org/).

For architectural rationale, see the ADRs under [docs/adr/](docs/adr/).

This changelog tracks the **open, source-available build** of IAGA Sentinel,
licensed under BUSL-1.1 with Change License: Apache-2.0 baked in.
IAGA Sentinel Enterprise is a planned commercial edition, currently in
development, built on the same governance kernel; see
[`ENTERPRISE.md`](ENTERPRISE.md) for the overview and how to join the
early-access list.

---

## [Unreleased]

---

## [1.9.1], 2026-07-23

Documentation release: **no change to runtime behavior, the public wire
contract, the receipt schema, or the Dictum language.** Signed receipts produced
by 1.9.0 verify unchanged. Ships `AGENTS.md`, a self-contained bootstrap manual
that lets a human or an LLM agent stand the system up from a clean checkout, plus
corrections to how Dictum's runtime behavior was described — every claim below was
verified against a live server rather than read off the source.

### Added

- **`AGENTS.md`**, a self-contained bootstrap manual: repository layout, the
  nine-crate workspace, build and run, the `iaga-sentinel.yaml` config, the HTTP
  API, auth and API-key bootstrapping, the embedded dashboard, Dictum, the CLI,
  receipts and offline verification, deploy, and every server environment
  variable. Written so an agent can follow it without prior context.
- A standing procedure for AI agents: encode your own operating instructions as a
  Dictum policy, load it as an overlay, connect over MCP, and tell the user the
  dashboard URL and which rules are in force.
- MCP documentation covering the verified stdio handshake (`initialize` →
  `tools/list` → `tools/call`), the two exposed tools `iaga.inspect` and
  `iaga.response_scan`, Claude Desktop / Cursor configuration, and `mcp-doctor`.
  Documents that `iaga mcp-server` is stdio-only and that sharing one
  `DATABASE_URL` with `iaga serve` is what makes MCP-governed actions visible in
  the dashboard.

### Documented

- **A Dictum policy referencing a context path that is absent at runtime blocks
  every action, including unrelated ones.** A missing path resolves to null, the
  ordering operators have no null case and raise an evaluation error, and an
  evaluation error on a `block`/`review` policy fails closed. The default build
  triggers this for budget policies, because `budget.limit` only exists when
  `IAGA_SENTINEL_SESSION_BUDGET_USD` is set. Neither `policy lint` nor `policy
  check` catches it. Documents the working guard, `when budget.limit and …`.
- Policy attribution is surfaced in `auditEvent.reasons` as
  `dictum[<name>]: <reason>`, **not** in `risk.reasons`, which carries only
  baseline reasons — which is why a policy-driven block can look unexplained.
- `policy_hash` is the SHA-256 of the **compiled policy AST**, not of the file
  bytes: reformatting and comments leave it unchanged, any semantic edit changes
  it, and it is bound into the signed receipt.
- The `usage` object on `/v1/inspect` requires `provider` and `model`, and its
  token fields are `promptTokens` / `completionTokens`. Spend counts toward
  subsequent requests, so the request that exceeds a budget is itself allowed.
- Two shipped example policies parse and type-check but over-block at runtime and
  must not be copied: `crates/iaga-sentinel-dictum/examples/no_pii_egress.dictum`
  references the non-existent `action.risk_score` and blocks every `shell`
  action, and `crates/iaga-sentinel-core/examples/policies/strict.dictum`
  compares a tool name against the domain allowlist and blocks every `http`
  action. Both are left in place for this release and flagged in `AGENTS.md`.
- `POST /v1/inspect` requires a **registered** `agentId` (an unknown one returns
  `404 agent_not_found`), shell payloads use the key `command`, and minting an
  API key ends open mode immediately — unauthenticated calls then return `401`
  even with `IAGA_SENTINEL_OPEN_MODE=true`.

---

## [1.9.0], 2026-07-19

An **evidence-integrity and deployment** release, closing an external code
review. Three things stop being best-effort: an operator can now demand that no
verdict ships without its receipt, the governance scope is derived from the
agent profile instead of the request body, and the deployment artifacts produce
a server that is actually reachable and keeps its signing key. Default
behaviour is unchanged and receipt bytes are identical: the fail-closed trade is
opt-in, and every existing chain still verifies.

This release also folds in the community pull requests merged since 1.8.1
(#5, #6, #8, #9, #10, #11, #12) and the hardening that shipped with them.

### Added

- **Opt-in fail-closed receipts** (`IAGA_SENTINEL_RECEIPT_FAIL_CLOSED`). A
  receipt that cannot be signed and persisted normally leaves a gap between the
  SQL audit trail and the signed chain while the verdict ships anyway. Operators
  who position on cryptographic evidence can now invert that trade: with the
  variable set, the governance call fails instead of returning a verdict with no
  evidence behind it, and a server that cannot build a receipt logger at all
  refuses to start (`serve`, `proxy`, `mcp-server`, `run`) rather than silently
  governing unevidenced. **Off by default** — receipts stay advisory evidence and
  never fail the decision, which keeps the 1.8.1 behaviour byte for byte.
  Documented limits, because the guarantee has edges: the audit row is written
  before the receipt so a crash between the two still diverges; a verdict whose
  receipt was lost emits no SSE event and fires no webhook; and
  `iaga.response_scan` over MCP records no receipt in either mode.
- **Startup API-key bootstrap** (`IAGA_SENTINEL_BOOTSTRAP_API_KEY`). With open
  mode off and a fresh database — what every deployment artifact in this repo
  configures — the server answered `401` on every route until someone ran
  `iaga gen-key` by hand, and the resulting key was unknowable to clients
  configured in advance. The server now registers an operator-supplied admin key
  at startup, idempotently, and never logs it. Distinct from the client-side
  `IAGA_SENTINEL_API_KEY` the plug-ins read.
- **Helm chart and Kubernetes manifests** (#5), with the signer key on a
  writable volume so receipts can be generated under a read-only root
  filesystem.
- CI now renders the Helm chart on every run: default values, a bring-your-own
  Secret, a supplied policy, and a rejected hex signer key.

### Changed

- **`workspaceId` and `tenantId` are no longer taken from the request body.**
  The workspace is derived from the agent profile; a request asserting a
  different one is refused with `403 scope_mismatch` instead of being evaluated
  against that workspace's thresholds, egress allowlist and tool policy. The
  tenant is derived from the profile, then the workspace policy; a supplied
  value is ignored rather than rejected, so existing callers do not break.
- **A config file that is present but unparseable is now fatal.** Previously the
  server logged a warning and continued with zero profiles and zero workspaces —
  configured-looking, governing nothing. A *missing* config file stays
  non-fatal.
- The sensitive-env denylist scrubbed from governed child processes grows to 24
  entries with the bootstrap credential.
- Docker images publish under `ghcr.io/iaga-team/iaga-sentinel`, matching the
  repository that owns the release tag. Tags published earlier under the
  previous namespace still resolve.
- Documentation honesty pass. The subhead now claims evidence "of every action
  an agent routes through it"; the sovereignty bullet becomes "Self-hosted, no
  vendor in the loop" with a claim about IAGA rather than about third parties;
  the Annex IV date is dropped, since Annex I and Annex III high-risk systems do
  not share one deadline. In the demo walkthrough the BLOCK beat no longer says
  the action is "stopped before it runs" — `/v1/inspect` is advisory and returns
  a verdict without intercepting, while `iaga run` blocks a launch outright — and
  the REVIEW beat's risk score is corrected from 41 to the 40 a clean first run
  actually produces.

### Fixed

- **Silent receipt-drop is now visible on the read API.** When a signed receipt
  is lost (append error or retry exhaustion) the SQL audit row still exists but
  the signed chain has a gap; `GET /v1/receipts/{run_id}` reported only the
  receipts that were present and could show the chain as valid with no signal of
  the divergence. The response now carries `receiptDropped` (bool) and
  `droppedReceipts` (count) so a compliance inspector sees the gap (#23).
- **Deployment paths lost the Ed25519 signing key on restart.** Docker Compose
  persisted only the database and the raw Kubernetes manifest used an `emptyDir`
  for the key directory, so the signer key was regenerated on every container or
  pod recreation, changing `signer_key_id` and breaking verification of every
  receipt signed before that point. Both now persist the key directory, matching
  what the Helm chart already did.
- **The Helm chart shipped a server with no policy.** `policy.config` was empty
  by default but still mounted over `/app/iaga-sentinel.yaml`, shadowing the
  valid example policy in the image. The mount is now conditional on a policy
  actually being supplied.
- **The Helm chart's liveness and readiness probes never rendered**, because
  `values.yaml` had no `enabled` key for the condition that gated them.
- **A bring-your-own Secret without a `receipt-signer-key` entry produced a pod
  stuck in `CreateContainerConfigError`**, because the signer-key `subPath` had
  nothing to bind. The mount is now gated on the inline value only.
- **`secrets.receiptSignerKey` was documented as hex but the loader requires 32
  raw bytes.** A 64-character hex string is itself valid base64, so it was
  accepted and decoded to 48 bytes, silently disabling receipts. The value is now
  base64 and a wrong length fails the template render.
- Receipt append retries back off between attempts, so two writers racing on the
  same `run_id` against a shared Postgres do not burn all five attempts at once.
- Session `block_count` no longer double-increments when the FSA and attack
  detection both fire (#10), the session DAG holds its lock across the full
  read-mutate cycle (#11), the cost budget check and add are atomic (#12),
  `EvalBudget::tick` increments after the exhaustion check rather than before
  (#9), `ReviewRequest` timestamps use the pinned decision time instead of a
  fresh `Utc::now()` (#8), and a redundant `#![cfg]` in the Dictum overlay is
  gone (#6).

### Security

- **Audit, receipt, and risk-feedback endpoints now require an admin-scoped
  key.** `GET /v1/audit`, `/v1/audit/export`, `/v1/audit/stats`, `/v1/receipts`,
  and `/v1/receipts/{run_id}` sat behind auth but not behind `RequireAdmin`, so
  an agent-scoped key could enumerate cross-agent audit events, risk scores, and
  signed receipt chains (#18). `POST /v1/risk/feedback` was likewise unguarded,
  letting an agent key floor the process-global adaptive risk weights and
  degrade static-pattern detection for every agent (#19). All six now return
  `403 admin_scope_required`, matching the existing admin surface; the OpenAPI
  spec documents the `403`.
- **`allowed_domains` egress allowlist could be bypassed via alternate payload
  fields.** The workspace egress check read only `payload["destination"]`, so an
  `http` action carrying its URL in `url`/`endpoint`/`href` evaded the domain
  allowlist and was silently allowed (#20). The extractor now scans
  `destination`, `url`, `endpoint`, and `href` and host-checks the first match
  against the allowlist.
- Policy and NHI mutations are admin-gated, response-side blocks are audited, and
  attestation replay is fixed.
- `crossbeam-epoch` bumped to 0.9.20 for RUSTSEC-2026-0204.

---

## [1.8.1], 2026-06-28

A **rebuilt Operator Console** and **cost visibility on by default**. The
governance kernel is unchanged, and signed-receipt bytes stay identical when a
caller reports no `usage` (golden vectors green) — enabling cost metering only
records usage the caller actually supplies.

### Added

- **Rebuilt Operator Console** (served at `/`): a structured multi-view app with
  a left section nav (Overview, Decisions, Agents, Live, Receipts, Telemetry,
  Audit, Reviews & sandbox, Cost, Security, Identity, Plugins, Settings) instead
  of one long page. Strict monochrome (ink-on-paper, brutalist, zero radius),
  system fonts, no external assets (stays air-gapped). The Overview leads with
  the posture question and live charts — governance activity over time, risk
  distribution, most-blocked tools — and every panel renders real endpoint data
  or an honest empty state that names the call to populate it.
- **Downloadable audit reports** (Audit view): fleet-wide or per single agent,
  with 7/30/90/365-day and all-time range presets, exported as **CSV, JSON, or a
  formatted PDF** (KPIs, charts, decision mix, models/frameworks, and the full
  action timeline). The PDF is produced through the browser print pipeline, so
  the console adds no dependency and works offline.
- **Settings view**: API-token connection, runtime/health status, refresh
  interval, and API-key create/list/delete.

### Changed

- **`cost-control` is on by default** (ADR 0020 revised). Token/cost metering,
  the `/v1/cost` API, the cost ledger, and per-model/agent/tool breakdowns are
  available out of the box, so the Cost view and audit reports surface real spend
  and the model(s) each agent used. Receipts stay byte-identical when no `usage`
  is reported (determinism and golden vectors unaffected); build with
  `--no-default-features` for the pre-1.5 wire.

### Fixed

- **Receipts panel** read the run summary with camelCase keys while the
  `/v1/receipts` wire is snake_case (`receipt_count`, `last_timestamp`,
  `terminal_verdict`); the receipt-count and last-seen columns now render.
- Internal cleanup: removed the empty legacy `policy_store` module and the unused
  `verify_all_policies`; the pipeline moves the canonical payload `Value` into
  plugin evaluation instead of cloning it.

## [1.8.0], 2026-06-26

Stronger **userspace process confinement** for `iaga run` and **reverse-shell
detection** in the threat-intel layer. Enforcement stays cooperative/userspace —
kernel eBPF/LSM confinement remains Enterprise (see
[ADR 0010](docs/adr/0010-oss-enterprise-boundary.md)), `iaga kernel status`
reports the posture honestly, and every OSS receipt still carries
`is_authoritative: false`. The default build and signed-receipt bytes are
unchanged from 1.7.2 (golden vectors green, including the frozen
`is_authoritative` shape).

### Added

- **Userspace child hardening** (`UserspaceKernel`): an allowed `iaga run` child
  is now spawned under `setsid`, with core dumps disabled (`RLIMIT_CORE = 0`),
  no-new-privileges (`PR_SET_NO_NEW_PRIVS`, Linux), and reaped with its parent
  (`kill_on_drop`). These are unprivileged POSIX/Linux controls, not eBPF/LSM
  kernel enforcement; `is_authoritative()` stays `false`.
- **Reverse-shell threat patterns**: netcat `-e`/`-c`, `bash` redirection to
  `/dev/tcp`, and `socat … EXEC` are flagged `critical`; recursive `chmod` is
  matched by regex so `chmod -R 777 /` is caught while `chmod +x` stays clean.
- **CI `notices` job**: regenerates `THIRD_PARTY_NOTICES.md` with pinned
  `cargo-about` and fails if it has drifted from `Cargo.lock`.

### Changed

- **`iaga kernel status`** copy clarified and a `containment:` line added
  (env-scrubbed, reaped); the boot banner now reads "EU AI Act conformity
  evidence" instead of the retired "Zero-Trust Security Runtime" framing.
- **`iaga run` default agent**: the `cli-runner` agent and a `ws-cli` workspace
  are seeded, so process governance works out of the box (a few harmless
  read-only commands auto-allow; everything else stays governed by the risk and
  threat-intel layers).
- **Documentation honesty pass**: corrected `docs/openapi.yaml` from "12-layer"
  to "8-layer" (two advisory) and softened "mapped to Annex IV" to the honest
  "structured to support / help produce"; de-softened wording across the README,
  added a verb to the EU AI Act badge, and added nominative-use / non-affiliation
  notes where third-party framework names appear. Removed `docs/CASE_STUDY.md`.

### Fixed

- A brittle kernel test that spawned `cargo` (a rustup proxy that breaks under
  environment scrubbing) now uses an environment-independent command, so the
  hardening suite is deterministic on Linux and Windows.

## [1.7.2], 2026-06-22

The **VoltAgent plug-in** and a consolidated `plug-ins/` home. **Additive and
docs-only for the core:** receipts, policy evaluation, and the default build are
byte-identical to 1.7.1; no wire or receipt-field change.

### Added

- **VoltAgent plug-in** (`@iaga-sentinel/voltagent`, `plug-ins/voltagent-plugin/`): a
  drop-in, dependency-free (global `fetch` only) in-the-loop plug-in for the
  [VoltAgent](https://github.com/VoltAgent/voltagent) framework. `createSentinelHooks()`
  wires VoltAgent's `onToolStart` hook to `POST /v1/inspect`: `allow` runs the tool,
  `block` throws `ToolDeniedError` so `execute()` never fires, `review` is denied by
  default (`onReview: "allow"` to pass through). Optional `scanInput` (prompt-injection
  firewall) and `scanOutput`/`redactOutput` (secret redaction of tool output via
  `/v1/response/scan`). Fail-closed by default; every receipt stays
  `is_authoritative: false`. Verified end-to-end against a real sidecar and a real
  LLM, with offline `CHAIN OK`.

### Changed

- **`plug-ins/` is the home for in-the-loop integrations.** Released plug-ins live as
  `*-plugin/` (e.g. `voltagent-plugin/`); the copy-paste framework integrations move
  there as `*-adapter/`. README, CONTRIBUTING, and the SDK adapter pointers follow.

---

## [1.7.1], 2026-06-19

Documentation and honesty hygiene. **No code-path or wire change:** receipts,
policy evaluation, and the default build are byte-identical to 1.7.0, and
receipts written by earlier releases still verify byte-for-byte unchanged.
Cut after a full audit pass (live end-to-end, tamper-evidence, determinism, and
the default plus `--all-features` test suites all green).

### Changed

- **Honest layer count.** The server boot banner read "12 Layers ARMED" and the
  historical `ARCHITECTURE.md` / `CASE_STUDY.md` notes claimed "12 layers"; the
  executable pipeline runs **8 layers** (two of them — sandbox and
  formal-verify — are advisory and do not change the verdict), plus four
  cross-cutting subsystems. The banner now reads "8 Layers ARMED" and the docs
  state the real count.
- **Documented the `cargo audit` advisory ignores.** `.cargo/audit.toml` now
  records, for each of the three ignored RUSTSEC advisories, the exact
  optional/compile-time path that pulls the crate (`rsa` via `sqlx-mysql`'s
  compile-time query macros, `fxhash` via `wasmtime`, `paste` via `tract`) and
  notes that none is in the default build. Re-verified with `cargo tree`.
- **Version and license hygiene.** The workspace version, the Python and
  TypeScript SDK manifests, and the BUSL `Licensed Work` line (still stamped
  `v1.6.0`) are aligned to the release.

### Fixed

- The README install snippet pinned a stale `--tag` (`v1.6.0`); it now matches
  the release tag.

## [1.7.0], 2026-06-17

OSS backlog closure toward the roadmap's 1.3-1.6 "cryptographic primitive" track:
the Dictum standard library grows deterministic builtins, the MCP wedge gains a
health-check and a Rust `GovernedTool`, the threat-feed *format* opens, SBOM
ingest learns SPDX, and plugins gain offline in-toto/SLSA attestation. **Fully
additive: no receipt field changed**, so receipts written by earlier releases
verify byte-for-byte unchanged, and every OSS receipt stays
`is_authoritative:false`. **No open-core ↔ Enterprise boundary moved** (ADR 0010):
where the faithful fix is Enterprise (verified SLSA, the curated/signed threat
feed, KMS/HSM, authoritative enforcement), OSS ships the honest mechanism and
leaves the Enterprise value intact.

### Added

- **Multilingual offline verifier (Python + Node), dependency-free.** The
  canonical Rust `iaga-verify` verdict is now reproducible on non-Rust stacks:
  `sdks/python/iaga_verify.py` (stdlib only, vendored Ed25519 RFC 8032) and
  `sdks/typescript/verify.mjs` (`node:crypto`) consume the same `ChainExport` and
  emit **byte-identical** `CHAIN OK … seq=0..N` output and exit codes
  (0 valid / 1 broken / 2 usage / 3 IO) as the Rust binary. Parity is anchored to
  a shared signed conformance vector (`sdks/conformance/golden_chain.json`, emitted
  by the canonical Rust code) and proven by `sdks/python/tests/test_iaga_verify.py`
  and `sdks/typescript/verify.smoke.mjs`. A new `python` CI matrix
  (ubuntu/macOS/windows × 3.11/3.12) gates the dependency-free verifier on every
  stack; the Node verifier parity smoke runs in the test job. A receipt carrying
  floats (`ml_scores`) is the one shape the re-serializers refuse rather than risk
  a divergent verdict — use the Rust verifier for those. (A browser WASM/WebCrypto
  build and `@iaga/verify` npm / `iaga-verify` PyPI packaging are follow-ups.)
- **`dictum-std` builtins `timestamp()` and `sha256()`.** Two pure, deterministic
  Dictum builtins. `timestamp(str) -> int` parses an RFC3339 instant to Unix epoch
  seconds, so a policy expresses temporal ranges with the ordinary numeric
  operators (`timestamp(action.ts) > timestamp(workspace.windowEnd)`) — no wall
  clock is read, so the verdict still replays bit-for-bit, and a malformed instant
  fails closed inside a Block/Review guard. `sha256(str) -> str` is a hex content
  digest (e.g. pin an approved payload by hash). NHI identity matching is
  intentionally omitted (redundant with `contains`/membership; verifiable
  asymmetric NHI is Enterprise, CRYPTO-NHI-2).
- **`mcp-doctor` CLI subcommand.** Spawns a target MCP server over stdio, drives
  `initialize` + `tools/list` as a client (the first MCP client driver in the
  tree), checks each tool's `inputSchema` is present and a well-formed JSON object
  (presence + shape, not a full JSON-Schema validator), optionally probes one
  named tool, and runs every listed tool through the same governance interception
  the `proxy` uses — reporting which calls the policy engine would allow / review
  / block. `--format json|table`; the report is always `authoritative:false`.
  Cooperative diagnostics: the governance check runs the real pipeline and writes
  a signed receipt per listed tool (proving each `tools/call` is encapsulable in a
  receipt), so it is not a pure read against the receipt store.
- **`iaga-sentinel-mcp` crate exposing `iaga::mcp::GovernedTool`.** A thin Rust
  client that maps an MCP `tools/call` into the public `InspectRequest`
  (`framework`/`protocol` = `mcp`), POSTs it to `/v1/inspect`, and runs the wrapped
  work only if the verdict is Allow — mirroring the Python/TS `GovernedTool`. A
  blocked call's work future is never polled. Fail-open by default
  (`.fail_closed(true)` to opt in), `is_authoritative:false`, no coupling to the
  core engine (it reuses the public `iaga-sentinel-integrations` client).
- **OSS threat-feed format `threat-intel.toml` + loader.** Point the server at a
  plain-text feed with `IAGA_SENTINEL_THREAT_FEED=path.toml`; its `[[indicator]]`
  entries are added to the built-in indicators. The *format* is open on purpose —
  the curated, signed Enterprise feed is a separate product, not a different
  format (ADR 0010). Loading is deterministic (no clock), so the `threatFeedHash`
  bound into each receipt stays reproducible against the exact indicator set. A
  malformed file is logged and skipped, so a bad config never disarms the
  baseline. Example at `examples/threat-intel.toml`.
- **SPDX SBOM ingest alongside CycloneDX.** `plugin verify` now accepts an SPDX
  JSON SBOM sibling (`<plugin>.spdx.json`) in addition to CycloneDX
  (`<plugin>.cdx.json`); the format is auto-detected (`parse_sbom_bytes`) and bound
  to the signed manifest the same way. Online Rekor inclusion / Fulcio root
  validation remain Enterprise (ADR 0013).
- **`iaga plugin attest --slsa-level N` (feature `plugin-manifest-signing`).** Emits
  an offline in-toto Statement v1 with a SLSA Provenance v1 predicate over the
  plugin's SHA-256; `--sign` wraps it in an Ed25519 DSSE envelope signed with the
  local BYOK signer. The SLSA level is recorded as **operator-declared build
  intent** (`declaredSlsaLevel` plus an in-band disclaimer), explicitly not a
  verified guarantee — offline OSS cannot attest hermeticity. Verified SLSA (Rekor
  inclusion + Fulcio keyless identity) remains Enterprise (ADR 0010/0013). No
  network access.

### Changed / Fixed

- **Logs go to stderr, never stdout.** `init_tracing` now writes to stderr in all
  formats, so the stdio MCP commands (`mcp-server`, `proxy`, `mcp-doctor`) keep
  stdout as a clean JSON-RPC channel — a log line on stdout had been corrupting the
  protocol for any MCP client.
- **`iaga-sentinel-integrations` `InspectRequest` gains an optional `protocol`
  field.** Elided when unset, so existing callers serialize byte-unchanged; the
  MCP `GovernedTool` sets it to `mcp`.
- **Retired the stale `gen_ai.*` OTel plan.** The receipt span describes a
  governance *verdict*, not an LLM call, so it carries `iaga.*` keys, not the
  OpenTelemetry `gen_ai.*` semantic conventions (which model prompts/tokens/model
  ids the verdict surface does not own). The earlier "`gen_ai.*` alignment lands in
  1.4" note is dropped rather than left as an open promise — emitting those keys
  here would misattribute a convention IAGA cannot populate honestly.

## [1.6.0], 2026-06-16

Hardening pass on the two product guarantees — a reproducible signed verdict and
a real, verifiable proof. **No open-core ↔ Enterprise boundary moved** (ADR 0010):
where the faithful fix is Enterprise, OSS ships an honest workaround and the
Enterprise value is left intact.

### Changed (signed-bytes / wire format — new receipts only)

- **Receipt `input_hash` now binds the action payload.** It was
  `SHA256(event_id ‖ agent_id ‖ tool_name)` with a *random* `event_id`, so it
  bound nothing about *what* the action did and was not reproducible. It is now
  `SHA256(agent_id ‖ tool_name ‖ input_sha256)`, where `input_sha256` is the
  SHA-256 of the canonical action payload (PROOF-INPUTHASH-BIND-3). The raw
  payload stays out of the receipt (privacy); only the digest is bound.
- **Signed verdict is now a pure function of (request + resolved policy +
  `decision_time` + ML digest).** A single `decision_time` is computed once per
  request, used as the receipt timestamp, and is the only clock the signed
  off-hours signal reads (DET-CLOCK-1). Signals derived from unregistered
  process-global mutable state — session/temporal burst, prior-block history,
  behavioral-fingerprint novelty/unusual-hours, adaptive baseline velocity —
  **no longer enter the signed score/decision/reasons**; they are surfaced as
  **advisory** on `GovernanceResult.advisory` for dashboards/alerts
  (DET-SESSION-2 / DET-BEHAVIORAL-2). Full session-state capture remains
  Enterprise.
- **ML tokenizer hash is now versioned and stable.** The reasoning-plane
  tokenizer (feature `ml`) replaced `std`'s `DefaultHasher` (SipHash, not stable
  across toolchains/targets) with vendored FNV-1a, so the signed `ml_scores`
  reproduce across builds and machines (DET-REASONING-1).
- **`policy_hash` now binds the real resolved policy.** With no Dictum overlay
  it was a constant placeholder (`SHA256("iaga-sentinel-policy-v0")`), so the
  workspace YAML that decides most verdicts was never digested. It is now the
  SHA-256 of the canonicalized resolved `WorkspacePolicy` (id, protocols,
  domains, tools + action types/decisions, block/review thresholds), stable
  under list reordering (CRYPTO-POLICYHASH-7a). With an overlay loaded the
  compiled Dictum bundle digest is still used.
- **`DictumEvalTrace` carries the real evaluation.** Its `policiesEvaluated` /
  `policiesFired` were hardcoded `0` / `[]`; they now reflect the actual
  evaluation, and a new optional `evidenceSha256` binds the SHA-256 of the fired
  policy's evidence value (not the raw evidence) into the signed bytes
  (PIP-DICTUM-UNBOUND / CRYPTO-POLICYHASH-7c). The trace stays capture-gated
  (`IAGA_SENTINEL_RECEIPT_CAPTURE=1`); `evidenceSha256` is elided when absent, so
  existing receipts are byte-identical.
- **Receipts bind the active threat-intel feed.** A new optional
  `threatFeedHash` records the SHA-256 of the active threat-feed indicator set
  (sorted by id), so the signed score is reproducible against the exact feed that
  produced it (DET-THREAT-1). Elided when absent, so older receipts stay
  byte-identical.
- **`run_id` is qualified by the agent.** A session-grouped run_id is now
  `agent_id:session_id` instead of the bare `session_id`, so two principals that
  pick the same `sessionId` can no longer interleave into one chain that verifies
  as Valid. `run_id` is in the signed bytes and the verifier already checks it is
  consistent across the chain, so this binds the principal with no new field
  (PIP-RUNID-COLLISION). `iaga replay <sessionId>` still resolves a bare session
  to its unique run. Tenant-scoped isolation remains Enterprise; session-less
  callers (run_id = event_id) are unchanged.

  These change the signed bytes of **new** receipts. **Receipts written by
  earlier releases still verify unchanged** — verification reads the stored
  bytes; only the derivation of newly written receipts changed.

### Added / Fixed

- **Chain integrity under concurrency.** The receipt store's `append` now
  validates the link against the current head inside the persistence layer and
  rejects an out-of-order `seq` / bad parent with `ChainViolation`; a concurrent
  `(run_id, seq)` collision surfaces as `DuplicateSeq`. The pipeline logger
  retries on a lost-head race instead of silently dropping the receipt, and
  emits `iaga_sentinel.receipts.signed` / `iaga_sentinel.receipts.dropped`
  counters (+`error!`) so a divergence between the audit trail and the signed
  chain is observable (SND-APPEND-RACE/DROP/NOCHECK, OBS-RECEIPT-DROP).
- **First-gate DoS fix** carried in: char-boundary-safe truncation in the
  injection firewall (attacker-controlled multibyte payloads no longer panic).
- **Honest attestation/verification:** plugin attestation separates
  "digest matches" from "signature verified" and supports operator-pinned-key
  Ed25519 verification; the offline verifier binds the printed `signer=` to the
  key that actually verified. Keyless Fulcio/Rekor identity remains Enterprise.
- **Dictum → WASM codegen declassed to non-canonical.** The tree-walk evaluator
  (`eval.rs`) is documented as the sole canonical executor; the feature-gated
  WASM codegen is labelled an experimental, non-canonical scaffold
  (i32-truncated, bitwise `and`/`or`) and removed from any proof claim. A
  faithful i64 codegen remains Enterprise.
- **Performance on the verdict hot path:** static risk regexes compile once
  (`Lazy`); the action payload is serialized once per request instead of three
  times.
- **Determinism is now tested:** an integration test re-runs the real pipeline
  twice with a pinned `decision_time` and asserts byte-identical
  `ReceiptBody::signing_bytes()`, plus a guard that `serde_json` keeps object
  keys ordered (`preserve_order` off). The governance OpenTelemetry span now
  carries the full decision context instead of only `agent.id`.
- **Stronger test coverage:** a labelled firewall corpus asserts an aggregate
  detection rate / false-positive baseline (TESTS-NO-ACCURACY-ASSERT-7); the
  chain tamper tests are parametrized over genesis/middle/head positions plus
  tail-truncation and middle-deletion (PROOF-CHAIN-EDGE-POS-5); and a property
  test asserts `signing_bytes` is a serialize→parse fixpoint
  (TESTS-FUZZ-NO-DETERMINISM-10). The demo's Allow→Review→Block flow and offline
  `CHAIN OK` are now end-to-end test-backed over real HTTP + the real offline
  verifier, so the recorded narration can't diverge from behaviour.
- **Operator dashboard surfaces the proof posture.** The live feed now shows the
  top signed *reason* on a Review/Block row, and **advisory** signals
  (burst/velocity/fingerprint novelty) as visually distinct dashed chips
  explicitly labelled *not part of the signed verdict* (advisory is now carried
  on the SSE event). The telemetry panel shows `receipts.signed` /
  `receipts.dropped`, flagging when the audit trail and the signed chain diverge.
  No new dependencies; the existing aesthetic is preserved.
- **Dictum overlay fails closed.** An eval error in a Block/Review policy's
  `when` now applies that policy's verdict (with reason `dictum-eval-error`)
  instead of being silently treated as no-fire — an attacker can no longer craft
  a payload that errors a guard to disable it (PIP-DICTUM-FAILOPEN). An erroring
  Allow policy cannot tighten, so evaluation keeps scanning for a stricter later
  policy; an `evidence` error keeps the verdict and drops the evidence (never a
  downgrade).
- **Per-policy Dictum budgets.** Each policy's `when` gets its own instruction
  budget and the fired policy's `evidence` a separate one, so one expensive
  expression can't starve later policies into a fail-open (DET-DICTUM-2).
- **Bundle-hash serialization error is fatal.** Computing a Dictum bundle's
  `policy_hash` no longer falls back to a constant on a serialization error
  (which would have signed a fake-but-valid hash); the host fails to load
  instead (CRYPTO-POLICYHASH-7b).
- **More wall-clock removed from the signed path.** Time-window policy rules now
  evaluate against the pipeline's single `decision_time` (not a fresh
  `Utc::now()`), and the configured `timezone` is honored for fixed offsets
  (`+02:00`, `Z`, …) — an IANA name falls back to UTC explicitly rather than
  silently guessing (DET-DICTUM-3). The NHI master seed is resolved once per
  process (was regenerated on every identity derivation when the env was unset),
  so derived identities/trust are stable within a run (DET-NHI-4); a short
  env-provided seed now warns (ERG-NHI-SEED-VALIDATION-1). Session-graph node
  ids are derived from the session + position + content instead of a random
  UUID, so the persisted/returned graph is reproducible (DET-SESSION-UUID-1).
- **Deterministic cost + ML scoring.** Token cost rounds each component to
  integer micro-USD and sums with `saturating_add` (specified, order-independent,
  overflow-safe) (DET-COST-1, feature `cost-control`); ML model scores are
  quantized onto a fixed `1e-6` grid before entering the signed `ml_scores`, so
  ULP differences across microarchitectures don't change the signed bytes
  (DET-REASONING-2, feature `ml`).
- **Receipt read-time integrity.** The receipt store now asserts the ordering
  `seq` column matches the `seq` inside the signed body on read, catching a
  divergent row instead of silently reordering the chain (DET-SEQ-COLUMN-5).
- **Signed plugin manifest binds the verifying key.** Verification now requires
  the trusted key that actually verifies the signature to be the one the
  manifest *declares* (`signer_key_id`), so with more than one trusted key a
  manifest signed by B can no longer claim `signer=A` and be reported as A
  (CRYPTO-MANIFEST-1, feature `plugin-manifest-signing`).
- **Offline verifier surfaces the chain range, honestly.** `iaga-verify` now
  prints `seq=0..N-1` on a `CHAIN OK`, and DATA_HANDLING documents that a
  `CHAIN OK` proves *prefix* integrity only — tail truncation is not detectable
  offline without an external anchor (Enterprise eIDAS B-LTA) (CRYPTO-EXPORT-TRUNC-7).
- **Kernel resolves the env denylist once.** The `UserspaceKernel` resolves the
  sensitive-env denylist at construction instead of re-reading the env + TOML on
  every launch, and logs a stable fingerprint of the scrubbed-variable set per
  governed launch so the secret-scrubbing posture is recorded (SOUND-KERNEL-1).
- **Secret detector no longer self-DoSes on benign numbers.** The Dictum
  `secret_ref()` credit-card pattern now requires a valid Luhn checksum, and the
  US SSN pattern requires an explicit SSN keyword, so an arbitrary 16-digit or
  `ddd-dd-dddd` value in a payload no longer forces a deterministic Block
  (CRYPTO-DICTUM-9).
- **NHI identity is labelled honestly.** The misleading `public_key_hex` field is
  renamed `key_commitment` (it is a symmetric HMAC commitment, not an asymmetric
  public key; old `publicKeyHex` JSON still deserializes via a serde alias, the
  DB column is unchanged), and the SPIFFE/PKI framing is removed from the module
  docs. Verifiable, relying-party-checkable asymmetric NHI is Enterprise
  (CRYPTO-NHI-2). The demo secret allowlist is clearly labelled as a demo, not a
  real vault (CRYPTO-SECRETS-1).
- **Receipt-store migration coexistence documented.** Investigated converting
  the receipt store to `sqlx::migrate!` (SND-MIGRATION-SPLIT-6) and deliberately
  kept the idempotent direct `CREATE … IF NOT EXISTS`: the receipt store can
  share one database with `iaga-sentinel-core`'s storage, which owns the single
  `_sqlx_migrations` table, so a second sqlx migrator would conflict and silently
  disable receipts. The reason is now documented in the code.
- **Rate-limit receipts declare non-replayability.** A rate-limit Block (which
  depends on `Instant::now()` + an in-memory window) now carries a
  `non-replayable:rate-limit` reason so the signed receipt is honest about not
  being reproducible by replay (DET-RATELIMIT-1).

## [1.5.6], 2026-06-15

The policy DSL is renamed from APL (Agent Policy Language) to **Dictum**. This is a
staged rebrand, not a blind search and replace: the language name, the `.dictum` file
extension, and the code identifiers move to Dictum, while frozen wire artifacts stay
byte-identical and historical references keep resolving. No governance, enforcement, or
receipt behavior changes, and the signed-receipt format is preserved exactly.

### Changed

- **Language rebrand: APL / Agent Policy Language to Dictum.** Prose, comments, docs,
  ADR bodies, dashboard strings, and CLI help now read "Dictum". One continuity note,
  "Dictum (formerly APL / Agent Policy Language)", is kept at the canonical definition
  point so existing references and the AISEC paper citation still resolve.
- **File extension `.apl` to `.dictum`.** Every example, fixture, and end-to-end policy
  file is renamed; loaders, glob patterns, CLI examples, and the Dockerfile follow.
- **Crate, lib, and Cargo features renamed.** `iaga-sentinel-apl` to
  `iaga-sentinel-dictum`, lib `iaga_sentinel_apl` to `iaga_sentinel_dictum`, features
  `apl` to `dictum` and `apl-wasm` to `dictum-wasm`. Internal types follow: `AplError`
  to `DictumError`, `AplOverlay` to `DictumOverlay`, module `apl_overlay` to
  `dictum_overlay`.
- **Runtime reason label `apl[...]` to `dictum[...]`** on audit events and signed receipts.
- **ADR filenames** carrying `apl` renamed to the `dictum` form, with all
  cross-references updated.

### Compatibility

- **Receipt wire format unchanged.** The receipt field `apl_eval_trace` is deliberately
  preserved (the byte-frozen golden vectors pass), so receipts produced before 1.5.6
  still verify bit-identically.

See [ADR 0004](docs/adr/0004-dictum-mvp.md).

## [1.5.5], 2026-06-13

A tooling and documentation release. It adds a self-contained demo recording kit
so anyone can reproduce a live governance run and verify a signed receipt
offline, on their own machine. No product behavior changes: no enforcement,
policy, receipt, or API code was touched, only the workspace version and the new
demo assets. Verdicts are deterministic and the receipt chain verifies offline.

### Added

- **Demo recording kit under `scripts/` and `docs/demo/`.** `scripts/demo.ps1`
  (with the `demo.sh` twin) builds the binaries, resets the demo database for an
  identical seed, and serves the operator dashboard on `:4010`.
  `scripts/demo_run.ps1` (with `demo_run.sh`) drives three real verdicts through
  the live pipeline, Allow then Review then Block, under one shared session so the
  signed receipts form a single hash-chained run. It asserts every verdict so a
  non-deterministic take can never be recorded, then exports the chain and
  verifies it offline with `iaga-verify` (embedded and pinned key). The
  Windows-first recording runbook is in [`docs/demo/README.md`](docs/demo/README.md).
- **`Test me now (1.5.5)` section in the README** with the exact first-person
  steps to run the demo end to end, including the Linux and macOS variant.

## [1.5.4], 2026-06-13

Makes the Armor Policy Language enforce what it advertised and hardens the core
decision path. Two Dictum builtins become real, three core fixes land, and the
signed-receipt schema stays backward compatible: receipts from any prior release
still verify, and a receipt minted without a session id is byte identical to a
1.5.3 receipt.

### Added

- **Functional `secret_ref()` Dictum builtin.** It now scans the serialized payload
  subtree for credentials and PII (AWS, OpenAI, and GitHub keys, PEM private
  keys, generic api_key and password assignments, bearer tokens, database
  connection strings, SSNs, and card numbers) with a fixed, deterministic
  pattern set in `iaga-sentinel-dictum`. Previously it was a placeholder that always
  returned `false`, so secret-egress policies such as
  `crates/iaga-sentinel-dictum/examples/no_pii_egress.dictum` could never fire. Object
  payloads are scanned correctly now, instead of flattening to null before the
  check.
- **`url_host()` Dictum builtin.** Extracts the lowercased host from a URL
  (stripping scheme, userinfo, port, and path), so a policy can express a true
  per-host egress allowlist, for example
  `url_host(action.payload.destination) not in workspace.allowlist`. This
  defeats look-alike bypasses such as `hooks.slack.com.attacker.tld` that a
  substring match would let through.

### Fixed

- **URL-aware workspace egress allowlist.** `evaluate_policy` now normalizes a
  request destination to its host before matching `allowed_domains`
  (case-insensitively), so a full URL to an allowed host (for example
  `https://api.github.com/repos`) is no longer over-blocked. Bare-host
  allowlists are unaffected.
- **No reasonless verdicts.** A `block` or `review` forced by the policy layer
  now surfaces its human-readable cause (for example
  `destination ... is outside allowed workspace domains`) in the audit event and
  the signed receipt, instead of only the generic "escalated by security layers"
  note. The previously silent schema-validation block records a reason too.
- **Session-grouped signed receipts.** When a caller supplies an explicit
  `metadata.sessionId`, every action in that session shares a receipt `run_id`,
  so receipts hash-chain (seq 0, 1, 2, ...) into one tamper-evident Merkle run
  that `iaga-verify` validates end to end. Without a session id the behavior is
  unchanged (one receipt per run) and the receipt body stays byte identical to
  earlier releases.

See [ADR 0023](docs/adr/0023-dictum-secret-detection-host-egress.md).

## [1.5.2], 2026-06-12

Technical-debt remediation across the whole open build: hardening of existing
features, test-coverage closure, and CI/workspace hygiene. No new product
surface beyond minimal API-key scopes; signed receipts produced by any prior
release verify unchanged (now enforced by golden-vector tests), and every new
tunable defaults to the previous hardcoded behavior.

### Added

- **Verified-API-key cache**: the auth middleware no longer pays one
  `list_keys()` query plus an Argon2 verification on *every* request — verified
  keys (stored as SHA-256, never raw) are cached per server instance with a TTL
  (`IAGA_SENTINEL_AUTH_CACHE_TTL_MS`, default 60 s; `0` restores
  verify-every-request). Key deletion invalidates the cache immediately.
- **API-key scopes** (minimal, single-tenant): `admin` (default — identical to
  pre-1.5.2 keys; all existing keys stay admin via migration 0005) and `agent`
  (governance surface only). `iaga gen-key --scope agent`, `scope` on
  `POST /v1/auth/keys`, and admin-only enforcement (403 `admin_scope_required`)
  on key/webhook/DLQ management, rate-limit config, threat-intel mutations, and
  plugin reloads. Multi-tenant/SSO/SIEM remain Enterprise (ADR 0010).
- **Network configuration**: `IAGA_SENTINEL_HOST` (bind interface, default
  `0.0.0.0`) and `IAGA_SENTINEL_CORS_ORIGINS` (comma-separated allowlist;
  unset keeps the permissive `Any` of previous releases).
- **Tunables for previously hardcoded constants** (defaults unchanged):
  session-graph cap/TTL/cooldown/strikes, background-cleanup cadence/age, and
  response-cache TTL/size (see README → Environment variables).
- **`POST /v1/risk/weights/reset`** (admin): drop feedback-learned adaptive-risk
  weight adjustments; the process-global weight behavior is now documented.
- **Strict env-denylist mode**: `IAGA_SENTINEL_ENV_DENYLIST_STRICT=1` makes
  `iaga run` fail closed (launch blocked) when the denylist TOML extension is
  unreadable or malformed, instead of silently degrading to the built-in list.
- **Pricing freshness**: the built-in price list now carries
  `BUILTIN_PRICING_EFFECTIVE_DATE` (also surfaced as `builtinEffectiveDate` on
  `/v1/cost/pricing`) and the server warns when it is older than 90 days.
- **ML failure visibility**: per-model inference failures are logged and
  recorded in a new additive `MlEvidence.failed_models` (elided when empty —
  serialized shape and receipts unchanged in the no-failure case).
- **Signer key permission posture**: on Unix a freshly created receipt signing
  key is re-checked post-write and creation fails if group/world accessible;
  loading a pre-existing loose key warns (`chmod 600` hint). Windows warns to
  restrict NTFS ACLs.
- **Test-coverage closure**: golden-vector tests freezing `signing_bytes()` for
  every receipt shape since 1.1; a live-Postgres receipts suite mirroring the
  SQLite one; Dictum tree-walk ↔ WASM differential tests (fixed corpus + 256
  property-based cases) plus clean-rejection checks for unsupported constructs;
  a mock-HTTP client suite for `iaga-sentinel-integrations` (verdict mapping +
  wire shape, no live sidecar needed); `iaga-verify` CLI smoke tests pinning
  the documented exit codes 0/1/2/3.
- **CI**: postgres:16 service container with real `--features postgres` test
  runs (receipts + core), a `cargo test --workspace --all-features` job, a
  `linux-bpf` scaffold compile check, and the cross-platform compile-sanity job
  promoted to a blocking status.
- **SDK e2e smoke in CI**: the test job now boots a real sidecar and runs the
  Python SDK adapter suite (previously auto-skipped without a server) plus the
  TypeScript `smoke.cjs` checks against it; a new
  `sdks/typescript/register-smoke-agents.cjs` helper provisions the fresh
  agent pool the smoke needs. The framework-heavy `tests/e2e` suites stay
  local-only.
- **Workspace hygiene**: declared MSRV (`rust-version = "1.88"`),
  `[workspace.lints]` shared by every crate (`unsafe_code = "deny"` among
  others), centralized `wasmtime` version and tokio dev-dependencies.

### Changed

- Raw IO failures now map to a dedicated `SentinelError::Io` and an `io_error`
  HTTP error body; previously they surfaced as `config_error`.
- The `linux-bpf` scaffold's block reason is now machine-readable
  (`bpf-loader-not-implemented: …`) so audit consumers can distinguish
  "loader not implemented" from a policy-driven block. Posture unchanged:
  `is_authoritative()` stays `false`; authoritative kernel enforcement is
  Enterprise (ADR 0010).
- `cargo audit` ignores consolidated into a single `.cargo/audit.toml` at the
  repo root (previously duplicated as CI flags).
- `ApiKeyRecord` gains a `scope` field (serde-defaulted to `admin` for old
  records); the `ApiKeyStore` trait gains `store_key_scoped` /
  `verify_raw_key_scoped` with backward-compatible default implementations.

### Fixed

- Corrupt JSON in storage rows (audit reasons/usage, workspace policies, rules,
  tenant metadata, NHI capabilities, sessions, taint labels, fingerprints) is
  no longer silently replaced by defaults: the same fallback now logs a warning
  naming the column, on both SQLite and Postgres backends.
- The background TTL-cleanup task now derives the durable taint-store prune age
  from the configured TTL instead of a hardcoded 3600 s.
- `docs/openapi.yaml` was three releases stale (frozen at 1.3.0): now at
  1.5.2 with every served route documented (receipts, cost API, audit
  export/stats, analytics, webhook DLQ, NHI challenge/verify, templates,
  workspace rules, plugins, policy overlay / reasoning / kernel status,
  risk-weights reset), admin-scope operations marked with their 403, and the
  `RiskWeights` / `HealthResponse` / error-code schemas corrected to match the
  actual wire shapes.
- The Python SDK `__version__` was stale at 1.4.0 while `pyproject.toml` said
  1.5.x; both now track the release version.

## [1.5.1], 2026-06-10

Patch release: a test-determinism fix only — no change to the open build's
runtime behavior, the public wire contract, or the receipt/cost schema.

### Fixed

- Deterministic adaptive-risk weight tests. The adaptive-risk weights are a
  process-global that `apply_feedback` mutates and `calculate_adaptive_risk`
  reads; in the test binary a parallel feedback test could lower the weight
  feeding a borderline assertion (`test_risk_high_risk_shell_rm_rf`) and fail CI
  nondeterministically. The risk-weight tests now serialize and reset to default
  weights via a new `reset_weights()` helper. Production behavior unchanged.

## [1.5.0], 2026-06-09

Cost control: meter, attribute, and cap LLM spend from the open build, fully
self-hosted (no external billing API), plus a deterministic response cache that
reduces spend on safe, repeated read-only tool calls. All additive and behind a
default-off `cost-control` feature — the default build is byte-identical to 1.4.0
and pre-1.5 signed receipts verify unchanged.

### Added

- **`iaga-sentinel-cost` crate**: canonical cost/usage types + a self-hosted
  pricing engine. `UsageReport` (wire, human USD) resolves to `UsageData` (the
  signed form; money is an integer micro-USD ledger). Local `PricingTable` (dated
  built-in, overridable via `IAGA_SENTINEL_PRICING_FILE`); a caller-supplied cost
  always wins (ADR 0020).
- **Cost on receipts + audit**: optional `usage` on the signed `ReceiptBody`
  (elided when absent, so pre-1.5 receipts stay byte-identical) and on audit
  events, with denormalized columns for fast aggregation (migration 0004).
- **Capture** of usage from `POST /v1/inspect` and the agent SDKs — a new optional
  `usage` field on the public wire contract, plus `with_usage` on the Rust client.
- **Observability**: `/v1/cost/{summary,by-agent,by-model,by-tool,over-time,budget,pricing}`,
  a "Cost Control" dashboard panel, and an `iaga cost` CLI.
- **Budget enforcement**: per-session cumulative spend (`IAGA_SENTINEL_SESSION_BUDGET_USD`)
  injected into the Dictum context as `usage.session_cost_usd` / `budget.limit`, so a
  policy can `when usage.session_cost_usd > budget.limit then block`; a non-Dictum
  fallback enforces the same cap. Stricter-wins: cost can only tighten a verdict
  (ADR 0020).
- **Deterministic response cache**: the MCP proxy serves an identical, safe,
  read-only tool call from cache instead of forwarding it; savings surface in the
  cost summary. Semantic caching is an Enterprise feature (ADR 0021).

### Notes

- The default build is unchanged; enable cost control with `--features cost-control`.
- Cost is reported by instrumented callers and priced locally — indicative, not an
  invoice. Session budgets are in-memory; durable spend, time-windowed budgets, and
  network/eBPF cost interception are Enterprise / follow-up work (ADR 0010).

## [1.4.0], 2026-06-09

Agent & framework integrations: put IAGA Sentinel in the loop of any agent stack,
one signed receipt per tool call. Cooperative governance (`allow` / `review` /
`block`, fail-open-by-default transport); every receipt still records
`is_authoritative: false`. All additive — no change to the receipt schema or the
existing public wire contract.

### Added

- **Python adapters** (`sdks/python/iaga_sentinel/adapters/`): `@governed` (custom),
  LangChain (`SentinelCallbackHandler`), LangGraph (`GovernedToolNode`), LlamaIndex
  (`IagaCallbackHandler`), Pydantic AI (`governed_tool`), OpenAI Agents SDK
  (`iaga_tool_guardrail` + `governed_tool`), CrewAI (`SentinelGuardrail`), AutoGen
  (`AutoGenSentinelHook`), Microsoft Agent Framework (`sentinel_middleware`), OpenAI
  (`sentinel_wrap_openai`), and MCP (`govern_tool`). Shared transport helper
  `_common.py`, fail-open by default (configurable via `fail_closed`).
- **TypeScript adapters** (`sdks/typescript/src/adapters/`): OpenAI
  (`sentinelWrapOpenAI`), Vercel AI SDK (`sentinelMiddleware`), LangGraph
  (`governedToolNode`), and MCP (`governMcpTool`); `failClosed` opt-in.
- **Claude Code** `PreToolUse` hook example (zero-dependency Python + Bash variants)
  and **Claude Agent SDK** examples (`canUseTool` for TS, `PreToolUse` hook for
  Python).
- **MCP `GovernedTool`** wrapper (Python + TS) for MCP servers you author;
  complements the existing `iaga proxy` transparent interception.
- **`iaga-sentinel-integrations` Rust crate**: a lightweight standalone async client
  (`SentinelClient` over `reqwest`) mirroring the public camelCase wire contract,
  decoupled from the pipeline internals (ADR 0019).
- **Examples** for all 15 framework integrations under `examples/integrations/`
  (runnable code + `*.policy.yaml` + README + an index and support matrix).
- **Tests**: dependency-free fakes drive every adapter against the live sidecar in
  CI (`sdks/python/tests/`, `sdks/typescript/smoke.cjs`), plus **real end-to-end
  tests** against the actual framework libraries (`sdks/python/tests/e2e/`,
  `importorskip`-guarded so CI stays green without them).

### License

Unchanged: BUSL-1.1 with Change License Apache-2.0 baked in.

---

## [1.3.1], 2026-06-08

The 1.3 conformity-closure patch: reconciles the shipped open build with the
1.3 roadmap's "verifier sovereignty" OSS track (ADR 0018). All changes are
additive, no breaking changes against 1.3.0. Receipts produced before 1.3.1
verify unchanged, the new optional field is elided when absent.

### Added

- ADR 0018: receipt honesty flag. `ReceiptBody` gains an optional
  `is_authoritative` field, populated `false` on every open-build receipt
  because OSS enforcement is soft (no authoritative kernel ships in the
  community edition; `UserspaceKernel::is_authoritative()` is `false`).
  Elided from `signing_bytes` when absent, so 1.3.0 receipts stay
  byte-identical and verify unchanged.
- OpenTelemetry receipt span now also carries the roadmap-named keys
  `iaga.receipt.id` (`run_id:seq`), `iaga.chain.head` (the receipt body
  hash) and `iaga.policy.verdict`, plus `iaga.is_authoritative`, alongside
  the existing `receipt.*` aliases. Full `gen_ai.*` GenAI semantic-convention
  alignment remains a 1.4 deliverable.
- Sensitive-environment scrub on `UserspaceKernel`: a denylist of 23 known
  secret-bearing variables (cloud and model-provider credentials, registry
  tokens, the receipt signing-key path) is stripped from every governed
  child environment, even when passed explicitly via `ProcessSpec.env`, and
  is extendable at runtime via a TOML file at `IAGA_SENTINEL_ENV_DENYLIST`.
- `verify-only` cargo feature on `iaga-sentinel-verify` (default-on), so the
  documented reproducible build
  `cargo build --release --no-default-features --features verify-only` is
  valid and stable across releases.
- CI now exercises the `otel-receipts` and `plugin-manifest-signing`
  features, 1.3 primitives that previously had no CI coverage.

### License

Unchanged: BUSL-1.1 with Change License Apache-2.0 baked in.

---

## [1.3.0], 2026-06-07

The conformity-evidence release: three additive, opt-in primitives that strengthen the trusted-evidence substrate, plus a repositioning of the public narrative around the EU AI Act conformity evidence layer. All changes are additive, no breaking changes against 1.2.0. Default behaviour and receipt bytes are unchanged with the new features off.

### Added

- ADR 0015: standalone receipt verifier. A new slim crate `iaga-sentinel-verify` (binary `iaga-verify`, no database, no async runtime, about 3 MB) verifies a signed receipt chain offline by reusing `verify_chain`. New CLI flag `iaga replay <run_id> --export <file.json>` writes a run as `{ run_id, signer_verifying_key, receipts }` for the verifier to consume. The expected public key is pinned with `--key`; the embedded key is a self-asserted fallback with a loud warning.
- ADR 0016: OpenTelemetry receipt export, behind the default-off `otel-receipts` feature, no new dependency. Each signed receipt also surfaces as an OTel span `iaga_sentinel.receipt` (run id, seq, verdict, input and policy hashes, risk score, signer key id) in the existing telemetry feed, visible via `GET /v1/telemetry/spans` and `/v1/telemetry/export`.
- ADR 0017: Ed25519-signed plugin manifests, behind the default-off `plugin-manifest-signing` feature, orthogonal to `plugin-attestation`. A plugin ships `<plugin>.manifest.json` plus a detached `.sig`; verification checks the plugin SHA-256 and the signature against a trusted-key list. New CLI `iaga plugins sign-manifest` and `iaga plugins verify-manifest --trusted-keys`.
- Data-handling and security documentation: `DATA_HANDLING.md` covering what a receipt contains, the default hashes-only PII posture, where data lives, the absence of call-home, and offline verification; plus a signing section in `SECURITY.md`. Both are linked from the README.

### Changed

- Public narrative repositioned from "zero-trust governance kernel" to the EU AI Act conformity evidence layer for AI agents. README, ENTERPRISE.md, the operator dashboard, contacts, and the project docs are reconciled to that frame and to the honest posture: soft enforcement today, authoritative eBPF/LSM on the Enterprise roadmap. The operator dashboard at `/` is restyled to a minimal theme.

### Removed

- The unwired `ui/` React visualization (the deferred Visual Plane scaffold), the `ui-embed` Cargo feature, and the optional `rust-embed` dependency are removed. The operator dashboard served at `/` is unaffected; it was never part of the `ui-embed` path. This drops the dead TypeScript and React surface and keeps the repository Rust-first.

---

## [1.2.0], 2026-05-28

The **primitive evolution release**: ships the 4 primitives that
ADR 0010 §3 reinstated to the OSS 1.2 roadmap. All changes are
**additive**; no breaking changes against 1.1.0. The
`IAGA Sentinel Enterprise` boundary (ADR 0010 §2, 20 categories)
is reaffirmed, see [`ENTERPRISE.md`](ENTERPRISE.md).

### Added

- [`docs/adr/0011-signer-trait-and-local-disk.md`](docs/adr/0011-signer-trait-and-local-disk.md) -
  `Signer` trait (async, object-safe) + `LocalDiskSigner` reference impl.
  `ReceiptSigner` becomes a type alias so every 1.0 / 1.1 callsite -
  production and test, compiles unchanged. `SignedReceiptLogger` now
  holds `Arc<dyn Signer>`, giving Enterprise builds a clean injection
  point for KMS-backed signers without ricompiling the OSS core.
- [`docs/adr/0012-drift-replay-additive.md`](docs/adr/0012-drift-replay-additive.md) -
  three new optional fields on `ReceiptBody` (`pipeline_inputs_capture`,
  `apl_eval_trace`, `ml_inference_inputs`), opt-in via host env
  `IAGA_SENTINEL_RECEIPT_CAPTURE=1`. New CLI flag
  `iaga replay --re-execute` surfaces per-receipt capture availability.
  Receipts produced with capture disabled are **byte-identical** to
  1.1, chain hashes and signatures stay stable.
- [`docs/adr/0013-plugin-attestation.md`](docs/adr/0013-plugin-attestation.md) -
  new Cargo feature `plugin-attestation` (default off) gates offline
  Sigstore bundle + CycloneDX 1.5 SBOM verification. Looks for sibling
  `<plugin>.sigstore.json` and `<plugin>.cdx.json` next to each WASM
  plugin; validates bundle well-formedness and confirms the payload
  digest matches the plugin bytes. New CLI subcmd
  `iaga plugin verify <path>`.
- [`docs/adr/0014-dictum-wasm-and-types.md`](docs/adr/0014-dictum-wasm-and-types.md) -
  Hindley-Milner type checker (Algorithm W) over the existing Dictum AST,
  always-available via `compile_with_types(src)` and the CLI
  `iaga policy check <file.dictum>`. New Cargo feature `dictum-wasm`
  (default off) adds a WASM codegen scaffolding for literal +
  boolean / numeric / comparison operations; `iaga policy compile`
  emits the module. The tree-walk evaluator remains canonical for the
  full Dictum surface, Path / Call / Membership are rejected by the WASM
  MVP with clear errors.
- New CLI subcmds (additive): `iaga replay --re-execute`,
  `iaga plugin verify <path>`, `iaga policy check <file.dictum>`,
  `iaga policy compile <file.dictum> [--output bundle.wasm]`.

### Changed

- Workspace version bumped to `1.2.0`. License **unchanged**
  (BUSL-1.1 + Change License Apache-2.0 baked-in).
- `ReceiptBody` gains three optional capture fields, elided from
  serialization when `None` (1.1 byte-equality preserved).
- `PluginManifest` gains three cfg-gated optional fields under
  `plugin-attestation` (`attestation`, `sbom`,
  `attestation_offline_verified`). All `None`/`false` by default.
- `PluginDigest` (in the receipt body) gains optional `attested`
  and `attestation_issuer`. Elided when `None`.
- `SignedReceiptLogger` now accepts `Arc<dyn Signer>` rather than
  the concrete struct. `ReceiptSigner` preserved as a type alias -
  zero breaking change for existing callers.

### Deferred (still OSS-eligible, no schedule)

- `iaga policy migrate` (YAML → Dictum converter), debt closure for
  ADR 0008, not a primitive evolution. Lands in 1.2.x or 1.3.
- Address the 3 RUSTSEC ignores in CI (`RUSTSEC-2023-0071`,
  `-2025-0057`, `-2024-0436`) via dependency hardening pass.
- Dictum WASM codegen full support for Path / Call / Membership +
  parity proptest tree-walk vs WASM. The 1.2 MVP ships scaffolding
  (literal + ops only); full coverage is 1.3.
- Postgres + macOS / Windows full CI matrix (1.2 adds compile
  sanity best-effort; promotion to required CI status is 1.3).

### Still Enterprise (boundary reaffirmed, see [`ENTERPRISE.md`](ENTERPRISE.md))

The OSS 1.2 primitive scope is intentionally narrow. The full
chain-of-trust / production-grade implementations remain in
IAGA Sentinel Enterprise per ADR 0010 §2 (20 categories), including:

- Native KMS SDK backends (AWS KMS / Azure Key Vault / HashiCorp
  Vault / PKCS#11 HSM) plug behind the new `Signer` trait but ship
  Enterprise-only.
- Forensic time-travel replay (event sourcing + DB-state-per-verdict
  temporal queries) vs OSS's input-capture-only drift replay.
- Planned hosted plugin marketplace + supply-chain support commitment
  + signed threat-intel feed integration vs OSS's offline-only Sigstore
  / SBOM primitive.
- Dictum AOT optimized codegen (cranelift opt-levels, WASI side-effects)
  + curated rule library + LSP / language server.
- All other ADR 0010 §2 categories: eIDAS qualified signature, managed
  key lifecycle, mesh tier-2, multi-tenant, Enterprise SSO, SIEM
  connectors, air-gap distro, EU AI Act + GDPR + DORA compliance pack,
  DPO dashboard, curated ML library, curated eBPF/LSM library,
  confidential-computing receipts, commercial support,
  conformity assessment notified-body, real eBPF/LSM loader,
  cross-platform kernel macOS/Windows, mesh single-cluster baseline,
  curated ONNX models + HF tokenizers.

---

## [1.1.0], 2026-05-23

A consolidation + rebrand release. 1.1.0 keeps 1.0.0's runtime
behaviour and API contract, but **renames the project Agent Armor →
IAGA Sentinel** across binary, crates, env vars, paths, and
identifiers (breaking for CLI / ops / crate consumers), and pins **how the OSS line is
positioned** relative to the planned IAGA Sentinel Enterprise commercial
edition.

The 1.0 GA shipped the full governance kernel concept: enforcement
kernel scaffold + `UserspaceKernel` cross-platform, signed Merkle
receipts, Dictum DSL with live overlay, probabilistic reasoning
framework, audit pipeline. That is the OSS contract preserved by
the **never retroactively remove** covenant in `ENTERPRISE.md`.

1.1 holds that line, no new runtime capabilities, and clarifies
the OSS↔Enterprise boundary in the public docs so that users and
would-be contributors know what to expect from the open-source
line going forward.

**Boundary clarification (canonical: [`docs/adr/0010-oss-enterprise-boundary.md`](docs/adr/0010-oss-enterprise-boundary.md)).**
Capabilities originally listed under "Deferred to 1.0.x" or
"Deferred to 1.1" in the 1.0.0 entry below have been re-scoped:

- **Reinstated to OSS 1.2 roadmap** (no fixed date; ships when
  ready, no breaking changes): Dictum WASM codegen + Hindley-Milner
  type checker (was 1.0.3), Sigstore + SBOM CycloneDX plugin
  attestation primitive (was 1.1), drift replay additivo + `iaga
  replay --re-execute` (was 1.1), `Signer` trait +
  `LocalDiskSigner` refactor (was implicit). These are primitive
  evolutions with no scale/UX value beyond what OSS already
  provides; keeping them OSS reinforces the open-core covenant
  without diminishing Enterprise.
- **Scoped to IAGA Sentinel Enterprise** (the planned commercial
  edition, currently in development): real Aya-rs eBPF/LSM loader on Linux
  (was 1.0.1), macOS Endpoint Security backend + Windows ETW/WFP
  backend (was 1.1), governance mesh single-cluster baseline + the
  pre-existing tier-2 multi-region active-active (was 1.1),
  curated ONNX reference models (intent-drift / prompt-injection
  / anomaly-seq) + HuggingFace tokenizer integration + calibration
  framework (was 1.0.2 + 1.1), four native KMS SDK signer backends
  AWS KMS / Azure Key Vault / HashiCorp Vault / PKCS#11 (was 1.1).
  These require specialist engineering at scale and are planned to ship
  in the Enterprise edition with contractual support, managed lifecycle,
  and a curated threat-intel feed.
  None shipped in 1.0 GA, the **never retroactively remove**
  covenant is preserved.

The Enterprise edition is where the EU AI Act + GDPR + DORA
compliance pack, DPO Dashboard, multi-tenant isolation, Enterprise
SSO, eIDAS qualified signature pipeline, native SIEM connectors,
air-gapped distribution, commercial support, confidential-computing
receipts, forensic time-travel replay, conformity assessment
notified-body workflow, and the curated AI-specific eBPF/LSM
program library also live. See [`ENTERPRISE.md`](ENTERPRISE.md) for
the concise Enterprise overview.

### Changed

- Workspace version bumped to `1.1.0`.
- [`CHANGELOG.md`](CHANGELOG.md), [`ENTERPRISE.md`](ENTERPRISE.md), and
  [`README.md`](README.md)
  updated to reflect the OSS↔Enterprise boundary clarification.
- ADR 0010 committed as the canonical public boundary note.

### Renamed (breaking)

- Complete rebrand **Agent Armor → IAGA Sentinel**: primary binary
  `agent-armor` → `iaga-sentinel` (short alias `armor` → `iaga`);
  crates `armor-*` → `iaga-sentinel-*`; library imports `agent_armor`
  / `armor_*` → `iaga_sentinel` / `iaga_sentinel_*`; env vars
  `AGENT_ARMOR_*` and `ARMOR_*` → `IAGA_SENTINEL_*` (clean break, no
  fallback); signer key dir `~/.armor/` → `~/.iaga-sentinel/`; default
  DB `agent_armor.db` → `iaga_sentinel.db`; API-key prefix `aa_` →
  `iaga_` (newly generated keys only, existing keys still validate);
  webhook headers `X-Armor-*` → `X-Iaga-Sentinel-*`; MCP tools
  `agentarmor.*` → `iaga.*`; public types `Armor*` → `Sentinel*`. The GitHub repository is now
  `EdoardoBambini/IAGA-Sentinel`.

### Added

- [`docs/adr/0010-oss-enterprise-boundary.md`](docs/adr/0010-oss-enterprise-boundary.md):
  canonical ADR documenting the 20-category Enterprise boundary +
  the 4 primitives reinstated to OSS 1.2 roadmap.

### Unchanged

- Runtime behaviour, verdict logic, receipt format (Ed25519 +
  Merkle), on-disk schema, Dictum/policy formats, feature flags, and
  the HTTP API contract (endpoints, camelCase JSON, Bearer auth) are
  identical to 1.0.0; existing API keys still validate. **Only
  identifiers were renamed (see Renamed above), behaviour did not
  change.**
- The covenant in `ENTERPRISE.md`: *Enterprise will never
  retroactively remove features from OSS. If something works in
  OSS today, it works in OSS forever.*

### License

Unchanged: BUSL-1.1 with Change License Apache-2.0 baked in. Each
release converts automatically and irrevocably to Apache-2.0 four
years after publication.

---

## [1.0.0], 2026-04-26 ("Fortezza")

Architectural leap from 0.4.0. The 0.4.0 sidecar HTTP gate becomes a
distributed, attested, replayable, probabilistically aware kernel for
autonomous AI agents. Every governance decision is now signed,
chained, and verifiable offline. Policy moves from YAML templates to
a typed deterministic DSL. ML is opt-in and produces evidence the
deterministic policy decides on.

### Fixed (GA pre-flight, after E2E smoke)

- **Dockerfile** rewritten for the workspace layout. Previous version
  pointed at the pre-M1 `community/` paths and shipped a stub binary
  that exited immediately. New Dockerfile builds the real binary
  single-shot and `docker compose up` is healthy on first attempt.
- CLI banner: "8 Layers ARMED" → "12 Layers ARMED" (consistent with
  the 1.0 marketing surface; M3.5 + M4 add 4 layers on top of the
  original 8).
- `iaga-sentinel-core` crate description: "(Community Edition)" →
  "(open-source edition)" for consistency with the new
  Community vs Enterprise docs.

### Added

- **Workspace split** into 5 crates under `crates/`: `iaga-sentinel-core`,
  `iaga-sentinel-receipts`, `iaga-sentinel-dictum`, `iaga-sentinel-reasoning`, `iaga-sentinel-kernel`.
  Single workspace `Cargo.toml` at the root.
- **M2, Signed Action Receipts.** Ed25519-signed records of every
  governance verdict, hash-chained per `run_id` (Merkle append-log).
  SQLite and Postgres backends. New CLI: `iaga replay --list`,
  `iaga replay <run_id>`, `iaga replay <run_id> --verify-only`.
  Signer key auto-generated at `~/.iaga-sentinel/keys/receipt_signer.ed25519`
  on first run, override via `IAGA_SENTINEL_SIGNER_KEY_PATH`.
- **M3, Dictum.** Typed DSL with deterministic
  tree-walk evaluator, instruction budget, short-circuit boolean
  evaluation, hash-linked replay safety. New crate `iaga-sentinel-dictum`. CLI:
  `iaga policy test <file.dictum>` and `iaga policy lint <file.dictum>`.
  WASM codegen for Dictum is tracked for 1.0.3.
- **M3.5, Probabilistic Reasoning Plane.** New crate `iaga-sentinel-reasoning`
  with always-available `NoopEngine` plus `TractEngine` (pure-Rust
  ONNX via `tract-onnx`) behind opt-in `ml` feature. Model SHA-256
  digests embedded in every receipt. CLI: `iaga reasoning info`.
  Pre-trained models ship in 1.0.2. *(See [1.1.0] entry for
  re-scoping: curated ONNX library lives in IAGA Sentinel Enterprise.)*
- **M4, Enforcement Kernel scaffold.** New crate `iaga-sentinel-kernel` with
  cross-platform `UserspaceKernel` (soft enforcement, every OS) and
  Linux `BpfKernel` scaffold under `linux-bpf` feature. New CLI:
  `iaga run [--agent-id ...] [--cwd ...] -- <cmd>` and
  `iaga kernel status`. The real eBPF/LSM loader lands in 1.0.1.
  *(See [1.1.0] entry: real Aya-rs loader re-scoped to IAGA Sentinel
  Enterprise; the OSS scaffold + honest posture continue in 1.x.)*
- **M5, `iaga run` traverses the full governance pipeline.** Every
  governed launch produces a signed receipt. Postgres receipt backend
  is wired automatically based on the `DATABASE_URL` scheme.
  Cargo feature composition: `iaga-sentinel-core/sqlite|postgres` transitively
  enables the matching `iaga-sentinel-receipts` feature.
- **M6, Dictum as live policy engine.** `iaga serve --policy <file.dictum>`
  loads an overlay merged stricter-wins with the YAML profile system.
  Receipts embed the SHA-256 of the active Dictum bundle in
  `policy_hash`. New CLI `iaga policy lint`.
- **UI embedded** in the binary via `rust-embed` behind `ui-embed`
  feature.
- **8 ADRs** documenting every architectural decision (`docs/adr/0001`
  through `0008`).
- **`iaga` short alias binary** alongside `iaga-sentinel`. Same entry
  point.

### Changed

- **Crate renamed**: package `iaga-sentinel` → `iaga-sentinel-core`. Binary
  name `iaga-sentinel` preserved for backward compatibility.
- **License**: stays on BUSL-1.1 with **Change License: Apache-2.0**
  baked into the licence. Each release converts automatically and
  irrevocably to Apache-2.0 four years after publication. See
  [ADR 0002](docs/adr/0002-open-source-license-and-scope.md) for the
  rationale and [`LICENSE`](LICENSE) for the legal text.
- **Defense-in-depth model**: 8 layers → 12 layers. The original 8 are
  hardened in M2-M5; M3.5 + M4 add supply chain attestation /
  blast radius enforcement / behavioral baseline / counterparty trust
  scaffolding.
- **All paths** `community/` → `crates/iaga-sentinel-core/`.
- **Cargo `default` features** for `iaga-sentinel-core`:
  `["demo", "sqlite", "receipts", "dictum", "reasoning", "kernel"]`.

### Re-scoped after 1.0 GA (boundary clarification, see 1.1.0 entry above)

> The lists below preserved verbatim from the 1.0 GA changelog for
> historical fidelity. The **2026-05-08 OSS↔Enterprise boundary
> clarification** re-scopes these capabilities, see the [1.1.0]
> entry above and [`docs/adr/0010-oss-enterprise-boundary.md`](docs/adr/0010-oss-enterprise-boundary.md).
> None of the items below shipped in 1.0 GA, so the **never
> retroactively remove** covenant is preserved.

#### Originally deferred to 1.0.x patch releases

- ~~**1.0.1**~~: real eBPF/LSM loader via `aya-rs` + LLVM 18. LSM
  hooks on `execve`, `openat`, `connect`, `sendto`. Landlock
  fallback. Cgroup jailing. Long-lived detached child handle
  ownership. **Re-scoped → IAGA Sentinel Enterprise.**
- ~~**1.0.2**~~: pre-trained ONNX models for intent-drift /
  prompt-injection / anomaly-seq, plus pluggable tokenizers shipped
  alongside model files. **Re-scoped → Enterprise** (curated ML
  model library with threat-intel feed + GPU acceleration).
- ~~**1.0.3**~~: WASM codegen for Dictum via `wasm-encoder`; full
  Hindley-Milner type checker. **Reinstated → OSS 1.2 roadmap.**

#### Originally deferred to 1.1

- Governance mesh (gRPC gossip, federated rate budgets, CRDT on
  receipt log). **Re-scoped → Enterprise** (single-cluster
  baseline + tier-2 multi-region active-active).
- macOS Endpoint Security + Windows ETW kernel backends.
  **Re-scoped → Enterprise** (signed/notarized turnkey).
- KMS / HSM signer backends for receipts. **OSS keeps the BYOK
  pattern** (filesystem-mount via `IAGA_SENTINEL_SIGNER_KEY_PATH`) and the
  `Signer` trait + `LocalDiskSigner` refactor (reinstated → OSS
  1.2 roadmap). **Re-scoped → Enterprise**: four native KMS SDK
  backends (AWS KMS / Azure Key Vault / HashiCorp Vault / PKCS#11
  HSM) + managed key lifecycle + eIDAS qualified signatures.
- GPU acceleration ML + native ONNX Runtime backend (`ort`).
  **Re-scoped → Enterprise** (curated ML model library).
- Drift replay with full pipeline re-execution against historical
  receipts (requires receipt schema change). **Reinstated → OSS
  1.2 roadmap** as additive (`iaga replay --re-execute`,
  schema-additive); the forensic *time-travel* variant (event
  sourcing + temporal queries DB-state-per-verdict) lives in
  Enterprise.
- Stateful cross-run anomaly detection. **Re-scoped → Enterprise**
  (curated ML model library `anomaly-seq`).
- HuggingFace tokenizers in `iaga-sentinel-reasoning`. **Re-scoped →
  Enterprise** (curated ML model library, paired with the curated
  ONNX models).
- `iaga policy migrate` (YAML → Dictum converter). **OSS-eligible**
  (small utility, debt closure for ADR 0008); not yet scheduled.

### Newly added to OSS 1.2 roadmap (reinstated primitives)

- Sigstore + SBOM CycloneDX plugin attestation primitive (closes
  Pillar 4). The hosted private marketplace + supply-chain SLA
  contractual layer remains Enterprise.

---

## [0.4.0], 2026-04-19 ("Azzurra")

The community runtime that proved the thesis. 8-layer defense in depth
behind a single `/v1/inspect` HTTP gate. Policy as YAML + templates.
SDKs in Python and TypeScript. SQLite + Postgres durable state.

See git history for the full 0.4.0 changelog.
