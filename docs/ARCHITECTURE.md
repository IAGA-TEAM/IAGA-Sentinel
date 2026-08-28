# Architecture

> **Historical document, describes the v0.4.0 community runtime.**
> The current 2.x architecture is documented in
> [`README.md`](../README.md) (Architecture section) and the
> OSS↔Enterprise boundary in
> [`adr/0010-oss-enterprise-boundary.md`](adr/0010-oss-enterprise-boundary.md).
> Path references in this file (`community/...`) reflect pre-1.0
> layout; current paths are `crates/iaga-sentinel-core/...`. The pipeline
> described here is still **8 layers** in 2.x, but not all eight decide. The
> verdict comes from the veto and scoring layers; **sandbox execution, formal
> policy verification, the behavioural fingerprint, and the session graph's
> `advisoryScore` are advisory** — reported in the response, never part of the
> verdict. The session graph's signed `anomalyScore` is a different field and
> is *not* advisory: it is a term in the composite and escalates to review on
> its own at 50. Each response carries a machine-readable `layerRoles` map
> (`veto` / `scoring` / `advisory`) so this is not something a reader has to
> infer. 1.0 added four cross-cutting subsystems on top (supply chain
> attestation, blast radius, behavioral baseline, counterparty trust).
>
> **Trademarks.** VoltAgent and Letta are trademarks of their
> respective owners. IAGA Sentinel is independent and not affiliated with, endorsed
> by, or sponsored by them; the names identify compatibility only. See
> [`TRADEMARKS.md`](../TRADEMARKS.md).

## Release Context

This document describes the current community architecture for `v0.4.0`.

It reflects the code that is actually present in `community/`, including:

- SQLite and optional PostgreSQL storage
- versioned migrations
- structured logging and correlation IDs
- policy templates plus persisted workspace rules
- feature-gated WASM plugin evaluation
- live HTTP end-to-end verification

## Governance Flow

Every governed action flows through the same ordered pipeline:

```text
Request
  -> Protocol DPI
  -> Taint Tracking
  -> NHI Identity
  -> Adaptive Risk
  -> Sandbox / Impact
  -> Policy Evaluation
  -> Plugin Evaluation (optional, feature-gated)
  -> Injection Firewall
  -> Telemetry
  -> Decision
```

The plugin slot lives between policy evaluation and the injection firewall.
Plugin findings and decision hints are merged into the final governance result
as `pluginResults`.

## Layer Summary

### Layer 1 - Protocol DPI

- detects MCP, ACP, A2A, and HTTP-style envelopes
- normalizes and validates request shapes before policy evaluation

### Layer 2 - Taint Tracking

- labels data as it moves through tool actions
- detects exfiltration and unsafe sink usage
- still keeps hot-path runtime state in memory today, with persistence hooks

### Layer 3 - NHI Registry

- creates non-human identities for agents
- supports challenge-response attestation
- issues capability tokens: signed with the agent's derived NHI secret, bound to
  one `agentId`, persisted, and revocable. `read:self` lets an agent read its own
  profile and analytics, which are otherwise admin-only. Symmetric HMAC, so only
  the server can verify (CRYPTO-NHI-2) — relying-party-checkable asymmetric agent
  identity is Enterprise (ADR 0010). Through 2.0.2 the token authorized nothing:
  the signature was never checked, tokens lived only in process memory, and there
  was no way to revoke one.
- still needs a fully closed restart hydration story

### Layer 4 - Adaptive Risk

- combines multiple signals into a 0-100 score
- consumes real session depth and recent timestamps
- includes sequence-aware heuristics such as `collection -> egress`,
  multi-read fan-in, and `http -> shell`

### Layer 5 - Sandbox / Impact Analysis

- estimates impact for risky actions
- supports approval and rejection flows for pending sandboxed actions
- **runs last, not fifth.** The list above is the conceptual order; since 2.0.1
  this layer executes after the composite risk score exists, because its
  thresholds are on the composite's scale and feeding it the adaptive score
  meant it never fired at all. It is advisory either way: `sandboxResult` is not
  part of the signed receipt and contributes no term to the composite, so its
  position cannot change a verdict.

### Layer 6 - Policy Engine

- checks profiles, workspaces, tool rules, protocols, and destinations
- exposes built-in templates
- persists workspace rules via `/v1/workspaces/{id}/rules`
- evaluates persisted rules during pipeline execution

### Plugin Evaluation

- feature-gated behind `--features plugins`
- loads `.wasm` plugins through `wasmtime`
- evaluates plugins through `PluginRegistry` and `PluginHost`
- surfaces registry state via `/v1/plugins` and `/v1/plugins/reload`

### Layer 7 - Injection Firewall

- uses staged rule-based prompt inspection
- tracks runtime stats in memory today
- no ML classifier in community `0.4.0`

### Layer 8 - Telemetry

- emits spans and metrics
- supports SSE and webhook fan-out
- logs request-level correlation via `x-request-id`
- returns pipeline-level `traceId` in governance responses

## Storage

### Backends

- default: SQLite
- optional: PostgreSQL via `--features postgres`

The runtime selects the backend from `DATABASE_URL`:

- `sqlite:...` -> SQLite
- `postgres://...` or `postgresql://...` -> PostgreSQL

### Migrations

> Unlike the rest of this file, this subsection is kept current: it is the one place a reader
> arrives at looking for where migrations live, and sending them to a directory that has not
> existed since 1.1.0 costs more than the inconsistency.

Schema migrations are versioned under:

- `crates/iaga-sentinel-core/migrations/sqlite/`
- `crates/iaga-sentinel-core/migrations/postgres/`

The runtime runs them through `sqlx::migrate!()`, which checksums each version — so a file that
has already been applied somewhere must never be edited, and a new migration must take the next
free number rather than reuse one.

The receipt store keeps its own schema under `crates/iaga-sentinel-receipts/migrations/`, and
deliberately does **not** use `sqlx::migrate!`: it frequently shares one SQLite database with the
core store, which owns the single `_sqlx_migrations` table, and a second migrator there sees
versions it does not know and refuses to open. That file is idempotent and re-executed on every
open instead.

There is also a compatibility layer that backfills columns needed by older
community databases.

### Durable State Status

`v0.4.0` adds storage traits and persistence hooks for:

- NHI state
- session graphs
- taint sessions
- behavioral fingerprints
- rate-limit configuration

This is meaningful progress, but the full restart story is still not closed.
Startup hydration and restart-proof end-to-end validation remain open.

## Runtime Surface

```text
community/src/
|- main.rs
|- core/
|- auth/
|- config/
|- dashboard/
|- events/
|- modules/
|- mcp_proxy/
|- mcp_server/
|- pipeline/
|- plugins/
|- server/
`- storage/
   |- traits.rs
   |- migrations.rs
   |- sqlite.rs
   `- postgres.rs
```

## Transport And API

- HTTP server: Axum
- auth: Bearer token with Argon2-hashed API keys
- public routes: `/`, `/health`
- protected routes: `/v1/*`
- real-time transport: SSE and webhooks
- MCP support: proxy/interceptor mode and MCP server mode over stdio
- plugin registry endpoints: `/v1/plugins`, `/v1/plugins/reload`

## SDK And Adapter Surface

The repo also ships:

- `sdks/python/` with expanded endpoint coverage and adapters for OpenAI,
  LangChain, CrewAI, and AutoGen
- `sdks/typescript/` with expanded endpoint coverage and adapters for OpenAI
  and Vercel AI style middleware helpers

Both SDKs now expose `sessionId` as a first-class request field and encode it
into `metadata.sessionId`, which keeps sequence-aware governance reachable from
client code.

## Logging And Correlation

`v0.4.0` supports:

- `IAGA_SENTINEL_LOG_FORMAT=pretty|compact|json`
- `IAGA_SENTINEL_LOG_LEVEL`
- `RUST_LOG` fallback
- `x-request-id` on HTTP responses
- `traceId` on governance results

## Verification Strategy

The community runtime is verified with:

- unit tests
- property tests
- direct integration tests
- live HTTP end-to-end tests
- CLI tests
- example plugin compilation and execution tests

The SDK layer is also checked with:

- TypeScript build validation
- Python compile smoke

## Known Architectural Gaps

These are the main remaining community architecture gaps:

- fully closed restart hydration and background sync for durable state
- enhanced CLI roadmap commands (`watch`, `benchmark`). `replay` and
  `policy test` were on this list and have shipped; see the CLI reference in
  [`AGENTS.md`](../AGENTS.md) §10.
- richer typed SDK response models for some endpoints
- **session state is process-global, not partitioned by workspace.** `SESSIONS`
  and `SESSION_TAINTS` are keyed by `sessionId` with a fallback to `agent_id`, so
  two workspaces sharing a process and a session key share the accumulated label
  set. Each verdict is still evaluated with its own workspace's policy; what is
  not partitioned is the history those checks read.
- **a `GET` to an allow-listed host can carry data in its query string.** The
  `secret` taint and response-side scanning cover part of that, not all of it.

## Dashboard

The dashboard is a live operator console served from the Rust runtime.

Current connected surfaces include:

- live overview metrics
- audit exploration
- review queue actions
- selected-agent analytics and fingerprint drill-down
- runtime posture cards for firewall, threat intel, telemetry, rate limiting,
  sessions, plugins, and policy verification
