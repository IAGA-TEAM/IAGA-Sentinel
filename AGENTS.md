# AGENTS.md — IAGA Sentinel

> **Read this first.** This file is a self-contained bootstrap manual for any human or LLM agent
> that needs to stand up IAGA Sentinel from a clean checkout: build it, run the server, open the
> dashboard, connect an agent, and push **real** governance runs (Allow / Review / Block) with
> cryptographically verifiable receipts. Every command here is copy-paste runnable. Paths are
> relative to the repo root unless noted.

---

## ⭐ Standing procedure for the AI agent (DO THIS EVERY TIME)

If **you are an AI agent** reading this file, this is your default operating procedure. Run it
proactively, in order — **but stop and wait for the user twice**: they **approve your rules before you
enforce them** (gate 1), and they **confirm your test calls are visible in the dashboard before you
sign off** (gate 2). Everything between the gates you do yourself. **You must both KNOW these facts and
SAY them to the user.** Never do the setup silently: the human has to be told, in chat, where to look
and what is happening. **Speak to the user in English by default** — switch to Italian (or their
language) only if they prefer it. The messages below are templates: say them in the user's language.

> **Step 0 — get a runnable `iaga` and a clean slate.** `iaga` is usually **not** on your `PATH` after
> a plain `cargo build`; the binary lands in `target/release/`. Build it (or install it onto PATH), and
> start from a **fresh database** — per-agent trust persists in the DB and re-hydrates on restart, so a
> stale DB makes verdicts drift and your smoke tests non-deterministic:
> ```bash
> cargo build --release -p iaga-sentinel-core -p iaga-sentinel-verify   # -> target/release/iaga[.exe]
> # optional, to get `iaga` on PATH:  cargo install --path crates/iaga-sentinel-core
> rm -f iaga_shared.db iaga_shared.db-wal iaga_shared.db-shm            # clean slate
> ```
> Below, **`iaga` means `./target/release/iaga`** (`.\target\release\iaga.exe` on Windows) unless you
> installed it on PATH. To see the whole mechanical loop end to end (build → policy → serve → MCP →
> two test calls → offline proof) **non-interactively** — i.e. without the two human gates below — run
> **`.\scripts\agent_bootstrap.ps1`** (or `./scripts/agent_bootstrap.sh`). When you are actually working
> *with* a user, follow the gated steps 1–5 instead so they approve the rules and watch the calls land.

1. **[GATE 1] Discover your OWN rules by reading your memory/instruction files, then get the user's OK
   — do NOT enforce anything yet.** **Do not invent plausible-sounding rules.** Go and *read the files
   that actually define how you operate* and extract the concrete rules from them — this is a real step
   you perform now, with your file tools:
   - **Your memory files** — the `.md` files in your memory directory. For Claude Code these live under
     `~/.claude/projects/<project-slug>/memory/*.md` (Windows: `%USERPROFILE%\.claude\projects\...\memory\`);
     the **`feedback_*.md`** files are literally "how you should work" and the `project_*.md` files hold
     project constraints. Read them (start from `MEMORY.md`, the index).
   - **`CLAUDE.md` / this `AGENTS.md` / repo conventions**, your **system prompt**, and anything the
     user told you this session (*"never touch production"*, *"commit only when asked"*, *"ask before
     writing files"*).

   For each rule you find, decide whether it is **action-governance** — does it constrain a concrete
   action (`shell`, `file_write`, `http`, `db_query`, …)? Only those can be encoded as Dictum. Rules
   that are copy, positioning, or design judgment (*"it's not a gateway"*, *"keep it minimal"*) are
   **not** encodable as action policy — say so and keep them as notes; do not fake a policy for them.
   Translate each encodable rule into a `.dictum` policy and **cite which memory file it came from**.

   Then **show the user the derived rules in plain language, each with its source, and ask for approval
   before you load anything.** Post something like:
   > "I read my memory files and these are the rules I actually carry; I'd enforce them as policy:
   >  • [from `feedback_no_claude_coauthor`] block commits carrying a *Co-Authored-By: Claude* trailer
   >  • [from `feedback_license_busl`] review any change to `LICENSE`
   >  • never destroy production data.
   >  Do they look right? Tell me to change any, or say **go** and I'll put them in force."

   **Wait for the user's answer. Do not write or load the policy until they approve** — if they correct
   a rule, adjust and re-show it. If your memory is empty, ask the user what their rules are. Full
   syntax, the context schema, verified example policies and a serious footgun: **§11**.

2. **On approval, write `agent_rules.dictum` and validate it** (parses? type-checks?):
   ```bash
   iaga policy lint  agent_rules.dictum
   iaga policy check agent_rules.dictum
   ```

3. **Start the dashboard server** (the human-visible UI on `localhost`) with your approved policy as an
   overlay, on a fixed database a second process can share:
   ```bash
   IAGA_SENTINEL_OPEN_MODE=true DATABASE_URL="sqlite:iaga_shared.db?mode=rwc" \
     iaga serve --seed-demo --port 4010 --policy agent_rules.dictum
   ```
   Wait until `GET http://localhost:4010/health` returns `{"ok":true}`, then confirm the policy loaded
   with `GET /v1/policy/overlay` (expect `"loaded": true` and your `policyCount`). The overlay is read
   **once at boot** — no hot reload, so restart after editing the policy.

4. **Connect yourself over MCP — same `DATABASE_URL` AND same `--policy` as your `serve`:**
   ```bash
   DATABASE_URL="sqlite:iaga_shared.db?mode=rwc" iaga mcp-server --policy agent_rules.dictum
   ```
   > **Pass `--policy` here too — this is not optional.** `iaga mcp-server` shares the *database* with
   > `iaga serve` (so your calls show up in the dashboard) but **not** its in-memory policy overlay. If
   > you launch `mcp-server` *without* `--policy`, the MCP verdicts you get back **ignore your policy** —
   > your rules would appear nowhere in the decision, only the calls would be logged. Load the same file
   > in both processes so the policy actually governs the actions you take. (Verified: an identical
   > `filesystem.read` returns `allow` with no overlay and `review` with your overlay loaded.)

   It speaks JSON-RPC (MCP `2024-11-05`) over **stdio** and exposes two tools — **`iaga.inspect`**
   (govern an action → allow/review/block) and **`iaga.response_scan`** (scan a tool result for
   leaked secrets/PII). Do the `initialize` → `tools/list` → `tools/call` handshake yourself before
   every real action you take, and honor the verdict. Full details + a copy-paste handshake: **§7d**.

5. **[GATE 2] Announce the dashboard, make two live test calls, wait for the user to confirm — then
   greet them.** The moment the server is healthy, post, in plain words:
   > "IAGA Sentinel is live. Open **http://localhost:4010/** and click **Live feed** — I'm about to make
   >  two test calls so you can watch them land in real time. Every tool call I make is checked
   >  (allow / review / block) and written to a signed receipt before I act. The rules you approved are
   >  in force: *never destroy production data*, *a human reviews every file write*, *no credentials to
   >  unapproved hosts*."

   Then make **two real `iaga.inspect` calls over MCP** — one that **allows** and one that **blocks**
   (e.g. a benign `filesystem.read`, then `rm -rf /var/lib/postgresql/data`) — so the dashboard counters
   and Live feed update in front of the user. Tell them what to look for: *"you should see one **allow**
   and one **block** appear."*

   **Wait for the user to confirm they can see the two calls in the dashboard (gate 2).** Only once they
   give the OK, print this line in chat, **exactly**:

   ```
   IAGA SENTINEL IN IT, WELCOME TO THE RODEO
   ```

   Never print that line before the user has confirmed the dashboard is updating — it is the sign-off
   that the whole loop (rules approved → enforced → visible) works end to end.

### What you (the agent) must KNOW and STATE

- **Two processes are required, and you must understand why.** `iaga mcp-server` is **stdio only — it
  does NOT serve the dashboard.** The dashboard is served by `iaga serve` on `:4010`. If you launch
  only the MCP server, there is no `localhost` page for the user — a mistake you must not make.
- **Sharing one `DATABASE_URL` makes actions *visible*; sharing one `--policy` makes them *governed*.**
  Point both `iaga serve` and `iaga mcp-server` at the *same* database file, and your MCP-governed
  actions show up in the human's dashboard (verified: an `iaga.inspect` BLOCK over MCP appears in the
  counters instantly). But the database is only shared *state*, not the live overlay: load the **same
  `--policy` file in both processes**, or the MCP verdict ignores your rules while still logging the
  call. Visibility and enforcement are two separate switches — you need both.
- **Say it, don't assume it.** The user cannot see your stdio MCP traffic. Your governance work is
  only visible to them through that dashboard URL, so handing over the link and explaining it is part
  of the job — every session, every time.
- **Policies are yours to draft, the user's to approve.** Do not wait to be asked to *draft* them, and
  do not hand the user a blank page: propose a starting `.dictum` from the instructions you already
  have and show it in plain language. But **do not load it until the user approves it (gate 1)** — then
  let them correct it and re-show. An unenforced rule in a prompt is not governance — the whole point of
  this product is that the rule is checked and the check is signed evidence.
- **The overlay can only tighten, never loosen.** Dictum merges with the YAML baseline "stricter
  wins", so a policy can turn an `allow` into `review`/`block` but can never turn a `block` into an
  `allow`. Do not try to use policy to grant yourself permissions.

---

## 0. TL;DR — fastest path to a live, agent-connected system

**AI agent? One command runs the whole standing procedure over MCP and proves your policy is enforced:**

```powershell
.\scripts\agent_bootstrap.ps1 -Build     # Windows;  ./scripts/agent_bootstrap.sh --build  on Linux/macOS
```

It builds, writes+validates `agent_rules.dictum`, serves **and** self-connects over MCP with the *same*
`--policy`, then drives three governed beats — proving an identical `filesystem.read` returns `allow`
for a normal file but `review` for a sensitive one **because of your policy** (`dictum[…]` attribution),
and `rm -rf` is blocked. Everything lands in the dashboard at `http://localhost:4010/`.

**Human recording the classic demo (Allow → Review → Block + offline proof):**

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
├── Cargo.toml                    # workspace root (9 crates), version 2.0.0, MSRV 1.88, BUSL-1.1
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
cargo install --git https://github.com/EdoardoBambini/IAGA-Sentinel --tag v2.0.0 --locked \
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
  "agentId": "openclaw-builder-01",
  "workspaceId": "ws-demo",
  "framework": "openclaw",
  "protocol": "mcp",
  "action": { "type": "shell", "toolName": "terminal.exec", "payload": { "command": "rm -rf /var/lib/postgresql/data", "intent": "cleanup" } },
  "metadata": { "sessionId": "my-session-1" }
}
```

(`openclaw-builder-01` / `ws-demo` are seeded by `--seed-demo` — use a registered agent, see the box below.)

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
  -d '{"agentId":"openclaw-builder-01","workspaceId":"ws-demo","framework":"openclaw","protocol":"mcp",
       "action":{"type":"shell","toolName":"terminal.exec","payload":{"command":"rm -rf /var/lib/postgresql/data","intent":"cleanup"}}}'
# -> {"decision":"block","risk":{"score":81,...}}
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
  Example (OpenAI): `sentinel_wrap_openai(client, agent_id="openclaw-builder-01",
  base_url="http://localhost:4010", api_key=None, fail_closed=False)` — wraps
  `chat.completions.create` / `responses.create` and runs a governance preflight.
- **Copy-paste adapters for 15+ frameworks:** `plug-ins/*-adapter/` (openai, langchain, langgraph,
  crewai, autogen, llamaindex, mcp, claude-code, claude-agent-sdk, vercel-ai, pydantic-ai, ...).
- **Released plugins:** `plug-ins/voltagent-plugin/`, `plug-ins/letta-plugin/`, `plug-ins/codex-plugin/`.
- **TypeScript SDK:** `sdks/typescript/`.
- **MCP (the recommended self-connect path):** speak MCP to `iaga mcp-server` — see **§7d**.

Client-side env the adapters read: `IAGA_BASE_URL`, `IAGA_AGENT_ID`, `IAGA_SENTINEL_API_KEY`
(the bearer token).

### 7d. MCP — how an AI agent self-connects (the default path; verified working)

This is the connection method the **standing procedure** at the top uses. `iaga mcp-server` exposes
IAGA's governance as **MCP tools over stdio** (JSON-RPC, protocol `2024-11-05`), so any MCP client —
Claude Desktop, Cursor, a custom agent, or you driving stdio directly — can govern its own actions.

**Two tools exposed** (`tools/list`):
- **`iaga.inspect`** — govern one action; returns `allow | review | block` + risk + full evidence.
- **`iaga.response_scan`** — scan a tool's response payload for leaked secrets / PII.

**Drive it yourself over stdio** (this exact exchange is verified — `initialize` → `tools/list` →
`tools/call`, one JSON-RPC message per line on stdin):

```bash
printf '%s\n' \
 '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"agent","version":"1.0"}}}' \
 '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
 '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"iaga.inspect","arguments":{"agentId":"openclaw-builder-01","workspaceId":"ws-demo","framework":"openclaw","protocol":"mcp","action":{"type":"shell","toolName":"terminal.exec","payload":{"command":"rm -rf /var/lib/postgresql/data","intent":"cleanup"}}}}}' \
 | DATABASE_URL="sqlite:iaga_shared.db?mode=rwc" iaga mcp-server --policy agent_rules.dictum
```

Expected: `initialize` → `serverInfo iaga-sentinel 2.0.0`; `tools/list` → `[iaga.inspect,
iaga.response_scan]`; the `iaga.inspect` call → `structuredContent.decision = "block"`, `risk.score
81`, `isError:false` (the verdict rides *inside* the result — enforcement is cooperative, you honor
it). The call also writes a signed receipt and, because of the shared `DATABASE_URL`, shows up live
in the dashboard at `http://localhost:4010/`.

> **Payload shape over MCP (`protocol: mcp`).** The payload must carry the target tool's fields:
> `filesystem.read` needs `path`; `filesystem.write` needs `path` + `content`; `terminal.exec` needs
> `command`; `http.fetch` needs `method` + `destination`. An `intent` string is **recommended** (it
> enriches the receipt) but is **advisory** — it no longer forces a block when missing. An unknown tool
> name, or a missing *structural* field, still fails schema validation and blocks.

**Register it in an MCP client** (Claude Desktop `claude_desktop_config.json`, Cursor
`~/.cursor/mcp.json`, same shape):

```json
{
  "mcpServers": {
    "iaga-sentinel": {
      "command": "iaga",
      "args": ["mcp-server"],
      "env": { "DATABASE_URL": "sqlite:iaga_shared.db?mode=rwc" }
    }
  }
}
```

Use the same `DATABASE_URL` as your `iaga serve` dashboard so governed calls are visible there.

**Health-check any MCP endpoint** with `iaga mcp-doctor` (flags go *before* `--command`; everything
after `--command` is the downstream server + its args):

```bash
iaga mcp-doctor --format table --agent-id openclaw-builder-01 --command iaga mcp-server --seed-demo
```

It runs `initialize` + `tools/list`, checks each tool's `inputSchema`, and reports what the
governance pipeline would allow/review/block (cooperative diagnostics, `authoritative: false`).

**Other MCP shape:** `iaga proxy --agent-id <id> --command <downstream-mcp-server> [args...]` sits
*between* an MCP client and a real downstream MCP server, governing every `tools/call` that passes
through.

---

## 8. Authentication & API keys

- Bearer token in `Authorization: Bearer <key>`. Keys are hashed with Argon2id. Raw key format:
  `iaga_<uuid-no-dashes>`.
- Two scopes: **`admin`** (everything) and **`agent`** (governance surface: `/v1/inspect`, cost, etc.).
  Admin-only routes return `403 admin_scope_required` for `agent` keys.
- **Open mode:** `IAGA_SENTINEL_OPEN_MODE=true` — while **no keys exist**, requests pass as implicit
  admin. This is the demo/local default. With open mode **off** and no keys, every route is `401`.
  > **Trap:** open mode is auth-optional *only while zero keys exist*. The moment you run
  > `iaga gen-key` (or `POST /v1/auth/keys`), `apiKeysConfigured` flips to `true` and **every**
  > unauthenticated request starts returning `401` — even with `IAGA_SENTINEL_OPEN_MODE=true`. In a
  > live demo, don't mint a key mid-session unless you're ready to send `Authorization: Bearer` on
  > every following call. (Verified: unauth `/v1/inspect` → `401` right after `gen-key`.)

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
| `proxy --agent-id --command [args...] [--policy <file>]` | Govern MCP tool calls between a client and a downstream MCP server. |
| `mcp-server [--seed-demo] [--policy <file>]` | Expose governance tools over stdio (MCP). **Pass `--policy` to enforce your overlay on MCP calls** — see the standing procedure and §7d. |
| `mcp-doctor --command [args] [--probe-tool] [--format]` | Health-check an MCP endpoint. |
| `policy {test\|lint\|check\|compile}` | Dictum tooling (`dictum` feature; `compile` needs `dictum-wasm`). |
| `plugins {list\|validate\|verify\|sign-manifest\|verify-manifest\|attest}` | Plugin tooling. |
| `reasoning info` | Reasoning plane status (`reasoning`). |
| `run --agent-id [--cwd] [--policy <file>] -- <cmd...>` | Launch a child under the userspace enforcement kernel (`kernel`). |
| `kernel status` | Kernel status. |

Separate binary: `iaga-verify <chain.json> [--key <hex-ed25519-pubkey>]`
(exit 0 valid / 1 broken/empty / 2 usage / 3 IO-parse).

---

## 11. Dictum policy language

**This is where you encode the agent's instructions as enforced rules.** See the standing procedure
at the top of this file: writing this policy is part of your setup, every session.

- Extension **`.dictum`**. Syntax:
  `policy "name" { when <expr> [and <expr>] then block|review|allow, reason="...", evidence=<expr> }`.
- Builtins: `secret_ref(<payload>)`, `url_host(<string>)`, `timestamp()`, `sha256(<string>)`.
- Example policies in the repo: `examples/e2e/secrets_and_egress.dictum` (**good** — correct idioms),
  `crates/iaga-sentinel-core/examples/policies/strict.dictum` and
  `crates/iaga-sentinel-dictum/examples/no_pii_egress.dictum` (+ `sample_context.json`) — these two
  **parse fine but misbehave at runtime; do not copy them.** See §11d.

### 11a. The runtime context you can reference

Built in `crates/iaga-sentinel-core/src/pipeline/dictum_overlay.rs`. **Always present:**

| Path | Meaning |
|---|---|
| `agent.id`, `agent.framework` | who is acting |
| `action.kind` | one of `shell`, `file_read`, `file_write`, `http`, `db_query`, `email`, `custom` |
| `action.tool_name` | e.g. `terminal.exec` |
| `action.payload.<field>` | the raw action payload (e.g. `action.payload.command`, `.destination`) |
| `workspace.id`, `workspace.allowlist` | the workspace and its **allowed domains** |
| `risk.score` (0–100), `risk.decision` | the baseline verdict, before your overlay |

**Conditionally present — dangerous, read §11c first:** `ml.*` (only with the `ml` feature and a
loaded model), `usage.session_cost_usd` (only when a session cost is tracked), `budget.limit` (only
when a budget is configured, e.g. `IAGA_SENTINEL_SESSION_BUDGET_USD`).

> `workspace.allowlist` holds **domains** (it is `workspace_policy.allowed_domains`), so
> `url_host(action.payload.destination) not in workspace.allowlist` is the correct idiom — see §11d
> for the shipped example that gets this wrong.

**These paths do NOT exist** (referencing them blocks everything — §11c): `action.url`,
`action.risk_score`, `agent.role`, `tenant`, `protocol`, `metadata`, `requested_secrets`.

### 11b. Translating instructions into policy (verified working)

Typical agent instructions on the left, enforceable policy on the right. This file passes both
`iaga policy lint` and `iaga policy check`:

```dictum
// "Never destroy production data."
policy "never_destroy_production_data" {
  when action.kind == "shell"
   and risk.score > 50
  then block, reason="destructive shell is outside my mandate"
}

// "Never send credentials to a host we haven't approved."
policy "no_secret_egress_off_allowlist" {
  when action.kind == "http"
   and url_host(action.payload.destination) not in workspace.allowlist
   and secret_ref(action.payload)
  then block, reason="credentials must not leave approved hosts",
       evidence=action.payload.destination
}

// "Ask me before you modify any file."
policy "human_approves_file_writes" {
  when action.kind == "file_write"
  then review, reason="a human confirms every file modification"
}
```

Load it, then confirm it is really in force:

```bash
iaga serve --seed-demo --policy agent_rules.dictum      # loads at boot; error -> exit 2
curl -s http://localhost:4010/v1/policy/overlay
# -> {"enabled":true,"loaded":true,"policyCount":3,"policyHash":"4531ee8e…","source":"agent_rules.dictum"}

Then smoke-test that you did not over-block (see §11c): a benign `file_read` must still come back
`allow`, while `rm -rf …` comes back `block`. Both verified with the policy above.

> **Where to see that a policy actually fired.** The attribution lands in
> **`auditEvent.reasons`**, as `dictum[<policy_name>]: <your reason>` — **not** in `risk.reasons`,
> which keeps only the baseline reasons. So a policy-driven block looks like
> `decision=block`, `risk.score=2`, `risk.reasons=["no high-risk rule matched"]`, and the real
> explanation sits in `auditEvent.reasons`. Always look there when debugging a policy.

**Verified functionally** (9-case suite, each on its own port + database):

| Behaviour | Result |
|---|---|
| No policy loaded → baseline untouched | ✅ |
| Policy tightens `allow` → `review` | ✅ |
| Policy tightens `allow` → `block` | ✅ |
| Policy **cannot** relax `block` → `allow` (stricter wins) | ✅ |
| `url_host()` + `secret_ref()` block a secret sent to an off-allowlist host | ✅ |
| Same policy does **not** fire on a clean call to an allowed host | ✅ |
| Guard pattern (§11c) keeps a benign action `allow` | ✅ |
| Guarded budget policy fires once real spend exceeds the budget | ✅ |
| A non-matching policy never fires | ✅ |
| `policy_hash` of the loaded overlay is bound into the signed receipt | ✅ |

Falsification controls were included (same payload against a no-policy server must come back `allow`
with no attribution), so the suite can actually fail rather than always reporting success.
```

### 11c. ⚠️ Footgun: referencing a field the context does not provide

> **Fixed in 1.9.2 for the common case.** A policy that references a path the runtime context can
> *never* provide (a typo like `action.risk_score` instead of `risk.score`, or an unknown root) is
> now **rejected when the overlay loads**: the server prints the offending path plus the valid roots
> and exits `2`. It can no longer reach production and block everything.
>
> What remains your responsibility is the **conditionally-present** roots — `usage.*`, `budget.*`,
> `ml.*` — which are legal paths that simply do not exist in every configuration. Referencing one
> logs a warning at load; guard it as shown below or it will still block everything when absent.

The rest of this section explains the failure mode, because it is worth understanding.

A policy whose condition references a context root that is absent at runtime causes *unrelated*
actions to be **blocked**. Example — this policy alone:

```dictum
policy "stop_when_over_budget" {
  when usage.session_cost_usd > budget.limit
  then block, reason="session budget exhausted"
}
```

With **no budget configured** (so `budget` is never inserted into the context), a harmless
`file_read` comes back `decision=block` with `risk.score=2` and
`risk.reasons=["no high-risk rule matched"]`. The baseline said allow and the overlay forced the
block — and because `risk.reasons` only ever carries baseline reasons, the block looks unexplained
unless you know to read `auditEvent.reasons`, where it appears as
`dictum[stop_when_over_budget]: dictum-eval-error`. Controlled comparison:

| Policy loaded | Budget configured | `file_read` verdict |
|---|---|---|
| budget rule only | **no** | ❌ **block** |
| a rule not touching `usage`/`budget` | n/a | ✅ allow |
| budget rule only | **yes** (`IAGA_SENTINEL_SESSION_BUDGET_USD=5.00`) | ✅ allow |

**`iaga policy lint` and `iaga policy check` both report OK on it** — the type checker cannot catch
this, because it is a runtime-context problem, not a typing problem. This is why the check moved to
overlay load time (1.9.2): `iaga serve --policy` is the only place that knows the real context.

**Why it happens** (source-verified): a missing path resolves to `Null` silently
(`eval.rs:342`), the ordering operators `< > <= >=` have no `Null` case and raise an eval error
(`eval.rs:324`), and `evaluate_program_traced` turns an eval error on a `block`/`review` policy into
a **fail-closed fire** (`eval.rs:202-221`), which stricter-wins then promotes to the final verdict.
`==` and `!=` never error, and `Null` is falsy — **only the ordering operators explode.**

**The default build triggers it.** `cost-control` is a default feature, so `usage.session_cost_usd`
is always present, but `budget.limit` only appears when `IAGA_SENTINEL_SESSION_BUDGET_USD` is set.
`Float > Null` → error → block everything.

**Guard pattern (verified working)** — `and` short-circuits on truthiness, so probe the field first:

```dictum
when budget.limit and usage.session_cost_usd > budget.limit
```

For a budget policy to ever fire, the caller must actually report usage. The `usage` object on
`/v1/inspect` is `UsageReport` (`crates/iaga-sentinel-cost/src/usage.rs:29`) and **`provider` and
`model` are required**; token fields are `promptTokens` / `completionTokens` (not
`inputTokens`/`outputTokens`), and `costUsd` overrides the pricing table:

```json
"usage": {"provider":"openai","model":"gpt-4o","promptTokens":1000,"completionTokens":1000,"costUsd":2.00}
```

Verified: with `IAGA_SENTINEL_SESSION_BUDGET_USD=0.50`, a request carrying that usage records the
spend (`/v1/cost/summary` → `grossCostUsd: 2.0`) and the **next** request is blocked by the guarded
policy. Note the ordering — spend is counted for *subsequent* requests, so the request that blows
the budget is itself allowed.

**Rule of thumb:** only reference `usage.*`, `budget.*` and `ml.*` behind that guard, and always
smoke-test a benign action (a `file_read` must stay `allow`) after loading a new policy. Stick to the
always-present fields in the §11a table and you are safe.

### 11d. Two shipped example policies were broken — fixed in 1.9.2

Both parsed and type-checked cleanly, then over-blocked at runtime for exactly the §11c reason. They
are corrected now, and a test asserts the shipped examples still load:

| File | Was | Now |
|---|---|---|
| `crates/iaga-sentinel-dictum/examples/no_pii_egress.dictum` | `action.risk_score > 80` — a path that does not exist, so `Null > 80` errored and **blocked every `shell` action** | `risk.score > 80` |
| `crates/iaga-sentinel-core/examples/policies/strict.dictum` | `action.tool_name not in workspace.allowlist` — the allowlist holds **domains** and `in` on a list is exact equality, so it was always true and **blocked every `http` action** | `url_host(action.payload.destination) not in workspace.allowlist` |

`crates/iaga-sentinel-dictum/examples/sample_context.json` was also rewritten: it used to describe a
context shape that does not exist at runtime, and now mirrors §11a.

Either example is now a fine reference, as is `examples/e2e/secrets_and_egress.dictum` and the §11b
policy.

### 11e. Other semantics worth knowing

- **A path pointing at an object evaluates to `Null`** (`eval.rs:365`). So bare `action.payload`,
  `ml`, `workspace`, `risk`, `agent`, `action` are all `Null`; drill down to scalar leaves. Arrays
  cannot be indexed (`workspace.allowlist.0` is `Null`) — they are only usable whole, with `in`.
- **`secret_ref(action.payload)` is special-cased** to receive the raw JSON subtree, which is why it
  works on a whole object while a bare path does not.
  > **`secret_ref()` detects RAW credential material, not `secretref://` references.** It scans the
  > subtree for actual secrets — AWS keys (`AKIA…`), PEM private-key blocks, high-entropy tokens — and
  > returns true only when it finds one. A `secretref://prod/github/token` *pointer* (the kind the
  > seeded REVIEW scenario carries in `requestedSecrets`) is **not** raw material, so `secret_ref` does
  > **not** fire on it. That is a different mechanism: `requestedSecrets` + the vault/secret-plan drive
  > the seeded review, while `secret_ref` guards against a plaintext credential sitting in the payload.
  > To see `no_secret_egress_off_allowlist` fire, put an actual credential string in the payload.
- **`in` / `not in`**: exact element equality when the right side is a **list**; **substring match**
  when it is a **string**; anything else is an eval error (→ fail-closed).
- **`url_host()`** lowercases and strips scheme/userinfo/port/path/query/fragment, and matching is
  exact-host: an allowlist entry `example.com` does **not** cover `api.example.com`. That is
  deliberate — it defeats look-alike hosts like `hooks.slack.com.attacker.tld`.
- Loaded via `iaga serve --policy <file>` as an **overlay** on the YAML baseline: **"stricter wins"**,
  it can only tighten (verified: an `allow`-everything policy cannot unblock a `block`). Load error
  → exit 2. **No hot reload** — restart after editing. Overlay status: `GET /v1/policy/overlay`.
- **`policy_hash` is the SHA-256 of the compiled policy AST, not of the file bytes**
  (`compute_policy_hash`, `dictum_overlay.rs:118`). Verified consequence: reformatting or adding
  comments leaves the hash **unchanged**, while any semantic edit (e.g. `block` → `review`) changes
  it. That hash is bound into every signed receipt, so the evidence records *which policy semantics*
  produced the verdict.
- Test/validate offline — run these against **your own** policy:
  ```bash
  iaga policy lint  agent_rules.dictum     # parses?
  iaga policy check agent_rules.dictum     # type-checks?
  iaga policy test  agent_rules.dictum --context some_context.json
  ```
  Remember: passing `lint` and `check` does **not** mean the policy is safe — neither catches the
  §11c footgun. The only reliable check is loading it and smoke-testing a benign action.

  The upstream fixture still works as a `--context` demo (its schema is not the runtime one, §11d):
  ```bash
  iaga policy test crates/iaga-sentinel-dictum/examples/no_pii_egress.dictum \
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
- **Served by `iaga serve`, NOT by `iaga mcp-server`.** The MCP server is stdio-only. To give the
  human a dashboard while an agent connects over MCP, run both on the **same `DATABASE_URL`** — the
  MCP-governed actions then appear here live (verified: an `iaga.inspect` BLOCK over MCP shows up in
  the dashboard's counters immediately).
- URL to hand the user: **http://localhost:4010/**. Tabs: **Live feed** (SSE `/v1/events/stream`),
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
| `IAGA_SENTINEL_DEFAULT_MODE` | `sidecar` (default) / `gateway`. Reported by `/health`. Sidecar matches the product's advisory positioning; set `gateway` only if you deliberately want that framing. |
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
- **`gen-key` ends open mode instantly.** Once any key exists, unauthenticated calls get `401` even
  in open mode — mint keys only when you're ready to send `Authorization: Bearer` on every request.

---

*IAGA Sentinel v2.0.0 · BUSL-1.1 · https://github.com/EdoardoBambini/IAGA-Sentinel*
