# IAGA Sentinel plug-ins — put governance in your agent's loop

This folder holds everything that wires IAGA Sentinel **into an agent framework's
tool-call path**: ask a local Sentinel sidecar for an `allow` / `review` / `block`
verdict before a tool runs, enforce it, and turn each verdict into an
Ed25519-signed, offline-verifiable receipt.

Two kinds live here:

- **Plugins** (`*-plugin/`) — complete, self-contained, **released** packages you
  drop into a framework: [`voltagent-plugin/`](voltagent-plugin) (npm `@iaga-sentinel/voltagent`),
  [`letta-plugin/`](letta-plugin) (PyPI `iaga-sentinel-letta`).
- **Adapters** (`*-adapter/`) — thin, copy-paste integrations that gate tool calls
  but aren't yet packaged as standalone, deployable plugins. One per framework
  (LangChain, LangGraph, CrewAI, Claude Code, …). The reusable client libraries they
  build on are in [`sdks/`](../sdks).

> Promotion path: an `*-adapter/` graduates to `*-plugin/` once it is a
> self-contained, tested, deployable package like `voltagent-plugin/`.

---

## Tutorial: govern any agent in 4 steps

### 1. Run the Sentinel sidecar

Build the image from the repo root and run it in open mode (no auth — for local dev/demos).
There is no published image to pull yet; see the note in the root `README.md`.

```bash
docker build -t iaga-sentinel:local .        # from the repo root
docker run -p 127.0.0.1:4010:4010 -e IAGA_SENTINEL_OPEN_MODE=true \
  iaga-sentinel:local serve --seed-demo
# Open mode makes every unauthenticated caller an implicit ADMIN while no API key exists, so
# publish on loopback only — otherwise /v1/audit, the signed decision log, is readable by the
# whole LAN. Pin the publish, not IAGA_SENTINEL_HOST: binding the container to its own loopback
# would make the published port unreachable.
```

The REST API and operator dashboard are now at <http://localhost:4010/>.

In production, drop open mode and require a key. The two sides use different
names on purpose: **server-side** you mint one with `iaga gen-key`, or register
an operator-supplied one at startup via `IAGA_SENTINEL_BOOTSTRAP_API_KEY`;
**client-side** the plug-ins read `IAGA_SENTINEL_API_KEY` and send it as the
bearer token. `IAGA_SENTINEL_API_KEY` is not read by the server at all.

### 2. Pick your integration

- A released **plugin**? Install it: e.g. `npm i @iaga-sentinel/voltagent` for
  VoltAgent, or `pip install iaga-sentinel-letta` for Letta.
- Only an **adapter** for your framework? Copy the folder's snippet into your app.
- Nothing yet? Follow the same recipe with the SDK client
  ([`sdks/typescript`](../sdks/typescript), [`sdks/python`](../sdks/python)) and
  consider contributing it back as a new `*-adapter/`.

### 3. Wire it into the tool-call path

Every integration does the same three things at the framework's interception
point (a hook, a callback, a middleware, a tool wrapper):

1. Map the tool call to an `InspectRequest` and `POST /v1/inspect`.
2. Enforce the verdict: **allow** → run; **review** → don't run (default), or pass
   through if configured; **block** → don't run.
3. Surface the policy reason into the framework's own error/flow.

The IAGA Sentinel plug-in for VoltAgent, end to end:

```ts
import { Agent } from "@voltagent/core";
import { createSentinelHooks } from "@iaga-sentinel/voltagent";

const agent = new Agent({
  name: "governed-agent",
  model: /* your model */,
  tools: [/* your tools */],
  hooks: createSentinelHooks({ agentId: "my-agent", sessionId: "run-1" }),
});
// A blocked tool throws ToolDeniedError before execute() runs.
```

### 4. Verify the evidence offline

Every governed action appends a signed receipt under `run_id = <agentId>:<sessionId>`.
Verify the whole chain with no network and no trust in the sidecar:

```bash
iaga replay <agentId>:<sessionId> --verify-only      # -> CHAIN OK  receipts=N  signer=ed25519-…
# or export + verify with the standalone tool:
iaga replay <agentId>:<sessionId> --export chain.json
iaga-verify chain.json                               # -> CHAIN OK
```

---

## Shared posture: cooperative governance, hard evidence

Everything here is **cooperative agent-loop tier**, not kernel enforcement:

- **Fail-closed by default — in the released plugins only.** `voltagent-plugin`
  (`failClosed: true`) and `letta-plugin` (`fail_closed: bool = True`) deny when
  the sidecar is unreachable. The copy-paste `*-adapter/` snippets are
  **fail-open** by default: pass `fail_closed=True` / `failClosed: true`
  yourself, or an outage silently ungoverns every call.
- **Bypassable** — if the host strips the integration (or calls the tool outside
  the framework), nothing stops execution. The block is cooperative.
- Every OSS receipt carries **`isAuthoritative: false`** — the community build
  ships no authoritative kernel.
- The **hard guarantee is the evidence**: a tamper-evident, signed, hash-chained
  receipt log that verifies offline.

---

## Inventory

### Plugins (released)

| Plugin | Framework | Interception |
| --- | --- | --- |
| [`voltagent-plugin/`](voltagent-plugin) | VoltAgent (`@voltagent/core`) | `onToolStart` / `onToolEnd` hooks |
| [`letta-plugin/`](letta-plugin) | Letta (`letta-client`) | `requires_approval` HITL tool-approval gate → `/v1/inspect` |

### Adapters (copy-paste, not yet packaged)

`claude-code-adapter` · `claude-agent-sdk-adapter` · `langchain-adapter` ·
`langgraph-adapter` · `llamaindex-adapter` · `pydantic-ai-adapter` ·
`openai-agents-adapter` · `microsoft-agent-framework-adapter` · `openai-adapter` ·
`openai-ts-adapter` · `vercel-ai-adapter` · `mcp-adapter` · `crewai-adapter` ·
`autogen-adapter` · `custom-adapter`

---

## Third-party frameworks & licenses

Each plugin **integrates with** a third-party framework or CLI that you install
separately — none is bundled or redistributed here, and no upstream source is copied:

- **VoltAgent** ([`voltagent-plugin/`](voltagent-plugin)) — imports the published
  `@voltagent/core` (MIT) as a peer dependency; the package ships only IAGA's own
  compiled TypeScript.
- **Letta** ([`letta-plugin/`](letta-plugin)) — compatibility via the published
  `letta-client` (Apache-2.0, optional `[letta]` extra); the sidecar client is Python
  stdlib `urllib`. One transitive dependency of `letta-client`, `certifi`, is MPL-2.0
  (file-scoped) — informational, not bundled here.

The full notices for the third-party Rust crates statically linked into the shipped
`iaga` binary are in the repo-root [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).

## Trademarks & non-affiliation

These plugins are **independent, community-built integrations**. IAGA Sentinel is **not
affiliated with, endorsed by, or sponsored by** any of the frameworks they integrate with.

- **VoltAgent** is a trademark of VoltAgent Inc.
- **Letta** (and the Letta logo) are trademarks of Letta / the Letta team.
- **OpenAI**, **Claude** / **Claude Code** (Anthropic), **LangChain** / **LangGraph**, **LlamaIndex**, **CrewAI**, **AutoGen**, the **Microsoft Agent Framework**, **Pydantic AI**, the **Vercel AI SDK**, and the **Model Context Protocol (MCP)** are trademarks of their respective owners.
- All other product and company names are trademarks of their respective owners; nominative use only. See [`TRADEMARKS.md`](../TRADEMARKS.md).

Each name is used **only** to identify the framework the corresponding plugin
works with (nominative use); no third-party logo or brand asset is used, and no upstream
source is copied or redistributed — you install each framework's own published package
separately. See [`TRADEMARKS.md`](../TRADEMARKS.md).
