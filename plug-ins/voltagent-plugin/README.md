# IAGA Sentinel — plug-in for VoltAgent

Govern every [VoltAgent](https://voltagent.dev) tool call through a local
[IAGA Sentinel](https://github.com/EdoardoBambini/IAGA-Sentinel) sidecar. Each
call is inspected for an `allow` / `review` / `block` verdict before it runs, and
every verdict becomes an Ed25519-signed receipt linked into a hash-chained append-log
that verifies offline.

Drop-in, dependency-light (built-in `fetch`, no runtime deps), fail-closed by
default.

## Quickstart

```bash
docker run -p 4010:4010 -e IAGA_SENTINEL_OPEN_MODE=true ghcr.io/edoardobambini/iaga-sentinel:v1.8.1 serve
npm i @iaga-sentinel/voltagent @voltagent/core
```

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

There is a runnable demo in [`examples/basic-agent.ts`](examples/basic-agent.ts)
(no API key needed) and a one-command stack in
[`docker-compose.yml`](docker-compose.yml):

```bash
docker compose up sentinel
node --experimental-strip-types examples/basic-agent.ts
#   allow  -> filesystem.read would run
#   DENIED -> terminal.exec: ... matched high-risk pattern: (?i)rm\s+-rf ...
```

## How it works

`createSentinelHooks()` returns a `createHooks({ onToolStart[, onToolEnd] })`
object. `onToolStart` runs before each tool executes and maps the verdict:

| Verdict | Behavior |
| --- | --- |
| `allow` | returns; the tool runs normally |
| `block` | throws `ToolDeniedError` (`code: "IAGA_BLOCK"`); `execute` never runs |
| `review` | applies `onReview` — default **block**, or pass through with `onReview: "allow"` |
| sidecar unreachable | `failClosed` (default) throws `ToolDeniedError` (`code: "IAGA_UNREACHABLE"`); else logs and allows |

Throwing from `onToolStart` aborts the call: VoltAgent never invokes the tool's
`execute`, and because the thrown error is a `ToolDeniedError`, VoltAgent
aborts the operation rather than feeding an error back to the model.

**MCP tools** surface through the same tool registry, so the same `onToolStart`
gate governs them — no separate code path. (For server-side enforcement, IAGA's
MCP proxy can also sit in front of `MCPConfiguration` servers.)

## Options

`createSentinelHooks(options?: SentinelOptions)`:

| Option | Default | Env | Notes |
| --- | --- | --- | --- |
| `baseUrl` | `http://localhost:4010` | `IAGA_SENTINEL_URL` | sidecar REST base |
| `apiKey` | – | `IAGA_SENTINEL_API_KEY` | Bearer key; omit in open mode |
| `agentId` | `voltagent-agent` | `IAGA_SENTINEL_AGENT_ID` | must be a registered agent |
| `framework` | `voltagent` | – | reported framework |
| `sessionId` | – | – | maps to `metadata.sessionId` = receipt `run_id` (chains a verifiable run) |
| `workspaceId` | – | – | optional workspace scope |
| `failClosed` | `true` | – | deny when the sidecar is unreachable |
| `onReview` | `"block"` | – | `"allow"` lets review pass through with a logged receipt |
| `scanInput` | `false` | – | pre-scan tool input via `/v1/firewall/scan`, deny on a blocked result |
| `scanOutput` | `false` | – | scan tool output via `/v1/response/scan` in `onToolEnd` |
| `redactOutput` | `false` | – | substitute `redactedPayload` into the result the model sees |
| `timeoutMs` | `5000` | – | per-request timeout |
| `fetch` | global | – | injectable fetch for older runtimes |
| `logger` | – | – | optional; VoltAgent's logger fits |
| `inferActionType` | heuristic | – | override the tool-name → action-type mapping |

## Posture: cooperative governance, hard evidence

This plugin is **cooperative agent-loop tier**, not kernel enforcement. Be clear
about what that means:

- It is **bypassable**. If the host strips the hook (or calls the tool outside
  VoltAgent), nothing stops execution. The block is cooperative.
- Every receipt the OSS sidecar signs carries **`isAuthoritative: false`** — the
  community build ships no authoritative kernel.
- The **hard guarantee is the evidence**, not the blocking: a tamper-evident,
  Ed25519-signed, hash-chained receipt log that verifies offline. The verdict
  is advisory; the signed record of what was decided is not.

### Output scanning is post-execution

`scanOutput`/`redactOutput` run in `onToolEnd`, **after** the tool has already
executed. With `redactOutput`, the plugin substitutes the sidecar's
`redactedPayload` so the *model* sees redacted output — but the tool's
side effects already happened. Treat output scanning as detection plus
redaction-of-record, not prevention.

## Verify offline

Every governed action flows through `/v1/inspect`, which appends a signed receipt
under `run_id = <agentId>:<sessionId>`. Verify the chain with no network and no
trust in the sidecar:

```bash
iaga replay <agentId>:<sessionId> --verify-only
# CHAIN OK  run_id=my-agent:run-1  receipts=3  signer=ed25519-...
```

or export and verify with the standalone tool:

```bash
iaga replay <agentId>:<sessionId> --export chain.json
iaga-verify chain.json   # CHAIN OK ...
```

## Roadmap

VoltAgent is building a pluggable `GuardrailProvider`
(`evaluateInput`/`evaluateOutput`). When it ships, IAGA Sentinel should also
implement it as a first-class provider. Until then, the `onToolStart` hook is the
tool-call gate.

## Distribution

Published as `@iaga-sentinel/voltagent`. Ready to submit to
[`awesome-voltagent`](https://github.com/VoltAgent/awesome-voltagent) — cc the
VoltAgent maintainers.

## Third-party & licenses

This package ships only IAGA's own compiled TypeScript (`dist/`) — it bundles no
third-party code. `@voltagent/core` (MIT) is a **peer dependency** you install
separately; no VoltAgent source is copied into this plugin.

## Trademarks & non-affiliation

This is an independent, community-built integration that connects IAGA Sentinel to
VoltAgent. It is **not affiliated with, endorsed by, or sponsored by VoltAgent Inc.**
"VoltAgent" is a trademark of VoltAgent Inc.; the name is used here only to identify the
framework this plugin integrates with. No VoltAgent logo or brand asset is used, and no
VoltAgent source is copied — the plugin imports the published `@voltagent/core` package.

## License

BUSL-1.1, matching the IAGA Sentinel project.
