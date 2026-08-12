# IAGA Sentinel TypeScript SDK

The TypeScript SDK wraps the IAGA Sentinel HTTP API and adds lightweight helpers
for OpenAI and Vercel AI style integrations.

## Highlights

- `SentinelClient` covers governance, policy, plugin, audit, telemetry, and threat
  intel endpoints exposed by the runtime
- `InspectRequest.sessionId` is normalized into `metadata.sessionId` so sequence
  aware governance survives across repeated tool calls
- adapter helpers are dependency-light and keep the package buildable without
  forcing framework installs

## Offline receipt verification (no dependencies)

`verify.mjs` is a standalone, dependency-free offline verifier for a signed
receipt chain exported by `iaga replay <run_id> --export`. It reaches the same
verdict as the canonical Rust `iaga-verify`, using only Node's built-in crypto:

```sh
node verify.mjs chain.json --key <hex-ed25519-pubkey>
# once installed, the SDK also exposes it as a CLI:
npx --package @iaga-sentinel/sdk iaga-verify chain.json --key <hex>
```

Exit codes mirror the Rust binary: `0` valid, `1` broken/empty, `2` usage,
`3` IO/parse. Cross-language parity is pinned by `verify.smoke.mjs` against
`../conformance/golden_chain.json` (a chain signed by the canonical Rust code).

## Quick start

```ts
import { SentinelClient } from "@iaga-sentinel/sdk";

const client = new SentinelClient({ apiKey: "ak-local" });

const result = await client.inspect({
  agentId: "builder-01",
  workspaceId: "ws-demo",
  framework: "openai",
  sessionId: "session-123",
  action: {
    type: "http",
    toolName: "openai.responses.create",
    payload: { model: "gpt-5.4-mini" },
  },
});

console.log(result.decision, result.traceId);
```

## Adapters

```ts
import OpenAI from "openai";
import { sentinelMiddleware, sentinelWrapOpenAI } from "@iaga-sentinel/sdk";

const openai = sentinelWrapOpenAI(new OpenAI(), {
  agentId: "builder-01",
  apiKey: "ak-local",
});

const middleware = sentinelMiddleware({
  agentId: "builder-01",
  apiKey: "ak-local",
  toolName: "vercel-ai.generate",
});
```

## Adapters classify by tool name — declare the action type

`governedToolNode` (LangGraph) and `governMcpTool` derive an action type from the
tool *name*, because a framework hands the adapter a name and not a type:

| name matches | action type |
| --- | --- |
| `shell`, `bash`, `terminal`, `exec`, `command` | `shell` |
| `http`, `fetch`, `web`, `url`, `request` | `http` |
| `write`, `edit`, `create`, `delete` | `file_write` |
| `read`, `file`, `glob`, `grep`, `cat`, `list` | `file_read` |
| anything else | `custom` |

Most real tool names land in the fallback (`search_docs`, `lookup_customer`,
`get_weather`, `query_database`). `custom` is a first-class action type, but no
shipped example policy lists it, so a workspace written only in terms of
`file_read`/`shell`/`http` refuses your first benign call with
`action type Custom is outside baseline for agent <id>`. That is the policy
working — it is refusing a name it was never told about.

Both adapters take an `actionType` that skips the guess:

```ts
import { governedToolNode } from "@iaga-sentinel/sdk";

const node = governedToolNode(tools, {
  agentId: "builder-01",
  actionType: "file_read", // `search_docs` is a read, not `custom`
});
```

It also overrides a *confident but wrong* guess: `read_customer_emails` matches
`read`, so the heuristic calls it a `file_read`.

The alternative is to widen the policy — add `custom` to the tool's
`allowedActionTypes` and the profile's `baselineActionTypes`. Simpler, but it
hands that tool the least specific type there is, and the policy stops being able
to distinguish a document search from a database write.

> The option is **per adapter instance**, not per tool. The Python SDK's
> `action_types` map classifies each tool name individually; the TypeScript
> adapters have no equivalent yet. With a mixed tool set, use one governed node
> per action type, or widen the policy.
