# IAGA Sentinel — plug-in for Letta

Govern a [Letta](https://github.com/letta-ai/letta) agent's tool calls through a
local [IAGA Sentinel](https://github.com/IAGA-TEAM/IAGA-Sentinel) sidecar.
Letta pauses a governed tool at its Human-in-the-Loop approval boundary; this plugin
asks IAGA for an `allow` / `review` / `block` verdict and replies approve or deny.
Every verdict becomes an Ed25519-signed receipt linked into a hash-chained append-log that
verifies offline.

Dependency-light (the sidecar client is Python stdlib), fail-closed by default.

## Why this differs from the plug-in for VoltAgent

Letta has **no in-process pre-tool hook**. Its interception seam is the
`requires_approval` mechanism: when a governed tool is about to run, Letta's agent
loop pauses and emits an `approval_request_message`; the tool does **not** run until
the caller replies. So this is not a hook — it is a small loop that adjudicates each
approval request and replies. **Letta holds the tool; IAGA supplies and signs the
verdict.** The hold is Letta's mechanism, not IAGA enforcement.

## Quickstart

```bash
# 1. IAGA sidecar (open mode, no auth) on :4010, and an OSS Letta server on :8283
docker compose up sentinel letta      # see docker-compose.yml (add your LLM key for Letta)

# 2. register the agent id this plugin reports to, with a policy.
#    `iaga import` takes a path and reads it with fs::read_to_string — it does not
#    treat `-` as stdin, so write the file first, then import it.
cat > letta-demo.policy.yaml <<'YAML'
profiles:
  - { agentId: letta-demo, workspaceId: ws-letta-demo, framework: letta, role: builder,
      approvedTools: [run_shell], approvedSecrets: [], baselineActionTypes: [shell] }
workspaces:
  - { workspaceId: ws-letta-demo, thresholdReview: 900, thresholdBlock: 950,
      allowedProtocols: [http-function, mcp], allowedDomains: ["*"],
      tools: [ { toolName: run_shell, allowedActionTypes: [shell], maxDecision: allow, requiresHumanReview: false } ] }
vault: []
YAML
./target/release/iaga import letta-demo.policy.yaml

# 3. install
pip install iaga-sentinel-letta letta-client
```

```python
from letta_client import Letta
from iaga_letta import SentinelApprovalHandler, SentinelOptions, govern_tool

letta = Letta(base_url="http://localhost:8283")

# govern_tool upserts the tool with default_requires_approval=True — that is the gate
tool = govern_tool(letta, RUN_SHELL_SRC)
agent = letta.agents.create(name="governed", model="openai/gpt-4o-mini", tool_ids=[tool.id])

handler = SentinelApprovalHandler(SentinelOptions(agent_id="letta-demo", session="run-1"))
run = handler.govern_run(letta, agent.id, "Run the cleanup command: rm -rf /tmp/cache")

for d in run.decisions:
    print(d.action, "-", d.reason)        # -> deny - ... matched high-risk pattern rm -rf ...
```

Already have an agent? Opt it (and its tools) into governance in one call:

```python
from iaga_letta import govern_agent
govern_agent(letta, agent.id)             # adds requires_approval rules to every attached tool
```

A runnable version is in [`examples/governed_agent.py`](examples/governed_agent.py).

### Marking tools for approval

Only a tool that *requires approval* reaches the gate. Two mechanisms do this
(both verified against a live Letta server):

- **`govern_tool(letta, source_code)`** — upserts the tool with
  `default_requires_approval=True` (gates it when attached). The simplest path.
- **`govern_agent(letta, agent_id)`** / **`require_approval(letta, agent_id, tool_name)`**
  — add an agent-level `requires_approval` tool rule; this works **retroactively** on
  an existing agent.

Note: Letta also has a per-agent `agents.tools.update_approval` toggle, but on the
tested release (Letta 0.16.8) it does **not** pause the loop, so this plugin does not
rely on it.

## How it works

`govern_run(letta, agent_id, message)` sends the message, then loops: it finds every
`approval_request_message`, maps each tool call to a verdict, and replies in one
`messages.create(type="approval", approvals=[...])`. The loop repeats until the run
settles.

| Verdict | Reply |
| --- | --- |
| `allow` | approve; the tool runs |
| `block` | deny with the policy reason; the agent gets the error and can adjust |
| `review` | `on_review` — default **deny**, or `"hold"` (leave pending for a human) / `"approve"` |
| sidecar unreachable | `fail_closed` (default) denies; else approves and logs |

In every case IAGA records an Ed25519-signed receipt. The plugin signs nothing.

### Tool execution modes
- **Server tools** run in Letta's sandbox. `requires_approval` gates the call
  *before* it runs, but IAGA does **not** observe what happens inside the sandbox.
- **Client tools** run on your machine via the same approval system — the natural
  spot to gate local shell / filesystem actions before they execute.
- **MCP tools** are forwarded to external MCP servers. IAGA's MCP proxy can sit in
  front of them, or be registered in Letta as a Streamable HTTP MCP server (Bearer
  auth + the per-agent `x-agent-id` header). That path is complementary to this one;
  this plugin is the approval-handler path.

## Options

`SentinelApprovalHandler(SentinelOptions(...))`:

| Option | Default | Env | Notes |
| --- | --- | --- | --- |
| `base_url` | `http://localhost:4010` | `IAGA_SENTINEL_URL` | sidecar REST base |
| `api_key` | – | `IAGA_SENTINEL_API_KEY` | Bearer key; omit in open mode |
| `agent_id` | `letta-agent` | `IAGA_SENTINEL_AGENT_ID` | must be a registered agent |
| `framework` | `letta` | – | reported framework |
| `session` | – | – | maps to `metadata.sessionId` = receipt `run_id` = `agent_id:session` |
| `fail_closed` | `True` | – | deny when the sidecar is unreachable |
| `on_review` | `"deny"` | – | `"hold"` leaves the approval pending; `"approve"` lets it pass with a logged receipt |
| `scan_input` | `False` | – | pre-scan tool args via `/v1/firewall/scan`, deny on a blocked result |
| `scan_output` | `False` | – | scan tool output via `/v1/response/scan` (detection only — see below) |
| `timeout_ms` | `5000` | – | per-request timeout |

## Posture: holds cooperatively, seals hard

- Letta holds the tool via `requires_approval` and waits for this plugin's
  approve/deny. The hold is **Letta's** mechanism, not IAGA enforcement.
- It is **bypassable**: a tool not marked `requires_approval`, or a host that calls
  the tool outside Letta, is not gated.
- Every receipt the OSS sidecar signs carries **`is_authoritative: false`** — the
  community build ships no authoritative kernel.
- The **hard guarantee is the evidence**, not the blocking: a tamper-evident,
  Ed25519-signed, hash-chained receipt log that verifies offline.
- For **server tools**, IAGA gates the call but does not observe execution inside
  Letta's sandbox.

### Output scanning is detection only
`scan_output` runs `/v1/response/scan` after a tool has produced its result. Letta's
loop does not let the plugin rewrite an already-produced tool result, so treat it as
detection plus a record, not prevention.

## Verify offline

Each governed action appends a signed receipt under `run_id = <agent_id>:<session>`.
Verify the chain with no network and no trust in the sidecar:

```bash
iaga replay letta-demo:run-1 --verify-only
# CHAIN OK  run_id=letta-demo:run-1  receipts=2  signer=ed25519-...

iaga replay letta-demo:run-1 --export chain.json
iaga-verify chain.json   # CHAIN OK ...
```

## Where this fits the EU AI Act

A defensible support story, not a compliance claim:
- **Article 12 (record-keeping):** every decision is a signed, append-only receipt.
- **Article 14 (human oversight):** `on_review="hold"` leaves the tool paused for a
  person to decide.
- **Article 15 (accuracy/robustness/cybersecurity):** `scan_input` / `scan_output`
  add prompt-injection and sensitive-data checks.

**This is not legal compliance.** Conformity is a judgement for a lawyer or notified
body. The OSS build is self-signed Ed25519 (not qualified/eIDAS signatures), detects
replay drift (not bit-exact replay), and does not prove which agent acted.

## Distribution

Package `iaga-sentinel-letta` (import `iaga_letta`). Ready to submit to
[`awesome-letta`](https://github.com/letta-ai/awesome-letta) and to share in the
Letta Discord / developer forum.

## Third-party & licenses

This package ships only the `iaga_letta` source (the sidecar client is Python
stdlib `urllib`) — it bundles no third-party code. `letta-client` (Apache-2.0,
optional `[letta]` extra) and `pytest` (MIT, test) are installed separately; no
Letta source is copied into this plugin. One transitive dependency of
`letta-client`, `certifi`, is MPL-2.0 (file-scoped) — informational, not bundled here.

## Trademarks & non-affiliation

This is an independent, community-built integration that connects IAGA Sentinel to
Letta. It is **not affiliated with, endorsed by, or sponsored by Letta.** "Letta" and
the Letta logo are trademarks of Letta, used here only to identify the framework this
plugin integrates with; no Letta logo or brand asset is used. Compatibility is via the
openly published `letta-client` (Apache-2.0), which this plugin imports — no Letta source
is copied or redistributed.

## License

BUSL-1.1, matching the IAGA Sentinel project.
