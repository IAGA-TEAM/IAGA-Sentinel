# IAGA Sentinel — LangGraph integration

Govern a LangGraph agent's tool calls. `GovernedToolNode` (Python) and
`governedToolNode` (JS) are drop-in replacements for LangGraph's `ToolNode`:
each tool call is inspected through `POST /v1/inspect` before it runs.

- **allow** → the tool runs and a signed receipt is produced
- **review** → raises `PermissionError` (Py) / `SentinelReviewError` (JS)
- **block** → raises `PermissionError` (Py) / `SentinelBlockedError` (JS)
- sidecar unreachable → fail-open by default (`fail_closed` / `failClosed` to deny)

Pure LLM nodes produce no action and need no receipt, so they are left untouched.

## 1. Start the sidecar

```bash
cargo build --release --workspace
# open mode makes every unauthenticated caller an implicit ADMIN; the default bind host is 0.0.0.0
IAGA_SENTINEL_HOST=127.0.0.1 IAGA_SENTINEL_OPEN_MODE=true ./target/release/iaga serve --seed-demo
```

## 2. Register the agent

`/v1/inspect` requires a known `agentId`, and tool names must be approved with
the matching action type:

```bash
./target/release/iaga import plug-ins/langgraph-adapter/langgraph.policy.yaml
```

The action type for each tool is inferred from its name (e.g. `*read*` →
`file_read`, `*shell*`/`*bash*` → `shell`, `*write*` → `file_write`); pass
`action_type` / `actionType` to override.

## 3. Run

- **Python:** `python python_example.py` (needs `langgraph langchain-openai langchain-core iaga-sentinel`)
- **JS:** `node js_example.mjs` (needs `@langchain/langgraph @langchain/openai @langchain/core zod @iaga-sentinel/sdk`)

A dangerous tool call (e.g. a `shell` with `curl … | sh`) is blocked by the
injection firewall before it runs, regardless of the policy decision.

## Receipts

Each governed tool call yields a signed receipt (`is_authoritative: false`).
`auditEvent.eventId` is the `run_id`:

```bash
./target/release/iaga replay <run_id> --export chain.json
./target/release/iaga-verify chain.json     # -> CHAIN OK
```
