# IAGA Sentinel — OpenAI Agents SDK

Govern an OpenAI Agents SDK agent. Two hooks (use either or both):

- **`iaga_tool_guardrail(...)`** — a real `ToolInputGuardrail`. Attach it to a
  function tool: `@function_tool(tool_input_guardrails=[iaga_tool_guardrail(...)])`.
  allow → runs; block/review → `reject_content` (the tool does not run and the
  model is told why).
- **`governed_tool(...)`** — wraps a plain function before `@function_tool`;
  block/review raise `PermissionError`.

Both inspect through `POST /v1/inspect` first and produce a signed receipt.
sidecar unreachable → fail-open by default (`fail_closed=True` to deny).

## 1. Start the sidecar

```bash
cargo build --release --workspace
# open mode makes every unauthenticated caller an implicit ADMIN; the default bind host is 0.0.0.0
IAGA_SENTINEL_HOST=127.0.0.1 IAGA_SENTINEL_OPEN_MODE=true ./target/release/iaga serve --seed-demo
```

## 2. Register the agent

```bash
./target/release/iaga import plug-ins/openai-agents-adapter/openai-agents.policy.yaml
```

The guardrail reports the tool's qualified name (e.g. `filesystem_read`); the
`governed_tool` wrapper uses the `tool_name` you pass. Approve those names.

## 3. Run

```bash
pip install openai-agents iaga-sentinel
python plug-ins/openai-agents-adapter/python_example.py
```

A dangerous tool call (e.g. a `shell` with `curl … | sh`) is blocked by the
firewall before it runs.

## Receipts

```bash
./target/release/iaga replay <run_id> --export chain.json
./target/release/iaga-verify chain.json     # -> CHAIN OK  (is_authoritative: false)
```
