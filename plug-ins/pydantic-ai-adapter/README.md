# IAGA Sentinel — Pydantic AI

Govern a Pydantic AI agent's tools. `governed_tool` wraps a tool function so each
call is inspected through `POST /v1/inspect` before the body runs. Stack it under
`@agent.tool` / `@agent.tool_plain`:

```python
@agent.tool
@governed_tool(agent_id="pydantic-ai-demo", tool_name="refund",
               base_url="http://localhost:4010")
async def refund(ctx, order_id: str) -> str: ...
```

- **allow** → the tool runs and a signed receipt is produced
- **review / block** → raises `PermissionError`
- sidecar unreachable → fail-open by default (`fail_closed=True` to deny)

The wrapper preserves the function signature (via `functools.wraps`), so Pydantic
AI still generates the tool schema correctly. The `ctx`/`context` argument is
excluded from the inspected payload.

## 1. Start the sidecar

```bash
cargo build --release --workspace
# open mode makes every unauthenticated caller an implicit ADMIN; the default bind host is 0.0.0.0
IAGA_SENTINEL_HOST=127.0.0.1 IAGA_SENTINEL_OPEN_MODE=true ./target/release/iaga serve --seed-demo
```

## 2. Register the agent

```bash
./target/release/iaga import plug-ins/pydantic-ai-adapter/pydantic-ai.policy.yaml
```

Pass `tool_name=` to map the tool to an approved name (the example uses
`filesystem.read`); otherwise the function name is used.

## 3. Run

```bash
pip install pydantic-ai iaga-sentinel
python plug-ins/pydantic-ai-adapter/python_example.py
```

## Receipts

```bash
./target/release/iaga replay <run_id> --export chain.json
./target/release/iaga-verify chain.json     # -> CHAIN OK  (is_authoritative: false)
```
