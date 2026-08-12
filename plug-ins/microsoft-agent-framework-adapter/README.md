# IAGA Sentinel — Microsoft Agent Framework

Govern a Microsoft Agent Framework agent's tool/function calls. `sentinel_middleware`
returns a function-invocation middleware `async (context, call_next)`: each call is
inspected through `POST /v1/inspect` first.

- **allow** → awaits `call_next()` (the tool runs); a signed receipt is produced
- **review / block** → raises `PermissionError` (`call_next` is never called)
- sidecar unreachable → fail-open by default (`fail_closed=True` to deny)

`call_next` takes no arguments — the framework mutates `context` in place. The same
`(context, call_next)` shape also works as a Semantic Kernel function-invocation filter.

## 1. Start the sidecar

```bash
cargo build --release --workspace
# open mode makes every unauthenticated caller an implicit ADMIN; the default bind host is 0.0.0.0
IAGA_SENTINEL_HOST=127.0.0.1 IAGA_SENTINEL_OPEN_MODE=true ./target/release/iaga serve --seed-demo
```

## 2. Register the agent

```bash
./target/release/iaga import plug-ins/microsoft-agent-framework-adapter/microsoft-agent-framework.policy.yaml
```

## 3. Run

```bash
pip install agent-framework iaga-sentinel
python plug-ins/microsoft-agent-framework-adapter/python_example.py
```

```python
from iaga_sentinel.adapters import sentinel_middleware

middleware = sentinel_middleware(agent_id="ms-agent-demo", base_url="http://localhost:4010")
# ChatAgent(..., middleware=[middleware])  — or agent.run(..., middleware=[middleware])
```

## Receipts

```bash
./target/release/iaga replay <run_id> --export chain.json
./target/release/iaga-verify chain.json     # -> CHAIN OK  (is_authoritative: false)
```
