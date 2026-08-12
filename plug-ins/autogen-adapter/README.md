# IAGA Sentinel — AutoGen / AG2

Govern an AutoGen (AG2) agent's tool calls. AutoGen's hooks operate on messages,
not tool execution, so to gate a tool **before** it runs, call
`AutoGenSentinelHook.pre_tool_call(...)` at the top of the registered function —
each call is inspected through `POST /v1/inspect` first.

- **allow** → the tool proceeds and a signed receipt is produced
- **review / block** → raises `PermissionError`
- sidecar unreachable → fail-open by default (`fail_closed=True` to deny)

`AutoGenSentinelHook` is dependency-light (it does not import autogen).

## 1. Start the sidecar

```bash
cargo build --release --workspace
# open mode makes every unauthenticated caller an implicit ADMIN; the default bind host is 0.0.0.0
IAGA_SENTINEL_HOST=127.0.0.1 IAGA_SENTINEL_OPEN_MODE=true ./target/release/iaga serve --seed-demo
```

## 2. Register the agent

```bash
./target/release/iaga import plug-ins/autogen-adapter/autogen.policy.yaml
```

## 3. Run

```bash
pip install ag2 iaga-sentinel   # or autogen-agentchat
python plug-ins/autogen-adapter/python_example.py
```

```python
from iaga_sentinel import ActionType
from iaga_sentinel.adapters import AutoGenSentinelHook

hook = AutoGenSentinelHook(agent_id="autogen-demo", base_url="http://localhost:4010")

def run_shell(cmd: str) -> str:
    hook.pre_tool_call("shell", {"cmd": cmd}, ActionType.SHELL)  # block -> PermissionError
    ...
```

## Receipts

```bash
./target/release/iaga replay <run_id> --export chain.json
./target/release/iaga-verify chain.json     # -> CHAIN OK  (is_authoritative: false)
```
