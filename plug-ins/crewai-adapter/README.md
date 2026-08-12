# IAGA Sentinel — CrewAI

Govern a CrewAI agent's tool calls. CrewAI's native `guardrail=` validates a
tool's **output** (post-execution), so to block a tool **before** it runs, call
`SentinelGuardrail.validate(...)` at the top of the tool's `_run` — each call is
inspected through `POST /v1/inspect` first.

- **allow** → the tool proceeds and a signed receipt is produced
- **review / block** → raises `PermissionError`
- sidecar unreachable → fail-open by default (`fail_closed=True` to deny)

`SentinelGuardrail` is dependency-light (it does not import crewai); it is also
callable — `guard(tool_name, payload, action_type)` returns the payload when allowed.

## 1. Start the sidecar

```bash
cargo build --release --workspace
# open mode makes every unauthenticated caller an implicit ADMIN; the default bind host is 0.0.0.0
IAGA_SENTINEL_HOST=127.0.0.1 IAGA_SENTINEL_OPEN_MODE=true ./target/release/iaga serve --seed-demo
```

## 2. Register the agent

```bash
./target/release/iaga import plug-ins/crewai-adapter/crewai.policy.yaml
```

## 3. Run

```bash
pip install crewai iaga-sentinel
python plug-ins/crewai-adapter/python_example.py
```

```python
from iaga_sentinel import ActionType
from iaga_sentinel.adapters import SentinelGuardrail

guard = SentinelGuardrail(agent_id="crewai-demo", base_url="http://localhost:4010")

class ShellTool(BaseTool):
    name = "shell"
    def _run(self, cmd: str) -> str:
        guard.validate("shell", {"cmd": cmd}, ActionType.SHELL)  # block -> PermissionError
        ...
```

## Receipts

```bash
./target/release/iaga replay <run_id> --export chain.json
./target/release/iaga-verify chain.json     # -> CHAIN OK  (is_authoritative: false)
```
