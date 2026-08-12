# IAGA Sentinel — LlamaIndex

Govern a LlamaIndex agent's tool calls. `IagaCallbackHandler` gates the
`FUNCTION_CALL` event: register it on the `CallbackManager` and every tool call
is inspected through `POST /v1/inspect` before it runs.

- **allow** → the tool runs and a signed receipt is produced
- **review / block** → raises `PermissionError`
- sidecar unreachable → fail-open by default (`fail_closed=True` to deny)

Dependency-light: the handler does not import llama_index; it reads the real
`EventPayload.TOOL` / `EventPayload.FUNCTION_CALL` keys of the event payload.

## 1. Start the sidecar

```bash
cargo build --release --workspace
# open mode makes every unauthenticated caller an implicit ADMIN; the default bind host is 0.0.0.0
IAGA_SENTINEL_HOST=127.0.0.1 IAGA_SENTINEL_OPEN_MODE=true ./target/release/iaga serve --seed-demo
```

## 2. Register the agent

```bash
./target/release/iaga import plug-ins/llamaindex-adapter/llamaindex.policy.yaml
```

The tool's `metadata.name` must be an approved tool name (the example uses
`filesystem.read`). The action type is inferred from the name.

## 3. Run

```bash
pip install llama-index-core iaga-sentinel
python plug-ins/llamaindex-adapter/python_example.py
```

```python
from llama_index.core.callbacks import CallbackManager
from llama_index.core.settings import Settings
from iaga_sentinel.adapters import IagaCallbackHandler

Settings.callback_manager = CallbackManager(
    [IagaCallbackHandler(agent_id="llamaindex-demo", base_url="http://localhost:4010")]
)
```

## Receipts

```bash
./target/release/iaga replay <run_id> --export chain.json
./target/release/iaga-verify chain.json     # -> CHAIN OK  (is_authoritative: false)
```
