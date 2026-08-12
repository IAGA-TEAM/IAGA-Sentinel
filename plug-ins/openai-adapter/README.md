# IAGA Sentinel — OpenAI (Python)

Govern an OpenAI client's calls. `sentinel_wrap_openai` returns a drop-in proxy:
every `chat.completions.create` / `responses.create` is inspected through
`POST /v1/inspect` before the request is sent.

- **allow** → the request is sent and a signed receipt is produced
- **review / block** → both raise `PermissionError` (the Python SDK defines no
  dedicated exception type; the message carries the score and the reasons)
- sidecar unreachable → fail-open by default (`fail_closed=True` to deny)

A dangerous prompt (e.g. one carrying `curl … | sh`) is blocked by the injection
firewall **before** any OpenAI spend.

## 1. Start the sidecar

```bash
cargo build --release --workspace
# open mode makes every unauthenticated caller an implicit ADMIN; the default bind host is 0.0.0.0
IAGA_SENTINEL_HOST=127.0.0.1 IAGA_SENTINEL_OPEN_MODE=true ./target/release/iaga serve --seed-demo
```

## 2. Register the agent

```bash
./target/release/iaga import plug-ins/openai-adapter/openai.policy.yaml
```

## 3. Run

```bash
pip install openai iaga-sentinel
# Set OPENAI_API_KEY in your shell, then:
python plug-ins/openai-adapter/python_example.py
```

```python
from openai import OpenAI
from iaga_sentinel.adapters import sentinel_wrap_openai

client = sentinel_wrap_openai(OpenAI(), agent_id="openai-demo", base_url="http://localhost:4010")
client.chat.completions.create(model="gpt-4o", messages=[...])  # inspected first
```

## Receipts

```bash
./target/release/iaga replay <run_id> --export chain.json
./target/release/iaga-verify chain.json     # -> CHAIN OK  (is_authoritative: false)
```
