# IAGA Sentinel Python SDK

`iaga-sentinel` wraps the IAGA Sentinel HTTP API for Python applications and ships
lightweight adapters for common agent frameworks.

## Highlights

- `SentinelClient` and `AsyncSentinelClient` cover governance, policy, plugin, audit,
  telemetry, and threat intel endpoints exposed by the runtime
- `InspectRequest` supports `session_id`, encoded into `metadata.sessionId` for
  sequence-aware governance
- dependency-light adapters exist for OpenAI, LangChain, CrewAI, and AutoGen

OpenAI, LangChain, CrewAI, and AutoGen are trademarks of their respective owners;
these adapters are independent integrations, not affiliated with or endorsed by them.
See the repository [`TRADEMARKS.md`](../../TRADEMARKS.md) for details.

## Offline receipt verification (no dependencies)

`iaga_verify.py` is a standalone, dependency-free offline verifier (Python
standard library only, vendored Ed25519) for a signed receipt chain exported by
`iaga replay <run_id> --export`. It reaches the same verdict as the canonical
Rust `iaga-verify`:

```sh
python iaga_verify.py chain.json --key <hex-ed25519-pubkey>
```

Exit codes mirror the Rust binary: `0` valid, `1` broken/empty, `2` usage,
`3` IO/parse/unsupported. Parity is pinned by `tests/test_iaga_verify.py`
against `../conformance/golden_chain.json` (a chain signed by the canonical Rust
code).

## Quick start

```python
from iaga_sentinel import ActionDetail, ActionType, SentinelClient, InspectRequest

client = SentinelClient(api_key="ak-local")
result = client.inspect(
    InspectRequest(
        agent_id="builder-01",
        workspace_id="ws-demo",
        framework="openai",
        session_id="session-123",
        action=ActionDetail(
            type=ActionType.FILE_READ,
            tool_name="filesystem.read",
            payload={"path": "README.md"},
        ),
    )
)

print(result.decision.value, result.trace_id)
```

## Adapters

```python
from openai import OpenAI

from iaga_sentinel.adapters import SentinelCallbackHandler, SentinelGuardrail, sentinel_wrap_openai

openai_client = sentinel_wrap_openai(OpenAI(), agent_id="builder-01", api_key="ak-local")
langchain_handler = SentinelCallbackHandler(agent_id="builder-01", api_key="ak-local")
crewai_guardrail = SentinelGuardrail(agent_id="builder-01", api_key="ak-local")
```

### Adapters classify by tool name — declare `custom`

A framework hands the adapter a tool *name*, not an action type, so
`adapters._common.infer_action_type` guesses one from substrings in that name:
`http`/`openai`/`response` → `http`, `shell`/`terminal` → `shell`,
`read`/`file` → `file_read`, `write` → `file_write`. Everything else falls back
to **`custom`** — and most real tool names fall in that bucket
(`search_docs`, `lookup_customer`, `get_weather`, `query_database`,
`summarize`, `calculator`, …).

`custom` is a first-class action type, but no shipped example policy lists it.
So a workspace written only in terms of `file_read`/`shell`/`http` refuses your
first benign tool call with

```
action type Custom is outside baseline for agent <id>
tool <name> cannot run action type Custom
```

That is the policy working, not a bug — but it is the policy refusing a name it
was never told about. Two ways out, and they are not equivalent:

**Tell the adapter what the tool is** (preferred). Every adapter takes an
`action_types` map, so the guess never applies to a tool you have classified:

```python
handler = SentinelCallbackHandler(
    agent_id="builder-01",
    action_types={
        "search_docs": ActionType.FILE_READ,
        "query_database": ActionType.DB_QUERY,
        "send_invoice": ActionType.EMAIL,
    },
)
```

It also overrides a *confident but wrong* guess: `read_customer_emails`
contains "read", so the heuristic calls it a `file_read`.

**Or widen the policy** — add `custom` to the tool's `allowedActionTypes` and
the profile's `baselineActionTypes`. Simpler, but it hands that tool the least
specific type there is, and the policy stops being able to distinguish a
document search from a database write.

`guard_tool()` still accepts a one-off `action_type` when you are calling the
adapter directly rather than through a framework callback.
