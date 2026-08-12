"""Govern a LlamaIndex agent's tools with IAGA Sentinel.

    pip install llama-index-core iaga-sentinel
    IAGA_SENTINEL_HOST=127.0.0.1 IAGA_SENTINEL_OPEN_MODE=true ./target/release/iaga serve --seed-demo
    # register the agent (see README.md), then run your agent.

`IagaCallbackHandler` gates the FUNCTION_CALL event: register it on the
CallbackManager and every tool call is inspected through IAGA before it runs.
allow -> runs and is receipted; block/review -> raises PermissionError.
"""
from llama_index.core.callbacks import CallbackManager
from llama_index.core.settings import Settings
from llama_index.core.tools import FunctionTool

from iaga_sentinel.adapters import IagaCallbackHandler


def filesystem_read(path: str) -> str:
    """Read a UTF-8 text file."""
    with open(path, encoding="utf-8") as fh:
        return fh.read()


# The only IAGA-specific lines: register the handler on the callback manager.
handler = IagaCallbackHandler(
    agent_id="llamaindex-demo",
    base_url="http://localhost:4010",
    # fail_closed=True,  # deny if the sidecar is unreachable (default: fail-open)
)
Settings.callback_manager = CallbackManager([handler])

# Tools whose .metadata.name is an approved tool name (see README policy).
read_tool = FunctionTool.from_defaults(fn=filesystem_read, name="filesystem.read")

# ... build your agent with these tools as usual; every FUNCTION_CALL is governed.
# A dangerous tool call (e.g. one carrying "curl ... | sh") is blocked by the
# firewall before it runs.
