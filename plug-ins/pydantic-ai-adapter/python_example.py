"""Govern a Pydantic AI agent's tools with IAGA Sentinel.

    pip install pydantic-ai iaga-sentinel
    IAGA_SENTINEL_HOST=127.0.0.1 IAGA_SENTINEL_OPEN_MODE=true ./target/release/iaga serve --seed-demo
    # register the agent (see README.md), then run your agent.

`governed_tool` wraps a tool so each call is inspected through IAGA before the
body runs. Stack it under `@agent.tool` / `@agent.tool_plain`; it preserves the
function signature so Pydantic AI still builds the tool schema.
allow -> runs; block/review -> PermissionError.
"""
from pydantic_ai import Agent, RunContext

from iaga_sentinel import ActionType
from iaga_sentinel.adapters.pydantic_ai import governed_tool

agent = Agent("openai:gpt-4o")  # your model


@agent.tool
@governed_tool(
    agent_id="pydantic-ai-demo",
    tool_name="filesystem.read",
    action_type=ActionType.FILE_READ,
    base_url="http://localhost:4010",
    # fail_closed=True,  # deny if the sidecar is unreachable (default: fail-open)
)
async def read_file(ctx: RunContext, path: str) -> str:
    """Read a UTF-8 text file."""
    with open(path, encoding="utf-8") as fh:
        return fh.read()


# Every call the model makes to read_file is inspected first. A dangerous tool
# call (e.g. one carrying "curl ... | sh") is blocked by the firewall.
