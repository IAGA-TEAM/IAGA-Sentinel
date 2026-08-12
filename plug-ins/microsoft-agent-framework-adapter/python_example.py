"""Govern a Microsoft Agent Framework agent's tools with IAGA Sentinel.

    pip install agent-framework iaga-sentinel
    IAGA_SENTINEL_HOST=127.0.0.1 IAGA_SENTINEL_OPEN_MODE=true ./target/release/iaga serve --seed-demo
    # register the agent (see README.md), then run your agent.

`sentinel_middleware` is a function-invocation middleware `async (context,
call_next)`: each tool/function call is inspected through IAGA first. allow ->
awaits call_next(); block/review -> raises PermissionError (call_next is never
called, so the tool does not run). The same shape also works as a Semantic
Kernel function-invocation filter.
"""
from iaga_sentinel.adapters import sentinel_middleware

middleware = sentinel_middleware(
    agent_id="ms-agent-demo",
    base_url="http://localhost:4010",
    # fail_closed=True,  # deny if the sidecar is unreachable (default: fail-open)
)

# Attach the middleware where your build exposes it, e.g.:
#
#   from agent_framework import ChatAgent
#   agent = ChatAgent(name="ops", chat_client=..., tools=[...], middleware=[middleware])
#
# or per run:
#
#   result = await agent.run("...", middleware=[middleware])
#
# Every function/tool invocation is inspected first; a dangerous one (curl | sh)
# is blocked before it runs.
