"""Govern an OpenAI Agents SDK agent with IAGA Sentinel.

    pip install openai-agents iaga-sentinel
    IAGA_SENTINEL_HOST=127.0.0.1 IAGA_SENTINEL_OPEN_MODE=true ./target/release/iaga serve --seed-demo
    # register the agent (see README.md), then run your agent.

Two hooks (use either or both):
  * governed_tool wraps a plain function before @function_tool (block -> PermissionError)
  * iaga_tool_guardrail is a real tool-input guardrail: attach it to a function
    tool; block/review -> reject_content (the tool does not run, the model is told why).
"""
from agents import Agent, function_tool

from iaga_sentinel import ActionType
from iaga_sentinel.adapters.openai_agents import governed_tool, iaga_tool_guardrail

BASE_URL = "http://localhost:4010"
AGENT_ID = "openai-agents-demo"


# Option A: a function tool guarded by an IAGA tool-input guardrail.
@function_tool(tool_input_guardrails=[iaga_tool_guardrail(agent_id=AGENT_ID, base_url=BASE_URL)])
def filesystem_read(path: str) -> str:
    """Read a file."""
    with open(path, encoding="utf-8") as fh:
        return fh.read()


# Option B: wrap a plain function (raises PermissionError on block).
@function_tool
@governed_tool(
    agent_id=AGENT_ID,
    tool_name="shell",
    action_type=ActionType.SHELL,
    base_url=BASE_URL,
)
def run_shell(cmd: str) -> str:
    """Run a shell command."""
    import subprocess

    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


agent = Agent(name="ops", tools=[filesystem_read, run_shell])
# Every tool call is inspected first; a dangerous one (curl | sh) is blocked.
