"""Govern an AutoGen / AG2 agent's tools with IAGA Sentinel.

    pip install autogen-agentchat iaga-sentinel
    IAGA_SENTINEL_HOST=127.0.0.1 IAGA_SENTINEL_OPEN_MODE=true ./target/release/iaga serve --seed-demo
    # register the agent (see README.md), then run your agent.

AutoGen's hooks operate on messages, not tool execution, so to gate a tool
*before* it runs, call `AutoGenSentinelHook.pre_tool_call(...)` at the top of the
registered function. allow -> proceeds; block/review -> PermissionError.
"""
import subprocess

from iaga_sentinel import ActionType
from iaga_sentinel.adapters import AutoGenSentinelHook

hook = AutoGenSentinelHook(
    agent_id="autogen-demo",
    base_url="http://localhost:4010",
    # fail_closed=True,  # deny if the sidecar is unreachable (default: fail-open)
)


def run_shell(cmd: str) -> str:
    """Run a shell command (governed)."""
    hook.pre_tool_call("shell", {"cmd": cmd}, ActionType.SHELL)  # block -> PermissionError
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


def read_file(path: str) -> str:
    """Read a file (governed)."""
    hook.pre_tool_call("filesystem.read", {"path": path}, ActionType.FILE_READ)
    with open(path, encoding="utf-8") as fh:
        return fh.read()


# Register run_shell / read_file with your AutoGen agent's function map as usual;
# each call is inspected first and a dangerous one (curl | sh) is blocked.
