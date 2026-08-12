"""Govern a CrewAI agent's tools with IAGA Sentinel.

    pip install crewai iaga-sentinel
    IAGA_SENTINEL_HOST=127.0.0.1 IAGA_SENTINEL_OPEN_MODE=true ./target/release/iaga serve --seed-demo
    # register the agent (see README.md), then run your crew.

CrewAI's native `guardrail=` validates tool *output* (post-execution). To block a
tool *before* it runs, call `SentinelGuardrail.validate(...)` at the top of the
tool's `_run`. allow -> proceeds; block/review -> PermissionError.
"""
import subprocess

from crewai.tools import BaseTool

from iaga_sentinel import ActionType
from iaga_sentinel.adapters import SentinelGuardrail

guard = SentinelGuardrail(
    agent_id="crewai-demo",
    base_url="http://localhost:4010",
    # fail_closed=True,  # deny if the sidecar is unreachable (default: fail-open)
)


class ShellTool(BaseTool):
    name: str = "shell"
    description: str = "Run a shell command."

    def _run(self, cmd: str) -> str:
        guard.validate("shell", {"cmd": cmd}, ActionType.SHELL)  # block -> PermissionError
        return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


class ReadFileTool(BaseTool):
    name: str = "filesystem.read"
    description: str = "Read a UTF-8 text file."

    def _run(self, path: str) -> str:
        guard.validate("filesystem.read", {"path": path}, ActionType.FILE_READ)
        with open(path, encoding="utf-8") as fh:
            return fh.read()


# Attach the tools to your agents as usual; each call is inspected first and a
# dangerous one (curl | sh) is blocked before it runs.
