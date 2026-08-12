"""Govern Claude Agent SDK (Python) tool calls via a PreToolUse hook + IAGA.

    pip install claude-agent-sdk iaga-sentinel
    IAGA_SENTINEL_HOST=127.0.0.1 IAGA_SENTINEL_OPEN_MODE=true ./target/release/iaga serve --seed-demo
    # register the agent first (see README.md), then:
    python plug-ins/claude-agent-sdk-adapter/hooks_example.py

The PreToolUse hook inspects each tool call through IAGA Sentinel; block/review
become a "deny" permission decision. allow lets Claude Code's normal flow run.
"""
import asyncio
import os

from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient, HookMatcher

from iaga_sentinel import ActionDetail, ActionType, AsyncSentinelClient, InspectRequest

BASE_URL = os.environ.get("IAGA_BASE_URL", "http://localhost:4010")
AGENT_ID = os.environ.get("IAGA_AGENT_ID", "claude-agent-sdk")

ACTION_TYPES = {
    "Bash": ActionType.SHELL,
    "Read": ActionType.FILE_READ,
    "Glob": ActionType.FILE_READ,
    "Grep": ActionType.FILE_READ,
    "Write": ActionType.FILE_WRITE,
    "Edit": ActionType.FILE_WRITE,
    "MultiEdit": ActionType.FILE_WRITE,
    "WebFetch": ActionType.HTTP,
}


async def iaga_pre_tool_use(input_data, tool_use_id, context):
    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})
    if not isinstance(tool_input, dict):
        tool_input = {"value": tool_input}

    request = InspectRequest(
        agent_id=AGENT_ID,
        framework="claude-agent-sdk",
        action=ActionDetail(
            type=ACTION_TYPES.get(tool_name, ActionType.CUSTOM),
            tool_name=tool_name,
            payload=tool_input,
        ),
    )
    try:
        async with AsyncSentinelClient(base_url=BASE_URL) as client:
            result = await client.inspect(request)
    except Exception:
        return {}  # fail-open: let the normal permission flow continue

    if result.blocked or result.needs_review:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "; ".join(result.risk.reasons)
                or "blocked by IAGA Sentinel",
            }
        }
    return {}


async def main():
    options = ClaudeAgentOptions(
        hooks={
            "PreToolUse": [
                HookMatcher(
                    matcher="Bash|Edit|Write|MultiEdit|WebFetch",
                    hooks=[iaga_pre_tool_use],
                )
            ]
        }
    )
    async with ClaudeSDKClient(options=options) as client:
        await client.query("Read README.md and summarize it.")
        async for message in client.receive_response():
            print(message)


if __name__ == "__main__":
    asyncio.run(main())
