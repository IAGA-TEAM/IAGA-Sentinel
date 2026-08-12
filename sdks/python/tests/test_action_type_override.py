"""An operator must be able to tell an adapter what a tool actually does.

A framework hands the adapter a tool NAME, never an action type, so
`infer_action_type` guesses one from substrings. Measured over ordinary tool
names, 11 of 15 (`search_docs`, `lookup_customer`, `get_weather`,
`query_database`, `summarize`, `calculator`, …) fall through to `custom`, and
no shipped example policy lists `custom` — so the first benign tool call comes
back `action type Custom is outside baseline for agent <id>`.

The two ways out are not equal: widening the policy to allow `custom` gives
that tool the least specific type there is, while telling the adapter "this one
is a file_read" keeps the narrow type. Only the first was reachable —
`guard_tool()` takes an `action_type`, but `on_tool_start()` is what the
framework calls, and it had no way to be told.

No sidecar needed: these pin which action type the adapter DECIDES to send.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from iaga_sentinel import ActionType  # noqa: E402
from iaga_sentinel.adapters import _common  # noqa: E402
from iaga_sentinel.adapters._common import (  # noqa: E402
    AdapterConfig,
    infer_action_type,
    resolve_action_type,
)


def test_the_name_heuristic_still_decides_when_nothing_is_declared():
    config = AdapterConfig(agent_id="a")
    assert resolve_action_type(config, "read_repo_file") == ActionType.FILE_READ
    assert resolve_action_type(config, "search_docs") == ActionType.CUSTOM
    assert resolve_action_type(config, "search_docs") == infer_action_type("search_docs")


def test_a_declared_type_wins_over_the_guess():
    config = AdapterConfig(
        agent_id="a",
        action_types={"search_docs": ActionType.FILE_READ},
    )
    assert resolve_action_type(config, "search_docs") == ActionType.FILE_READ
    # Undeclared tools are untouched.
    assert resolve_action_type(config, "run_shell") == ActionType.SHELL
    assert resolve_action_type(config, "book_flight") == ActionType.CUSTOM


def test_a_declaration_can_also_narrow_a_confident_wrong_guess():
    """`read_customer_emails` looks like a file read to the heuristic."""
    assert infer_action_type("read_customer_emails") == ActionType.FILE_READ
    config = AdapterConfig(
        agent_id="a",
        action_types={"read_customer_emails": ActionType.EMAIL},
    )
    assert resolve_action_type(config, "read_customer_emails") == ActionType.EMAIL


def test_the_langchain_callback_honours_the_declaration(monkeypatch):
    """`on_tool_start` is the entry point LangChain calls, and the one that
    could not be told anything before."""
    from iaga_sentinel.adapters import langchain as lc

    sent = []
    monkeypatch.setattr(
        _common, "inspect_sync", lambda config, request: sent.append(request)
    )
    monkeypatch.setattr(
        lc, "inspect_sync", lambda config, request: sent.append(request)
    )

    handler = lc.SentinelCallbackHandler(
        agent_id="a",
        action_types={"search_docs": ActionType.FILE_READ},
    )
    handler.on_tool_start({"name": "search_docs"}, "how do receipts chain")

    assert len(sent) == 1, "the callback must still consult the sidecar"
    assert sent[0].action.type == ActionType.FILE_READ, (
        "on_tool_start ignored the declared type and fell back to the name "
        f"heuristic; sent {sent[0].action.type}"
    )
    assert sent[0].action.tool_name == "search_docs"
