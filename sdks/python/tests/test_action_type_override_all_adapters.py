"""Every adapter that ACCEPTS `action_types` must actually honour it.

The first version of this fix threaded `action_types` into `AdapterConfig` for
all ten adapters and then routed only the ones that called `infer_action_type`
through the resolver. Three did not call it — `crewai` and `autogen` defaulted
their public methods to a hardcoded `ActionType.CUSTOM`, `openai` hardcoded
`ActionType.HTTP` — so those constructors accepted the parameter and silently
ignored it. Every test passed, because the one test covered `langchain`.

A parameter that is accepted and ignored is worse than one that does not exist:
the operator declares the narrow type, sees no error, and is still refused with
`action type Custom is outside baseline`.

So this is table-driven over the adapters rather than over one of them. Adding
an adapter without adding a row here fails `test_every_adapter_is_covered`.

No sidecar: each case captures the request the adapter WOULD send.
"""
from __future__ import annotations

import inspect
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from iaga_sentinel import ActionType  # noqa: E402
from iaga_sentinel.adapters import _common  # noqa: E402

DECLARED = ActionType.DB_QUERY  # deliberately not what any heuristic would pick


def _drive_langchain(sent, action_types):
    from iaga_sentinel.adapters import langchain as m
    h = m.SentinelCallbackHandler(agent_id="a", action_types=action_types)
    h.on_tool_start({"name": "target_tool"}, "input")


def _drive_crewai(sent, action_types):
    from iaga_sentinel.adapters import crewai as m
    m.SentinelGuardrail(agent_id="a", action_types=action_types).validate("target_tool", {"x": 1})


def _drive_crewai_call(sent, action_types):
    from iaga_sentinel.adapters import crewai as m
    m.SentinelGuardrail(agent_id="a", action_types=action_types)("target_tool", {"x": 1})


def _drive_autogen(sent, action_types):
    from iaga_sentinel.adapters import autogen as m
    m.AutoGenSentinelHook(agent_id="a", action_types=action_types).pre_tool_call("target_tool", {"x": 1})


def _drive_llamaindex(sent, action_types):
    from iaga_sentinel.adapters import llamaindex as m

    event = type("E", (), {"value": "function_call", "name": "function_call"})()
    tool = type("T", (), {"name": "target_tool"})()
    m.IagaCallbackHandler(agent_id="a", action_types=action_types).on_event_start(
        event, payload={"tool": tool, "function_call": {"x": 1}}, event_id="e1"
    )


def _drive_openai(sent, action_types):
    from iaga_sentinel.adapters import openai as m

    class _Fake:
        class responses:
            @staticmethod
            def create(*a, **k):
                return "ok"

        class chat:
            class completions:
                @staticmethod
                def create(*a, **k):
                    return "ok"

    m.sentinel_wrap_openai(_Fake(), agent_id="a", action_types=action_types).responses.create(model="m")


# (id, driver, the tool name the driver emits)
ADAPTERS = [
    ("langchain", _drive_langchain, "target_tool"),
    ("crewai.validate", _drive_crewai, "target_tool"),
    ("crewai.__call__", _drive_crewai_call, "target_tool"),
    ("autogen", _drive_autogen, "target_tool"),
    ("llamaindex", _drive_llamaindex, "target_tool"),
    ("openai", _drive_openai, "openai.responses.create"),
]


@pytest.fixture()
def sent(monkeypatch):
    """Capture the request each adapter would send, without a sidecar."""
    captured = []

    def _capture(config, request):
        captured.append(request)
        return None

    async def _capture_async(config, request):
        captured.append(request)
        return None

    import iaga_sentinel.adapters as pkg

    monkeypatch.setattr(_common, "inspect_sync", _capture)
    monkeypatch.setattr(_common, "inspect_async", _capture_async)
    for name in dir(pkg):
        mod = getattr(pkg, name, None)
        if getattr(mod, "__name__", "").startswith("iaga_sentinel.adapters"):
            for fn, repl in (("inspect_sync", _capture), ("inspect_async", _capture_async)):
                if hasattr(mod, fn):
                    monkeypatch.setattr(mod, fn, repl)
    # run_guarded_* build the request themselves, so patch the layer under them
    monkeypatch.setattr(_common, "inspect_sync", _capture)
    return captured


@pytest.mark.parametrize("name,drive,tool", ADAPTERS, ids=[a[0] for a in ADAPTERS])
def test_a_declared_action_type_reaches_the_request(name, drive, tool, sent, monkeypatch):
    import iaga_sentinel.adapters._common as c

    captured = []
    monkeypatch.setattr(c, "inspect_sync", lambda config, request: captured.append(request))
    for modname in ("langchain", "crewai", "autogen", "llamaindex", "openai",
                    "langgraph", "microsoft_agent_framework", "openai_agents",
                    "mcp", "pydantic_ai"):
        mod = __import__(f"iaga_sentinel.adapters.{modname}", fromlist=["x"])
        if hasattr(mod, "inspect_sync"):
            monkeypatch.setattr(mod, "inspect_sync", lambda config, request: captured.append(request))
        if hasattr(mod, "run_guarded_sync"):
            monkeypatch.setattr(
                mod, "run_guarded_sync",
                lambda config, *, tool_name, action_type, payload, metadata=None, call: (
                    captured.append(c.build_request(
                        config, tool_name=tool_name, action_type=action_type, payload=payload))
                    or call()),
            )

    drive(captured, {tool: DECLARED})

    assert captured, f"{name}: the adapter never consulted the sidecar at all"
    got = captured[-1].action.type
    assert got == DECLARED, (
        f"{name}: declared {DECLARED} for {tool!r} and the adapter sent {got}. "
        "The constructor accepts action_types and ignores it, which is worse "
        "than not accepting it: the operator sees no error and is still refused."
    )


def test_every_adapter_that_accepts_action_types_is_covered():
    """A new adapter must not be able to ship with an inert parameter."""
    import iaga_sentinel.adapters as pkg

    accepting = set()
    root = Path(pkg.__file__).parent
    for path in sorted(root.glob("*.py")):
        if path.name.startswith("_"):
            continue
        text = path.read_text(encoding="utf-8")
        if "action_types=action_types" in text:
            accepting.add(path.stem)

    covered = {n.split(".")[0] for n, _, _ in ADAPTERS}
    # Exempt because they reach the resolver by a route the drivers above do
    # not exercise: `mcp` and `pydantic_ai` hand `action_type=None` to
    # `governed_callable`, which resolves; `langgraph`,
    # `microsoft_agent_framework` and `openai_agents` call
    # `resolve_action_type` directly at their single request site. Both shapes
    # are verified by grep in `test_every_adapter_routes_through_the_resolver`.
    delegating = {"mcp", "pydantic_ai", "langgraph", "microsoft_agent_framework", "openai_agents"}
    missing = accepting - covered - delegating
    assert not missing, (
        f"these adapters accept action_types with no test that it is honoured: {sorted(missing)}"
    )


def test_every_adapter_routes_through_the_resolver():
    """Structural companion to the behavioural cases above.

    The drivers can only exercise entry points a framework-free test can call.
    This one asks the weaker but exhaustive question — does each adapter that
    accepts `action_types` reach `resolve_action_type` at all — so an adapter
    whose entry point is awkward to drive cannot quietly keep an inert
    parameter.
    """
    import iaga_sentinel.adapters as pkg

    root = Path(pkg.__file__).parent
    offenders = []
    for path in sorted(root.glob("*.py")):
        if path.name.startswith("_"):
            continue
        text = path.read_text(encoding="utf-8")
        if "action_types=action_types" not in text:
            continue
        reaches_resolver = "resolve_action_type" in text
        # `governed_callable` resolves for its caller when handed None.
        delegates = (
            "governed_callable" in text
            and "action_type: Optional[ActionType] = None" in text
        )
        if not (reaches_resolver or delegates):
            offenders.append(path.name)

    assert not offenders, (
        "these adapters accept `action_types` and can never consult it: "
        f"{offenders}. A parameter that is accepted and ignored is worse than "
        "one that does not exist."
    )


def test_the_resolver_default_does_not_swallow_a_declaration():
    cfg = _common.AdapterConfig(agent_id="a", action_types={"t": ActionType.EMAIL})
    assert _common.resolve_action_type(cfg, "t", default=ActionType.HTTP) == ActionType.EMAIL
    assert _common.resolve_action_type(cfg, "other", default=ActionType.HTTP) == ActionType.HTTP
    # With no default the name heuristic still decides.
    assert _common.resolve_action_type(cfg, "run_shell") == ActionType.SHELL


def test_public_signatures_still_accept_an_explicit_action_type():
    """Changing the default to None must not break a caller passing one."""
    from iaga_sentinel.adapters import autogen, crewai

    for fn in (crewai.SentinelGuardrail.validate, autogen.AutoGenSentinelHook.pre_tool_call):
        params = inspect.signature(fn).parameters
        assert "action_type" in params, fn
        assert params["action_type"].default is None, (
            f"{fn.__qualname__} must default to None so the declaration is consulted"
        )
