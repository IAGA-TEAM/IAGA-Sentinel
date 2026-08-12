"""`import iaga_sentinel` must not drag in the framework adapters.

D6. `decorator.py` imported `named_payload`/`_safe_value` from
`adapters._common`, and importing any submodule of a package executes that
package's `__init__.py` first — so the simplest entry point in the SDK
(`from iaga_sentinel import governed`) executed `adapters/__init__.py` and with
it nine framework adapters.

No cycle existed, which is why nothing caught it. The defect is directional: a
leaf module became dependent on the widest surface in the package, so one
adapter with a broken third-party import fails `import iaga_sentinel` itself,
for a caller who never asked for an adapter.

These tests run the import in a SUBPROCESS. Doing it in-process is worthless:
pytest has already imported half the package via the other test modules, so
`sys.modules` is polluted before the assertion runs and the test passes whatever
the import graph looks like.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

# The SDK root, so the child process can import `iaga_sentinel` wherever pytest
# was started from. Without this the subprocess inherits the caller's cwd and
# the import only resolves when pytest runs from `sdks/python`; CI runs
# `python -m pytest sdks/python/tests` from the REPO ROOT, where both tests died
# with CalledProcessError instead of reporting anything about the import graph.
SDK_ROOT = Path(__file__).resolve().parents[1]

# Every adapter listed in `iaga_sentinel/adapters/__init__.py`.
ADAPTER_MODULES = [
    "iaga_sentinel.adapters",
    "iaga_sentinel.adapters.autogen",
    "iaga_sentinel.adapters.crewai",
    "iaga_sentinel.adapters.langchain",
    "iaga_sentinel.adapters.langgraph",
    "iaga_sentinel.adapters.llamaindex",
    "iaga_sentinel.adapters.mcp",
    "iaga_sentinel.adapters.microsoft_agent_framework",
    "iaga_sentinel.adapters.openai",
    "iaga_sentinel.adapters.openai_agents",
]


def _modules_after(import_stmt: str) -> list[str]:
    """Names under `iaga_sentinel.` loaded by `import_stmt`, in a fresh process."""
    script = (
        "import json, sys\n"
        f"{import_stmt}\n"
        "print(json.dumps(sorted(m for m in sys.modules "
        "if m.startswith('iaga_sentinel'))))\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        check=True,
        cwd=SDK_ROOT,
    )
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_importing_the_package_does_not_load_any_adapter() -> None:
    loaded = _modules_after("import iaga_sentinel")
    leaked = sorted(set(loaded) & set(ADAPTER_MODULES))
    assert not leaked, (
        "`import iaga_sentinel` pulled in framework adapters: "
        f"{leaked}. Something on the `__init__` -> client/decorator/types path "
        "is importing from `adapters/`; the generic helpers live in "
        "`iaga_sentinel._payload` precisely so it does not have to."
    )


def test_importing_the_decorator_does_not_load_any_adapter() -> None:
    """The specific regression: `decorator` imported from `adapters._common`."""
    loaded = _modules_after("from iaga_sentinel.decorator import governed")
    leaked = sorted(set(loaded) & set(ADAPTER_MODULES))
    assert not leaked, f"`iaga_sentinel.decorator` pulled in {leaked}"


def test_adapters_still_re_export_the_helpers() -> None:
    """Moving the helpers must not break anything that imports them.

    `adapters/_common.py` re-exports both names; `langchain.py` imports
    `_safe_value` from there. If the re-export is dropped as an 'unused import',
    this fails.
    """
    from iaga_sentinel._payload import _safe_value, named_payload
    from iaga_sentinel.adapters import _common

    assert _common._safe_value is _safe_value
    assert _common.named_payload is named_payload


def test_the_decorator_and_the_adapters_build_the_same_payload() -> None:
    """Both entry points must agree — they feed the same signed receipt hash."""
    from iaga_sentinel._payload import named_payload
    from iaga_sentinel.decorator import _build_payload

    def tool(sql: str, limit: int) -> None: ...

    args, kwargs = ("select 1",), {"limit": 10}
    assert _build_payload(args, kwargs, tool) == named_payload(tool, args, kwargs)


def test_self_is_never_sent() -> None:
    """`self` reached `action.payload`, which is hashed into the receipt.

    An instance repr nobody chose to send — potentially carrying a credential
    held on the object — was being signed.
    """
    from iaga_sentinel.decorator import _build_payload

    class Client:
        def __repr__(self) -> str:  # pragma: no cover - only on failure
            return "Client(api_key='sk-live-must-never-be-signed')"

        def run(self, sql: str) -> None: ...

    payload = _build_payload((Client(), "select 1"), {}, Client.run)

    assert "self" not in payload
    assert "sk-live" not in json.dumps(payload)
