"""The `tests/e2e/` package must always COLLECT, whatever is installed.

Every module under `tests/e2e/` guards its framework import with
`pytest.importorskip(...)` so the suite runs on a machine that has none of the
frameworks. The guard only works if it names the module the file actually
imports: `importorskip("mcp")` followed by `from mcp.server.fastmcp import
FastMCP` passes the guard on any `mcp` release that no longer ships
`fastmcp`, and the resulting ImportError is a *collection* error, not a skip.

Collection errors are not local. pytest aborts the whole session with
`Interrupted: 1 error during collection`, so one restructured upstream package
takes the entire SDK suite down — measured against `mcp` 2.0.0, which moved
`mcp.server.fastmcp`: `6 skipped, 1 error`, and none of the real tests ran.

This asserts the property directly rather than second-guessing which dotted
name each file should have guarded.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

E2E_DIR = Path(__file__).resolve().parent / "e2e"


def test_e2e_package_collects_cleanly() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", str(E2E_DIR)],
        capture_output=True,
        text=True,
        cwd=E2E_DIR.parents[1],
        timeout=300,
    )
    # 0 = collected something, 5 = EXIT_NOTESTSCOLLECTED. Both mean "no
    # collection ERROR", which is the property under test. CI installs none of
    # the frameworks (`pip install pytest httpx requests` in ci.yml), so every
    # module skips and pytest returns 5 there — asserting 0 would have made this
    # guard fail in exactly the environment it exists to protect, while passing
    # on a developer box that happens to have langchain installed.
    assert proc.returncode in (0, 5), (
        "collecting tests/e2e failed, which aborts the whole SDK suite:\n"
        f"{proc.stdout[-4000:]}\n{proc.stderr[-2000:]}"
    )
