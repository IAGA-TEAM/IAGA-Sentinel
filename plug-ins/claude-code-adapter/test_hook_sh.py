"""Transport-error contract tests for the Bash PreToolUse hook.

    pytest plug-ins/claude-code-adapter/test_hook_sh.py -v

The sibling `test_hook.py` covers `iaga_claude_hook.py`; this file covers
`iaga-claude-hook.sh`, which shipped through 2.0.2 with no test at all. That gap
is what let the two diverge: the Python hook classified an HTTP error as
"unreachable" and applied the fail-open/fail-closed policy, and the shell hook
did not.

No live sidecar is needed. A stub server replies with the exact status/body
pairs the real one produces (`SentinelError` always serializes to JSON, see
crates/iaga-sentinel-core/src/core/errors.rs), because the whole defect lived in
how a JSON *error* body was told apart from a JSON *verdict*.

Skips on Windows-without-bash and wherever curl or jq is missing, since the hook
declares both as requirements.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

HOOK = Path(__file__).parent / "iaga-claude-hook.sh"

BASH = shutil.which("bash")
MISSING = [t for t in ("bash", "curl", "jq") if shutil.which(t) is None]
needs_shell = pytest.mark.skipif(
    bool(MISSING), reason=f"shell hook needs {', '.join(MISSING)} on PATH"
)

# (status, body) keyed by URL suffix. The error bodies are copied from the real
# `impl IntoResponse for SentinelError`; the point of the test is that they are
# valid JSON, which is exactly why `jq -e .` used to accept them as a verdict.
CASES = {
    "/404": (404, {"error": "agent_not_found", "message": "Agent not found: claude-code"}),
    "/403": (403, {"error": "scope_mismatch", "message": "workspace scope mismatch"}),
    "/500": (500, {"error": "storage_error", "message": "database is locked"}),
    "/allow": (200, {"decision": "allow", "risk": {"score": 2, "reasons": []}}),
    "/review": (
        200,
        {"decision": "review", "risk": {"score": 55, "reasons": ["unusual for baseline"]}},
    ),
    "/block": (
        200,
        {"decision": "block", "risk": {"score": 81, "reasons": ["rm -rf detected"]}},
    ),
    "/text": (200, None),  # non-JSON body
}


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        status, body = CASES[self.path.replace("/v1/inspect", "") or "/allow"]
        if body is None:
            raw, ctype = b"upstream is on fire", "text/plain"
        else:
            raw, ctype = json.dumps(body).encode(), "application/json"
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def stub():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    thread.join(timeout=5)


def run_hook(base_url: str, fail_closed: bool = False, timeout: str = "5"):
    """Always kills the child on timeout: an orphan here wedges the whole run."""
    env = dict(os.environ)
    env["IAGA_BASE_URL"] = base_url
    env["IAGA_TIMEOUT"] = timeout
    env.pop("IAGA_FAIL_CLOSED", None)
    if fail_closed:
        env["IAGA_FAIL_CLOSED"] = "1"
    proc = subprocess.Popen(
        [BASH, str(HOOK)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    event = json.dumps({"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}})
    try:
        out, err = proc.communicate(event, timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        pytest.fail(f"hook did not exit; stderr={err!r}")
    return proc.returncode, out, err


def decision_of(stdout: str) -> str | None:
    """`{}` means 'do not interfere', i.e. the action proceeds."""
    parsed = json.loads(stdout or "{}")
    if parsed == {}:
        return None
    return parsed["hookSpecificOutput"]["permissionDecision"]


@needs_shell
@pytest.mark.parametrize("case", ["/404", "/403", "/500"])
def test_http_error_is_denied_when_fail_closed(stub, case):
    """The regression. Each of these bodies is valid JSON with no `.decision`.

    Before the fix `jq -e .` accepted them, the fail-closed branch was skipped
    entirely and `.decision // "allow"` produced "allow" -- so a governance
    database outage let every tool call through with fail-closed switched ON.
    """
    rc, out, err = run_hook(stub + case, fail_closed=True)
    assert rc == 0, "the hook must never crash Claude Code"
    assert decision_of(out) == "deny"
    assert "[iaga-claude-hook]" in err, "an outage must not be silent"


@needs_shell
@pytest.mark.parametrize("case", ["/404", "/403", "/500"])
def test_http_error_is_reported_when_fail_open(stub, case):
    """Fail-open still lets the action through -- but says so on stderr."""
    rc, out, err = run_hook(stub + case, fail_closed=False)
    assert rc == 0
    assert decision_of(out) is None
    assert "failing open" in err


@needs_shell
def test_404_names_the_unregistered_agent(stub):
    """The first-run misconfiguration deserves the actionable message."""
    _, _, err = run_hook(stub + "/404", fail_closed=True)
    assert "not registered" in err and "claude-code" in err


@needs_shell
def test_non_json_body_is_treated_as_unreachable(stub):
    rc, out, err = run_hook(stub + "/text", fail_closed=True)
    assert rc == 0
    assert decision_of(out) == "deny"
    assert "non-JSON" in err


@needs_shell
@pytest.mark.parametrize(
    ("case", "expected"),
    [("/allow", None), ("/review", "ask"), ("/block", "deny")],
)
@pytest.mark.parametrize("fail_closed", [False, True])
def test_real_verdicts_are_unchanged(stub, case, expected, fail_closed):
    """Non-regression: a 2xx verdict is still honoured verbatim, and
    IAGA_FAIL_CLOSED must not colour a decision the sidecar actually made."""
    rc, out, _ = run_hook(stub + case, fail_closed=fail_closed)
    assert rc == 0
    assert decision_of(out) == expected


@needs_shell
@pytest.mark.parametrize(
    ("fail_closed", "expected"), [(False, None), (True, "deny")]
)
def test_dead_port_keeps_working(fail_closed, expected):
    """The one path that already worked, pinned so the fix cannot regress it."""
    rc, out, _ = run_hook("http://127.0.0.1:4999", fail_closed=fail_closed, timeout="1")
    assert rc == 0
    assert decision_of(out) == expected


@needs_shell
def test_base_url_trailing_slash_is_tolerated(stub):
    """Mirrors the Python hook's rstrip("/"); a doubled slash 404s on a real
    sidecar, which -- before the fix -- was itself silently an allow."""
    rc, out, _ = run_hook(stub + "/allow" + "/", fail_closed=True)
    assert rc == 0
    assert decision_of(out) is None
