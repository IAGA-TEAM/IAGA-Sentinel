"""Shared fixtures for the IAGA Sentinel Python SDK integration tests.

Drive the real governance sidecar. Start it first:

    IAGA_SENTINEL_HOST=127.0.0.1 IAGA_SENTINEL_OPEN_MODE=true ./target/release/iaga serve --seed-demo

The engine keeps per-agent behavioral state: an agent that issues many calls
(or any blocked call) accumulates risk and is eventually escalated to
review/block. To keep the allow-path tests deterministic, each test gets its
OWN freshly registered agent from a per-session pool, so no agent ever makes
more than a couple of calls. The pool ids carry a per-run nonce, so re-runs
never reuse a "burned" agent. Tests skip automatically when the sidecar is
unreachable; the fail-open/fail-closed tests don't use these fixtures.
"""
from __future__ import annotations

import itertools
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import uuid
from pathlib import Path

import pytest

# Make the SDK importable without an install step.
SDK_ROOT = Path(__file__).resolve().parents[1]
if str(SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(SDK_ROOT))

REPO_ROOT = Path(__file__).resolve().parents[3]
BASE_URL = os.environ.get("IAGA_BASE_URL", "http://localhost:4010")
NONCE = uuid.uuid4().hex[:8]
POOL_SIZE = 32
AGENT_IDS = [f"sdk-test-{NONCE}-{i:02d}" for i in range(POOL_SIZE)]
WORKSPACE_IDS = [f"ws-sdk-{NONCE}-{i:02d}" for i in range(POOL_SIZE)]
_dispenser = itertools.count()
_REGISTERED = False


def _server_up() -> bool:
    try:
        with urllib.request.urlopen(f"{BASE_URL}/health", timeout=2) as resp:
            return resp.status < 500
    except Exception:
        return False


def _find_iaga_bin() -> "str | None":
    candidate = os.environ.get("IAGA_BIN")
    if candidate and Path(candidate).exists():
        return candidate
    for name in ("iaga.exe", "iaga"):
        path = REPO_ROOT / "target" / "release" / name
        if path.exists():
            return str(path)
    return shutil.which("iaga")


def _pool_policy_yaml() -> str:
    profiles = "\n".join(
        f"  - agentId: {aid}\n"
        f"    workspaceId: {wid}\n"
        f"    framework: sdk-adapter\n"
        f"    role: builder\n"
        f"    approvedTools: [filesystem.read, shell, "
        f"openai.chat.completions.create, openai.responses.create, "
        f"Bash, Read, Glob, Grep, Write, Edit, MultiEdit, WebFetch]\n"
        f"    approvedSecrets: []\n"
        f"    baselineActionTypes: [file_read, shell, http]"
        for aid, wid in zip(AGENT_IDS, WORKSPACE_IDS)
    )
    # Each test gets its own agent AND its own workspace: per-workspace
    # behavioral state accumulates over a busy run and would otherwise escalate
    # benign calls, so a 1:1 fresh workspace keeps the allow path deterministic.
    # The injection firewall still hard-blocks dangerous payloads (curl | sh).
    workspaces = "\n".join(
        f"  - workspaceId: {wid}\n"
        f"    thresholdReview: 900\n"
        f"    thresholdBlock: 950\n"
        f"    allowedProtocols: [http-function, mcp]\n"
        f'    allowedDomains: ["*"]\n'
        f"    tools:\n"
        f"      - {{ toolName: filesystem.read, allowedActionTypes: [file_read], maxDecision: allow, requiresHumanReview: false }}\n"
        f"      - {{ toolName: shell, allowedActionTypes: [shell], maxDecision: allow, requiresHumanReview: false }}\n"
        f"      - {{ toolName: openai.chat.completions.create, allowedActionTypes: [http], maxDecision: allow, requiresHumanReview: false }}\n"
        f"      - {{ toolName: openai.responses.create, allowedActionTypes: [http], maxDecision: allow, requiresHumanReview: false }}\n"
        f"      - {{ toolName: Bash, allowedActionTypes: [shell], maxDecision: allow, requiresHumanReview: false }}\n"
        f"      - {{ toolName: Read, allowedActionTypes: [file_read], maxDecision: allow, requiresHumanReview: false }}\n"
        f"      - {{ toolName: Glob, allowedActionTypes: [file_read], maxDecision: allow, requiresHumanReview: false }}\n"
        f"      - {{ toolName: Grep, allowedActionTypes: [file_read], maxDecision: allow, requiresHumanReview: false }}\n"
        f"      - {{ toolName: Write, allowedActionTypes: [file_write], maxDecision: allow, requiresHumanReview: false }}\n"
        f"      - {{ toolName: Edit, allowedActionTypes: [file_write], maxDecision: allow, requiresHumanReview: false }}\n"
        f"      - {{ toolName: MultiEdit, allowedActionTypes: [file_write], maxDecision: allow, requiresHumanReview: false }}\n"
        f"      - {{ toolName: WebFetch, allowedActionTypes: [http], maxDecision: allow, requiresHumanReview: false }}"
        for wid in WORKSPACE_IDS
    )
    return f"profiles:\n{profiles}\n\nworkspaces:\n{workspaces}\n\nvault: []\n"


def _register_pool() -> None:
    global _REGISTERED
    if _REGISTERED:
        return
    binary = _find_iaga_bin()
    if not binary:
        return
    fh = tempfile.NamedTemporaryFile(
        "w", suffix=".yaml", delete=False, encoding="utf-8"
    )
    try:
        fh.write(_pool_policy_yaml())
        fh.close()
        subprocess.run(
            [binary, "import", fh.name],
            capture_output=True,
            text=True,
            timeout=60,
        )
        _REGISTERED = True
    finally:
        try:
            os.unlink(fh.name)
        except OSError:
            pass


SERVER_UP = _server_up()


@pytest.fixture(scope="session")
def base_url() -> str:
    return BASE_URL


@pytest.fixture()
def fresh_agent() -> str:
    """A freshly registered agent id, unique per test (low behavioral risk)."""
    if not SERVER_UP:
        pytest.skip(f"IAGA sidecar not reachable at {BASE_URL}")
    _register_pool()
    idx = next(_dispenser)
    if idx >= POOL_SIZE:
        pytest.skip("agent pool exhausted; raise POOL_SIZE in conftest.py")
    return AGENT_IDS[idx]
