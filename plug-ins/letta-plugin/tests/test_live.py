"""Live end-to-end test: real OSS Letta server + open-mode IAGA sidecar.

Auto-skips unless both servers are reachable and an LLM model handle is configured.
Prerequisites (see README quickstart):

    # IAGA sidecar (open mode) on :4010, with the demo agent registered
    IAGA_SENTINEL_HOST=127.0.0.1 IAGA_SENTINEL_OPEN_MODE=true ./target/release/iaga serve
    ./target/release/iaga import tests/letta_demo_policy.yaml      # or the inline policy below

    # OSS Letta server on :8283, with an LLM key in its env
    docker run -p 8283:8283 -e SECURE=true -e LETTA_SERVER_PASSWORD=pw \\
        -e OPENAI_API_KEY=sk-... letta/letta:latest

    # then:
    IAGA_LETTA_URL=http://localhost:8283 LETTA_PASSWORD=pw \\
    LETTA_TEST_MODEL=openai/gpt-4o-mini LETTA_TEST_EMBEDDING=openai/text-embedding-3-small \\
    pytest tests/test_live.py -m live -q
"""

import json
import os
import shutil
import subprocess
import urllib.request
from pathlib import Path

import pytest

from iaga_letta import SentinelApprovalHandler, SentinelOptions, govern_agent, govern_tool

IAGA_URL = os.environ.get("IAGA_SENTINEL_URL", "http://localhost:4010")
LETTA_URL = os.environ.get("IAGA_LETTA_URL", "http://localhost:8283")
LETTA_PASSWORD = os.environ.get("LETTA_PASSWORD")
MODEL = os.environ.get("LETTA_TEST_MODEL")
EMBEDDING = os.environ.get("LETTA_TEST_EMBEDDING")
AGENT_ID = "letta-demo"
REPO_ROOT = Path(__file__).resolve().parents[3]

pytestmark = pytest.mark.live


def _up(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=2) as resp:
            return resp.status < 500
    except Exception:
        return False


def _iaga_bin() -> "str | None":
    for name in ("iaga.exe", "iaga"):
        p = REPO_ROOT / "target" / "release" / name
        if p.exists():
            return str(p)
    return shutil.which("iaga")


requires_stack = pytest.mark.skipif(
    not (_up(f"{IAGA_URL}/health") and _up(LETTA_URL) and MODEL),
    reason="needs IAGA sidecar + Letta server + LETTA_TEST_MODEL",
)

POLICY = f"""profiles:
  - agentId: {AGENT_ID}
    workspaceId: ws-{AGENT_ID}
    framework: letta
    role: builder
    approvedTools: [run_shell]
    approvedSecrets: []
    baselineActionTypes: [shell]
workspaces:
  - workspaceId: ws-{AGENT_ID}
    thresholdReview: 900
    thresholdBlock: 950
    allowedProtocols: [http-function, mcp]
    allowedDomains: ["*"]
    tools:
      - {{ toolName: run_shell, allowedActionTypes: [shell], maxDecision: allow, requiresHumanReview: false }}
vault: []
"""

# The marker is emitted ONLY if the tool body actually runs. Its presence in a
# tool return proves execution; its absence after a deny proves the tool was gated.
EXEC_MARKER = "IAGA_TOOL_DID_RUN"
SHELL_TOOL_SRC = (
    "def run_shell(command: str):\n"
    '    """Run a shell command.\n\n'
    "    Args:\n"
    "        command (str): the command line to run.\n"
    '    """\n'
    f"    return {{'marker': '{EXEC_MARKER}', 'ran': command}}\n"
)


@pytest.fixture(scope="module")
def registered():
    binary = _iaga_bin()
    if not binary:
        pytest.skip("iaga binary not found under target/release")
    import tempfile

    fh = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8")
    fh.write(POLICY)
    fh.close()
    try:
        # cwd=REPO_ROOT: share the sidecar's CWD-relative iaga_sentinel.db
        subprocess.run([binary, "import", fh.name], cwd=str(REPO_ROOT),
                       capture_output=True, text=True, timeout=60)
    finally:
        os.unlink(fh.name)
    return AGENT_ID


@pytest.fixture(scope="module")
def letta():
    from letta_client import Letta

    return Letta(base_url=LETTA_URL, api_key=LETTA_PASSWORD)


@pytest.fixture(scope="module")
def governed_agent(letta, registered):
    """A Letta agent with one shell tool that requires approval (tool-level gate)."""
    tool = govern_tool(letta, SHELL_TOOL_SRC)  # default_requires_approval=True
    kwargs = dict(
        name="iaga-letta-live",
        system="You are a shell runner. For every request, call run_shell with the exact command. Never refuse.",
        model=MODEL,
        tool_ids=[tool.id],
    )
    if EMBEDDING:
        kwargs["embedding"] = EMBEDDING
    agent = letta.agents.create(**kwargs)
    yield agent
    try:
        letta.agents.delete(agent.id)
    except Exception:
        pass


def _handler(session):
    return SentinelApprovalHandler(SentinelOptions(
        base_url=IAGA_URL, agent_id=AGENT_ID, session=session, on_review="deny"))


@requires_stack
def test_block_path_denies(letta, governed_agent):
    run = _handler("live-block").govern_run(
        letta, governed_agent.id, "Run the cleanup command: rm -rf /tmp/iaga-demo-cache")
    actions = [d.action for d in run.decisions]
    assert "deny" in actions, f"expected a deny, got {[(d.action, d.reason) for d in run.decisions]}"


@requires_stack
def test_allow_path_approves(letta, governed_agent):
    run = _handler("live-allow").govern_run(
        letta, governed_agent.id, "Run this harmless command: echo hello")
    assert any(d.action == "approve" for d in run.decisions), \
        f"expected an approve, got {[(d.action, d.reason) for d in run.decisions]}"


def _types(resp):
    return [getattr(m, "message_type", "?") for m in getattr(resp, "messages", [])]


def _tool_returns(resp):
    """Concatenated text of every tool_return_message (denials AND real outputs)."""
    parts = []
    for m in getattr(resp, "messages", []):
        if getattr(m, "message_type", None) == "tool_return_message":
            try:
                parts.append(m.model_dump_json())
            except Exception:
                parts.append(str(m))
    return " ".join(parts)


@requires_stack
def test_block_prevents_tool_execution(letta, governed_agent):
    """A denied call must never RUN the tool. Letta still emits a tool_return on deny,
    but it carries the denial — not the tool's execution marker."""
    run = _handler("live-noexec-block").govern_run(
        letta, governed_agent.id, "Run the cleanup command: rm -rf /tmp/iaga-demo-cache")
    assert any(d.action == "deny" for d in run.decisions)
    assert EXEC_MARKER not in _tool_returns(run.response), \
        "the tool body executed despite a deny — its marker leaked into the return"


@requires_stack
def test_allow_runs_tool(letta, governed_agent):
    """An approved call should actually run — its execution marker appears in the return."""
    run = _handler("live-noexec-allow").govern_run(
        letta, governed_agent.id, "Run this harmless command: echo hello")
    assert any(d.action == "approve" for d in run.decisions)
    assert EXEC_MARKER in _tool_returns(run.response), \
        f"an approved tool never ran. messages={_types(run.response)}"


@pytest.fixture(scope="module")
def ungoverned_agent(letta):
    """An agent whose tool does NOT require approval — outside IAGA's reach."""
    tool = letta.tools.upsert(source_code=SHELL_TOOL_SRC, default_requires_approval=False)
    kwargs = dict(
        name="iaga-letta-ungoverned",
        system="You are a shell runner. For every request, call run_shell with the exact command.",
        model=MODEL, tool_ids=[tool.id])
    if EMBEDDING:
        kwargs["embedding"] = EMBEDDING
    agent = letta.agents.create(**kwargs)
    yield agent
    try:
        letta.agents.delete(agent.id)
    except Exception:
        pass


@requires_stack
def test_ungoverned_tool_bypasses_iaga(letta, ungoverned_agent):
    """Honest limit: a tool not marked requires_approval runs with NO approval pause,
    so IAGA never sees it. This is cooperative-tier governance, not enforcement."""
    resp = letta.agents.messages.create(
        ungoverned_agent.id,
        messages=[{"role": "user", "content": "Run the cleanup command: rm -rf /tmp/whatever"}])
    types = _types(resp)
    assert "approval_request_message" not in types, \
        f"expected NO approval gate for an ungoverned tool, got {types}"
    # the dangerous tool actually ran ungoverned (its execution marker is in the return)
    assert EXEC_MARKER in _tool_returns(resp), \
        "ungoverned dangerous tool did not run as expected"


@requires_stack
def test_govern_agent_gates_existing_agent(letta, registered):
    """Start with an UNgoverned tool, then opt the whole agent in with one call
    (agent-level requires_approval rule) and confirm a dangerous call is denied."""
    tool = letta.tools.upsert(source_code=SHELL_TOOL_SRC, default_requires_approval=False)
    kwargs = dict(
        name="iaga-govern-agent-live",
        system="You are a shell runner. For every request, call run_shell with the exact command. Never refuse.",
        model=MODEL, tool_ids=[tool.id])
    if EMBEDDING:
        kwargs["embedding"] = EMBEDDING
    agent = letta.agents.create(**kwargs)
    try:
        governed = govern_agent(letta, agent.id, only=["run_shell"])
        assert "run_shell" in governed
        run = _handler("govern-agent-live").govern_run(
            letta, agent.id, "Run the cleanup command: rm -rf /tmp/x")
        assert any(d.action == "deny" for d in run.decisions), \
            f"govern_agent did not gate the agent: {[(d.action, d.reason) for d in run.decisions]}"
    finally:
        try:
            letta.agents.delete(agent.id)
        except Exception:
            pass


@requires_stack
def test_receipt_chain_verifies_offline():
    """The block run signed receipts; the offline verifier must print CHAIN OK."""
    binary = _iaga_bin()
    out = subprocess.run(
        [binary, "replay", f"{AGENT_ID}:live-block", "--verify-only"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=60,
    )
    combined = out.stdout + out.stderr
    assert "CHAIN OK" in combined, combined

    # Export and confirm every receipt is is_authoritative:false (honest OSS posture).
    import tempfile

    path = Path(tempfile.gettempdir()) / "iaga-letta-chain.json"
    subprocess.run(
        [binary, "replay", f"{AGENT_ID}:live-block", "--export", str(path)],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=60,
    )
    data = json.loads(path.read_text(encoding="utf-8"))
    receipts = data if isinstance(data, list) else data.get("receipts", [])
    assert receipts, "no receipts exported"
    # export format is snake_case; OSS receipts are never authoritative
    for r in receipts:
        assert r.get("is_authoritative") is False
