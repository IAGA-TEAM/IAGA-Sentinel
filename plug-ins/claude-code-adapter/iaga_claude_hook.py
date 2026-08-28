#!/usr/bin/env python3
"""IAGA Sentinel - Claude Code ``PreToolUse`` hook.

Reads a Claude Code ``PreToolUse`` event on stdin, asks the IAGA Sentinel
sidecar to govern the action (``POST /v1/inspect``), and emits a permission
decision on stdout. One signed, offline-verifiable receipt per tool call.

Cross-platform, zero third-party dependencies (Python standard library only).

Configuration (environment variables):
  IAGA_BASE_URL    sidecar base URL          (default: http://localhost:4010)
  IAGA_AGENT_ID    agentId on the receipt    (default: claude-code)
  IAGA_FRAMEWORK   framework label           (default: claude-code)
  IAGA_API_KEY     bearer token, if required (default: none)
  IAGA_TIMEOUT     request timeout, seconds  (default: 5)
  IAGA_FAIL_CLOSED if truthy, deny when the sidecar is unreachable
                   (default: fail-open - the action proceeds, no receipt)

Enforcement:
  block  -> permissionDecision "deny" (Claude Code refuses the tool call)
  review -> permissionDecision "ask"  (Claude Code prompts the user)
  allow  -> no decision; Claude Code's normal permission flow continues.
The inspect call always runs, so allow actions still produce a receipt and the
hook never silently widens the user's own permission choices.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

DEFAULT_BASE_URL = "http://localhost:4010"

# Claude Code tool name -> IAGA action.type. The firewall scans the whole
# payload regardless, so the type only modulates the risk score, but policies
# can gate on it - so map it as precisely as possible. Unknown names fall back
# to a name-based heuristic (mirrors the SDK's infer_action_type), then "custom".
TOOL_ACTION_TYPES = {
    "Bash": "shell",
    "Read": "file_read",
    "Glob": "file_read",
    "Grep": "file_read",
    "Write": "file_write",
    "Edit": "file_write",
    "MultiEdit": "file_write",
    "NotebookEdit": "file_write",
    "WebFetch": "http",
    "WebSearch": "http",
}


def action_type_for(tool_name: str) -> str:
    if tool_name in TOOL_ACTION_TYPES:
        return TOOL_ACTION_TYPES[tool_name]
    name = tool_name.lower()
    if any(k in name for k in ("shell", "bash", "terminal", "exec", "command")):
        return "shell"
    if any(k in name for k in ("http", "fetch", "web", "url", "request")):
        return "http"
    if any(k in name for k in ("write", "edit", "create", "delete")):
        return "file_write"
    if any(k in name for k in ("read", "file", "glob", "grep", "cat", "list")):
        return "file_read"
    return "custom"


def _truthy(value: "str | None") -> bool:
    return bool(value) and value.strip().lower() in {"1", "true", "yes", "on"}


def _log(message: str) -> None:
    # Diagnostics go to stderr so stdout stays a clean JSON decision.
    print(f"[iaga-claude-hook] {message}", file=sys.stderr)


def _emit(decision: "str | None", reason: str = "") -> None:
    """Write a PreToolUse hook result and exit 0.

    ``decision is None`` emits an empty object: do not interfere, let Claude
    Code's normal permission flow run (used for allow and fail-open).
    """
    if decision is None:
        print(json.dumps({}))
    else:
        print(
            json.dumps(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": decision,
                        "permissionDecisionReason": reason,
                    }
                }
            )
        )
    sys.exit(0)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow a redirect to the sidecar.

    ``urlopen`` uses the default opener, which follows 301/302/303 (re-issuing a
    POST as a GET) and 307/308. Measured on the TypeScript SDK, that was a
    complete governance bypass: a 307 from the configured URL to an
    attacker-controlled server made the client return that server's
    ``decision: "allow"`` with no evidence anywhere. Returning ``None`` is
    urllib's documented "do not follow" signal, so the original 3xx surfaces as
    an ``HTTPError`` and lands in the fail-open/fail-closed policy below.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)

_REDIRECT_CODES = (301, 302, 303, 307, 308)


def _unreachable(fail_closed: bool, detail: str) -> None:
    """Apply the transport-error policy: fail-open (default) or fail-closed."""
    if fail_closed:
        _log(f"{detail}; failing closed -> deny")
        _emit("deny", f"IAGA Sentinel unavailable: {detail}")
    _log(f"{detail}; failing open -> allow")
    _emit(None)


def main() -> None:
    fail_closed = _truthy(os.environ.get("IAGA_FAIL_CLOSED"))

    raw = sys.stdin.read()
    try:
        event = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError as exc:
        _log(f"could not parse stdin as JSON ({exc}); failing open")
        _emit(None)

    tool_name = event.get("tool_name", "")
    tool_input = event.get("tool_input", {})
    if not isinstance(tool_input, dict):
        tool_input = {"value": tool_input}

    request = {
        "agentId": os.environ.get("IAGA_AGENT_ID", "claude-code"),
        "framework": os.environ.get("IAGA_FRAMEWORK", "claude-code"),
        "action": {
            "type": action_type_for(tool_name),
            "toolName": tool_name or "unknown",
            "payload": tool_input,
        },
    }
    session_id = event.get("session_id")
    if session_id:
        request["metadata"] = {"sessionId": session_id}

    base_url = os.environ.get("IAGA_BASE_URL", DEFAULT_BASE_URL).rstrip("/")
    try:
        timeout = float(os.environ.get("IAGA_TIMEOUT", "5"))
    except ValueError:
        timeout = 5.0

    headers = {"Content-Type": "application/json"}
    api_key = os.environ.get("IAGA_API_KEY")
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    http_request = urllib.request.Request(
        f"{base_url}/v1/inspect",
        data=json.dumps(request).encode("utf-8"),
        headers=headers,
        method="POST",
    )

    try:
        with _OPENER.open(http_request, timeout=timeout) as response:
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            _unreachable(
                fail_closed,
                f"agent '{request['agentId']}' not registered at IAGA (404)",
            )
        if exc.code in _REDIRECT_CODES:
            _unreachable(
                fail_closed,
                f"IAGA redirected (HTTP {exc.code}); refusing to follow",
            )
        _unreachable(fail_closed, f"IAGA returned HTTP {exc.code}")
    except (urllib.error.URLError, OSError, json.JSONDecodeError, ValueError) as exc:
        _unreachable(fail_closed, f"IAGA unreachable ({exc})")

    decision = result.get("decision", "allow")
    risk = result.get("risk") or {}
    reasons = risk.get("reasons") or []
    reason = "; ".join(str(r) for r in reasons)
    event_id = (result.get("auditEvent") or {}).get("eventId", "")

    if decision == "block":
        _log(f"block (risk={risk.get('score')}, receipt={event_id})")
        _emit("deny", reason or "blocked by IAGA Sentinel")
    elif decision == "review":
        _log(f"review (receipt={event_id})")
        _emit("ask", reason or "IAGA Sentinel requires human review")
    else:
        _log(f"allow (risk={risk.get('score')}, receipt={event_id})")
        _emit(None)


if __name__ == "__main__":
    main()
