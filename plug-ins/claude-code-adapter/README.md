# IAGA Sentinel — Claude Code hook

Govern every Claude Code tool call with a `PreToolUse` hook. Before Claude runs
a `Bash`, `Edit`, `Write`, `WebFetch`, … the hook asks the IAGA Sentinel sidecar
for a verdict (`POST /v1/inspect`) and **denies** dangerous actions. Every call
leaves one signed, offline-verifiable receipt.

This is **cooperative** governance (Claude Code calls the hook). A hostile agent
that bypasses the hook is out of scope for the open build; transparent,
unbypassable interception is the eBPF/LSM kernel on the Enterprise roadmap. Open
receipts honestly record `is_authoritative = false`.

## Files

| File | Use |
|---|---|
| `iaga_claude_hook.py` | Cross-platform hook (Python stdlib, **no dependencies**). Recommended. |
| `iaga-claude-hook.sh` | Same logic in Bash (needs `curl` + `jq`). Unix/macOS. |
| `claude-code.policy.yaml` | Registers the `claude-code` agent so its tools are governed. |
| `test_hook.py` | `pytest` integration tests (allow / block / fail-open / fail-closed). |

## 1. Start the sidecar

```bash
cargo build --release --workspace
# open mode makes every unauthenticated caller an implicit ADMIN; the default bind host is 0.0.0.0
IAGA_SENTINEL_HOST=127.0.0.1 IAGA_SENTINEL_OPEN_MODE=true ./target/release/iaga serve --seed-demo
```

The sidecar listens on `http://localhost:4010`.

## 2. Register the agent (important)

`/v1/inspect` requires a known `agentId`. An **unregistered** agent returns
`404`, and the hook then falls back to its fail-open/closed policy — so it would
govern nothing until you register it. Import the bundled policy once:

```bash
./target/release/iaga import plug-ins/claude-code-adapter/claude-code.policy.yaml
```

It maps Claude Code's tool names (`Bash`, `Read`, `Write`, …) to action types
and defaults every decision to **allow**, so each call still produces a receipt
while the injection firewall blocks dangerous payloads (e.g. `curl … | sh`)
regardless. Tighten any tool to `maxDecision: review` to require human approval.

## 3. Wire up the hook in `.claude/settings.json`

**macOS / Linux** (make `iaga-claude-hook.sh` executable, or call the `.py`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Edit|Write|MultiEdit|NotebookEdit|WebFetch",
        "hooks": [
          {
            "type": "command",
            "command": "python3 \"${CLAUDE_PROJECT_DIR}/plug-ins/claude-code-adapter/iaga_claude_hook.py\""
          }
        ]
      }
    ]
  }
}
```

**Windows**:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Edit|Write|MultiEdit|NotebookEdit|WebFetch",
        "hooks": [
          {
            "type": "command",
            "command": "python \"C:\\path\\to\\plug-ins\\claude-code-adapter\\iaga_claude_hook.py\""
          }
        ]
      }
    ]
  }
}
```

Set `matcher` to `*` to govern every tool (including read-only `Read`/`Glob`/`Grep`).

## 4. Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `IAGA_BASE_URL` | `http://localhost:4010` | Sidecar base URL. |
| `IAGA_AGENT_ID` | `claude-code` | `agentId` recorded on the receipt. |
| `IAGA_FRAMEWORK` | `claude-code` | Framework label. |
| `IAGA_API_KEY` | _(none)_ | Bearer token, if the sidecar requires auth. |
| `IAGA_TIMEOUT` | `5` | Request timeout (seconds). |
| `IAGA_FAIL_CLOSED` | _(unset)_ | If truthy, **deny** when the sidecar is unreachable. Default is fail-open. |

## 5. What the hook does

| IAGA decision | Hook output | Effect in Claude Code |
|---|---|---|
| `allow` | `{}` | No interference; your normal permission flow continues. |
| `review` | `permissionDecision: "ask"` | Claude Code prompts you to approve. |
| `block` | `permissionDecision: "deny"` | The tool call is refused (reason = risk reasons). |
| _unreachable_ | fail-open `{}` (or `deny` if `IAGA_FAIL_CLOSED`) | Governance outage doesn't take Claude down. |

The `inspect` call runs on every matched tool, so even `allow` actions produce a
receipt — and the hook never silently widens your own permission choices.

## 6. Verify a receipt offline

The receipt's `run_id` is `<IAGA_AGENT_ID>:<session_id>` — `claude-code:<session_id>` with the
default agent id — because the hook forwards Claude Code's `session_id` as `metadata.sessionId`,
so one chain covers the whole session. (`auditEvent.eventId` is the `run_id` only for a
session-less caller, which this hook is not.)

```bash
./target/release/iaga replay --list
./target/release/iaga replay <run_id> --export chain.json
./target/release/iaga-verify chain.json        # -> CHAIN OK
```

The exported receipt includes `is_authoritative: false`.

## 7. Run the tests

```bash
pip install pytest
# open mode makes every unauthenticated caller an implicit ADMIN; the default bind host is 0.0.0.0
IAGA_SENTINEL_HOST=127.0.0.1 IAGA_SENTINEL_OPEN_MODE=true ./target/release/iaga serve --seed-demo &
pytest plug-ins/claude-code-adapter/test_hook.py -v
```

Allow/block tests skip automatically if the sidecar isn't reachable; the
fail-open/closed tests always run (they target a dead port).
