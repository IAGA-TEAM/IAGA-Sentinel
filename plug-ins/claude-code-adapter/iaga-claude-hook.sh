#!/usr/bin/env bash
# IAGA Sentinel - Claude Code PreToolUse hook (Bash variant, Unix/macOS).
#
# Reads a PreToolUse event on stdin, asks the IAGA Sentinel sidecar to govern
# the action (POST /v1/inspect), and emits a permission decision on stdout.
# One signed, offline-verifiable receipt per tool call. Requires: curl, jq.
#
# The cross-platform reference is iaga_claude_hook.py; this script mirrors it
# for users who prefer a pure-shell hook. Env vars are identical.
#
#   IAGA_BASE_URL    sidecar base URL          (default: http://localhost:4010)
#   IAGA_AGENT_ID    agentId on the receipt    (default: claude-code)
#   IAGA_FRAMEWORK   framework label           (default: claude-code)
#   IAGA_API_KEY     bearer token, if required (default: none)
#   IAGA_TIMEOUT     request timeout, seconds  (default: 5)
#   IAGA_FAIL_CLOSED truthy -> deny when the sidecar is unreachable
#                    (default: fail-open - the action proceeds, no receipt)
set -u

BASE_URL="${IAGA_BASE_URL:-http://localhost:4010}"
BASE_URL="${BASE_URL%/}"                       # mirrors the Python hook's rstrip("/")
AGENT_ID="${IAGA_AGENT_ID:-claude-code}"
FRAMEWORK="${IAGA_FRAMEWORK:-claude-code}"
TIMEOUT="${IAGA_TIMEOUT:-5}"

emit_allow() { echo '{}'; exit 0; }            # do not interfere; normal flow
emit() {                                       # $1=decision $2=reason
  jq -cn --arg d "$1" --arg r "$2" \
    '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:$d,permissionDecisionReason:$r}}'
  exit 0
}
# Diagnostics go to stderr so stdout stays a clean JSON decision, matching
# `_log` in the Python reference. Without this an outage was completely silent.
log() { printf '[iaga-claude-hook] %s\n' "$1" >&2; }
is_truthy() { case "${1:-}" in 1|true|TRUE|yes|on) return 0 ;; *) return 1 ;; esac; }

payload="$(cat)"
tool_name="$(jq -r '.tool_name // "unknown"' <<<"$payload" 2>/dev/null || echo unknown)"
session_id="$(jq -r '.session_id // empty' <<<"$payload" 2>/dev/null || echo '')"

case "$tool_name" in
  Bash)                              action_type="shell" ;;
  Read|Glob|Grep)                    action_type="file_read" ;;
  Write|Edit|MultiEdit|NotebookEdit) action_type="file_write" ;;
  WebFetch|WebSearch)                action_type="http" ;;
  *)                                 action_type="custom" ;;
esac

request="$(jq -cn \
  --arg agentId "$AGENT_ID" --arg framework "$FRAMEWORK" \
  --arg type "$action_type" --arg toolName "$tool_name" \
  --arg sessionId "$session_id" \
  --argjson input "$(jq -c '.tool_input // {}' <<<"$payload" 2>/dev/null || echo '{}')" \
  '{agentId:$agentId, framework:$framework,
    action:{type:$type, toolName:$toolName, payload:$input}}
   + (if $sessionId == "" then {} else {metadata:{sessionId:$sessionId}} end)')"

# Capture the HTTP status, not just the body.
#
# `curl -s` alone exits 0 for any status it managed to receive, so a 404 or a
# 500 landed in $verdict as an ERROR body. Every SentinelError serializes to
# JSON, so `jq -e .` accepted it, the fail-open/fail-closed branch below was
# skipped entirely, and `.decision // "allow"` returned "allow" because the key
# simply was not there. IAGA_FAIL_CLOSED was inert for exactly the statuses
# that matter: 404 agent_not_found (the state of every install until the policy
# is imported), 403 scope_mismatch, and 500 storage_error - so an outage of the
# governance database let every tool call through with fail-closed switched on.
#
# `-w` rather than `--fail-with-body`: the latter needs curl >= 7.76 and stock
# macOS ships older. The status is appended on its own final line and split off
# here, which leaves $verdict byte-identical to what it was before on 2xx.
if [ -n "${IAGA_API_KEY:-}" ]; then
  response="$(curl -s -w '\n%{http_code}' --max-time "$TIMEOUT" -X POST "${BASE_URL}/v1/inspect" \
    -H 'Content-Type: application/json' -H "Authorization: Bearer ${IAGA_API_KEY}" \
    -d "$request")" || response=""
else
  response="$(curl -s -w '\n%{http_code}' --max-time "$TIMEOUT" -X POST "${BASE_URL}/v1/inspect" \
    -H 'Content-Type: application/json' -d "$request")" || response=""
fi

if [ -z "$response" ]; then
  status=""
  verdict=""
else
  status="${response##*$'\n'}"
  verdict="${response%$'\n'*}"
fi

unreachable() {                                # $1=detail
  if is_truthy "${IAGA_FAIL_CLOSED:-}"; then
    log "$1; failing closed -> deny"
    emit "deny" "IAGA Sentinel unavailable: $1"
  fi
  log "$1; failing open -> allow"
  emit_allow
}

case "$status" in
  2??) ;;                                      # fall through to the verdict
  "")  unreachable "IAGA unreachable at ${BASE_URL}" ;;
  404) unreachable "agent '${AGENT_ID}' not registered at IAGA (404)" ;;
  *)   unreachable "IAGA returned HTTP ${status}" ;;
esac

if [ -z "$verdict" ] || ! jq -e . >/dev/null 2>&1 <<<"$verdict"; then
  unreachable "IAGA returned a non-JSON body"
fi

decision="$(jq -r '.decision // "allow"' <<<"$verdict")"
reason="$(jq -r '(.risk.reasons // []) | join("; ")' <<<"$verdict")"

case "$decision" in
  block)  emit "deny" "${reason:-blocked by IAGA Sentinel}" ;;
  review) emit "ask" "${reason:-IAGA Sentinel requires human review}" ;;
  *)      emit_allow ;;
esac
