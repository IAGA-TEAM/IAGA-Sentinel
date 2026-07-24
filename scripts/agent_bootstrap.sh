#!/usr/bin/env bash
# IAGA Sentinel agent self-bootstrap (Linux/macOS). Runs the AGENTS.md standing
# procedure over the MCP self-connect path, deterministically, and proves the
# agent's own policy governs its MCP calls. Needs: curl, jq.
#
# Usage:  ./scripts/agent_bootstrap.sh [--build] [--keep-server]
#
# What it proves that the old procedure did NOT: passing --policy to BOTH
# `serve` and `mcp-server` is what makes your authored policy actually decide the
# MCP verdict. `mcp-server` shares the database with `serve` but not its
# in-memory overlay, so without --policy the MCP verdict ignores your rules.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"
IAGA="$REPO_ROOT/target/release/iaga"
POLICY="$REPO_ROOT/agent_rules.dictum"
DBURL="sqlite:iaga_shared.db?mode=rwc"
PORT="${PORT:-4010}"
BASE="http://localhost:$PORT"

BUILD=0; KEEP=0
for a in "$@"; do
  case "$a" in
    --build) BUILD=1 ;;
    --keep-server) KEEP=1 ;;
  esac
done

rule() { printf '\n%s\n  %s\n%s\n\n' "$(printf '=%.0s' {1..64})" "$1" "$(printf '=%.0s' {1..64})"; }

command -v jq >/dev/null 2>&1 || { echo "this script needs jq"; exit 2; }

rule "IAGA SENTINEL  -  AGENT SELF-BOOTSTRAP (MCP self-connect)"

# 1. Resolve/build the binary (do not assume it is on PATH).
if [ "$BUILD" = 1 ] || [ ! -x "$IAGA" ]; then
  rule "Building release binary (CARGO_INCREMENTAL=0)"
  CARGO_INCREMENTAL=0 cargo build --release -p iaga-sentinel-core
fi
[ -x "$IAGA" ] || { echo "iaga not found at $IAGA"; exit 1; }
echo "Binary  : $IAGA"

# 2. Fresh shared DB (per-agent trust persists, so only a clean DB is deterministic).
rm -f iaga_shared.db iaga_shared.db-wal iaga_shared.db-shm
echo "DB      : fresh iaga_shared.db"

# 3. Encode the agent's instructions as enforced Dictum policy.
cat > "$POLICY" <<'DICTUM'
// agent_rules.dictum - my operating instructions, encoded as ENFORCED policy.
// Loaded by BOTH `iaga serve --policy` and `iaga mcp-server --policy`.

policy "never_destroy_production_data" {
  when action.kind == "shell" and risk.score > 50
  then block, reason="destructive shell is outside my mandate"
}

// secret_ref() detects RAW credential material (AWS keys, PEM blocks), NOT
// secretref:// references. See AGENTS.md: secret_ref vs secretref://.
policy "no_secret_egress_off_allowlist" {
  when action.kind == "http"
   and url_host(action.payload.destination) not in workspace.allowlist
   and secret_ref(action.payload)
  then block, reason="credentials must not leave approved hosts",
       evidence=action.payload.destination
}

policy "human_approves_file_writes" {
  when action.kind == "file_write"
  then review, reason="a human confirms every file modification"
}

// Demonstrable rule: a plain README read stays ALLOW, so a REVIEW on secret.env
// proves THIS overlay decided the MCP verdict (dictum[human_reviews_sensitive_reads]).
policy "human_reviews_sensitive_reads" {
  when action.kind == "file_read" and action.payload.path == "/workspace/secret.env"
  then review, reason="a human reviews access to sensitive files"
}
DICTUM
echo "Policy  : wrote $(basename "$POLICY") (4 rules)"

echo "> iaga policy lint / check"
"$IAGA" policy lint  "$POLICY"
"$IAGA" policy check "$POLICY"

# 4. Serve with the overlay on the shared DB.
export IAGA_SENTINEL_OPEN_MODE=true
export DATABASE_URL="$DBURL"
echo ""
echo "Starting dashboard server (iaga serve --policy) ..."
"$IAGA" serve --seed-demo --port "$PORT" --policy "$POLICY" >/tmp/iaga_bootstrap_serve.log 2>&1 &
SRV=$!
cleanup() { [ "$KEEP" = 1 ] || kill "$SRV" 2>/dev/null || true; }
trap cleanup EXIT

for _ in $(seq 1 60); do
  curl -fsS "$BASE/health" 2>/dev/null | grep -q '"ok":true' && break || sleep 0.5
done
curl -fsS "$BASE/health" | grep -q '"ok":true' || { echo "server not healthy"; tail -20 /tmp/iaga_bootstrap_serve.log; exit 1; }
OVERLAY="$(curl -fsS "$BASE/v1/policy/overlay")"
echo "$OVERLAY" | grep -q '"loaded":true' || { echo "overlay did not load"; exit 1; }
echo "Overlay : $OVERLAY"

# 5. Self-connect over MCP (SAME --policy) and drive three beats over stdio.
mcp_arg() { # id type tool payload_json
  printf '{"jsonrpc":"2.0","id":%s,"method":"tools/call","params":{"name":"iaga.inspect","arguments":{"agentId":"openclaw-builder-01","workspaceId":"ws-demo","framework":"openclaw","protocol":"mcp","action":{"type":"%s","toolName":"%s","payload":%s},"metadata":{"sessionId":"agent-bootstrap"}}}}' "$1" "$2" "$3" "$4"
}
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"agent","version":"1.0"}}}'
B_README="$(mcp_arg 2 file_read filesystem.read '{"path":"/workspace/README.md","intent":"inspect repository documentation"}')"
B_SECRET="$(mcp_arg 3 file_read filesystem.read '{"path":"/workspace/secret.env","intent":"inspect configuration"}')"
B_RMRF="$(mcp_arg 4 shell terminal.exec '{"command":"rm -rf /var/lib/postgresql/data","intent":"cleanup old data"}')"

OUT="$(printf '%s\n' "$INIT" "$B_README" "$B_SECRET" "$B_RMRF" | DATABASE_URL="$DBURL" "$IAGA" mcp-server --policy "$POLICY" 2>/dev/null)"

verdict() { printf '%s\n' "$OUT" | jq -c "select(.id==$1)" | jq -r '.result.structuredContent.decision'; }
dictum()  { printf '%s\n' "$OUT" | jq -c "select(.id==$1)" | jq -r '[.result.structuredContent.auditEvent.reasons[] | select(startswith("dictum["))] | join("; ")'; }

rule "MCP SELF-CONNECT  -  three governed beats (overlay IN FORCE)"
FAIL=0
check() { # label id expected
  local d; d="$(verdict "$2")"; local k; k="$(dictum "$2")"
  printf '  %-34s -> %-6s %s\n' "$1" "$(echo "$d" | tr a-z A-Z)" "${k:+[$k]}"
  [ "$d" = "$3" ] || { echo "    EXPECTED $3"; FAIL=1; }
}
check "read README.md            (allow)"  2 allow
check "read secret.env  (MY POLICY->review)" 3 review
check "rm -rf DB                 (block)"  4 block
dictum 3 | grep -q 'human_reviews_sensitive_reads' || { echo "  MISSING dictum[human_reviews_sensitive_reads]"; FAIL=1; }

echo ""
if [ "$FAIL" = 0 ]; then
  rule "PASS  -  your policy governs your MCP calls (visible in the dashboard)"
  echo "  Dashboard : $BASE/"
else
  rule "FAIL  -  verdicts did not match (see above)"
  exit 1
fi
