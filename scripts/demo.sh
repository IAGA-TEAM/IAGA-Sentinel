#!/usr/bin/env bash
# IAGA Sentinel demo launcher (Linux/macOS).
#
# Secondary to the primary Windows version scripts/demo.ps1. Same behaviour:
# build the release binaries if needed, wipe the demo SQLite DB for an identical
# seeded state, start `iaga serve --seed-demo` and wait for /health. See
# docs/demo/README.md for the full runbook.
#
# Usage:  ./scripts/demo.sh [--build]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

PORT="${PORT:-4010}"
IAGA="$REPO_ROOT/target/release/iaga"
VERIFY="$REPO_ROOT/target/release/iaga-verify"
HEALTH="http://localhost:$PORT/health"

BUILD=0
case "${1:-}" in
  --build|--force) BUILD=1 ;;
esac

if [[ $BUILD -eq 1 || ! -x "$IAGA" || ! -x "$VERIFY" ]]; then
  echo "Building release binaries (CARGO_INCREMENTAL=0) ..."
  CARGO_INCREMENTAL=0 cargo build --release -p iaga-sentinel-core -p iaga-sentinel-verify
fi

# Reset the demo DB for an identical seeded state every run.
rm -f iaga_sentinel.db iaga_sentinel.db-wal iaga_sentinel.db-shm

# Open mode makes every unauthenticated caller an implicit ADMIN while no
# API key exists, and the server's own default bind host is 0.0.0.0 - so
# without this the script publishes an admin API to the whole LAN. Every
# probe below already talks to 127.0.0.1.
export IAGA_SENTINEL_HOST=127.0.0.1
export IAGA_SENTINEL_OPEN_MODE=true CARGO_INCREMENTAL=0 PORT="$PORT"

"$IAGA" serve --seed-demo &
SRV=$!
trap 'kill "$SRV" 2>/dev/null || true' EXIT INT TERM

for _ in $(seq 1 60); do
  if curl -fsS "$HEALTH" >/dev/null 2>&1; then break; fi
  sleep 0.5
done

# The loop above exits after its attempts whether or not the server ever
# answered. Without this check the script printed READY and then blocked in
# `wait`, so a server that failed to start looked exactly like one that
# worked. agent_bootstrap.sh already does this; demo.ps1 exits 1 here.
curl -fsS "$HEALTH" >/dev/null 2>&1 || {
  echo "server did not become healthy on $HEALTH" >&2
  exit 1
}

echo ""
echo "READY -> http://localhost:$PORT/"
echo "In a second pane: ./scripts/demo_run.sh"
echo "Ctrl+C here to stop the server."
wait "$SRV"
