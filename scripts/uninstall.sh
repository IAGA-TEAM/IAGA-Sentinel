#!/usr/bin/env bash
# Detach from IAGA Sentinel. Prints what it would remove and exits; pass --yes to
# actually remove it.
#
#   ./scripts/uninstall.sh              # dry run, shows everything it found
#   ./scripts/uninstall.sh --yes        # remove the install, KEEP the signing key
#   ./scripts/uninstall.sh --yes --include-key   # also destroy the signing key
#
# The signing key is deliberately not removed by default, and the flag that does
# remove it is spelled out rather than implied. Deleting the database throws away
# the evidence; deleting the key throws away your ability to check evidence you
# already exported — including chains sitting in someone else's audit folder.
set -uo pipefail

DIR="."
YES=0
INCLUDE_KEY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes|-y)        YES=1 ;;
    --include-key)   INCLUDE_KEY=1 ;;
    --dir)           DIR="$2"; shift ;;
    -h|--help)       sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1 (try --help)"; exit 2 ;;
  esac
  shift
done

KEY_DEFAULT="$HOME/.iaga-sentinel/keys/receipt_signer.ed25519"
KEY="${IAGA_SENTINEL_SIGNER_KEY_PATH:-$KEY_DEFAULT}"

echo "IAGA Sentinel: detach"
echo "  working directory: $(cd "$DIR" && pwd)"
echo

# 1. Anything still running keeps a handle on the database.
running="$(pgrep -f '[i]aga(-sentinel)? (serve|mcp-server|proxy)' 2>/dev/null || true)"
if [[ -n "$running" ]]; then
  echo "STILL RUNNING (stop these first, or this script cannot free the database):"
  echo "$running" | sed 's/^/    pid /'
  echo
fi

found=()
add() { [[ -e "$1" ]] && found+=("$1"); }

add "$DIR/iaga_sentinel.db"
add "$DIR/iaga_sentinel.db-wal"
add "$DIR/iaga_sentinel.db-shm"
add "$DIR/iaga_shared.db"
add "$DIR/iaga_shared.db-wal"
add "$DIR/iaga_shared.db-shm"
add "$DIR/iaga-sentinel.yaml"
add "$DIR/iaga-sentinel.yml"
add "$DIR/iaga-sentinel.json"
add "$DIR/agent_rules.dictum"
add "$DIR/chain.json"

if [[ ${#found[@]} -eq 0 ]]; then
  echo "Nothing to remove in this directory."
else
  echo "WOULD REMOVE:"
  for f in "${found[@]}"; do echo "    $f"; done
  echo
  echo "  What that costs you: the audit trail and every signed receipt in that"
  echo "  database. Chains you already exported to a .json file stay valid and"
  echo "  keep verifying — that is the point of exporting them."
fi
echo

if [[ -e "$KEY" ]]; then
  if [[ $INCLUDE_KEY -eq 1 ]]; then
    echo "WOULD ALSO DESTROY THE SIGNING KEY:"
    echo "    $KEY"
    echo "  Every receipt ever produced on this machine becomes permanently"
    echo "  unverifiable, including chains already exported and handed to someone"
    echo "  else. There is no recovery. Archive the file instead if you are unsure."
  else
    echo "KEEPING the signing key: $KEY"
    echo "  It is shared by every project on this machine and is what makes past"
    echo "  receipts verifiable. Pass --include-key to destroy it anyway."
  fi
else
  echo "No signing key at $KEY (nothing to keep)."
fi
echo

if [[ $YES -ne 1 ]]; then
  echo "Dry run. Nothing was removed. Re-run with --yes to proceed."
  exit 0
fi

if [[ -n "$running" ]]; then
  echo "Refusing to remove anything while a governed process is still running."
  echo "Stop it and re-run."
  exit 1
fi

for f in "${found[@]:-}"; do [[ -n "$f" ]] && rm -f "$f" && echo "removed  $f"; done
if [[ $INCLUDE_KEY -eq 1 && -e "$KEY" ]]; then
  rm -f "$KEY" && echo "removed  $KEY"
fi

echo
echo "Done. What is left on this machine:"
echo "  - the checkout itself (delete the directory to remove it)"
echo "  - the binary, if you ran 'cargo install' (cargo uninstall iaga-sentinel-core)"
[[ $INCLUDE_KEY -ne 1 ]] && echo "  - the signing key, on purpose: $KEY"
echo
echo "Your agent is now ungoverned: nothing is checked and nothing is recorded."
echo "Say so out loud rather than assuming it is still protecting you."
