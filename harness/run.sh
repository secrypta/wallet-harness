#!/usr/bin/env bash
#
# wallet-harness v0 - runs the corpus vectors against their toy targets and prints a
# verdict per target: VULNERABLE (vector lands) or BLOCKED (target defends it).
#
# The vectors are executed as Foundry tests inside Docker. Each test measures the real
# on-chain outcome and logs a line "[<vector>] target=<name> verdict=<VULNERABLE|BLOCKED>";
# this script collects those lines and enforces the validation bar:
#   * every vulnerable target MUST be VULNERABLE (no false negatives)
#   * every protected target MUST be BLOCKED   (no false positives)
#
# Usage:  harness/run.sh
# Requires: Docker + the ghcr.io/foundry-rs/foundry image. forge-std must be in lib/
#           (see README: git clone the pinned forge-std into lib/forge-std).

set -euo pipefail

usage() {
  cat <<'EOF'
usage: harness/run.sh                (no arguments)

Runs the corpus vectors against their toy targets as Foundry tests inside Docker and prints
one verdict per target - VULNERABLE (the vector lands) or BLOCKED (the target defends) - then
enforces the bar: every *vulnerable* target must be VULNERABLE and every *safe* target must be
BLOCKED (0 false negatives / 0 false positives).

Requires: Docker + the ghcr.io/foundry-rs/foundry image, and forge-std in lib/ (make forge-std).
Exit: 0 when the bar is met; non-zero on any FP/FN or if no verdicts were emitted.
For the full labeled-corpus confusion matrix + precision/recall, use harness/benchmark.sh.
EOF
}
case "${1:-}" in -h|--help) usage; exit 0 ;; esac

IMAGE="ghcr.io/foundry-rs/foundry:stable"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MAX_CONTAINERS=3
MEM_LIMIT="2g"

cd "$REPO_ROOT"

# --- preflight: forge-std present? ---
if [ ! -f lib/forge-std/src/Test.sol ]; then
  echo "error: lib/forge-std not found. Fetch it first, e.g.:" >&2
  echo "  git clone --depth 1 --branch v1.9.4 https://github.com/foundry-rs/forge-std lib/forge-std" >&2
  exit 1
fi

# --- preflight: docker + container cap (shared VM, ceiling of 3) ---
running="$(docker ps -q | wc -l | tr -d ' ')"
if [ "$running" -ge "$MAX_CONTAINERS" ]; then
  echo "error: $running containers already running (cap $MAX_CONTAINERS). Free one first." >&2
  exit 1
fi

echo "== wallet-harness v0 =="
echo "running corpus vectors in Docker ($IMAGE), mem=$MEM_LIMIT ..."
echo

out="$(mktemp)"
trap 'rm -f "$out"' EXIT

# Run the Foundry test suite inside the container. The repo is mounted READ-ONLY and
# copied to a writable, container-owned dir before building: this keeps the host repo
# pristine (no out/cache/.svm written back) and sidesteps uid-mapping write issues on
# user-namespaced Docker daemons. We only need stdout (the verdict lines) back.
docker run --rm \
  --cpus=4 --memory="$MEM_LIMIT" --memory-swap="$MEM_LIMIT" --pids-limit=1024 \
  -e HOME=/tmp \
  -v "$REPO_ROOT":/src:ro \
  --entrypoint sh \
  "$IMAGE" \
  -c 'cp -r /src /tmp/work && cd /tmp/work && forge test -vv' 2>&1 | tee "$out"

echo
echo "== verdict report =="
verdicts="$(grep -oE '\[[a-z0-9-]+\] target=[a-z0-9-]+ verdict=(VULNERABLE|BLOCKED)' "$out" || true)"

if [ -z "$verdicts" ]; then
  echo "error: no verdict lines emitted - did the tests run?" >&2
  exit 1
fi
# Canonical report form, as named in the corpus specs: "<vector>: VERDICT".
while IFS= read -r line; do
  vector="$(sed -E 's/^\[([a-z0-9-]+)\].*/\1/' <<<"$line")"
  target="$(sed -E 's/.*target=([a-z0-9-]+).*/\1/' <<<"$line")"
  verdict="$(sed -E 's/.*verdict=([A-Z]+).*/\1/' <<<"$line")"
  printf '%-18s %-10s (target: %s)\n' "$vector:" "$verdict" "$target"
done <<<"$verdicts"
echo

# --- enforce the validation bar (0 false positives / 0 false negatives) ---
fail=0
while IFS= read -r line; do
  target="$(sed -E 's/.*target=([a-z0-9-]+).*/\1/' <<<"$line")"
  verdict="$(sed -E 's/.*verdict=([A-Z]+).*/\1/' <<<"$line")"
  case "$target" in
    *vulnerable*) [ "$verdict" = "VULNERABLE" ] || { echo "FALSE NEGATIVE: $target reported $verdict"; fail=1; } ;;
    *safe*|*protected*) [ "$verdict" = "BLOCKED" ] || { echo "FALSE POSITIVE: $target reported $verdict"; fail=1; } ;;
  esac
done <<<"$verdicts"

if [ "$fail" -ne 0 ]; then
  echo "== HARNESS: FAIL (validation bar not met) =="
  exit 1
fi

echo "== HARNESS: OK - 0 false positives, 0 false negatives =="
