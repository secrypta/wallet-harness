#!/usr/bin/env bash
#
# wallet-harness benchmark - corpus self-consistency check: runs every labeled fixture's own
# exploit/control test and checks that it reproduces its ground-truth label, printing a
# confusion matrix and precision/recall.
#
# Ground truth lives in fixtures/<vector>/<tier>/<target>/meta (see fixtures/README.md).
# The harness verdict comes from the Foundry suite: each target emits one line
#   [<vector>] target=<target> verdict=<VULNERABLE|BLOCKED>
# Each fixture is joined to its verdict by the pair (vector, target) and scored:
#   label vuln + VULNERABLE = TP    label vuln + BLOCKED = FN
#   label safe + BLOCKED    = TN    label safe + VULNERABLE = FP
# Target bar: recall 1.0 on vuln, precision 1.0 on safe (0 false positives).
#
# Non-zero exit on any FP/FN, or any labeled fixture with no emitted verdict (coverage gap).
#
# Usage:  harness/benchmark.sh
# Requires: Docker + ghcr.io/foundry-rs/foundry; forge-std in lib/ (see README).

set -euo pipefail

usage() {
  cat <<'EOF'
usage: harness/benchmark.sh          (no arguments)

Runs EVERY labeled fixture through the Foundry exploit/control suite in Docker, joins each to
its ground-truth label, and prints the confusion matrix (TP/FP/FN/TN, missing) with precision
and recall. This is a corpus self-consistency check (each fixture's own test must reproduce its
label), not an independent accuracy measurement - see README, "Benchmark".

Requires: Docker + the ghcr.io/foundry-rs/foundry image, and forge-std in lib/ (make forge-std).
Exit: 0 when every fixture passes (0 FP/FN, 0 coverage gaps); non-zero otherwise.
Score a saved verdict file instead (no Docker): bench/score.sh <verdicts.txt>.
EOF
}
case "${1:-}" in -h|--help) usage; exit 0 ;; esac

IMAGE="ghcr.io/foundry-rs/foundry:stable"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MAX_CONTAINERS=3
MEM_LIMIT="2g"

cd "$REPO_ROOT"

# --- preflight ---
if [ ! -f lib/forge-std/src/Test.sol ]; then
  echo "error: lib/forge-std not found. See README (git clone the pinned forge-std into lib/)." >&2
  exit 1
fi
if [ ! -d fixtures ] || [ -z "$(find fixtures -name meta 2>/dev/null)" ]; then
  echo "error: no labeled fixtures found under fixtures/**/meta" >&2
  exit 1
fi
running="$(docker ps -q | wc -l | tr -d ' ')"
if [ "$running" -ge "$MAX_CONTAINERS" ]; then
  echo "error: $running containers already running (cap $MAX_CONTAINERS). Free one first." >&2
  exit 1
fi

echo "== wallet-harness benchmark =="

# --- 1. load ground-truth labels: label[vector/target]=vuln|safe ---
declare -A label
declare -A seen_fixture
nfix=0
while IFS= read -r meta; do
  vector=""; target=""; lbl=""
  while IFS='=' read -r k v; do
    case "$k" in
      vector) vector="$v" ;;
      target) target="$v" ;;
      label)  lbl="$v" ;;
    esac
  done < <(grep -vE '^\s*#' "$meta")
  if [ -z "$vector" ] || [ -z "$target" ] || [ -z "$lbl" ]; then
    echo "error: $meta missing vector/target/label" >&2; exit 1
  fi
  if [ "$lbl" != "vuln" ] && [ "$lbl" != "safe" ]; then
    echo "error: $meta has invalid label '$lbl' (expected vuln|safe)" >&2; exit 1
  fi
  key="$vector/$target"
  label["$key"]="$lbl"
  nfix=$((nfix+1))
done < <(find fixtures -name meta | sort)
echo "loaded $nfix labeled fixtures"
echo

# --- 2. run the Foundry suite in Docker, harvest verdict lines ---
echo "running Foundry suite in Docker ($IMAGE, mem=$MEM_LIMIT) ..."
out="$(mktemp)"; trap 'rm -f "$out"' EXIT
docker run --rm \
  --cpus=4 --memory="$MEM_LIMIT" --memory-swap="$MEM_LIMIT" --pids-limit=1024 \
  -e HOME=/tmp \
  -v "$REPO_ROOT":/src:ro \
  --entrypoint sh \
  "$IMAGE" \
  -c 'cp -r /src /tmp/work && cd /tmp/work && forge test -vv' > "$out" 2>&1 || {
    echo "error: forge suite failed to run:" >&2; tail -20 "$out" >&2; exit 1; }

declare -A verdict
while IFS= read -r line; do
  v="$(sed -E 's/^\[([a-z0-9-]+)\].*/\1/' <<<"$line")"
  t="$(sed -E 's/.*target=([a-z0-9-]+).*/\1/' <<<"$line")"
  r="$(sed -E 's/.*verdict=([A-Z]+).*/\1/' <<<"$line")"
  verdict["$v/$t"]="$r"
done < <(grep -oE '\[[a-z0-9-]+\] target=[a-z0-9-]+ verdict=(VULNERABLE|BLOCKED)' "$out" | sort -u)

# --- 3. score each labeled fixture ---
TP=0; FP=0; FN=0; TN=0; missing=0
echo
printf '%-22s %-18s %-5s %-11s %-4s\n' "VECTOR" "TARGET" "LABEL" "VERDICT" "CELL"
printf '%s\n' "---------------------------------------------------------------------"
for key in $(printf '%s\n' "${!label[@]}" | sort); do
  lbl="${label[$key]}"
  vrd="${verdict[$key]:-<none>}"
  vector="${key%%/*}"; target="${key#*/}"
  cell="?"
  if [ "$vrd" = "<none>" ]; then
    cell="MISS"; missing=$((missing+1))
  elif [ "$lbl" = "vuln" ] && [ "$vrd" = "VULNERABLE" ]; then
    cell="TP"; TP=$((TP+1))
  elif [ "$lbl" = "vuln" ] && [ "$vrd" = "BLOCKED" ]; then
    cell="FN"; FN=$((FN+1))
  elif [ "$lbl" = "safe" ] && [ "$vrd" = "BLOCKED" ]; then
    cell="TN"; TN=$((TN+1))
  elif [ "$lbl" = "safe" ] && [ "$vrd" = "VULNERABLE" ]; then
    cell="FP"; FP=$((FP+1))
  fi
  printf '%-22s %-18s %-5s %-11s %-4s\n' "$vector" "$target" "$lbl" "$vrd" "$cell"
done

# --- 4. metrics ---
echo
echo "== confusion matrix =="
echo "  TP=$TP  FP=$FP  FN=$FN  TN=$TN  (missing=$missing)"

prec="n/a"; rec="n/a"
if [ $((TP+FP)) -gt 0 ]; then
  prec="$(LC_NUMERIC=C awk "BEGIN{printf \"%.3f\", $TP/($TP+$FP)}")"
fi
if [ $((TP+FN)) -gt 0 ]; then
  rec="$(LC_NUMERIC=C awk "BEGIN{printf \"%.3f\", $TP/($TP+$FN)}")"
fi
echo "  precision=$prec  recall=$rec"
echo

fail=0
[ "$missing" -ne 0 ] && { echo "FAIL: $missing labeled fixture(s) emitted no verdict (coverage gap)"; fail=1; }
[ "$FP" -ne 0 ] && { echo "FAIL: $FP false positive(s) - safe code flagged VULNERABLE"; fail=1; }
[ "$FN" -ne 0 ] && { echo "FAIL: $FN false negative(s) - real bug reported BLOCKED"; fail=1; }

if [ "$fail" -ne 0 ]; then
  echo "== BENCHMARK: FAIL =="
  exit 1
fi
echo "== BENCHMARK: OK - precision=$prec, recall=$rec, 0 false positives, 0 false negatives =="
