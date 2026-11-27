#!/usr/bin/env bash
#
# drain-bench - BASELINE adapter: run a third-party analyzer over the fixture corpus in Docker
# (default config, no tuning) and write its verdicts in the drain-bench format, so a generic
# tool's score can sit beside wal's. External baselines only - the analyzer is RUN here, never
# linked into wal's MIT core. (Slither is AGPL; Solhint MIT; Wake ISC; Aderyn MIT; SMTChecker is
# part of solc GPL-3.0. Every tool runs as an external process in Docker; none is imported.)
#
# Usage:  bench/tools/run-baseline.sh <tool>
#   tools: slither | mythril | semgrep | solhint | smtchecker | wake
#   -> bench/results/<tool>/raw/*.{json,txt}  (one per analyzed .sol) + verdicts.txt
#
# Mapping (native output -> VULNERABLE/BLOCKED) is applied by bench/tools/map_verdicts.py and
# documented in bench/results/<tool>/META.md. Docker container cap 3 (checked). Offline fixtures
# are first-party; Docker is used per policy for the third-party tool, not for untrusted code.
# Tools with no suitable prebuilt image are installed at a PINNED version inside a base image at
# run time (documented in each META); nothing is written to the host, and --rm keeps disk flat.

set -uo pipefail

TOOL="${1:-}"
case "$TOOL" in
  slither|mythril|semgrep|solhint|smtchecker|wake|falcon|solc|remix) ;;
  *) echo "usage: $0 <slither|mythril|semgrep|solhint|smtchecker|wake|falcon|solc|remix> [sol ...]" >&2; exit 2 ;;
esac
# Optional DELTA mode: extra args are explicit sol paths to (re)analyze. In this mode raw/ is NOT
# wiped and only the named sources are run; verdicts.txt is then regenerated from the FULL raw/
# (the mapper reads every raw file + baseline-targets.tsv), so a corpus-growth delta replays cheap
# instead of re-running the whole tool over all sources. Whole-project tools (wake) always run
# over the whole tree regardless. No args = full run (wipe raw/, analyze all mapped sources).
shift || true
SUBSET=("$@")

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MAP="$REPO_ROOT/bench/tools/baseline-targets.tsv"
OUTDIR="$REPO_ROOT/bench/results/$TOOL"
RAWDIR="$OUTDIR/raw"
MAX_CONTAINERS=3
MEM_LIMIT="6g"

# raw-file extension the parser expects for this tool (text for compiler tools, sarif for wake)
EXT="json"; { [ "$TOOL" = "smtchecker" ] || [ "$TOOL" = "solc" ]; } && EXT="txt"; [ "$TOOL" = "wake" ] && EXT="sarif"

case "$TOOL" in
  slither)    IMAGE="trailofbits/eth-security-toolbox:latest" ;;
  mythril)    IMAGE="mythril/myth:latest" ;;
  semgrep)    IMAGE="semgrep/semgrep:latest" ;;
  solhint)    IMAGE="node:20-alpine" ;;
  wake)       IMAGE="python:3.11-slim-bookworm" ;;
  falcon)     IMAGE="python:3.10-slim-bookworm" ;;     # 3.10: Falcon's pysha3 dep won't build on 3.11
  smtchecker) IMAGE="mythril/myth:latest" ;;          # carries libz3.so.4.12 that solc's CHC needs
  solc)       IMAGE="python:3.11-slim-bookworm" ;;     # just runs the staged host solc (glibc base)
  remix)      IMAGE="node:20-alpine" ;;                # Remix analyzer lib + solc-js (pure JS)
esac

# Containers have no outbound solc download path wired for the compiler tools. Stage the host's
# solc-select binaries into a py-solc-x-style cache and mount it; Mythril finds them via
# SOLCX_BINARY_PATH, and SMTChecker invokes them directly. Needs 0.8.24 (+ 0.8.17 for the
# Uniswap-Permit2-pragma fixtures) installed via solc-select on the host.
EXTRA=()
if [ "$TOOL" = "mythril" ] || [ "$TOOL" = "smtchecker" ] || [ "$TOOL" = "solc" ]; then
  STAGE="$(mktemp -d)"
  art=""
  for d in "$HOME"/drain-scan/.venv/.solc-select/artifacts "$HOME"/.solc-select/artifacts; do
    [ -d "$d" ] && [ -f "$d/solc-0.8.24/solc-0.8.24" ] && { art="$d"; break; }
  done
  [ -n "$art" ] || { echo "error: no solc-select artifacts dir with solc 0.8.24 found" >&2; exit 1; }
  for v in 0.8.24 0.8.17; do
    b="$art/solc-$v/solc-$v"
    [ -f "$b" ] && { cp "$b" "$STAGE/solc-v$v"; chmod +x "$STAGE/solc-v$v"; }
  done
  ls "$STAGE"/solc-v0.8.24 >/dev/null 2>&1 || { echo "error: host solc 0.8.24 not found under $art" >&2; exit 1; }
  # mktemp -d is mode 700; the non-root container user must traverse + exec the solc.
  chmod 0755 "$STAGE"; chmod 0755 "$STAGE"/solc-v* 2>/dev/null || true
  EXTRA=(-e SOLCX_BINARY_PATH=/tmp/.solcx -v "$STAGE":/tmp/.solcx)
fi

[ -f "$MAP" ] || { echo "error: map not found: $MAP" >&2; exit 2; }
running="$(docker ps -q | wc -l | tr -d ' ')"
if [ "$running" -ge "$MAX_CONTAINERS" ]; then
  echo "error: $running containers running (cap $MAX_CONTAINERS). Free one first." >&2; exit 1
fi

# distinct first-party sol files to analyze (full run), or the explicit delta subset
if [ "${#SUBSET[@]}" -gt 0 ]; then
  SOLS=("${SUBSET[@]}")
  DELTA=1
else
  mapfile -t SOLS < <(awk -F'\t' '$1!~/^#/ && NF>=4{print $4}' "$MAP" | sort -u)
  DELTA=0
fi
echo "== baseline: $TOOL over ${#SOLS[@]} source(s)${DELTA:+ (delta=$DELTA)} ($IMAGE, mem=$MEM_LIMIT) =="

mkdir -p "$RAWDIR"
# full run: start raw/ clean. delta run: keep existing raw/ and only (re)write the named subjects.
[ "$DELTA" -eq 0 ] && { rm -f "$RAWDIR"/*.json "$RAWDIR"/*.txt "$RAWDIR"/*.sarif 2>/dev/null || true; }
# some tool images run as a non-root user; make bind-mounted output writable regardless of uid.
chmod 0777 "$OUTDIR" "$RAWDIR" 2>/dev/null || true
printf '%s\n' "${SOLS[@]}" > "$OUTDIR/sources.txt"

# in-container driver: $1 = tool, $2 = ext. Installs the tool (pinned) if needed, then reads
# /out/sources.txt and writes /out/raw/<sanitized>.<ext> per file.
# NB: a quoted heredoc (<<'INSCRIPT') carries the body verbatim. The body has literal single
# quotes (grep -oE '...') that a single-quoted assignment IN_SCRIPT='...' would terminate early,
# silently truncating the script sent to docker (all tools -> MISS). Do NOT revert to that form.
IN_SCRIPT="$(cat <<'INSCRIPT'
set -u
TOOL="$1"; EXT="$2"
have() { command -v "$1" >/dev/null 2>&1; }

# --- per-tool install (pinned; network used once at run time, nothing persisted) ---
case "$TOOL" in
  solhint)
    npm i -g solhint@5.0.3 >/tmp/install.log 2>&1 || { echo "INSTALL_FAIL solhint"; tail -3 /tmp/install.log; exit 3; }
    ;;
  wake)
    pip install --quiet eth-wake==4.16.1 >/tmp/install.log 2>&1 || { echo "INSTALL_FAIL wake"; tail -3 /tmp/install.log; exit 3; }
    ;;
  falcon)
    # Falcon (MetaTrust), a Slither-derived analyzer; installed from git (no PyPI release).
    apt-get update >/tmp/install.log 2>&1; apt-get install -y --no-install-recommends git gcc g++ >>/tmp/install.log 2>&1
    pip install --quiet "git+https://github.com/MetaTrustLabs/falcon-metatrust.git@${FALCON_REF:-93c1be7914f24e5567ff17da45be6f87b506c069}" >>/tmp/install.log 2>&1 || { echo "INSTALL_FAIL falcon"; tail -4 /tmp/install.log; exit 3; }
    pip install --quiet solc-select >>/tmp/install.log 2>&1
    solc-select install 0.8.24 >>/tmp/install.log 2>&1; solc-select install 0.8.17 >>/tmp/install.log 2>&1
    ;;
esac

cp -r /src /tmp/work && cd /tmp/work
# solhint uses the tools own recommended ruleset (no project tuning)
[ "$TOOL" = "solhint" ] && echo "{ \"extends\": \"solhint:recommended\" }" > .solhint.json

# --- whole-project tools: one run over the repo -> /out/raw/_repo.<ext>; mapper filters by file ---
if [ "$TOOL" = "wake" ]; then
  # wake is a project analyzer: it compiles the whole tree and runs all default detectors.
  # --ignore-errors so a non-subject file that cannot compile (e.g. a forge-std test) does not
  # abort the run; detectors still report on the units that compiled.
  wake detect --export sarif --ignore-errors all >/out/wake.log 2>&1 || true
  if [ -f wake-detections.sarif ]; then
    cp wake-detections.sarif /out/raw/_repo.sarif && echo "ok   _repo (wake whole-project)"
  else
    echo "EMPTY _repo (wake produced no sarif)"; tail -3 /out/wake.log 2>/dev/null
  fi
  exit 0
fi

# --- Remix static analyzer: a Node driver (bench/tools/remix-analyze.js) compiles each source
#     with solc-js and runs the Remix Security modules -> per-file raw JSON (line-located). ---
if [ "$TOOL" = "remix" ]; then
  mkdir -p /tmp/rm && cd /tmp/rm && npm init -y >/dev/null 2>&1
  npm i @remix-project/remix-analyzer@0.5.76 solc@0.8.24 fast-levenshtein@3.0.0 >/tmp/install.log 2>&1 \
    || { echo "INSTALL_FAIL remix"; tail -4 /tmp/install.log; exit 3; }
  NODE_PATH=/tmp/rm/node_modules node /tmp/work/bench/tools/remix-analyze.js /tmp/work /out/raw /out/sources.txt 2>>/out/remix.log
  exit 0
fi

sanitize() { echo "$1" | sed -E "s/[^A-Za-z0-9]+/_/g; s/^_//; s/_$//"; }
# Choose a solc for this source. Permit2 pins exactly 0.8.17; our own sources and the
# vendored OpenZeppelin (caret ^0.8.20) compile under 0.8.24 (our supported max). An EXACT
# pin "pragma solidity [=]0.8.NN;" is honored so a future fixture is not silently compiled
# under the wrong compiler - which would surface as a MISS, not a visible error. Carets and
# ranges fall through to 0.8.24 (unchanged). A pinned version other than 0.8.17/0.8.24 is
# used but logged, so an incompatible pin is loud instead of a silent MISS.
pick_solc() {
  local pin
  if grep -qE "pragma solidity[^;]*0\.8\.17" "$1"; then echo "0.8.17"; return; fi
  pin="$(grep -oE 'pragma solidity[[:space:]]*=?[[:space:]]*0\.8\.[0-9]+[[:space:]]*;' "$1" \
         | grep -oE '0\.8\.[0-9]+' | head -1)"
  if [ -n "$pin" ] && [ "$pin" != "0.8.24" ]; then
    echo "WARN: $1 pins exact $pin (not 0.8.17/0.8.24); compiling with $pin - add to CI matrix if intentional" >&2
    echo "$pin"; return
  fi
  echo "0.8.24"
}

while IFS= read -r sol; do
  [ -z "$sol" ] && continue
  out="/out/raw/$(sanitize "$sol").$EXT"
  case "$TOOL" in
    semgrep)
      semgrep scan --config auto --json --quiet --output "$out" "$sol" >/dev/null 2>&1 || true ;;
    slither)
      ver="$(pick_solc "$sol")"; solc-select use "$ver" --always-install >/dev/null 2>&1
      slither "$sol" --json "$out" >/dev/null 2>&1 || true ;;
    falcon)
      ver="$(pick_solc "$sol")"; solc-select use "$ver" >/dev/null 2>&1
      falcon "$sol" --json "$out" >/dev/null 2>&1 || true ;;
    mythril)
      ver="$(pick_solc "$sol")"; solc-select use "$ver" --always-install >/dev/null 2>&1
      timeout 180 myth analyze "$sol" --solv "$ver" --execution-timeout 90 -o json > "$out" 2>/dev/null || true ;;
    solhint)
      # strip the update-notifier banner (keep from the first JSON "["); solhint prints NOTHING
      # on zero findings, so if it ran cleanly (rc<=1) but produced no array, record an empty
      # "[]" (ran, found nothing -> BLOCKED) rather than leaving it empty (which = MISS).
      solhint -f json "$sol" >/tmp/sh.out 2>/dev/null; rc=$?
      sed -n "/^\[/,\$p" /tmp/sh.out > "$out"
      if [ ! -s "$out" ] && [ "$rc" -le 1 ]; then echo "[]" > "$out"; fi ;;
    smtchecker)
      ver="$(pick_solc "$sol")"
      export LD_LIBRARY_PATH="/usr/local/lib/python3.10/site-packages/z3/lib:${LD_LIBRARY_PATH:-}"
      # solc SMTChecker: CHC engine, all safety targets; diagnostics go to stderr as text.
      # Classify the outcome so "compiled, no model-checker finding" scores BLOCKED (not a gap),
      # while a compile error or a CHC timeout scores MISS (the tool could not analyze the file).
      # -s KILL: solc can be unresponsive to SIGTERM mid-z3-query, so force-kill at the deadline.
      # Per-query model-checker-timeout 8s + a 120s hard ceiling per file bound a runaway CHC.
      timeout -s KILL 120 /tmp/.solcx/solc-v"$ver" "$sol" \
        --model-checker-engine chc --model-checker-targets all \
        --model-checker-timeout 8000 --model-checker-show-unproved \
        > /dev/null 2> /tmp/mc.err; rc=$?
      if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
        : # CHC timed out (SIGTERM/SIGKILL) -> no raw file -> MISS (analysis did not complete)
      elif grep -qE '^Error:' /tmp/mc.err 2>/dev/null; then
        : # compilation failed -> no raw file -> MISS (could not analyze)
      else
        cp /tmp/mc.err "$out"
        [ -s "$out" ] || echo "Info: SMTCHECKER_CLEAN - compiled, no model-checker finding" > "$out"
      fi ;;
    solc)
      ver="$(pick_solc "$sol")"
      # Plain compiler run (no model checker): collect the solc DEFAULT diagnostics (warnings).
      # Same outcome classification as smtchecker: compile error / timeout -> MISS; a clean
      # compile with no warning -> BLOCKED (sentinel).
      timeout -s KILL 60 /tmp/.solcx/solc-v"$ver" "$sol" > /dev/null 2> /tmp/sc.err; rc=$?
      if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
        : # timed out -> MISS
      elif grep -qE '^Error:' /tmp/sc.err 2>/dev/null; then
        : # compile error -> MISS
      else
        cp /tmp/sc.err "$out"
        [ -s "$out" ] || echo "Info: SOLC_CLEAN - compiled, no warning" > "$out"
      fi ;;
  esac
  if [ -s "$out" ]; then echo "ok   $sol"; else echo "EMPTY $sol"; rm -f "$out"; fi
done < /out/sources.txt
INSCRIPT
)"

docker run --rm --cpus=4 --memory="$MEM_LIMIT" --memory-swap="$MEM_LIMIT" --pids-limit=1024 -e HOME=/tmp ${EXTRA[@]+"${EXTRA[@]}"} \
  -v "$REPO_ROOT":/src:ro -v "$OUTDIR":/out \
  --entrypoint sh "$IMAGE" -c "$IN_SCRIPT" _ "$TOOL" "$EXT" 2>&1 | tee "$OUTDIR/run.log" | \
  awk '/^INSTALL_FAIL/{print; f=1} /^EMPTY/{e++} /^ok/{o++} END{printf "  analyzed ok=%d empty=%d%s\n", o+0, e+0, (f?" (INSTALL FAILED)":"")}'

# delta run only re-analyzed a subset; record sources.txt as the FULL corpus raw/ now covers.
if [ "$DELTA" -ne 0 ]; then
  awk -F'\t' '$1!~/^#/ && NF>=4{print $4}' "$MAP" | sort -u > "$OUTDIR/sources.txt"
fi

# map raw -> verdicts (always over the FULL raw/ dir + the map, so a delta yields complete verdicts)
VFILE="$OUTDIR/verdicts.txt"
{
  echo "# $TOOL baseline verdicts - generated by bench/tools/run-baseline.sh on $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "# image=$IMAGE  mapping=bench/tools/map_verdicts.py (see META.md)"
  python3 "$REPO_ROOT/bench/tools/map_verdicts.py" "$TOOL" "$RAWDIR" --repo "$REPO_ROOT" 2>"$OUTDIR/map.log" | sort -u
} > "$VFILE"
echo "map summary: $(tail -1 "$OUTDIR/map.log")"
n="$(grep -cE '^\[' "$VFILE" || true)"
echo "wrote $n verdict lines -> $VFILE"
echo "score it:  bench/score.sh $VFILE"
