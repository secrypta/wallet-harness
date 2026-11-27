#!/usr/bin/env bash
#
# wallet-harness CTF - "patch the drain" training runner.
#
# This sits on top of the frozen drain corpus: every challenge is one wallet-drain
# vector served as a vulnerable contract you must FIX. A hidden exploit test (the gate)
# then checks two things at once, inside Docker:
#
#   * SECURITY     - the drain exploit no longer empties the wallet, AND
#   * FUNCTIONALITY - the legitimate operation the contract is for still works.
#
# You only pass when BOTH hold. Deleting the feature to dodge the exploit fails the
# functionality check; leaving the hole fails the security check. That two-sided gate is
# the same bar the benchmark uses (catch the vector on the vulnerable side, stay correct
# on the safe side), expressed as a puzzle.
#
# Usage:
#   ctf/ctf.sh list                 # list challenges
#   ctf/ctf.sh start   <challenge>   # seed a work copy you edit: ctf/work/<challenge>/src/Challenge.sol
#   ctf/ctf.sh solve   <challenge>   # run the hidden gate against your edited copy (Docker)
#   ctf/ctf.sh reset   <challenge>   # throw away your work copy and re-seed from scratch
#   ctf/ctf.sh hint    <challenge>   # print just the hint from the brief
#   ctf/ctf.sh diff    <challenge>   # show what you changed vs the vulnerable seed
#   ctf/ctf.sh selftest [challenge]  # ground-truth check: gate must FAIL on seed, PASS on solution
#   ctf/ctf.sh doctor                # check prerequisites (Docker daemon, forge-std, container cap)
#
# Requires: Docker + the ghcr.io/foundry-rs/foundry image, and lib/forge-std in the repo
#           (see the top-level README for the pinned forge-std clone command).
#
# Border rule: these contracts are deliberately vulnerable toys. Never deploy them to a
# real network. Everything runs offline in Docker.

set -euo pipefail

IMAGE="ghcr.io/foundry-rs/foundry:stable"
MEM_LIMIT="2g"
MAX_CONTAINERS=3

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CTF_DIR="$REPO_ROOT/ctf"
CH_DIR="$CTF_DIR/challenges"
WORK_DIR="$CTF_DIR/work"
PROGRESS_FILE="$WORK_DIR/.solved"   # local offline progress tracker (under gitignored work/)

# Color only when stdout is a real terminal (and NO_COLOR is unset). Decided ONCE here at
# top level: inside a $(...) command substitution stdout is a pipe, so a per-call `[ -t 1 ]`
# would wrongly disable color even in an interactive terminal.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then COLOR=1; else COLOR=0; fi
c_red()  { if [ "$COLOR" = 1 ]; then printf '\033[31m%s\033[0m' "$1"; else printf '%s' "$1"; fi; }
c_grn()  { if [ "$COLOR" = 1 ]; then printf '\033[32m%s\033[0m' "$1"; else printf '%s' "$1"; fi; }
c_dim()  { if [ "$COLOR" = 1 ]; then printf '\033[2m%s\033[0m'  "$1"; else printf '%s' "$1"; fi; }

die() { echo "error: $*" >&2; exit 1; }

# --- meta helpers ---------------------------------------------------------------
meta_get() { # <challenge> <key>
  local f="$CH_DIR/$1/meta"
  [ -f "$f" ] || return 1
  sed -n "s/^$2=//p" "$f" | head -1
}

challenge_exists() { [ -d "$CH_DIR/$1" ] && [ -f "$CH_DIR/$1/meta" ]; }

list_challenges() { # bare names, sorted
  find "$CH_DIR" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null | sort
}

# --- progress (local, offline; stored under gitignored ctf/work/) ---------------
is_solved()   { [ -f "$PROGRESS_FILE" ] && grep -qxF "$1" "$PROGRESS_FILE" 2>/dev/null; }
mark_solved() { mkdir -p "$WORK_DIR"; is_solved "$1" || printf '%s\n' "$1" >> "$PROGRESS_FILE"; }

# --- ordering helpers -----------------------------------------------------------
diff_rank() { case "$1" in intro) echo 0 ;; core) echo 1 ;; advanced) echo 2 ;; *) echo 3 ;; esac; }
# Challenges newest-learner-first: intro -> core -> advanced, then name.
list_by_difficulty() {
  local ch d
  while IFS= read -r ch; do
    [ -z "$ch" ] && continue
    d="$(meta_get "$ch" difficulty || echo '?')"
    printf '%s\t%s\n' "$(diff_rank "$d")" "$ch"
  done < <(list_challenges) | sort -k1,1n -k2,2 | cut -f2
}
next_unsolved() { # first unsolved challenge in difficulty order, or empty
  local ch
  while IFS= read -r ch; do is_solved "$ch" || { printf '%s' "$ch"; return; }; done < <(list_by_difficulty)
}

# --- preflight ------------------------------------------------------------------
preflight_docker() {
  command -v docker >/dev/null 2>&1 || die "docker not found on PATH"
  [ -f "$REPO_ROOT/lib/forge-std/src/Test.sol" ] || die \
    "lib/forge-std not found - clone it first (see README)"
  local running
  running="$(docker ps -q 2>/dev/null | wc -l | tr -d ' ')"
  if [ "$running" -ge "$MAX_CONTAINERS" ]; then
    die "$running containers already running (cap $MAX_CONTAINERS on this shared VM). Free one first."
  fi
}

# --- work-dir layout ------------------------------------------------------------
# A challenge work copy is a standalone Foundry project under ctf/work/<challenge>/:
#   foundry.toml      - remaps forge-std to the repo's copy (mounted read-only in Docker)
#   src/Challenge.sol  - the contract you edit (seeded from the vulnerable version)
#   test/             - the hidden gate is dropped here only for the duration of `solve`
write_work_foundry_toml() { # <work>
  cat > "$1/foundry.toml" <<'TOML'
[profile.default]
src = "src"
test = "test"
out = "out"
libs = []
# forge-std is mounted read-only at /repo in Docker; remap to it so the work copy
# stays standalone and compiles only the challenge contract + the gate test.
remappings = ["forge-std/=/repo/lib/forge-std/src/"]
auto_detect_solc = true
optimizer = true
optimizer_runs = 200
TOML
}

seed_work() { # <challenge>  -> creates ctf/work/<challenge>
  local ch="$1" work="$WORK_DIR/$1"
  rm -rf "$work"
  mkdir -p "$work/src" "$work/test"
  cp "$CH_DIR/$ch/seed/Challenge.sol" "$work/src/Challenge.sol"
  write_work_foundry_toml "$work"
}

# Run the hidden gate in Docker against <srcfile> as src/Challenge.sol of a throwaway
# project. Echoes the gate verdict line and returns forge's exit code.
run_gate() { # <challenge> <srcfile>  (srcfile is an absolute path inside the repo)
  local ch="$1" srcfile="$2"
  local tmp="$WORK_DIR/.gate-$ch"
  rm -rf "$tmp"; mkdir -p "$tmp/src" "$tmp/test"
  cp "$srcfile" "$tmp/src/Challenge.sol"
  cp "$CH_DIR/$ch/hidden/"*.sol "$tmp/test/"
  write_work_foundry_toml "$tmp"

  # Mount the repo read-only (it carries both forge-std and this throwaway project, which
  # lives under ctf/work/). The container's non-root user can't write into a bind mount, so
  # - like harness/run.sh - copy the project to a writable /tmp inside the container and
  # build there. The foundry image's entrypoint is `forge`, so drive it via `sh -c`.
  local rel="${tmp#$REPO_ROOT/}"
  local rc=0
  docker run --rm \
    --memory "$MEM_LIMIT" \
    -e HOME=/tmp \
    -v "$REPO_ROOT":/repo:ro \
    --entrypoint sh \
    "$IMAGE" \
    -c "cp -r /repo/$rel /tmp/w && cd /tmp/w && forge test --match-path 'test/Exploit.t.sol' -vv" \
    2>&1 | sed 's/^/    /' || rc=$?
  rm -rf "$tmp"
  return $rc
}

# --- subcommands ----------------------------------------------------------------
cmd_list() {
  local n; n="$(list_challenges | wc -l | tr -d ' ')"
  local solved=0
  echo "wallet-harness CTF - $n challenge(s):"
  echo
  local ch
  while IFS= read -r ch; do
    [ -z "$ch" ] && continue
    local vec diff title mark
    vec="$(meta_get "$ch" vector || echo '?')"
    diff="$(meta_get "$ch" difficulty || echo '?')"
    title="$(meta_get "$ch" title || echo '')"
    if is_solved "$ch"; then mark="$(c_grn '✓')"; solved=$((solved+1)); else mark="$(c_dim '-')"; fi
    printf '  %s %-26s %-10s %s\n' "$mark" "$ch" "[$diff]" "$title"
    [ -n "$vec" ] && printf '        %s\n' "$(c_dim "vector: $vec")"
  done < <(list_by_difficulty)
  echo
  local nxt; nxt="$(next_unsolved)"
  if [ -n "$nxt" ]; then
    printf 'solved %d/%d.  Next:  ctf/ctf.sh start %s\n' "$solved" "$n" "$nxt"
  else
    printf 'solved %d/%d - all challenges solved. Nice.\n' "$solved" "$n"
  fi
}

cmd_start() {
  local ch="${1:-}"; [ -n "$ch" ] || die "usage: ctf.sh start <challenge>"
  challenge_exists "$ch" || die "no such challenge: $ch (see 'ctf.sh list')"
  if [ -d "$WORK_DIR/$ch" ]; then
    echo "work copy already exists at ctf/work/$ch/ - use 'reset' to start over." >&2
  else
    seed_work "$ch"
  fi
  echo "== CTF challenge: $ch =="
  echo
  cat "$CH_DIR/$ch/prompt.md"
  echo
  echo "Edit:  $(c_dim "ctf/work/$ch/src/Challenge.sol")"
  echo "Check: ctf/ctf.sh solve $ch"
}

cmd_solve() {
  local ch="${1:-}"; [ -n "$ch" ] || die "usage: ctf.sh solve <challenge>"
  challenge_exists "$ch" || die "no such challenge: $ch"
  local src="$WORK_DIR/$ch/src/Challenge.sol"
  [ -f "$src" ] || die "no work copy - run 'ctf.sh start $ch' first"
  preflight_docker
  echo "== gate: $ch =="
  echo "running the hidden exploit test against your copy (Docker $IMAGE) ..."
  echo
  local gatelog rc=0
  gatelog="$(mktemp "${TMPDIR:-/tmp}/ctf-solve.XXXXXX")"
  set +e
  run_gate "$ch" "$src" | tee "$gatelog"
  rc=${PIPESTATUS[0]}
  set -e
  echo
  # Parse the two-sided verdict the hidden gate prints ([ctf:<ch>] check=... result=...).
  local sec func
  sec="$(grep -oE 'check=security result=[^ ]+' "$gatelog" | head -1 | sed -E 's/.*result=//')"
  func="$(grep -oE 'check=functionality result=[^ ]+' "$gatelog" | head -1 | sed -E 's/.*result=//')"
  rm -f "$gatelog"
  echo "GATE:"
  echo "  security:      ${sec:-?}   (the drain must be blocked)"
  echo "  functionality: ${func:-?}   (the legitimate feature must still work)"
  echo
  if [ "$rc" -eq 0 ]; then
    mark_solved "$ch"
    echo "$(c_grn 'SOLVED') - the drain is patched and the feature still works."
    local vec title nxt
    vec="$(meta_get "$ch" vector || echo '?')"
    title="$(meta_get "$ch" title || echo '')"
    echo
    echo "Why it mattered: $title"
    echo "  mechanism: $(c_dim "corpus/$vec.md")   reference fix: $(c_dim "ctf/challenges/$ch/solution/Challenge.sol")"
    nxt="$(next_unsolved)"
    [ -n "$nxt" ] && echo "Next: ctf/ctf.sh start $nxt"
  else
    echo "$(c_red 'NOT SOLVED') - fix the side shown FAIL above; both must be OK to pass."
  fi
  return $rc
}

cmd_reset() {
  local ch="${1:-}"; [ -n "$ch" ] || die "usage: ctf.sh reset <challenge>"
  challenge_exists "$ch" || die "no such challenge: $ch"
  seed_work "$ch"
  echo "re-seeded ctf/work/$ch/src/Challenge.sol from the vulnerable original."
}

# Ground-truth check: a well-formed challenge must FAIL the gate on its seed (the hole is
# real) and PASS on its reference solution (the fix is reachable). This is the CTF analog
# of the benchmark's "catch on vulnerable, stay silent on safe" bar.
cmd_selftest() {
  preflight_docker
  local only="${1:-}"
  local fails=0 total=0
  local ch
  while IFS= read -r ch; do
    [ -z "$ch" ] && continue
    [ -n "$only" ] && [ "$ch" != "$only" ] && continue
    total=$((total+1))
    echo "== selftest: $ch =="

    echo "  [seed] expect gate FAIL (vulnerability is real):"
    local rc_seed=0
    run_gate "$ch" "$CH_DIR/$ch/seed/Challenge.sol" >/dev/null 2>&1 || rc_seed=$?
    if [ "$rc_seed" -ne 0 ]; then echo "    $(c_grn OK) gate rejected the vulnerable seed"; else
      echo "    $(c_red FAIL) gate PASSED the vulnerable seed (challenge is broken)"; fails=$((fails+1)); fi

    echo "  [solution] expect gate PASS (fix is reachable):"
    local rc_sol=0
    run_gate "$ch" "$CH_DIR/$ch/solution/Challenge.sol" >/dev/null 2>&1 || rc_sol=$?
    if [ "$rc_sol" -eq 0 ]; then echo "    $(c_grn OK) gate accepted the reference solution"; else
      echo "    $(c_red FAIL) gate REJECTED the reference solution (gate too strict / fix wrong)"; fails=$((fails+1)); fi
    echo
  done < <(list_challenges)

  [ "$total" -gt 0 ] || die "no challenges matched"
  if [ "$fails" -eq 0 ]; then
    echo "$(c_grn "selftest OK") - $total challenge(s), seed->FAIL and solution->PASS on all."
  else
    echo "$(c_red "selftest FAILED") - $fails problem(s) across $total challenge(s)."
    return 1
  fi
}

cmd_hint() {
  local ch="${1:-}"; [ -n "$ch" ] || die "usage: ctf.sh hint <challenge>"
  challenge_exists "$ch" || die "no such challenge: $ch"
  local h
  h="$(awk '/^> *[Hh]int/{f=1} f==1 && /^>/{s=$0; sub(/^> ?/,"",s); print s; next} f==1{exit}' "$CH_DIR/$ch/prompt.md")"
  if [ -n "$h" ]; then printf '%s\n' "$h"; else
    echo "no standalone hint for '$ch' - read the full brief: ctf/ctf.sh start $ch"
  fi
}

cmd_diff() {
  local ch="${1:-}"; [ -n "$ch" ] || die "usage: ctf.sh diff <challenge>"
  challenge_exists "$ch" || die "no such challenge: $ch"
  local seed="$CH_DIR/$ch/seed/Challenge.sol" work="$WORK_DIR/$ch/src/Challenge.sol"
  [ -f "$work" ] || die "no work copy - run 'ctf.sh start $ch' first"
  if diff -u -L "seed (vulnerable original)" -L "your work copy" "$seed" "$work"; then
    echo "(no changes yet vs the vulnerable seed - edit $work)"
  fi
}

# Prerequisite check: Docker present + daemon up, forge-std cloned, container headroom.
# Gives an explicit fix for each missing piece instead of failing cryptically later.
cmd_doctor() {
  local ok=1 have_docker=0
  echo "== wallet-harness CTF doctor =="
  if command -v docker >/dev/null 2>&1; then
    have_docker=1
    echo "  $(c_grn OK)   docker found ($(docker --version 2>/dev/null | head -1))"
  else
    echo "  $(c_red MISS) docker not on PATH - install Docker: https://docs.docker.com/get-docker/"; ok=0
  fi
  if [ "$have_docker" -eq 1 ] && docker info >/dev/null 2>&1; then
    echo "  $(c_grn OK)   docker daemon reachable"
  else
    echo "  $(c_red MISS) docker daemon not reachable - start Docker and retry"; ok=0
  fi
  if [ -f "$REPO_ROOT/lib/forge-std/src/Test.sol" ]; then
    echo "  $(c_grn OK)   lib/forge-std present"
  else
    echo "  $(c_red MISS) lib/forge-std missing - clone it (pinned):"
    echo "         git clone --depth 1 --branch v1.9.4 \\"
    echo "           https://github.com/foundry-rs/forge-std lib/forge-std"; ok=0
  fi
  if [ "$have_docker" -eq 1 ] && docker info >/dev/null 2>&1; then
    local running; running="$(docker ps -q 2>/dev/null | wc -l | tr -d ' ')"
    if [ "$running" -lt "$MAX_CONTAINERS" ]; then
      echo "  $(c_grn OK)   $running/$MAX_CONTAINERS containers running (room to run a gate)"
    else
      echo "  $(c_red WARN) $running containers running (cap $MAX_CONTAINERS) - free one before 'solve'"
    fi
  fi
  echo
  if [ "$ok" -eq 1 ]; then
    echo "$(c_grn 'ready') - try: ctf/ctf.sh list"
  else
    echo "$(c_red 'not ready') - fix the MISS line(s) above, then re-run: ctf/ctf.sh doctor"
    return 1
  fi
}

# --- dispatch -------------------------------------------------------------------
cmd="${1:-list}"; shift || true
case "$cmd" in
  list)     cmd_list "$@" ;;
  start)    cmd_start "$@" ;;
  solve)    cmd_solve "$@" ;;
  reset)    cmd_reset "$@" ;;
  hint)     cmd_hint "$@" ;;
  diff)     cmd_diff "$@" ;;
  selftest) cmd_selftest "$@" ;;
  doctor)   cmd_doctor "$@" ;;
  -h|--help|help) sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//' ;;
  *) die "unknown command: $cmd (try: list | start | solve | hint | diff | reset | selftest | doctor)" ;;
esac
