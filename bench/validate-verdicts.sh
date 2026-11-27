#!/usr/bin/env bash
#
# drain-bench - verdict-file validator (lint, not scorer).
#
# Checks a verdict file for the mistakes that bench/score.sh silently swallows, BEFORE you
# score or submit it. score.sh ignores every line that doesn't match the schema and
# `sort -u`s the rest, so a typo'd vector name, a conflicting duplicate, or a malformed
# line vanishes without warning and quietly skews the numbers. This script surfaces them.
#
# It does NOT score (no labels, no precision/recall) and never runs any suite - use
# bench/score.sh for that. It only lints the file against the dataset keys.
#
# VERDICT FILE FORMAT (same as score.sh; one line per scored target):
#     [<vector>] target=<target> verdict=<VULNERABLE|BLOCKED>
#   <vector>,<target> match [a-z0-9-]+. Blank lines and '#' comments are ignored.
#
# CHECKS:
#   MALFORMED - a line that looks like a verdict attempt (starts with '[', or contains
#               target=/verdict=) but does not match the schema exactly. Likely a typo;
#               score.sh would silently ignore it.
#   UNKNOWN   - a well-formed line whose (vector,target) is not in the manifest. The tool
#               reported on something that isn't in the dataset; score.sh ignores it.
#   CONFLICT  - the same (vector,target) given two DIFFERENT verdicts. score.sh keeps only
#               one (order-dependent) - a real, silent bug.
#   DUP       - the same (vector,target) repeated with the SAME verdict (harmless; noted).
#   MISS      - a manifest fixture with no verdict line (coverage gap). Informational: not
#               garbage - a tool may legitimately not cover every vector.
#
# Report-only by default (prints a summary, exits 0). --strict exits non-zero on any
# MALFORMED, UNKNOWN, or CONFLICT (the "garbage"); DUP and MISS never fail.
#
# Usage:
#   bench/validate-verdicts.sh <verdicts-file> [--manifest <path>] [--strict]
#     --manifest  dataset manifest TSV (default: bench/dataset/manifest.tsv)
#     --strict    exit non-zero on MALFORMED / UNKNOWN / CONFLICT

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="$SCRIPT_DIR/dataset/manifest.tsv"
STRICT=0
VFILE=""

while [ $# -gt 0 ]; do
  case "$1" in
    --manifest) if [ $# -lt 2 ]; then echo "error: --manifest needs a path argument" >&2; exit 2; fi
                MANIFEST="$2"; shift 2 ;;
    --strict)   STRICT=1; shift ;;
    -h|--help)  grep -E '^#' "$0" | sed -E 's/^# ?//'; exit 0 ;;
    -*)         echo "unknown option: $1" >&2; exit 2 ;;
    *)          if [ -z "$VFILE" ]; then VFILE="$1"; else echo "unexpected arg: $1" >&2; exit 2; fi; shift ;;
  esac
done

if [ -z "$VFILE" ]; then
  echo "usage: bench/validate-verdicts.sh <verdicts-file> [--manifest <path>] [--strict]" >&2
  exit 2
fi
[ -f "$VFILE" ]    || { echo "error: verdict file not found: $VFILE" >&2; exit 2; }
[ -f "$MANIFEST" ] || { echo "error: manifest not found: $MANIFEST (run bench/tools/gen-manifest.sh)" >&2; exit 2; }

SCHEMA='^\[[a-z0-9-]+\] target=[a-z0-9-]+ verdict=(VULNERABLE|BLOCKED)$'

# --- 1. load manifest keys (skip comments + header) ---
declare -A known
nfix=0
while IFS=$'\t' read -r vector tier target lbl split test source_dir provenance; do
  case "$vector" in '#'*|vector|'') continue ;; esac
  known["$vector/$target"]=1
  nfix=$((nfix+1))
done < "$MANIFEST"
[ "$nfix" -gt 0 ] || { echo "error: no labeled entries in $MANIFEST" >&2; exit 2; }

# --- 2. walk the verdict file line by line (no dedup - we WANT to see duplicates) ---
declare -A seen_verdict      # key -> first verdict seen
declare -A seen_count        # key -> how many well-formed lines for it
MALFORMED=(); UNKNOWN=(); CONFLICT=(); DUP=()
nvalid=0; lineno=0

while IFS= read -r line || [ -n "$line" ]; do
  lineno=$((lineno+1))
  line="${line%$'\r'}"                             # tolerate CRLF
  case "$line" in ''|'#'*) continue ;; esac        # blank / comment: ignored
  if [[ "$line" =~ $SCHEMA ]]; then
    vec="$(sed -E 's/^\[([a-z0-9-]+)\].*/\1/' <<<"$line")"
    tgt="$(sed -E 's/.*target=([a-z0-9-]+).*/\1/' <<<"$line")"
    vrd="$(sed -E 's/.*verdict=([A-Z]+).*/\1/' <<<"$line")"
    key="$vec/$tgt"
    nvalid=$((nvalid+1))
    if [ -z "${known[$key]+x}" ]; then
      UNKNOWN+=("line $lineno: $key (not in manifest)")
    fi
    if [ -n "${seen_count[$key]+x}" ]; then
      if [ "${seen_verdict[$key]}" != "$vrd" ]; then
        CONFLICT+=("$key: ${seen_verdict[$key]} vs $vrd (line $lineno)")
      else
        DUP+=("$key=$vrd (line $lineno)")
      fi
      seen_count[$key]=$(( ${seen_count[$key]} + 1 ))
    else
      seen_verdict[$key]="$vrd"
      seen_count[$key]=1
    fi
  else
    # not schema-valid: flag only if it looks like an attempted verdict
    case "$line" in
      \[*|*target=*|*verdict=*) MALFORMED+=("line $lineno: $line") ;;
      *) : ;;                                       # free-text note: ignored, like score.sh
    esac
  fi
done < "$VFILE"

# --- 3. coverage: manifest keys with no well-formed verdict line ---
MISS=()
for key in "${!known[@]}"; do
  [ -z "${seen_count[$key]+x}" ] && MISS+=("$key")
done

# --- 4. report ---
echo "== drain-bench verdict validation =="
echo "verdicts : $VFILE"
echo "manifest : $MANIFEST ($nfix fixtures)"
echo "parsed   : $nvalid well-formed verdict line(s), covering $(( ${#seen_count[@]} )) distinct target(s)"
echo

emit() { # emit <label> <array-name...>
  local label="$1"; shift
  local -n arr="$1"
  local n="${#arr[@]}"
  if [ "$n" -eq 0 ]; then
    printf '  %-10s 0\n' "$label:"
  else
    printf '  %-10s %d\n' "$label:" "$n"
    local item; for item in "${arr[@]}"; do printf '      - %s\n' "$item"; done
  fi
}

echo "findings:"
emit "MALFORMED" MALFORMED
emit "UNKNOWN"   UNKNOWN
emit "CONFLICT"  CONFLICT
emit "DUP"       DUP
# MISS can be large; print the count and (only) the list when small.
if [ "${#MISS[@]}" -eq 0 ]; then
  printf '  %-10s 0\n' "MISS:"
else
  printf '  %-10s %d (coverage gap - informational)\n' "MISS:" "${#MISS[@]}"
  if [ "${#MISS[@]}" -le 12 ]; then
    for key in $(printf '%s\n' "${MISS[@]}" | sort); do printf '      - %s\n' "$key"; done
  else
    echo "      (list suppressed; >12 - run bench/score.sh to see per-vector MISS)"
  fi
fi
echo

ngarbage=$(( ${#MALFORMED[@]} + ${#UNKNOWN[@]} + ${#CONFLICT[@]} ))
if [ "$STRICT" -eq 1 ]; then
  if [ "$ngarbage" -ne 0 ]; then
    echo "== VALIDATE: FAIL (strict) - $ngarbage problem(s): ${#MALFORMED[@]} MALFORMED, ${#UNKNOWN[@]} UNKNOWN, ${#CONFLICT[@]} CONFLICT =="
    exit 1
  fi
  echo "== VALIDATE: OK (strict) - schema clean, 0 MALFORMED/UNKNOWN/CONFLICT (${#DUP[@]} DUP, ${#MISS[@]} MISS allowed) =="
else
  if [ "$ngarbage" -ne 0 ]; then
    echo "== VALIDATE: $ngarbage problem(s) found (report-only; re-run with --strict to fail) =="
  else
    echo "== VALIDATE: clean (report-only) =="
  fi
fi
