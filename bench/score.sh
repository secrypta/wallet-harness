#!/usr/bin/env bash
#
# drain-bench - tool-agnostic scorer.
#
# Scores ANY detector's verdicts against the dataset ground truth. Unlike the wal
# harness (harness/benchmark.sh), this script does NOT run any suite - it takes a plain
# verdict file produced by whatever tool you ran, joins it to the dataset labels, and
# prints a confusion matrix, precision/recall/F1, and a per-vector breakdown.
#
# VERDICT FILE FORMAT (one line per scored target; extra lines are ignored):
#     [<vector>] target=<target> verdict=<VULNERABLE|BLOCKED>
#   <vector>,<target> match [a-z0-9-]+. VULNERABLE = "tool flagged a drain"; BLOCKED =
#   "tool stayed silent / judged safe". Map your tool's output to this schema yourself
#   (that mapping is a judgement call - document it alongside your results).
#
# SCORING (per dataset entry, keyed by the pair (vector,target)):
#     label vuln + VULNERABLE = TP     label vuln + BLOCKED = FN
#     label safe + BLOCKED    = TN     label safe + VULNERABLE = FP
#   A labeled entry with no matching verdict line is a coverage gap (MISS) - the tool did
#   not report on it. MISS is shown but, by default, does not fail the run.
#
# HONESTY: the wal detectors were tuned against every `dev`-split fixture, so wal's own
# numbers here are a sanity-check, not an independent result. See bench/README.md.
#
# Usage:
#   bench/score.sh <verdicts-file> [--manifest <path>] [--split dev|holdout|all]
#                  [--tier a|b|c|bc|all] [--strict]
#   bench/score.sh --list     [--split ...] [--tier ...]   # just print the targets to score
#   bench/score.sh --template [--split ...] [--tier ...]   # print a fillable verdict file
#     --list      print the (vector, target) pairs you must produce verdicts for, then exit.
#                 No verdict file needed. Labels are NOT shown - score blind, then compare.
#     --template  like --list but emits ready-to-fill "[vec] target=t verdict=" lines.
#     --json      emit a single machine-readable JSON result (counts, metrics, misses) instead
#                 of the human tables. Composes with --strict (exit 1 on FP/FN/MISS).
#     --manifest  dataset manifest TSV (default: bench/dataset/manifest.tsv)
#     --split     score only this split, or all (default: all)
#     --tier      score only this tier (default: all). Tiers: a = synthetic toy
#                 (illustrative contract-of-record / smoke, not a headline result);
#                 b = minimized real public incidents; c = real published safe code.
#                 `bc` = the all-real headline slice (real incidents + real safe code,
#                 no synthetic fixtures). Composes with --split.
#     --strict    exit non-zero on any FP, FN, or MISS (for our own CI; off for 3rd-party)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="$SCRIPT_DIR/dataset/manifest.tsv"
SPLIT="all"
TIER="all"
STRICT=0
LIST=0
TEMPLATE=0
JSON=0
VFILE=""

while [ $# -gt 0 ]; do
  case "$1" in
    --manifest) MANIFEST="$2"; shift 2 ;;
    --split)    SPLIT="$2"; shift 2 ;;
    --tier)     TIER="$2"; shift 2 ;;
    --strict)   STRICT=1; shift ;;
    --list)     LIST=1; shift ;;
    --template) TEMPLATE=1; shift ;;
    --json)     JSON=1; shift ;;
    -h|--help)  grep -E '^#' "$0" | sed -E 's/^# ?//'; exit 0 ;;
    -*)         echo "unknown option: $1" >&2; exit 2 ;;
    *)          if [ -z "$VFILE" ]; then VFILE="$1"; else echo "unexpected arg: $1" >&2; exit 2; fi; shift ;;
  esac
done

NEEDVF=1; { [ "$LIST" -eq 1 ] || [ "$TEMPLATE" -eq 1 ]; } && NEEDVF=0
if [ "$NEEDVF" -eq 1 ] && [ -z "$VFILE" ]; then
  echo "usage: bench/score.sh <verdicts-file> [--manifest <path>] [--split dev|holdout|all] [--strict] [--json]" >&2
  echo "       bench/score.sh --list       [--split ...] [--tier ...]   # print the targets to score" >&2
  echo "       bench/score.sh --template   [--split ...] [--tier ...]   # print a fillable verdict file" >&2
  exit 2
fi
[ -z "$VFILE" ] || [ -f "$VFILE" ] || { echo "error: verdict file not found: $VFILE" >&2; exit 2; }
[ -f "$MANIFEST" ] || { echo "error: manifest not found: $MANIFEST (run bench/tools/gen-manifest.sh)" >&2; exit 2; }
case "$SPLIT" in dev|holdout|all) ;; *) echo "error: --split must be dev|holdout|all" >&2; exit 2 ;; esac
case "$TIER" in a|b|c|bc|all) ;; *) echo "error: --tier must be a|b|c|bc|all" >&2; exit 2 ;; esac

# Does a fixture's tier pass the --tier filter? bc = b or c (the all-real slice).
tier_match() { # <tier>
  case "$TIER" in
    all) return 0 ;;
    bc)  [ "$1" = "b" ] || [ "$1" = "c" ] ;;
    *)   [ "$1" = "$TIER" ] ;;
  esac
}

# --- 1. load labels from the manifest (skip comments + header row) ---
declare -A label
declare -A vcount_vuln vcount_safe
vectors=""
nfix=0
while IFS=$'\t' read -r vector tier target lbl split test source_dir provenance; do
  case "$vector" in '#'*|vector|'') continue ;; esac
  [ "$SPLIT" = "all" ] || [ "$split" = "$SPLIT" ] || continue
  tier_match "$tier" || continue
  key="$vector/$target"
  label["$key"]="$lbl"
  case " $vectors " in *" $vector "*) ;; *) vectors="$vectors $vector" ;; esac
  nfix=$((nfix+1))
done < "$MANIFEST"

if [ "$nfix" -eq 0 ]; then
  echo "error: no labeled entries for split='$SPLIT' tier='$TIER' in $MANIFEST" >&2; exit 2
fi

# --- 1b. --list: print the targets to produce verdicts for, then exit ---
if [ "$LIST" -eq 1 ]; then
  echo "== drain-bench targets (split=$SPLIT, tier=$TIER, $nfix fixtures) =="
  echo "Produce ONE verdict line per target below, in this format:"
  echo "  [<vector>] target=<target> verdict=<VULNERABLE|BLOCKED>"
  echo "(labels are intentionally not shown - score blind, then run bench/score.sh to compare.)"
  echo
  printf '%-24s %s\n' "VECTOR" "TARGET"
  printf '%s\n' "------------------------------------------------------------"
  for key in $(printf '%s\n' "${!label[@]}" | sort); do
    printf '%-24s %s\n' "${key%%/*}" "${key#*/}"
  done
  exit 0
fi

# --- 1c. --template: print a fillable verdict file (one line per target), then exit ---
if [ "$TEMPLATE" -eq 1 ]; then
  echo "# drain-bench verdict template (split=$SPLIT, tier=$TIER, $nfix targets)."
  echo "# Fill each verdict= with VULNERABLE (tool flags a drain) or BLOCKED (tool stays silent),"
  echo "# then: bench/score.sh <this-file> --split $SPLIT"
  echo "# Unfilled lines score as MISS (coverage gap), never a guessed verdict."
  for key in $(printf '%s\n' "${!label[@]}" | sort); do
    printf '[%s] target=%s verdict=\n' "${key%%/*}" "${key#*/}"
  done
  exit 0
fi

# --- 2. load verdicts from the tool's output file ---
declare -A verdict
CONFLICTS=0
while IFS= read -r line; do
  v="$(sed -E 's/^\[([a-z0-9-]+)\].*/\1/' <<<"$line")"
  t="$(sed -E 's/.*target=([a-z0-9-]+).*/\1/' <<<"$line")"
  r="$(sed -E 's/.*verdict=([A-Z]+).*/\1/' <<<"$line")"
  key="$v/$t"
  # A verdict file must assign each (vector,target) exactly one verdict. If the same key
  # appears with BOTH verdicts, the matrix below would silently count whichever sorts last.
  # Surface it instead of guessing (validate-verdicts.sh also flags this as CONFLICT).
  if [ -n "${verdict[$key]+x}" ] && [ "${verdict[$key]}" != "$r" ]; then
    echo "WARNING: conflicting verdicts for [$v] target=$t (${verdict[$key]} vs $r) in $VFILE" >&2
    CONFLICTS=$((CONFLICTS+1))
  fi
  verdict["$key"]="$r"
done < <(grep -oE '\[[a-z0-9-]+\] target=[a-z0-9-]+ verdict=(VULNERABLE|BLOCKED)' "$VFILE" | sort -u)

# --- 3. score ---
TP=0; FP=0; FN=0; TN=0; MISS=0
declare -A vtp vfp vfn vtn vmiss
misslist=()   # actionable rows: only FP / FN / MISS (what the tool got wrong)
jmiss=()      # same rows as JSON objects (for --json)
for vec in $vectors; do vtp[$vec]=0; vfp[$vec]=0; vfn[$vec]=0; vtn[$vec]=0; vmiss[$vec]=0; done

if [ "$JSON" -eq 0 ]; then
  echo "== drain-bench score =="
  echo "verdicts : $VFILE"
  echo "manifest : $MANIFEST  (split=$SPLIT, tier=$TIER, $nfix labeled fixtures)"
  echo
  printf '%-22s %-20s %-5s %-11s %-4s\n' "VECTOR" "TARGET" "LABEL" "VERDICT" "CELL"
  printf '%s\n' "----------------------------------------------------------------------"
fi
for key in $(printf '%s\n' "${!label[@]}" | sort); do
  lbl="${label[$key]}"
  vrd="${verdict[$key]:-<none>}"
  vector="${key%%/*}"; target="${key#*/}"
  cell="?"
  if [ "$vrd" = "<none>" ]; then
    cell="MISS"; MISS=$((MISS+1)); vmiss[$vector]=$((vmiss[$vector]+1))
  elif [ "$lbl" = "vuln" ] && [ "$vrd" = "VULNERABLE" ]; then
    cell="TP"; TP=$((TP+1)); vtp[$vector]=$((vtp[$vector]+1))
  elif [ "$lbl" = "vuln" ] && [ "$vrd" = "BLOCKED" ]; then
    cell="FN"; FN=$((FN+1)); vfn[$vector]=$((vfn[$vector]+1))
  elif [ "$lbl" = "safe" ] && [ "$vrd" = "BLOCKED" ]; then
    cell="TN"; TN=$((TN+1)); vtn[$vector]=$((vtn[$vector]+1))
  elif [ "$lbl" = "safe" ] && [ "$vrd" = "VULNERABLE" ]; then
    cell="FP"; FP=$((FP+1)); vfp[$vector]=$((vfp[$vector]+1))
  fi
  [ "$JSON" -eq 0 ] && printf '%-22s %-20s %-5s %-11s %-4s\n' "$vector" "$target" "$lbl" "$vrd" "$cell"
  case "$cell" in
    FP|FN|MISS)
      misslist+=("$(printf '%-6s %-22s %-20s %-5s %s' "$cell" "$vector" "$target" "$lbl" "$vrd")")
      jmiss+=("$(printf '{"cell":"%s","vector":"%s","target":"%s","label":"%s","verdict":"%s"}' "$cell" "$vector" "$target" "$lbl" "$vrd")")
      ;;
  esac
done

# --- 4. per-vector breakdown ---
if [ "$JSON" -eq 0 ]; then
  echo
  echo "== per-vector =="
  printf '%-22s %3s %3s %3s %3s %5s\n' "VECTOR" "TP" "FP" "FN" "TN" "MISS"
  for vec in $(printf '%s\n' $vectors | sort); do
    printf '%-22s %3d %3d %3d %3d %5d\n' "$vec" "${vtp[$vec]}" "${vfp[$vec]}" "${vfn[$vec]}" "${vtn[$vec]}" "${vmiss[$vec]}"
  done
fi

# --- 5. metrics ---
metric() { # metric <num> <den> ; prints x.xxx or n/a
  if [ "$2" -gt 0 ]; then LC_NUMERIC=C awk "BEGIN{printf \"%.3f\", $1/$2}"; else echo "n/a"; fi
}
prec="$(metric "$TP" "$((TP+FP))")"
rec="$(metric "$TP" "$((TP+FN))")"
f1="n/a"
if [ "$((TP+FP))" -gt 0 ] && [ "$((TP+FN))" -gt 0 ] && [ "$TP" -gt 0 ]; then
  f1="$(LC_NUMERIC=C awk "BEGIN{p=$TP/($TP+$FP); r=$TP/($TP+$FN); printf \"%.3f\", 2*p*r/(p+r)}")"
fi

if [ "$JSON" -eq 0 ]; then
  echo
  echo "== confusion matrix =="
  echo "  TP=$TP  FP=$FP  FN=$FN  TN=$TN  (MISS=$MISS)"
  echo "  precision=$prec  recall=$rec  F1=$f1"
  echo

  # --- 5b. actionable misses: just the rows the tool got wrong (FP/FN) or skipped (MISS) ---
  if [ "${#misslist[@]}" -gt 0 ]; then
    echo "== what to look at (${#misslist[@]}) =="
    echo "  FP   = flagged safe code as a drain (false alarm)"
    echo "  FN   = called a real drain safe (missed bug)"
    echo "  MISS = no verdict produced for this fixture (coverage gap)"
    echo
    printf '  %-6s %-22s %-20s %-5s %s\n' "CELL" "VECTOR" "TARGET" "LABEL" "VERDICT"
    printf '  %s\n' "----------------------------------------------------------------------"
    for row in "${misslist[@]}"; do printf '  %s\n' "$row"; done
    echo
  else
    echo "== clean: no FP / FN / MISS - every scored fixture matched its label =="
    echo
  fi
fi

# --- 5c. --json: single machine-readable object on stdout, then exit by strict rules ---
if [ "$JSON" -eq 1 ]; then
  jnum() { if [ "$2" -gt 0 ] && [ "$1" != "n/a" ]; then printf '%s' "$1"; else printf 'null'; fi; }
  jp="$(jnum "$prec" "$((TP+FP))")"
  jr="$(jnum "$rec" "$((TP+FN))")"
  if [ "$f1" = "n/a" ]; then jf="null"; else jf="$f1"; fi
  miss_json="$(IFS=,; echo "${jmiss[*]:-}")"
  printf '{"split":"%s","tier":"%s","n_fixtures":%d,"tp":%d,"fp":%d,"fn":%d,"tn":%d,"miss":%d,"precision":%s,"recall":%s,"f1":%s,"misses":[%s]}\n' \
    "$SPLIT" "$TIER" "$nfix" "$TP" "$FP" "$FN" "$TN" "$MISS" "$jp" "$jr" "$jf" "$miss_json"
  if [ "$STRICT" -eq 1 ] && { [ "$MISS" -ne 0 ] || [ "$FP" -ne 0 ] || [ "$FN" -ne 0 ] || [ "$CONFLICTS" -ne 0 ]; }; then
    exit 1
  fi
  exit 0
fi

if [ "$STRICT" -eq 1 ]; then
  fail=0
  [ "$MISS" -ne 0 ] && { echo "FAIL(strict): $MISS labeled fixture(s) had no verdict (coverage gap)"; fail=1; }
  [ "$FP" -ne 0 ]   && { echo "FAIL(strict): $FP false positive(s) - safe code flagged VULNERABLE"; fail=1; }
  [ "$FN" -ne 0 ]   && { echo "FAIL(strict): $FN false negative(s) - real bug reported BLOCKED"; fail=1; }
  [ "$CONFLICTS" -ne 0 ] && { echo "FAIL(strict): $CONFLICTS conflicting duplicate verdict(s) in $VFILE"; fail=1; }
  if [ "$fail" -ne 0 ]; then echo "== SCORE: FAIL (strict) =="; exit 1; fi
  echo "== SCORE: OK (strict) - precision=$prec recall=$rec F1=$f1, 0 FP, 0 FN, 0 MISS =="
else
  echo "== SCORE: reported (precision=$prec recall=$rec F1=$f1) =="
  echo "note: report-only mode. A non-perfect score may just mean the tool was not designed"
  echo "      to catch drain-UX - see bench/README.md scope caveats. Use --strict for CI."
fi
