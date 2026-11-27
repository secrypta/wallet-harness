#!/usr/bin/env python3
"""drain-bench baseline - map a tool's raw per-file output to drain-bench verdicts.

Reads bench/tools/baseline-targets.tsv (vector, target, subject_contract, sol_path) and a
directory of raw tool output (one JSON per analyzed .sol, named by the sanitized sol path),
and emits verdict lines:  [<vector>] target=<target> verdict=<VULNERABLE|BLOCKED>

MAPPING RULE (identical for vuln and safe; documented in each META.md):
  A target is VULNERABLE iff the tool emits >=1 QUALIFYING finding whose source line falls
  within the subject contract's line span in sol_path; otherwise BLOCKED. A tool that produced
  no parseable output for the file (compile/run error) yields NO verdict line -> the scorer
  counts it as MISS (a coverage gap we never guess).

  QUALIFYING per tool:
    slither    : impact in {High, Medium} (Low / Informational / Optimization excluded as noise)
    mythril    : any reported issue       (Mythril emits only security issues by default)
    semgrep    : any reported result      (generic registry; emits only rule matches)
    solhint    : ruleId in Solhint's SECURITY category only (style / gas / naming warnings are
                 excluded as noise - the same noise exclusion applied to Slither Low/Info; without
                 it Solhint's recommended ruleset flags every file and the verdict is meaningless)
    wake       : any detection at impact/confidence that Wake reports by default
    aderyn     : any High-severity issue  (Low excluded as noise, mirroring Slither)
    smtchecker : any SMTChecker (CHC/BMC) model-checker warning (overflow/assert/etc.); the
                 compiler's own non-model-checker warnings (SPDX, unused var, ...) are excluded

  Line-span attribution lets vuln and safe contracts in the SAME file be told apart.

Usage: map_verdicts.py <tool> <raw_dir> [--map <tsv>] [--repo <root>]
"""
import json, os, re, sys

# Solhint "Security Rules" category (https://github.com/protofire/solhint docs). Only these count
# as a qualifying (serious) finding; style/gas/naming/best-practice rules are treated as noise.
SOLHINT_SECURITY = {
    "avoid-call-value", "avoid-low-level-calls", "avoid-sha3", "avoid-suicide",
    "avoid-throw", "avoid-tx-origin", "check-send-result", "multiple-sends",
    "no-complex-fallback", "no-inline-assembly", "not-rely-on-time", "reentrancy",
}
# Deliberately EXCLUDED from "serious": compiler-version, func-visibility, state-visibility,
# immutable-vars-naming, gas-*, one-contract-per-file - best-practice/style/gas rules that fire
# indiscriminately on both safe and vuln code; counting them would make the verdict noise, the
# same reason Slither Low/Informational are excluded.

def sanitize(p):
    return re.sub(r'[^A-Za-z0-9]+', '_', p).strip('_')

DECL_RE = re.compile(r'^\s*(?:abstract\s+)?(?:contract|library|interface)\s+([A-Za-z_]\w*)')

def contract_spans(sol_abs):
    """{contract_name: (start_line, end_line_exclusive)} by top-level declaration order."""
    try:
        lines = open(sol_abs, encoding="utf-8", errors="replace").read().splitlines()
    except OSError:
        return {}
    decls = []
    for i, ln in enumerate(lines, 1):
        m = DECL_RE.match(ln)
        if m:
            decls.append((i, m.group(1)))
    spans = {}
    for idx, (start, name) in enumerate(decls):
        end = decls[idx + 1][0] if idx + 1 < len(decls) else len(lines) + 1
        # last decl wins if a name repeats (shouldn't in our fixtures)
        spans[name] = (start, end)
    return spans

def lines_slither(raw, solbase):
    """(lineno, qualifies) pairs from a slither --json file."""
    out = []
    data = raw if isinstance(raw, dict) else {}
    dets = (data.get("results") or {}).get("detectors") or []
    for d in dets:
        qual = d.get("impact") in ("High", "Medium")
        for el in d.get("elements") or []:
            sm = el.get("source_mapping") or {}
            fn = sm.get("filename_short") or sm.get("filename_relative") or ""
            if solbase and solbase not in fn:
                continue
            for L in sm.get("lines") or []:
                out.append((L, qual))
    return out

def lines_mythril(raw, solbase):
    out = []
    issues = (raw or {}).get("issues") or []
    for it in issues:
        L = it.get("lineno")
        if L is not None:
            out.append((int(L), True))
    return out

def lines_semgrep(raw, solbase):
    out = []
    for r in (raw or {}).get("results") or []:
        L = (r.get("start") or {}).get("line")
        if L is not None:
            out.append((int(L), True))
    return out

def lines_solhint(raw, solbase):
    """Solhint JSON is a list of findings (+ a trailing conclusion object). Qualify only
    Security-category ruleIds; style/gas/naming are noise."""
    out = []
    items = raw if isinstance(raw, list) else []
    for it in items:
        if not isinstance(it, dict) or "ruleId" not in it:
            continue  # skip the trailing {"conclusion": ...} summary object
        fp = it.get("filePath") or ""
        if solbase and solbase != os.path.basename(fp):
            continue
        L = it.get("line")
        if L is None:
            continue
        out.append((int(L), it.get("ruleId") in SOLHINT_SECURITY))
    return out

def lines_sarif(raw, solbase):
    """Standard SARIF 2.1.0 (used by Wake `--export sarif` and Aderyn `--output-format sarif`).
    Walk runs[].results[].locations[].physicalLocation -> (startLine, uri). A result qualifies
    unless its level is 'note'/'none' (informational) - error/warning count as a serious flag."""
    out = []
    data = raw if isinstance(raw, dict) else {}
    for run in data.get("runs") or []:
        for res in run.get("results") or []:
            level = (res.get("level") or "warning").lower()
            qual = level in ("error", "warning")
            for loc in res.get("locations") or []:
                pl = (loc.get("physicalLocation") or {})
                uri = ((pl.get("artifactLocation") or {}).get("uri") or "")
                L = (pl.get("region") or {}).get("startLine")
                if L is None:
                    continue
                if solbase and solbase != os.path.basename(uri):
                    continue
                out.append((int(L), qual))
    return out

def lines_aderyn(raw, solbase):
    """Aderyn JSON report: {"high_issues":{"issues":[{"instances":[{"contract_path","line_no"}]}]},
    "low_issues":{...}}. Only High-severity instances qualify (Low excluded as noise)."""
    out = []
    data = raw if isinstance(raw, dict) else {}
    for sev, qual in (("high_issues", True), ("low_issues", False)):
        block = data.get(sev) or {}
        for issue in block.get("issues") or []:
            for inst in issue.get("instances") or []:
                fn = inst.get("contract_path") or ""
                if solbase and solbase != os.path.basename(fn):
                    continue
                L = inst.get("line_no")
                if L is not None:
                    out.append((int(L), qual))
    return out

MC_RE = re.compile(r'-->\s*([^\s:]+):(\d+):\d+')
def lines_smtchecker(text, solbase):
    """Parse solc text diagnostics. A SMTChecker finding is a `Warning (CODE): ...` block whose
    code is a model-checker code, followed by a `--> file:line:col`. Non-model-checker warnings
    (SPDX 1878, unused var 2072, ...) are ignored."""
    MC_CODES = {"6328", "4984", "3944", "2661", "8656", "3046", "4281", "6838",
                "1218", "2529", "7812", "9123", "4661", "2512", "5729"}
    out = []
    if not isinstance(text, str):
        return out
    blocks = re.split(r'(?=^(?:Warning|Error)\b)', text, flags=re.MULTILINE)
    for b in blocks:
        head = b.lstrip()[:120]
        m_code = re.match(r'(?:Warning|Error)\s*\((\d+)\)', head)
        is_mc = False
        if m_code and m_code.group(1) in MC_CODES:
            is_mc = True
        # fallback: explicit CHC/BMC phrasing even if code not matched
        if ("CHC:" in b) or ("BMC:" in b) or ("might happen" in b) or ("happens here" in b):
            is_mc = True
        if not is_mc:
            continue
        for mm in MC_RE.finditer(b):
            fn, L = mm.group(1), int(mm.group(2))
            if solbase and solbase != os.path.basename(fn):
                continue
            out.append((L, True))
    return out

# solc default warning codes that are pure code-hygiene / style (not security): excluded so the
# compiler-level baseline counts only a security-semantic warning as a "flag". The bare compiler
# has essentially no drain-aware warning, so this is expected to flag ~nothing (honest: even the
# compiler does not catch drains) - like the generic Semgrep registry.
SOLC_HYGIENE = {
    "1878",  # SPDX license identifier not provided
    "3420",  # SPDX via pragma (older)
    "2072",  # Unused local variable
    "5667",  # Unused function parameter
    "2519",  # This declaration shadows an existing declaration
    "8760",  # This declaration has the same name as another (shadowing variant)
    "2018",  # Function state mutability can be restricted
    "6133",  # Statement has no effect
    "3805",  # pragma experimental
    "1699",  # pragma / abi v2 note
    "6321",  # Unnamed return variable
}
SOLC_HYGIENE_TEXT = (  # phrases of solc warnings that are pure hygiene/style (no numeric code form)
    "SPDX license identifier", "Unused local variable", "Unused function parameter",
    "shadows an existing declaration", "state mutability can be restricted",
    "Statement has no effect", "Unused try/catch", "Unnamed return variable",
    "Visibility for constructor is ignored",
)
def lines_solc(text, solbase):
    """Plain solc diagnostics. Qualify a Warning iff it is NOT pure hygiene/style - matched by
    numeric code (SOLC_HYGIENE) when solc prints codes, else by message text (SOLC_HYGIENE_TEXT)
    for the `Warning: <message>` form. Errors and hygiene warnings do not qualify. (On this
    corpus solc emits zero warnings at all, so this yields no flags - an honest R=0.)"""
    out = []
    if not isinstance(text, str):
        return out
    for b in re.split(r'(?=^(?:Warning|Error)\b)', text, flags=re.MULTILINE):
        if not b.lstrip().startswith("Warning"):
            continue
        head = b.lstrip()
        m = re.match(r'Warning\s*\((\d+)\)', head)
        if m:
            if m.group(1) in SOLC_HYGIENE:
                continue
        else:
            # no numeric code -> classify by message text
            if any(p in head[:200] for p in SOLC_HYGIENE_TEXT):
                continue
        for mm in MC_RE.finditer(b):
            fn, L = mm.group(1), int(mm.group(2))
            if solbase and solbase != os.path.basename(fn):
                continue
            out.append((L, True))
    return out

def lines_remix(raw, solbase):
    """Remix analyzer driver output: {"findings":[{"line":N,"module":"..."}]}. The driver already
    kept only entry-file, Security-category findings, so each one qualifies."""
    out = []
    for f in (raw or {}).get("findings") or []:
        L = f.get("line")
        if L is not None:
            out.append((int(L), True))
    return out

PARSERS = {
    "slither": lines_slither, "mythril": lines_mythril, "semgrep": lines_semgrep,
    "solhint": lines_solhint, "wake": lines_sarif, "aderyn": lines_aderyn,
    "smtchecker": lines_smtchecker, "solc": lines_solc, "remix": lines_remix,
    # Falcon (MetaTrust) is a Slither fork: identical results.detectors[] JSON (impact/elements).
    "falcon": lines_slither,
}
EXTS = {t: "json" for t in PARSERS}
EXTS["smtchecker"] = "txt"
EXTS["solc"] = "txt"
EXTS["wake"] = "sarif"
# whole-repo tools emit ONE report for the whole project (raw/_repo.<ext>); the parser filters
# findings to each subject file by basename. Per-file tools emit raw/<sanitized-sol>.<ext>.
WHOLE_REPO = {"wake"}

def main():
    if len(sys.argv) < 3:
        sys.exit("usage: map_verdicts.py <tool> <raw_dir> [--map <tsv>] [--repo <root>]")
    tool = sys.argv[1]
    raw_dir = sys.argv[2]
    repo = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    mapf = os.path.join(repo, "bench", "tools", "baseline-targets.tsv")
    args = sys.argv[3:]
    while args:
        if args[0] == "--map": mapf = args[1]; args = args[2:]
        elif args[0] == "--repo": repo = os.path.abspath(args[1]); args = args[2:]
        else: sys.exit(f"unknown arg {args[0]}")
    if tool not in PARSERS:
        sys.exit(f"unknown tool {tool} ({'|'.join(PARSERS)})")
    parse = PARSERS[tool]
    ext = EXTS[tool]
    whole_repo = tool in WHOLE_REPO

    # whole-repo tools: load the single project-wide report once; its absence = every target MISS
    repo_raw = None
    if whole_repo:
        rp = os.path.join(raw_dir, "_repo." + ext)
        try:
            repo_raw = json.load(open(rp, encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            repo_raw = None

    span_cache = {}
    n_vuln = n_blk = n_miss = 0
    for line in open(mapf, encoding="utf-8"):
        if line.startswith("#") or not line.strip():
            continue
        parts = line.rstrip("\n").split("\t")
        if len(parts) < 4:
            continue
        vector, target, subj, sol = parts[:4]
        if whole_repo:
            if repo_raw is None:
                n_miss += 1
                sys.stderr.write(f"MISS (no repo report): {vector}/{target} [{sol}]\n")
                continue
            raw = repo_raw
        else:
            rawp = os.path.join(raw_dir, sanitize(sol) + "." + ext)
            if not os.path.isfile(rawp):
                n_miss += 1
                sys.stderr.write(f"MISS (no raw): {vector}/{target} [{sol}]\n")
                continue
            try:
                if ext == "txt":
                    raw = open(rawp, encoding="utf-8", errors="replace").read()
                else:
                    raw = json.load(open(rawp, encoding="utf-8", errors="replace"))
            except (json.JSONDecodeError, OSError):
                n_miss += 1
                sys.stderr.write(f"MISS (bad raw): {vector}/{target} [{sol}]\n")
                continue
        sol_abs = os.path.join(repo, sol)
        if sol_abs not in span_cache:
            span_cache[sol_abs] = contract_spans(sol_abs)
        span = span_cache[sol_abs].get(subj)
        solbase = os.path.basename(sol)
        hits = parse(raw, solbase)
        vuln = False
        if span:
            lo, hi = span
            for L, qual in hits:
                if qual and lo <= L < hi:
                    vuln = True
                    break
        else:
            # no span found -> attribute file-wide (conservative: any qualifying hit)
            vuln = any(q for _, q in hits)
        verdict = "VULNERABLE" if vuln else "BLOCKED"
        if vuln: n_vuln += 1
        else: n_blk += 1
        print(f"[{vector}] target={target} verdict={verdict}")
    sys.stderr.write(f"{tool}: VULNERABLE={n_vuln} BLOCKED={n_blk} MISS={n_miss}\n")

if __name__ == "__main__":
    main()
