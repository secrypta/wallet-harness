#!/usr/bin/env python3
"""drain-bench baseline - resolve each (vector,target) to the first-party contract source(s)
under test, so an external static analyzer can be pointed at the same code the wal harness
exercises.

How: each manifest row names a Foundry `test`. In that test, the block that calls
`_report("<target>", ...)` instantiates the contract(s) under test via `new <Name>(...)`.
We map `<Name>` -> its `.sol` via the test's `import {<Name>} from "<path>";` lines, and keep
only FIRST-PARTY sources (under src/ or fixtures/, excluding vendored libraries in
fixtures/vendor/** and forge-std). The result is target -> list of .sol paths.

Output (TSV, one row per target):  vector<TAB>target<TAB>label<TAB>split<TAB>sol1,sol2,...
A target that resolves to no first-party source is emitted with an empty source list and a
warning on stderr (so it is visible, never silently dropped).

This is the ONLY target->source mapping step; it is a judgement call and is documented in each
baseline's META.md. No tool is run here.
"""
import os, re, sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MANIFEST = os.path.join(REPO, "bench", "dataset", "manifest.tsv")

IMPORT_RE = re.compile(r'import\s*\{([^}]*)\}\s*from\s*"([^"]+)"', re.S)
FUNC_RE = re.compile(r'function\s+\w+\s*\([^)]*\)[^{]*\{', re.S)
REPORT_RE = re.compile(r'_report\(\s*"([a-z0-9-]+)"')
NEW_RE = re.compile(r'\bnew\s+([A-Z]\w*)\s*[({]')


def first_party(path):
    p = path.replace("\\", "/")
    if "fixtures/vendor/" in p or p.startswith("forge-std/") or "/lib/" in p:
        return False
    return ("/src/" in "/" + p) or p.startswith("src/") or "fixtures/" in p


def resolve_test(test_rel):
    """Return {target: set(sol_abspaths)} parsed from one test file."""
    test_abs = os.path.join(REPO, test_rel)
    try:
        text = open(test_abs, encoding="utf-8", errors="replace").read()
    except OSError:
        return {}
    # import name -> path (resolved relative to the test file's dir)
    name2sol = {}
    tdir = os.path.dirname(test_abs)
    for names, path in IMPORT_RE.findall(text):
        if not first_party(path):
            continue
        sol = os.path.normpath(os.path.join(tdir, path)) if path.startswith(".") \
            else os.path.normpath(os.path.join(REPO, path))
        for nm in names.split(","):
            nm = nm.strip().split()[-1] if nm.strip() else ""
            if nm:
                name2sol[nm] = sol
    # split the file into function bodies and attribute `new X` to the target _report'd nearby
    out = {}
    # find all function start positions, then slice each body to the next function/EOF
    starts = [m.start() for m in FUNC_RE.finditer(text)] + [len(text)]
    for i in range(len(starts) - 1):
        body = text[starts[i]:starts[i + 1]]
        targets = REPORT_RE.findall(body)
        if not targets:
            continue
        news = NEW_RE.findall(body)
        sols = {name2sol[n] for n in news if n in name2sol}
        for t in targets:
            out.setdefault(t, set()).update(sols)
    return out


def main():
    rows = []
    with open(MANIFEST, encoding="utf-8") as fh:
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 8:
                continue
            vector, tier, target, label, split, test = parts[:6]
            if vector in ("#", "vector") or vector.startswith("#") or vector == "":
                continue
            rows.append((vector, tier, target, label, split, test))

    # cache per-test resolution
    cache = {}
    missing = 0
    for vector, tier, target, label, split, test in rows:
        if test not in cache:
            cache[test] = resolve_test(test)
        sols = sorted(cache[test].get(target, set()))
        rels = [os.path.relpath(s, REPO) for s in sols if os.path.isfile(s)]
        if not rels:
            missing += 1
            sys.stderr.write(f"WARN unresolved: {vector}/{target} (test={test})\n")
        print(f"{vector}\t{target}\t{label}\t{split}\t{','.join(rels)}")
    sys.stderr.write(f"resolved {len(rows)-missing}/{len(rows)} targets to first-party sources\n")


if __name__ == "__main__":
    main()
