#!/usr/bin/env node
/*
 * drain-bench baseline driver for Remix's static analyzer (@remix-project/remix-analyzer).
 *
 * Remix ships its analysis as a library, not a CLI, so this thin driver: compiles each subject
 * with solc-js (standard JSON, AST output, imports resolved from the repo copy), runs ONLY the
 * Security-category (`SEC`) modules - tx.origin, check-effects-interaction (reentrancy), inline
 * assembly, block timestamp/hash, low-level calls, selfdestruct - and writes one raw JSON per
 * source:  { "findings": [ { "line": N, "module": "..." }, ... ] }  (only findings located in the
 * ENTRY file; attribution to a subject contract is done later by bench/tools/map_verdicts.py).
 *
 * Usage: node remix-analyze.js <base_dir> <out_raw_dir> <sources_list_file>
 * Compile error / solc failure on a file -> no raw file written -> scored MISS (never guessed).
 */
'use strict';
const fs = require('fs');
const path = require('path');
const solc = require('solc');
const { CodeAnalysis } = require('@remix-project/remix-analyzer');

const base = process.argv[2];
const outDir = process.argv[3];
const sources = fs.readFileSync(process.argv[4], 'utf8').split('\n').map(s => s.trim()).filter(Boolean);

const sanitize = p => p.replace(/[^A-Za-z0-9]+/g, '_').replace(/^_|_$/g, '');
const readSafe = p => { try { return fs.readFileSync(p, 'utf8'); } catch (e) { return null; } };

// Resolve an import to file contents under the repo copy. solc normalizes relative imports to a
// path relative to the import graph; try that directly, then a couple of common fallbacks.
function importCallback(importPath) {
  const cands = [
    path.join(base, importPath),
    path.join(base, importPath.replace(/^\.?\/*/, '')),
  ];
  for (const c of cands) { const txt = readSafe(c); if (txt != null) return { contents: txt }; }
  return { error: 'File not found: ' + importPath };
}

const runner = new CodeAnalysis();
const allModules = runner.modules();
const secIdx = [];
allModules.forEach((M, i) => {
  try { const m = new M(); if (m.category && m.category.id === 'SEC') secIdx.push(i); } catch (e) {}
});

function offsetToLine(src, off) { return src.slice(0, off).split('\n').length; }

let ok = 0, miss = 0;
for (const rel of sources) {
  const abs = path.join(base, rel);
  const content = readSafe(abs);
  if (content == null) { miss++; continue; }
  const input = {
    language: 'Solidity',
    sources: { [rel]: { content } },
    // AST for the walker + 'abi' so solc populates `contracts` (Remix modules' report() needs it)
    settings: { outputSelection: { '*': { '': ['ast'], '*': ['abi'] } } },
  };
  let out;
  try { out = JSON.parse(solc.compile(JSON.stringify(input), { import: importCallback })); }
  catch (e) { miss++; continue; }
  if ((out.errors || []).some(e => e.severity === 'error')) { miss++; continue; }

  let reports;
  try { reports = runner.run(out, secIdx); } catch (e) { miss++; continue; }

  const findings = [];
  for (const r of reports || []) {
    for (const w of (r.report || [])) {
      if (!w.location) continue;
      const parts = String(w.location).split(':').map(Number);
      const start = parts[0], fileIdx = parts[2];
      let fname = null;
      for (const k in out.sources) { if (out.sources[k].id === fileIdx) { fname = k; break; } }
      if (fname !== rel) continue;               // keep only findings in the entry file
      findings.push({ line: offsetToLine(content, start), module: r.name });
    }
  }
  fs.writeFileSync(path.join(outDir, sanitize(rel) + '.json'), JSON.stringify({ findings }));
  ok++;
  console.log('ok   ' + rel);
}
console.error(`remix-analyze: ok=${ok} miss=${miss} (sec-modules=${secIdx.length})`);
