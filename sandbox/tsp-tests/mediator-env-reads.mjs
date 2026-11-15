#!/usr/bin/env node
// Condition 16.2(b) (Security, register L8, bus 11984): at every pin and re-pin, list every environment name the
// mediator's own crates read, and fail unless each is on the allow list or the deny list. A prefix read
// (`env::vars()` scanned for a prefix, e.g. `MEDIATOR_TAG_`) fails, and so does a read whose name this script can't
// resolve to a literal. Build-time reads (`env!`, `option_env!`) are listed the same way: they bake the build
// environment into the binary.
//
// Usage: node mediator-env-reads.mjs <mediator checkout> <lists.json> <out.json>
// Prints counts and names only (names are the mediator's public source, never a value). Exit 0 only when nothing is
// unlisted, no prefix read and nothing unresolved.
//
// What it skips, and says so in the record: `#[cfg(test)]` modules (brace-matched) and files under tests/ or benches/,
// because they are not in the binary. Dependencies outside the workspace are not read here: `env -i` plus the 16.2(c)
// /proc/<pid>/environ test closes them.
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';

export function stripTestModules(src) {
  // Remove `#[cfg(test)] mod x { ... }` blocks by brace matching (ignores braces inside "..." strings and // comments).
  let out = '';
  let skipped = 0;
  let i = 0;
  const re = /#\[cfg\(test\)\]\s*(?:#\[[^\]\n]*\]\s*)*(pub(\([^)]*\))?\s+)?mod\s+\w+\s*\{/g;
  for (;;) {
    re.lastIndex = i;
    const m = re.exec(src);
    if (!m) { out += src.slice(i); break; }
    out += src.slice(i, m.index);
    let j = m.index + m[0].length;
    let depth = 1;
    let inStr = false;
    while (j < src.length && depth > 0) {
      const c = src[j];
      if (inStr) {
        if (c === '\\') j++;
        else if (c === '"') inStr = false;
      } else if (c === '"') inStr = true;
      else if (c === '/' && src[j + 1] === '/') { const nl = src.indexOf('\n', j); j = nl < 0 ? src.length : nl; continue; }
      else if (c === '{') depth++;
      else if (c === '}') depth--;
      j++;
    }
    const block = src.slice(m.index, j);
    skipped += block.split('\n').length - 1;
    out += '\n'.repeat(block.split('\n').length - 1); // keep line numbers
    i = j;
  }
  return { text: out, skipped };
}

export function constsOf(text) {
  const c = new Map();
  for (const m of text.matchAll(/(?:pub(?:\([^)]*\))?\s+)?const\s+([A-Z0-9_]+)\s*:\s*&(?:'static\s+)?str\s*=\s*"([^"]*)"/g)) c.set(m[1], m[2]);
  return c;
}

// One source text → reads. Each read: { kind, name|null, line, raw }.
export function readsOf(text, consts = constsOf(text)) {
  const reads = [];
  const arg = (a) => {
    a = a.trim();
    const lit = a.match(/^"([^"]*)"$/);
    if (lit) return lit[1];
    if (/^[A-Z0-9_]+$/.test(a) && consts.has(a)) return consts.get(a);
    return null;
  };
  // Calls span lines (rustfmt splits long ones), so match on the whole text with comments blanked, keeping offsets.
  const code = text.replace(/\/\/[^\n]*/g, (c) => ' '.repeat(c.length));
  const lineAt = (i) => code.slice(0, i).split('\n').length;
  const push = (kind, name, m) => {
    // the macros' own definitions read `$env_var`; the names are at the call sites
    if (/\$env_var/.test(m[0])) return;
    reads.push({ kind, name, line: lineAt(m.index), raw: m[0].replace(/\s+/g, ' ') });
  };
  for (const m of code.matchAll(/\benv_override(?:_opt|_list)?!\s*\(\s*[^,]+,\s*([^)]+)\)/g)) push('runtime', arg(m[1]), m);
  for (const m of code.matchAll(/\b(?:std::)?env::var(?:_os)?\s*\(\s*([^)]*)\)/g)) push('runtime', arg(m[1]), m);
  for (const m of code.matchAll(/\b(?:std::)?env::vars(?:_os)?\s*\(\s*\)/g)) push('prefix', null, m);
  for (const m of code.matchAll(/(?<![\w$])(option_env|env)!\s*\(\s*([^),]+)/g)) push('build', arg(m[2]), m);
  return reads;
}

// Functions that take a name and read it (e.g. vault's `require_env(var)`): their call sites carry the names.
export function wrapperCalls(text, consts) {
  const names = [];
  const params = new Set();
  for (const m of text.matchAll(/\bfn\s+(\w+)\s*\(\s*(\w+)\s*:\s*&str\s*\)[^{]*\{[^}]*?\benv::var(?:_os)?\s*\(\s*(\w+)\s*\)/g)) {
    if (m[2] === m[3]) { names.push(m[1]); params.add(m[2]); }
  }
  const reads = [];
  const lines = text.split('\n');
  for (const fn of names) {
    lines.forEach((l, k) => {
      for (const m of l.replace(/\/\/.*$/, '').matchAll(new RegExp(`(?<!\\bfn\\s+)\\b${fn}\\s*\\(\\s*([^)]+)\\)`, 'g'))) {
        const a = m[1].trim();
        const name = /^"([^"]*)"$/.test(a) ? a.slice(1, -1) : consts.get(a) ?? null;
        reads.push({ kind: 'runtime', name, line: k + 1, raw: m[0], via: fn });
      }
    });
  }
  return { names, params, reads };
}

export function classify(reads, lists) {
  const allow = new Set(lists.allow);
  const deny = new Set(Object.values(lists.deny).flat());
  const res = { onAllow: new Set(), onDeny: new Set(), unlisted: new Map(), prefix: [], unresolved: [] };
  for (const r of reads) {
    if (r.kind === 'prefix') { res.prefix.push(r.at); continue; }
    if (r.name === null) { res.unresolved.push(r.at); continue; }
    if (allow.has(r.name)) res.onAllow.add(r.name);
    else if (deny.has(r.name)) res.onDeny.add(r.name);
    else {
      const k = `${r.kind}:${r.name}`;
      if (!res.unlisted.has(k)) res.unlisted.set(k, []);
      res.unlisted.get(k).push(r.at);
    }
  }
  return res;
}

function rsFiles(dir) {
  const out = [];
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    const s = statSync(p);
    if (s.isDirectory()) { if (e !== 'tests' && e !== 'benches') out.push(...rsFiles(p)); }
    else if (e.endsWith('.rs')) out.push(p);
  }
  return out.sort();
}

export function scan(root, lists) {
  const all = [];
  let skipped = 0;
  // A constant may be declared in one file and read in another (crate-wide `pub const`): collect them all first.
  const files = lists.crates.flatMap((c) => rsFiles(join(root, c)));
  const texts = new Map();
  const consts = new Map();
  for (const f of files) {
    const s = stripTestModules(readFileSync(f, 'utf8'));
    skipped += s.skipped;
    texts.set(f, s.text);
    for (const [k, v] of constsOf(s.text)) consts.set(k, v);
  }
  for (const [f, t] of texts) {
    const at = relative(root, f);
    const w = wrapperCalls(t, consts);
    for (const r of readsOf(t, consts)) {
      // the wrapper's own body reads its parameter; its callers are counted instead
      const p = r.raw.match(/env::var(?:_os)?\s*\(\s*(\w+)\s*\)$/);
      if (r.name === null && p && w.params.has(p[1])) continue;
      all.push({ ...r, at: `${at}:${r.line}` });
    }
    for (const r of w.reads) all.push({ ...r, at: `${at}:${r.line}` });
  }
  return { reads: all, files: files.length, testLinesSkipped: skipped };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [root, listsPath, outPath] = process.argv.slice(2);
  if (!root || !listsPath || !outPath) { console.error('usage: mediator-env-reads.mjs <checkout> <lists.json> <out.json>'); process.exit(2); }
  const lists = JSON.parse(readFileSync(listsPath, 'utf8'));
  const { reads, files, testLinesSkipped } = scan(root, lists);
  const c = classify(reads, lists);
  const rec = {
    files, test_lines_skipped: testLinesSkipped, reads: reads.length,
    on_allow: [...c.onAllow].sort(), on_deny: [...c.onDeny].sort(),
    unlisted: Object.fromEntries([...c.unlisted].sort()), prefix_reads: c.prefix, unresolved: c.unresolved,
  };
  rec.pass = c.unlisted.size === 0 && c.prefix.length === 0 && c.unresolved.length === 0;
  writeFileSync(outPath, JSON.stringify(rec, null, 2) + '\n');
  console.log(`env reads: ${files} files, ${reads.length} reads; allow ${rec.on_allow.length}, deny ${rec.on_deny.length}, unlisted ${c.unlisted.size}, prefix ${c.prefix.length}, unresolved ${c.unresolved.length}: ${rec.pass ? 'PASS' : 'FAIL'}`);
  process.exit(rec.pass ? 0 : 1);
}
