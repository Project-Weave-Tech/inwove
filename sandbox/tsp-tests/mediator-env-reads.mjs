#!/usr/bin/env node
// Condition 16.2(b) at the pin (Security, register L8; bus 11984, reshaped by bus 12079). `mediator-env-lists.json`
// is a COMMITTED record of a Security read at the pin: `allow` (the 3), `deny` (every other name the grep finds, each
// with its gate), `exceptions` (the named reads that aren't plain names), `build_time`, and a hand-pinned `floor` that
// a regeneration can't drop. In the job this script re-greps the mediator's own linked crates and COMPARES against
// that record. It never writes the file in the job. Any difference fails, in either direction: a name that is new, a
// name that is gone, a moved or changed exception, a second prefix scan, a new build-time name, a floor name off its
// list, a pin that isn't the checkout's, or a raw count of read sites that the resolver doesn't account for (12079.7).
//
// Usage:
//   node mediator-env-reads.mjs <checkout> <lists.json> <out.json>            compare (the job; exit 0 only on a match)
//   node mediator-env-reads.mjs <checkout> <lists.json> --write               re-pin only: rewrite the record from the
//                                                                             grep, keeping floor, gates and allow; its
//                                                                             own commit, green once Security names it
//   node mediator-env-reads.mjs <checkout> <lists.json> <out.json> --planted <tmpdir>
//                                                                             test the instrument (12079.6): copy one
//                                                                             linked crate, plant three reads, and exit 0
//                                                                             only if the compare fails on all three
// Prints counts and names only (names are the mediator's public source, never a value).
//
// What it skips, and says so in the record: `#[cfg(test)]` modules (brace-matched) and files under tests/ or benches/,
// because they are not in the binary. What it does NOT cover is written into every record as `does_not_cover`.
import { cpSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync, appendFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';

// Security 12144.4, at the next re-pin (not before: the record at 44c7d92 is compared to this exact sentence): add a
// clause that `build.rs` (trust_tasks_build, run at build time on the runner) is covered by neither env -i nor this grep;
// today the lean `cargo tree` sha256 and a clean job cover it.
export const DOES_NOT_COVER = '16.2(b) reads the four mediator crates the binary links, and nothing else. The crates they depend on read the environment too (logging, TLS roots, proxies, the Redis and AWS clients). Those reads are closed by the entrypoint\'s `env -i` with the allow list, and proven by the 16.2(c) /proc/<pid>/environ test, not by this grep. A green 16.2(b) means only: every name these four crates read was read by Security at this pin.';

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
export function readsOf(text, consts = constsOf(text), skippedDefs = []) {
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
    // the macros' own definitions read `$env_var`; the names are at the call sites (counted for the recall check)
    if (/\$env_var/.test(m[0])) { skippedDefs.push(lineAt(m.index)); return; }
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

// 12079.7, the recall count: a deliberately plain text count of read sites, independent of the resolver's regexes
// (comments blanked, test modules stripped). The resolver must account for every one of them.
export const RAW_PATTERNS = ['env_override!(', 'env_override_opt!(', 'env_override_list!(', 'env::var(', 'env::var_os(', 'env::vars(', 'env::vars_os(', 'option_env!(', 'env!('];
export function rawCount(text) {
  const code = text.replace(/\/\/[^\n]*/g, '');
  const counts = Object.fromEntries(RAW_PATTERNS.map((k) => [k, 0]));
  for (const k of RAW_PATTERNS) {
    let i = 0;
    for (;;) {
      i = code.indexOf(k, i);
      if (i < 0) break;
      const before = code[i - 1] ?? ' ';
      // `env!(` inside `option_env!(` / `my_env!(` is not a separate site; `env::var(` inside `std::env::var(` is.
      if (!(k === 'env!(' && /[\w]/.test(before)) && !(k.startsWith('env_override') && /[\w]/.test(before))) counts[k]++;
      i += k.length;
    }
  }
  return counts;
}

// A read whose name is a closure parameter (e.g. `let resolve = |label: &str, env_var: &str, raw: &str| ...
// env::var_os(env_var)`): list the closure's call sites and the literal each passes in that position (12079.3).
export function closureCallers(text, line) {
  const lines = text.split('\n');
  const upto = lines.slice(0, line).join('\n');
  const defs = [...upto.matchAll(/let\s+(\w+)\s*=\s*\|([^|]*)\|/g)];
  const d = defs.at(-1);
  if (!d) return null;
  const params = d[2].split(',').map((x) => x.split(':')[0].trim());
  const readLine = lines[line - 1];
  const used = readLine.match(/env::var(?:_os)?\s*\(\s*(\w+)\s*\)/)?.[1];
  const idx = params.indexOf(used);
  if (idx < 0) return null;
  const code = text.replace(/\/\/[^\n]*/g, (c) => ' '.repeat(c.length));
  const after = code.indexOf(d[0]) + d[0].length;
  const callers = [];
  for (const m of code.slice(after).matchAll(new RegExp(`\\b${d[1]}\\s*\\(`, 'g'))) {
    const start = after + m.index + m[0].length;
    // split the arguments at top-level commas
    let depth = 0; let j = start; const args = []; let cur = '';
    for (; j < code.length; j++) {
      const c = code[j];
      if ('([{'.includes(c)) depth++;
      if (')]}'.includes(c)) { if (depth === 0) break; depth--; }
      if (c === ',' && depth === 0) { args.push(cur); cur = ''; continue; }
      cur += c;
    }
    args.push(cur);
    const a = (args[idx] ?? '').trim();
    callers.push({ line: code.slice(0, after + m.index).split('\n').length, name: /^"([^"]*)"$/.test(a) ? a.slice(1, -1) : null });
  }
  return { closure: d[1], param: used, callers };
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
  const raw = Object.fromEntries(RAW_PATTERNS.map((k) => [k, 0]));
  let macroDefs = 0; let wrapperBodies = 0;
  const exceptions = [];
  for (const [f, t] of texts) {
    const at = relative(root, f);
    for (const [k, n] of Object.entries(rawCount(t))) raw[k] += n;
    const w = wrapperCalls(t, consts);
    const defs = [];
    for (const r of readsOf(t, consts, defs)) {
      // the wrapper's own body reads its parameter; its callers are counted instead
      const p = r.raw.match(/env::var(?:_os)?\s*\(\s*(\w+)\s*\)$/);
      if (r.name === null && p && w.params.has(p[1])) { wrapperBodies++; continue; }
      const read = { ...r, at: `${at}:${r.line}` };
      if (r.kind === 'prefix') {
        const near = t.split('\n').slice(r.line - 1, r.line + 6).join('\n');
        read.prefix = near.match(/"([A-Z0-9_]+_)"/)?.[1] ?? null;
      }
      if (r.kind === 'runtime' && r.name === null) {
        const c = closureCallers(t, r.line);
        if (c) read.callers = c.callers.map((x) => ({ at: `${at}:${x.line}`, name: x.name }));
        if (c) read.via = c.closure;
      }
      all.push(read);
    }
    macroDefs += defs.length;
    for (const r of w.reads) all.push({ ...r, at: `${at}:${r.line}` });
  }
  const accounted = all.filter((r) => !r.via || r.callers).length + macroDefs + wrapperBodies;
  const rawTotal = Object.values(raw).reduce((a, b) => a + b, 0);
  return { reads: all, files: files.length, testLinesSkipped: skipped, recall: { raw, raw_total: rawTotal, accounted, macro_definitions: macroDefs, wrapper_bodies: wrapperBodies } };
}

// What the grep found, in the record's own shape (the part a compare checks).
export function derive(reads) {
  const runtime = new Set(); const build = new Set(); const exceptions = [];
  for (const r of reads) {
    if (r.kind === 'prefix') { exceptions.push({ kind: 'prefix', at: r.at, read: r.raw, prefix: r.prefix }); continue; }
    if (r.name === null) {
      exceptions.push({ kind: 'unresolved', at: r.at, read: r.raw, ...(r.callers ? { callers: r.callers } : {}) });
      for (const c of r.callers ?? []) if (c.name) runtime.add(c.name);
      continue;
    }
    (r.kind === 'build' ? build : runtime).add(r.name);
  }
  return { runtime: [...runtime].sort(), build_time: [...build].sort(), exceptions: exceptions.sort((a, b) => a.at.localeCompare(b.at)) };
}

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// Compare the grep against the committed record. Every difference is a named problem; none = PASS.
export function compare(found, lists, recall) {
  const problems = [];
  const allow = new Set(lists.allow);
  const deny = new Set(Object.keys(lists.deny));
  const seen = new Set(found.runtime);
  for (const n of lists.allow) if (deny.has(n)) problems.push(`on both lists: ${n}`);
  for (const n of found.runtime) if (!allow.has(n) && !deny.has(n)) problems.push(`new name, not in the record: ${n}`);
  for (const n of [...allow, ...deny]) if (!seen.has(n)) problems.push(`gone, in the record but not read at this pin: ${n}`);
  for (const n of lists.floor?.allow ?? []) if (!allow.has(n)) problems.push(`floor name off the allow list: ${n}`);
  for (const n of lists.floor?.deny ?? []) if (!deny.has(n)) problems.push(`floor name off the deny list: ${n}`);
  if (!lists.floor || !(lists.floor.allow?.length) || !(lists.floor.deny?.length)) problems.push('the record has no floor');
  for (const [n, g] of Object.entries(lists.deny)) if (!/^(ungated|feature=[\w-]+)$/.test(g)) problems.push(`deny name with no gate written: ${n}`);
  const bt = new Set(lists.build_time);
  for (const n of found.build_time) if (!bt.has(n)) problems.push(`new build-time read (bakes the runner's environment in): ${n}`);
  for (const n of lists.build_time) if (!found.build_time.includes(n)) problems.push(`build-time name gone: ${n}`);
  const want = [...lists.exceptions].sort((a, b) => a.at.localeCompare(b.at));
  for (const e of found.exceptions) if (!want.some((w) => same(w, e))) problems.push(`exception new, moved or changed: ${e.kind} at ${e.at}`);
  for (const w of want) if (!found.exceptions.some((e) => same(w, e))) problems.push(`exception in the record not found as written: ${w.kind} at ${w.at}`);
  for (const e of found.exceptions) for (const c of e.callers ?? []) {
    if (!c.name) problems.push(`unresolved caller at ${c.at}`);
    else if (!deny.has(c.name)) problems.push(`a name passed to ${e.at} is not on deny: ${c.name}`);
  }
  if (recall && recall.raw_total !== recall.accounted) problems.push(`recall: ${recall.raw_total} read sites by plain count, ${recall.accounted} accounted for by the resolver`);
  return problems;
}

export function sha256File(path) { return createHash('sha256').update(readFileSync(path)).digest('hex'); }

function headOf(root) {
  const r = spawnSync('git', ['-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8' });
  return r.status === 0 ? r.stdout.trim() : null;
}

// Test the instrument (12079.6): copy one linked crate's source into a temp tree, plant a plain env::var, an
// env_override! with a new name and a second env::vars() scan, and run the compare on it. All three must be caught.
export function planted(root, lists, tmp) {
  const crate = lists.crates.find((c) => c.endsWith('-config/src')) ?? lists.crates[0];
  mkdirSync(tmp, { recursive: true });
  for (const c of lists.crates) cpSync(join(root, c), join(tmp, c), { recursive: true });
  const f = join(tmp, crate, 'wpi_planted.rs');
  writeFileSync(f, 'fn wpi_planted() {\n    let _ = std::env::var("WPI_PLANTED_READ");\n    env_override!(config.wpi, "WPI_PLANTED_OVERRIDE");\n    for (k, _) in std::env::vars() { if k.starts_with("WPI_PLANTED_") {} }\n}\n');
  const s = scan(tmp, lists);
  const p = compare(derive(s.reads), lists, s.recall);
  const caught = {
    plain_read: p.some((x) => x.includes('WPI_PLANTED_READ')),
    env_override: p.some((x) => x.includes('WPI_PLANTED_OVERRIDE')),
    second_prefix_scan: p.some((x) => /exception new.*prefix/.test(x)),
  };
  return { crate, caught, problems: p, pass: Object.values(caught).every(Boolean) };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  const [root, listsPath, outPath] = args;
  if (!root || !listsPath || !outPath) { console.error('usage: mediator-env-reads.mjs <checkout> <lists.json> <out.json>|--write [--planted <tmpdir>]'); process.exit(2); }
  const lists = JSON.parse(readFileSync(listsPath, 'utf8'));
  const head = headOf(root);
  const { reads, files, testLinesSkipped, recall } = scan(root, lists);
  const found = derive(reads);

  if (outPath === '--write') {
    // Re-pin only, in its own commit. Allow, floor and gates are kept; a new deny name is written `unread` (which the
    // compare refuses) until Security writes its gate. Never run in the job.
    const deny = {};
    for (const n of found.runtime) if (!lists.allow.includes(n)) deny[n] = lists.deny?.[n] ?? 'unread';
    const next = { ...lists, pin: head, deny, exceptions: found.exceptions, build_time: found.build_time.filter((n) => lists.build_time?.includes(n) || ['CARGO_PKG_VERSION', 'OUT_DIR'].includes(n)), does_not_cover: DOES_NOT_COVER };
    writeFileSync(listsPath, JSON.stringify(next, null, 2) + '\n');
    console.log(`written: ${Object.keys(deny).length} deny, ${found.exceptions.length} exceptions, ${next.build_time.length} build-time, pin ${head}`);
    process.exit(0);
  }

  const problems = compare(found, lists, recall);
  if (lists.pin !== head) problems.unshift(`the record was read at ${lists.pin}, the checkout is at ${head}`);
  if (lists.does_not_cover !== DOES_NOT_COVER) problems.push('the record\'s does_not_cover sentence is missing or changed');
  const rec = {
    pin: head, record: { path: listsPath, sha256: sha256File(listsPath), read_at: lists.pin },
    files, test_lines_skipped: testLinesSkipped, reads: reads.length, recall,
    allow: lists.allow, deny: Object.keys(lists.deny).length, build_time: found.build_time, exceptions: found.exceptions.map((e) => `${e.kind} ${e.at}`),
    problems, does_not_cover: DOES_NOT_COVER,
  };
  const pi = args.indexOf('--planted');
  if (pi >= 0) {
    const p = planted(root, lists, args[pi + 1]);
    rec.planted = { crate: p.crate, caught: p.caught, pass: p.pass };
    console.log(`planted (must be caught): ${JSON.stringify(p.caught)}: ${p.pass ? 'PASS' : 'FAIL'}`);
  }
  rec.pass = problems.length === 0 && (pi < 0 || rec.planted.pass);
  writeFileSync(outPath, JSON.stringify(rec, null, 2) + '\n');
  for (const p of problems) console.log(`  ${p}`);
  console.log(`env reads @ ${head}: ${files} files, ${reads.length} reads; recall ${recall.raw_total}/${recall.accounted}; allow ${lists.allow.length}, deny ${Object.keys(lists.deny).length}, ${found.exceptions.length} exceptions, record sha256 ${rec.record.sha256}: ${rec.pass ? 'PASS' : 'FAIL'}`);
  process.exit(rec.pass ? 0 : 1);
}
