#!/usr/bin/env node
// Security 12422 (rekey image): the store tool the one-off rekey image carries is `mediator-store.mjs` with every
// `ship:drop-begin` … `ship:drop-end` block REMOVED (not disabled): the admin-out, delete-admin and both test-only
// subcommands, the functions only they use, and the header that names them. The rekey image's check then reads the
// shipped file (never the source) and lists what it can do.
//
//   mediator-store-ship.mjs <source> <out>     writes <out> (0644); prints {"sha256","subcommands"}; exit 0
//                                              exit 1 on unbalanced markers, or if the result fails shippedVerdict
import fs from 'node:fs';
import crypto from 'node:crypto';

// The subcommands the shipped tool may have, and the words that must not appear in it at all (12422: "removed from
// the shipped file, not disabled").
export const SHIPPED_ALLOWED = ['absent', 'names', 'opens', 'rekey'];
// `getEntry` (Security 12940 change 1): the one primitive that hands back a single decrypted value; only admin-out
// uses it, so it is dropped with admin-out, and a re-pin that moves it out of a drop block goes red here.
export const SHIPPED_FORBIDDEN = ['admin-out', 'delete-admin', 'seal-test', 'encrypt-test', 'deleteAdmin', 'sealTest', 'getEntry'];

export function strip(src) {
  const out = [];
  let depth = 0;
  for (const line of src.split('\n')) {
    const t = line.trim();
    if (t.startsWith('// ship:drop-begin')) { if (depth) throw new Error('nested ship:drop-begin'); depth = 1; continue; }
    if (t.startsWith('// ship:drop-end')) { if (!depth) throw new Error('ship:drop-end without a begin'); depth = 0; continue; }
    if (!depth) out.push(line);
  }
  if (depth) throw new Error('ship:drop-begin without an end');
  return out.join('\n');
}

// Every `case '<name>':` in the file, sorted. The tool's only dispatch is main()'s switch.
export function subcommands(text) {
  return [...new Set([...text.matchAll(/\bcase\s+'([^']+)'\s*:/g)].map((m) => m[1]))].sort();
}

// The rekey image's check on the shipped file: green only when its subcommands are a subset of SHIPPED_ALLOWED that
// still includes `rekey`, no forbidden word appears anywhere, and no marker survived.
export function shippedVerdict(text) {
  const subs = subcommands(text);
  const extra = subs.filter((s) => !SHIPPED_ALLOWED.includes(s));
  const words = SHIPPED_FORBIDDEN.filter((w) => text.includes(w));
  const markers = text.includes('ship:drop');
  const ok = extra.length === 0 && subs.includes('rekey') && words.length === 0 && !markers;
  return { ok, subcommands: subs, extra_subcommands: extra, forbidden_words: words, markers_left: markers };
}

export const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

if (process.argv[1]?.endsWith('mediator-store-ship.mjs')) {
  const [src, out] = process.argv.slice(2);
  try {
    const text = strip(fs.readFileSync(src, 'utf8'));
    const v = shippedVerdict(text);
    fs.writeFileSync(out, text, { mode: 0o644 });
    console.log(JSON.stringify({ sha256: sha256(Buffer.from(text)), ...v }));
    process.exit(v.ok ? 0 : 1);
  } catch (e) { console.error(`mediator-store-ship: ${e.message}`); process.exit(1); }
}
