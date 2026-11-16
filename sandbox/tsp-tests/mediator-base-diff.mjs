#!/usr/bin/env node
// The rekey image's base-diff line (Security 11869.4). A list of encodings can't close the gap: the full store tool as
// base64, hex, raw deflate, brotli under any name, a gzip one byte in, a tar member, the source reversed — each passes
// every content and archive line. So the rekey image is judged against the pinned base image it is built FROM, file by
// file, on both images' `docker export` streams (read here as tar, so mode and owner are the image's own, not what an
// extract on the runner would leave):
//
//   - every regular file is either byte-identical to the base's file at that path, with the same mode and owner, or in
//     the ADDED SET (rekey-added.json): the shipped tool at the L8 pin plus each @noble/hashes file at its pinned sha;
//   - a base entry whose bytes, mode, owner, type or link target changed is red (a setuid bit added counts);
//   - an added directory is allowed only at /opt/rekey or under it; an added link, hard link or device is red;
//   - an added-set file that is missing, or an added file with a setuid/setgid bit, is red;
//   - deleted base entries are fine, and listed.
// The line must first go red on the planted tree plus a base64 copy of the full tool (instrument bites), or it can't
// pass. Names, paths, shas and verdicts only; no file's bytes are printed.
//
//   mediator-base-diff.mjs <rekey export tar> <base export tar> <added.json> <planted dir> <full tool source> <out.json>
// Exit 0 only when instrument_bites and rekey_matches_base_plus_added_set are both PASS.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const sha = () => crypto.createHash('sha256');
const norm = (p) => p.replace(/^(\.\/)+/, '').replace(/^\/+/, '').replace(/\/+$/, '');
const octal = (b) => { const s = b.toString('latin1').replace(/\0.*$/s, '').trim(); return s ? parseInt(s, 8) : 0; };
const str = (b) => b.toString('utf8').replace(/\0.*$/s, '');
const TYPES = { '0': 'file', '\0': 'file', '7': 'file', '1': 'hardlink', '2': 'link', '5': 'dir', '3': 'other', '4': 'other', '6': 'other' };

// Every entry of a tar file: Map path → {type, mode, uid, gid, size, sha256 (files), linkname (links)}. Reads ustar,
// pax ('x'; 'g' is ignored) and GNU long names ('L'/'K'). The file is read in chunks; content is hashed, never kept.
export function tarList(file) {
  const fd = fs.openSync(file, 'r');
  const out = new Map();
  const hdr = Buffer.alloc(512);
  let pos = 0, pax = {}, longName = null, longLink = null;
  const readExact = (buf, len, at) => { let n = 0; while (n < len) { const r = fs.readSync(fd, buf, n, len - n, at + n); if (!r) throw new Error('tar: short read'); n += r; } };
  const readBody = (size, onChunk) => {
    const chunk = Buffer.alloc(1 << 20);
    let left = size, at = pos;
    while (left > 0) { const n = Math.min(left, chunk.length); readExact(chunk, n, at); onChunk(chunk.subarray(0, n)); left -= n; at += n; }
    pos += Math.ceil(size / 512) * 512;
  };
  try {
    for (;;) {
      if (fs.readSync(fd, hdr, 0, 512, pos) < 512) break;
      if (hdr.every((b) => b === 0)) break;
      pos += 512;
      const t = String.fromCharCode(hdr[156]);
      let size = octal(hdr.subarray(124, 136));
      if (t === 'x' || t === 'g' || t === 'L' || t === 'K') {
        const parts = []; readBody(size, (c) => parts.push(Buffer.from(c)));
        const body = Buffer.concat(parts);
        if (t === 'L') longName = str(body);
        else if (t === 'K') longLink = str(body);
        else if (t === 'x') {
          let i = 0;
          while (i < body.length) {
            const sp = body.indexOf(0x20, i); const len = parseInt(body.subarray(i, sp).toString(), 10);
            if (!(len > 0)) break;
            const rec = body.subarray(sp + 1, i + len - 1).toString('utf8'); const eq = rec.indexOf('=');
            pax[rec.slice(0, eq)] = rec.slice(eq + 1); i += len;
          }
        }
        continue;
      }
      const prefix = str(hdr.subarray(345, 500));
      let name = longName ?? pax.path ?? (prefix ? `${prefix}/${str(hdr.subarray(0, 100))}` : str(hdr.subarray(0, 100)));
      const linkname = longLink ?? pax.linkpath ?? str(hdr.subarray(157, 257));
      if (pax.size !== undefined) size = Number(pax.size);
      const e = {
        type: TYPES[t] ?? 'other',
        mode: octal(hdr.subarray(100, 108)) & 0o7777,
        uid: pax.uid !== undefined ? Number(pax.uid) : octal(hdr.subarray(108, 116)),
        gid: pax.gid !== undefined ? Number(pax.gid) : octal(hdr.subarray(116, 124)),
      };
      if (e.type === 'file') { const h = sha(); readBody(size, (c) => h.update(c)); e.size = size; e.sha256 = h.digest('hex'); }
      else { if (size) readBody(size, () => {}); if (e.type === 'link' || e.type === 'hardlink') e.linkname = linkname; }
      name = norm(name);
      if (name) out.set(name, e);
      pax = {}; longName = null; longLink = null;
    }
  } finally { fs.closeSync(fd); }
  return out;
}

// A directory on disk as the same kind of Map (for the planted tree). lstat only; links are never followed.
export function dirList(root, into = new Map(), rel = '') {
  for (const d of fs.readdirSync(path.join(root, rel), { withFileTypes: true })) {
    const r = rel ? `${rel}/${d.name}` : d.name;
    const st = fs.lstatSync(path.join(root, r));
    const e = { mode: st.mode & 0o7777, uid: st.uid, gid: st.gid };
    if (st.isDirectory()) { into.set(r, { type: 'dir', ...e }); dirList(root, into, r); }
    else if (st.isSymbolicLink()) into.set(r, { type: 'link', ...e, linkname: fs.readlinkSync(path.join(root, r)) });
    else if (st.isFile()) { const b = fs.readFileSync(path.join(root, r)); into.set(r, { type: 'file', ...e, size: b.length, sha256: sha().update(b).digest('hex') }); }
    else into.set(r, { type: 'other', ...e });
  }
  return into;
}

export const ADDED_DIR_ROOT = 'opt/rekey';
const underAddedRoot = (p) => p === ADDED_DIR_ROOT || p.startsWith(`${ADDED_DIR_ROOT}/`);
const SUID = 0o6000;

// The added set as a Map path → sha256, from rekey-added.json's {tool: {path, sha256}, noble: [{path, sha256}]}.
export function addedSet(j) {
  const m = new Map();
  for (const f of [j.tool, ...(j.noble || [])]) m.set(norm(f.path), f.sha256);
  return m;
}

// rek, base: Maps from tarList. added: Map path → sha256. Returns the hits by kind, and ok.
export function baseDiff(rek, base, added) {
  const changed = [], addedFile = [], addedDir = [], addedOther = [], suid = [], missing = [], deleted = [];
  for (const [p, e] of rek) {
    const b = base.get(p);
    if (b) {
      const why = [];
      if (b.type !== e.type) why.push('type');
      if (b.mode !== e.mode) why.push('mode');
      if (b.uid !== e.uid || b.gid !== e.gid) why.push('owner');
      if (e.type === 'file' && b.type === 'file' && (b.sha256 !== e.sha256 || b.size !== e.size)) why.push('bytes');
      if ((e.type === 'link' || e.type === 'hardlink') && b.linkname !== e.linkname) why.push('link');
      if (why.length) changed.push({ path: `/${p}`, why });
      continue;
    }
    if (e.type === 'dir') { if (!underAddedRoot(p)) addedDir.push(`/${p}`); continue; }
    if (e.type !== 'file') { addedOther.push({ path: `/${p}`, type: e.type }); continue; }
    if (e.mode & SUID) suid.push(`/${p}`);
    if (!underAddedRoot(p) || added.get(p) !== e.sha256) addedFile.push({ path: `/${p}`, sha256: e.sha256, in_added_set: added.has(p) });
  }
  for (const p of added.keys()) { const e = rek.get(p); if (!e || e.type !== 'file') missing.push(`/${p}`); }
  for (const p of base.keys()) if (!rek.has(p)) deleted.push(`/${p}`);
  const ok = !changed.length && !addedFile.length && !addedDir.length && !addedOther.length && !suid.length && !missing.length;
  return { ok, changed, added_file_not_in_set: addedFile, added_dir_outside: addedDir, added_not_a_file: addedOther,
    added_setuid: suid, added_set_missing: missing, deleted_base_entries: deleted.sort() };
}

// The instrument: the rekey listing plus the planted tree and a base64 copy of the full tool at usr/share/<name>.
// It bites only when every planted file and the base64 copy come back red.
export function instrument(rek, base, added, plantedDir, toolSource) {
  const planted = dirList(plantedDir);
  const withPlant = new Map(rek);
  const plantedFiles = [];
  for (const [p, e] of planted) { withPlant.set(p, e); if (e.type === 'file') plantedFiles.push(p); }
  const b64 = Buffer.from(Buffer.from(toolSource).toString('base64'));
  const b64Path = 'usr/share/rekey-planted/notes.txt';
  withPlant.set(b64Path, { type: 'file', mode: 0o644, uid: 0, gid: 0, size: b64.length, sha256: sha().update(b64).digest('hex') });
  plantedFiles.push(b64Path);
  const v = baseDiff(withPlant, base, added);
  const red = new Set([...v.added_file_not_in_set.map((h) => h.path), ...v.changed.map((h) => h.path)]);
  const missed = plantedFiles.filter((p) => !red.has(`/${p}`));
  return { bites: !v.ok && plantedFiles.length > 1 && missed.length === 0, planted_files: plantedFiles.length, missed };
}

if (process.argv[1]?.endsWith('mediator-base-diff.mjs')) {
  const [rekTar, baseTar, addedJson, planted, tool, out] = process.argv.slice(2);
  try {
    if (!out) { console.error('usage: mediator-base-diff.mjs <rekey tar> <base tar> <added.json> <planted dir> <full tool> <out.json>'); process.exit(2); }
    const rek = tarList(rekTar), base = tarList(baseTar);
    const added = addedSet(JSON.parse(fs.readFileSync(addedJson, 'utf8')));
    const ins = instrument(rek, base, added, planted, fs.readFileSync(tool));
    const v = baseDiff(rek, base, added);
    // What the image actually holds under /opt/rekey, printed once for Security to pin (the noble files' shas).
    const added_read = [...rek].filter(([p, e]) => e.type === 'file' && !base.has(p)).map(([p, e]) => ({ path: `/${p}`, sha256: e.sha256, mode: e.mode.toString(8), owner: `${e.uid}:${e.gid}` })).sort((a, b) => (a.path < b.path ? -1 : 1));
    const checks = { instrument_bites: ins.bites ? 'PASS' : 'FAIL', rekey_matches_base_plus_added_set: v.ok ? 'PASS' : 'FAIL' };
    const ok = Object.values(checks).every((x) => x === 'PASS');
    fs.writeFileSync(out, `${JSON.stringify({ what: 'rekey image base diff (Security 11869.4)', ok, checks, instrument: ins, ...v, added_read, rek_entries: rek.size, base_entries: base.size }, null, 2)}\n`);
    console.log(JSON.stringify({ ok, checks, changed: v.changed.length, added_file_not_in_set: v.added_file_not_in_set, added_dir_outside: v.added_dir_outside, added_not_a_file: v.added_not_a_file, added_setuid: v.added_setuid, added_set_missing: v.added_set_missing, deleted: v.deleted_base_entries.length }));
    process.exit(ok ? 0 : 1);
  } catch (e) { console.error(`mediator-base-diff: ${e.message}`); process.exit(1); }
}
