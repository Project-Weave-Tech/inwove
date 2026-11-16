#!/usr/bin/env node
// The rekey image's base-diff line (Security 11869.4). A list of encodings can't close the gap: the full store tool as
// base64, hex, raw deflate, brotli under any name, a gzip one byte in, a tar member, the source reversed — each passes
// every content and archive line. So the rekey image is judged against the pinned base image it is built FROM, file by
// file. Security 12430 (a): both sides are read from the images' own layers (`docker save`, applied by
// mediator-image-save.mjs), never through a container: a container's export shows the runtime's own /etc/hosts,
// /etc/hostname, /etc/resolv.conf and /.dockerenv, whatever the image holds there.
//
//   - every regular file is either byte-identical to the base's file at that path, with the same mode and owner, or in
//     the ADDED SET (rekey-added.json): the shipped tool at the L8 pin plus each @noble/hashes file at its pinned sha;
//   - a base entry whose bytes, mode, owner, type or link target changed is red (a setuid bit added counts);
//   - an added directory is allowed only at /opt/rekey or under it; an added link, hard link or device is red;
//   - an added-set file that is missing, or an added file with a setuid/setgid bit, is red;
//   - extended attributes (the pax `SCHILY.xattr.<name>` records, e.g. security.capability, which can give a binary
//     privileges without a setuid bit): any xattr added, removed or changed on any path, base entry or added entry,
//     /opt/rekey included, is red. Only each value's sha256 is kept; a value is never printed;
//   - a base directory whose mode or owner changed is red (directories are compared like files, bar bytes);
//   - deleted base entries are fine, and listed.
// Security 12327 + 12358: the base side is the tree built from the pinned layers (mediator-base-layers.mjs), never the
// local pull; the local pull's saved tree is cross-checked against that tree entry for entry with ZERO exceptions
// (12430 (f); its own instrument plants one changed file). Names are read after pax/GNU headers; a doubled, orphan or
// global-path header is red.
// The line must first go red on the planted tree plus a base64 copy of the full tool (instrument bites), or it can't
// pass. Names, paths, shas and verdicts only; no file's bytes are printed.
//
//   mediator-base-diff.mjs <rekey tree.json> <registry tree.json> <local base tree.json> <added.json> <planted dir> <full tool source> <out.json>
// (each tree.json as mediator-image-save.mjs / mediator-base-layers.mjs write it)
// Exit 0 only when instrument_bites and rekey_matches_base_plus_added_set are both PASS.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const sha = () => crypto.createHash('sha256');
const norm = (p) => p.replace(/^(\.\/)+/, '').replace(/^\/+/, '').replace(/\/+$/, '');
const octal = (b) => { const s = b.toString('latin1').replace(/\0.*$/s, '').trim(); return s ? parseInt(s, 8) : 0; };
const str = (b) => b.toString('utf8').replace(/\0.*$/s, '');
const XATTR_PREFIX = 'SCHILY.xattr.';
const TYPES = { '0': 'file', '\0': 'file', '7': 'file', '1': 'hardlink', '2': 'link', '5': 'dir', '3': 'other', '4': 'other', '6': 'other' };

// Security 12358 (Railroad 12351): every name is the EFFECTIVE one tar will write: after a pax 'x' header (`path`,
// `linkpath`) and GNU 'L'/'K' long-name/long-link entries, never the raw ustar field. These are red, as `anomalies`:
//   - a pax global header ('g') carrying `path` or `linkpath`;
//   - two headers of one kind ('x', 'L' or 'K') before one member, or a GNU long name and a pax path that disagree;
//   - a pax/long-name header with no member after it;
//   - a malformed pax record.
// tarWalk(file, onEntry) calls onEntry({name, linkname, type, mode, uid, gid, size, xattrs?, sha256? (files)}) for each
// member in stream order, with `name`/`linkname` as written (not normalised), and returns the anomalies. Content is
// hashed in chunks, never kept.
export function tarWalk(file, onEntry) {
  const fd = fs.openSync(file, 'r');
  const anomalies = [];
  const hdr = Buffer.alloc(512);
  let pos = 0, pax = null, xattrs = {}, longName = null, longLink = null, member = 0;
  const readExact = (buf, len, at) => { let n = 0; while (n < len) { const r = fs.readSync(fd, buf, n, len - n, at + n); if (!r) throw new Error('tar: short read'); n += r; } };
  const readBody = (size, onChunk) => {
    const chunk = Buffer.alloc(1 << 20);
    let left = size, at = pos;
    while (left > 0) { const n = Math.min(left, chunk.length); readExact(chunk, n, at); onChunk(chunk.subarray(0, n)); left -= n; at += n; }
    pos += Math.ceil(size / 512) * 512;
  };
  const paxRecords = (body, where) => {
    const recs = {};
    let i = 0;
    while (i < body.length) {
      const sp = body.indexOf(0x20, i); const len = sp > i ? Number(body.subarray(i, sp).toString()) : NaN;
      if (!(Number.isInteger(len) && len > 0) || i + len > body.length || body[i + len - 1] !== 0x0a) { anomalies.push({ kind: 'pax_malformed', at: where }); break; }
      const rec = body.subarray(sp + 1, i + len - 1); const eq = rec.indexOf(0x3d);
      if (eq < 1) { anomalies.push({ kind: 'pax_malformed', at: where }); break; }
      recs[rec.subarray(0, eq).toString('utf8')] = rec.subarray(eq + 1);
      i += len;
    }
    return recs;
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
        const where = `before member ${member + 1}`;
        if (t === 'L') { if (longName !== null) anomalies.push({ kind: 'two_long_names', at: where }); longName = str(body); }
        else if (t === 'K') { if (longLink !== null) anomalies.push({ kind: 'two_long_links', at: where }); longLink = str(body); }
        else if (t === 'g') {
          const recs = paxRecords(body, where);
          for (const k of ['path', 'linkpath']) if (k in recs) anomalies.push({ kind: `pax_global_${k}`, at: where });
        } else {
          if (pax !== null) anomalies.push({ kind: 'two_pax_headers', at: where });
          pax = {}; xattrs = {};
          for (const [key, val] of Object.entries(paxRecords(body, where))) {
            // xattr values are binary: hash the bytes, keep only the digest
            if (key.startsWith(XATTR_PREFIX)) xattrs[key.slice(XATTR_PREFIX.length)] = sha().update(val).digest('hex');
            else pax[key] = val.toString('utf8');
          }
        }
        continue;
      }
      member += 1;
      const p = pax || {};
      const prefix = str(hdr.subarray(345, 500));
      const ustarName = prefix ? `${prefix}/${str(hdr.subarray(0, 100))}` : str(hdr.subarray(0, 100));
      if (longName !== null && p.path !== undefined && longName !== p.path) anomalies.push({ kind: 'long_name_and_pax_path_disagree', at: `member ${member}` });
      if (longLink !== null && p.linkpath !== undefined && longLink !== p.linkpath) anomalies.push({ kind: 'long_link_and_pax_linkpath_disagree', at: `member ${member}` });
      const name = p.path ?? longName ?? ustarName;
      const linkname = p.linkpath ?? longLink ?? str(hdr.subarray(157, 257));
      if (p.size !== undefined) size = Number(p.size);
      const e = {
        name,
        type: TYPES[t] ?? 'other',
        mode: octal(hdr.subarray(100, 108)) & 0o7777,
        uid: p.uid !== undefined ? Number(p.uid) : octal(hdr.subarray(108, 116)),
        gid: p.gid !== undefined ? Number(p.gid) : octal(hdr.subarray(116, 124)),
      };
      if (Object.keys(xattrs).length) e.xattrs = xattrs;
      if (e.type === 'file') { e.offset = pos; const h = sha(); readBody(size, (c) => h.update(c)); e.size = size; e.sha256 = h.digest('hex'); }
      else { if (size) readBody(size, () => {}); if (e.type === 'link' || e.type === 'hardlink') e.linkname = linkname; }
      onEntry(e);
      pax = null; xattrs = {}; longName = null; longLink = null;
    }
    if (pax !== null || longName !== null || longLink !== null) anomalies.push({ kind: 'header_without_member', at: 'end of archive' });
  } finally { fs.closeSync(fd); }
  return anomalies;
}

// A name's path components after the effective-name read, or a reason it is red: absolute, or a `..` component.
export function components(name) {
  const s = String(name);
  if (s.startsWith('/')) return { red: 'absolute' };
  const parts = s.split('/').filter((c) => c !== '' && c !== '.');
  if (parts.includes('..')) return { red: 'dotdot' };
  return { parts };
}

// Every entry of a tar file (an export stream): Map path → {type, mode, uid, gid, size, sha256 (files and hard links,
// a hard link carrying its target's bytes' sha), linkname (links)}. The map carries `.anomalies` (the 12358 list, plus
// a `..` member or a hard link whose target is missing or outside the stream).
export function tarList(file) {
  const out = new Map();
  const extra = [];
  const anomalies = tarWalk(file, (e) => {
    const name = norm(e.name);
    if (!name) return;
    if (components(name).red === 'dotdot') extra.push({ kind: 'dotdot_member', path: `/${name}` });
    delete e.name;
    if (e.type === 'hardlink') {
      const c = components(norm(e.linkname));
      const tgt = c.parts ? out.get(c.parts.join('/')) : null;
      if (!tgt || tgt.sha256 === undefined) extra.push({ kind: 'hardlink_target_not_a_file_in_the_stream', path: `/${name}` });
      else { e.sha256 = tgt.sha256; e.size = tgt.size; }
    }
    out.set(name, e);
  });
  out.anomalies = [...anomalies, ...extra];
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

// The added set as a Map path → sha256, from rekey-added.json's {tool: {path, sha256}, entrypoint?: {path, sha256}, noble: [{path, sha256}]}.
export function addedSet(j) {
  const m = new Map();
  // Security 12024.1: the rekey entrypoint is one more added file, beside the tool, once a Security block pins it.
  for (const f of [j.tool, ...(j.entrypoint ? [j.entrypoint] : []), ...(j.noble || [])]) m.set(norm(f.path), f.sha256);
  return m;
}

// The xattr names that differ between two entries (added, removed or changed value); b may be undefined (an added entry).
const xattrDiff = (e, b) => {
  const x = e.xattrs || {}, y = b?.xattrs || {};
  return [...new Set([...Object.keys(x), ...Object.keys(y)])].filter((n) => x[n] !== y[n]).sort();
};

// Two entries compared field by field, the way the walk compares them: kind (a hard link counts as a file, judged by
// its target's bytes, since which path of a linked pair a tar writer calls "the file" is the writer's choice), mode,
// owner, bytes (sha256 + size) for files, target for symlinks, xattrs. Returns the names of the fields that differ.
const kindOf = (e) => (e.type === 'hardlink' ? 'file' : e.type);
export function entryDiff(e, b) {
  const why = [];
  if (kindOf(b) !== kindOf(e)) why.push('type');
  if (b.mode !== e.mode) why.push('mode');
  if (b.uid !== e.uid || b.gid !== e.gid) why.push('owner');
  if (kindOf(e) === 'file' && kindOf(b) === 'file' && (b.sha256 === undefined || b.sha256 !== e.sha256 || b.size !== e.size)) why.push('bytes');
  if (e.type === 'link' && b.type === 'link' && b.linkname !== e.linkname) why.push('link');
  if (xattrDiff(e, b).length) why.push('xattrs');
  return why;
}

// The 12327.4 cross-check, exact (Security 12430 (f)): the local pull's saved tree must equal the registry-built tree
// entry for entry, zero exceptions (no container is read, so there are no runtime entries to allow).
export function crossCheck(local, registry) {
  const only_local = [], only_registry = [], differ = [];
  for (const [p, e] of local) {
    const r = registry.get(p);
    if (!r) { only_local.push({ path: `/${p}`, type: kindOf(e) }); continue; }
    const why = entryDiff(e, r);
    if (why.length) differ.push({ path: `/${p}`, why });
  }
  for (const p of registry.keys()) if (!local.has(p)) only_registry.push(`/${p}`);
  return { ok: !only_local.length && !only_registry.length && !differ.length, only_local, only_registry: only_registry.sort(), differ };
}

// rek, base: Maps (applied trees, or tarList). added: Map path → sha256. Returns the hits by kind, and ok.
export function baseDiff(rek, base, added) {
  const xattr = [], changed = [], addedFile = [], addedDir = [], addedOther = [], suid = [], missing = [], deleted = [];
  for (const [p, e] of rek) {
    const b = base.get(p);
    const xn = xattrDiff(e, b);
    if (xn.length) xattr.push({ path: `/${p}`, names: xn });
    if (b) {
      const why = entryDiff(e, b).filter((w) => w !== 'xattrs');
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
  const ok = !changed.length && !addedFile.length && !addedDir.length && !addedOther.length && !suid.length && !missing.length && !xattr.length;
  return { ok, changed, added_file_not_in_set: addedFile, added_dir_outside: addedDir, added_not_a_file: addedOther,
    xattr_changed: xattr, added_setuid: suid, added_set_missing: missing, deleted_base_entries: deleted.sort() };
}

// Every path a base diff calls red, by kind (for the plants: "red by name").
export function redPaths(v) {
  return [...new Set([...v.changed.map((h) => h.path), ...v.added_file_not_in_set.map((h) => h.path), ...v.added_dir_outside,
    ...v.added_not_a_file.map((h) => h.path), ...v.xattr_changed.map((h) => h.path), ...v.added_setuid, ...v.added_set_missing])].sort();
}

// The registry-built tree, as mediator-base-layers.mjs writes it: {entries: [[path, entry], …]}.
export function treeFromJson(j) {
  if (!Array.isArray(j?.entries)) throw new Error('registry tree: no entries');
  return new Map(j.entries.map(([p, e]) => { const { src: _s, ...rest } = e; return [p, rest]; }));
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

// The cross-check's own instrument: the local walk with one file's bytes changed must come back red on that path.
export function crossCheckBites(local, registry) {
  const f = [...local].find(([p, e]) => e.type === 'file' && registry.has(p));
  if (!f) return { bites: false, why: 'no file in both walks' };
  const planted = new Map(local); planted.set(f[0], { ...f[1], sha256: '0'.repeat(64) });
  const v = crossCheck(planted, registry);
  return { bites: !v.ok && v.differ.some((d) => d.path === `/${f[0]}` && d.why.includes('bytes')) };
}

if (process.argv[1]?.endsWith('mediator-base-diff.mjs')) {
  const [rekTree, treeJson, localTree, addedJson, planted, tool, out] = process.argv.slice(2);
  try {
    if (!out) { console.error('usage: mediator-base-diff.mjs <rekey tree.json> <registry tree.json> <local base tree.json> <added.json> <planted dir> <full tool> <out.json>'); process.exit(2); }
    // Security 12327: the base side is the tree built from the pinned layers (mediator-base-layers.mjs); 12430: the rekey
    // side and the local pull are the trees their own saved layers apply to (mediator-image-save.mjs). A missing tree
    // (a layer check failed, or the fetch or the save did) throws here, so the line is red, never a pass.
    const rd = (f) => treeFromJson(JSON.parse(fs.readFileSync(f, 'utf8')));
    const base = rd(treeJson), rek = rd(rekTree), local = rd(localTree);
    const added = addedSet(JSON.parse(fs.readFileSync(addedJson, 'utf8')));
    const ins = instrument(rek, base, added, planted, fs.readFileSync(tool));
    const v = baseDiff(rek, base, added);
    const cc = crossCheck(local, base);
    const ccb = crossCheckBites(local, base);
    // What the image actually holds under /opt/rekey, printed once for Security to pin (the noble files' shas).
    const added_read = [...rek].filter(([p, e]) => e.type === 'file' && !base.has(p)).map(([p, e]) => ({ path: `/${p}`, sha256: e.sha256, mode: e.mode.toString(8), owner: `${e.uid}:${e.gid}` })).sort((a, b) => (a.path < b.path ? -1 : 1));
    const checks = {
      instrument_bites: ins.bites ? 'PASS' : 'FAIL',
      rekey_matches_base_plus_added_set: v.ok ? 'PASS' : 'FAIL',
      local_base_equals_registry_tree: cc.ok ? 'PASS' : 'FAIL',
      cross_check_bites: ccb.bites ? 'PASS' : 'FAIL',
    };
    const ok = Object.values(checks).every((x) => x === 'PASS');
    fs.writeFileSync(out, `${JSON.stringify({ what: 'rekey image base diff against the registry-built base, both read from saved layers (Security 11869.4, 12327, 12358, 12430)', ok, checks, instrument: ins, cross_check: cc, cross_check_instrument: ccb, ...v, red_paths: redPaths(v), added_read, rek_entries: rek.size, local_base_entries: local.size, registry_entries: base.size }, null, 2)}\n`);
    console.log(JSON.stringify({ ok, checks, changed: v.changed.length, red_paths: redPaths(v), added_file_not_in_set: v.added_file_not_in_set, added_dir_outside: v.added_dir_outside, added_not_a_file: v.added_not_a_file, added_setuid: v.added_setuid, xattr_changed: v.xattr_changed, added_set_missing: v.added_set_missing, deleted: v.deleted_base_entries.length,
      cross_check: { only_local: cc.only_local, only_registry: cc.only_registry.length, differ: cc.differ.slice(0, 50), differ_count: cc.differ.length } }));
    process.exit(ok ? 0 : 1);
  } catch (e) { console.error(`mediator-base-diff: ${e.message}`); process.exit(1); }
}
