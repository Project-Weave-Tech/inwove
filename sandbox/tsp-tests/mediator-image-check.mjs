#!/usr/bin/env node
// The image checks (Security 12195.1 d, 12422 e + the rekey image, 12491 b's image half), run on an image's whole
// filesystem plus its config. Security 12430: the filesystem is read from the image's own saved layers (`save:<tree.json>`
// from mediator-image-save.mjs), never through a container, and the config is the saved config blob (inspect-shaped);
// the searches also run over every regular file in every ADDED layer's own tar (bytes a later layer deletes still ship).
// A plain directory still works (the planted trees, the units). Names, paths and verdicts only.
//
//   service <rootfs> <inspect.json> <planted dir> <out.json>
//     (d) no file named mediator-setup anywhere;
//     (e) no file named mediator-store.mjs, and no regular file whose bytes carry rekey, delete-admin, admin-out,
//         seal-test or encrypt-test (a name search alone misses a renamed copy);
//     (b) no dbus-daemon / dbus-broker / dbus-launch anywhere, no /run/dbus/system_bus_socket, no /run/user/*/bus, and
//         the image's own Env names no DBUS_* and no XDG_RUNTIME_DIR;
//     the image: a non-root User, the exec-form entrypoint `/bin/bash -p /opt/mediator/mediator-entrypoint.sh`, the
//         baked deny sha256 beside it, and the keyring probe (12519 e).
//     Every search first runs on <planted dir> (a renamed copy of the store tool, a mediator-setup, a dbus-daemon,
//     a bus socket path) and must hit each, so a search that can't hit can't pass.
//   rekey <rootfs> <inspect.json> <shipped tool path in the image> <out.json> <planted dir>
//     the shipped tool's subcommands are within rekey/opens/names/absent (rekey present), none of the removed words
//     is in it, its sha256 for L8; (d) no mediator-setup; no mediator binary; no other copy of the store tool by
//     name, AND (Security 12940 change 2) no regular file outside the shipped path whose bytes carry delete-admin,
//     admin-out, seal-test or encrypt-test (`rekey` is left out: node itself may carry it); (Security 13081.2) no
//     archive-shaped file outside the shipped path (by magic bytes; brotli by name), since a byte search can't see
//     inside one; no exposed port; a non-root User. The content search first runs on <planted dir> and must hit its
//     renamed copy, and the archive list must hit the planted gzip of the full tool.
// Exit 0 only when every line is PASS.
import fs from 'node:fs';
import path from 'node:path';
import { shippedVerdict, sha256 } from './mediator-store-ship.mjs';

export const STORE_WORDS = ['rekey', 'delete-admin', 'admin-out', 'seal-test', 'encrypt-test'];
// The rekey image's content search (12940 change 2): the removed subcommands' names only; `rekey` is the shipped
// tool's own subcommand and may be in node's own files.
export const REKEY_IMAGE_WORDS = ['delete-admin', 'admin-out', 'seal-test', 'encrypt-test'];
const DBUS_BINS = ['dbus-daemon', 'dbus-broker', 'dbus-launch'];
// Security 13081.2: a byte search can't see inside a compressed file, so the rekey image also lists every
// archive-shaped file outside the shipped path, by its first bytes (a renamed archive is still found) and, for brotli,
// which has no magic, by name. Red outside ARCHIVES_ALLOWED. Plain tar is not listed: its members' bytes are stored as
// they are, so the content search already reads them.
// The zlib magic 78 5e is the text `x^`, so a plain text file that starts `x^` goes red too. That is fine on the rekey
// image (red is the safe side, Security 11869.5): don't loosen it.
export const ARCHIVE_MAGIC = [
  ['gzip', [0x1f, 0x8b]], ['zip', [0x50, 0x4b, 0x03, 0x04]], ['zip', [0x50, 0x4b, 0x05, 0x06]], ['zip', [0x50, 0x4b, 0x07, 0x08]],
  ['bzip2', [0x42, 0x5a, 0x68]], ['xz', [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]], ['zstd', [0x28, 0xb5, 0x2f, 0xfd]],
  ['7z', [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]], ['lz4', [0x04, 0x22, 0x4d, 0x18]], ['lzip', [0x4c, 0x5a, 0x49, 0x50]],
  ['zlib', [0x78, 0x01]], ['zlib', [0x78, 0x5e]], ['zlib', [0x78, 0x9c]], ['zlib', [0x78, 0xda]],
];
export const ARCHIVE_NAME = /\.(gz|tgz|zip|br|bz2|tbz2?|xz|txz|zst|tzst|7z|lz4|lzma|lz|z|jar|whl)$/i;
// Security 11869.3 (b)-(d): ONE triple, read from the pinned base node:22-bookworm-slim@sha256:e9f565d3…21ee (manifest
// amd64 47725aca…99fc, layer dd051e1b…63e3; dpkg's alternatives record for builtins.7.gz, a text file by name only).
// Allowed only when path, sha256, size AND kinds (exactly ['by-name']) all match: other bytes, another size, any magic
// kind, or any other path stays red. Widened only by a Security block at a base re-pin (REPIN.md item 12), never in place.
export const ARCHIVES_ALLOWED = Object.freeze([
  Object.freeze({ path: '/var/lib/dpkg/alternatives/builtins.7.gz', sha256: '6cd368606c13e12657f237f25e3ddfd89c6ebc34b52b8391561ff89d0c052f62', size: 83, kinds: Object.freeze(['by-name']) }),
]);
// The allowed entry this hit is, or null. Reads the file's bytes only for a path the list names.
export function allowedArchive(src, hit, allowed = ARCHIVES_ALLOWED) {
  const v = asView(src);
  const a = allowed.find((x) => x.path === hit.path);
  if (!a || JSON.stringify(hit.kinds) !== JSON.stringify(a.kinds)) return null;
  let buf;
  try { buf = hit.entry ? v.read(hit.entry) : v.readRel(hit.path.replace(/^\/+/, '')); } catch { return null; }
  return buf && buf.length === a.size && sha256(buf) === a.sha256 ? a : null;
}
// What the job prints: each allowed path as read in the image (sha256, size, kinds), or absent.
export function allowedRead(src, entries, allowed = ARCHIVES_ALLOWED) {
  const v = viewOf(src, entries);
  const hits = archives(v);
  return allowed.map((a) => {
    let buf = null;
    try { if (v.isFile(a.path.slice(1))) buf = v.readRel(a.path.slice(1)); } catch { /* absent */ }
    return buf === null ? { path: a.path, absent: true }
      : { path: a.path, sha256: sha256(buf), size: buf.length, kinds: hits.find((h) => h.path === a.path)?.kinds ?? [] };
  });
}
// Every archive-shaped regular file in a view (or under a root): {path, kinds} (+ layer for an added-layer view).
// Reads only each file's first bytes.
export function archives(src, entries) {
  const v = viewOf(src, entries);
  const out = [];
  for (const e of v.entries) {
    if (e.kind !== 'file') continue;
    const kinds = [];
    let head;
    try { head = v.head(e, 8); } catch { head = null; }
    const at = { path: `/${e.rel}`, ...(e.layer !== undefined ? { layer: e.layer } : {}) };
    if (!head) { out.push({ ...at, kinds: ['unreadable'] }); continue; }
    for (const [k, m] of ARCHIVE_MAGIC) if (head.length >= m.length && m.every((b, i) => head[i] === b) && !kinds.includes(k)) kinds.push(k);
    if (ARCHIVE_NAME.test(e.rel)) kinds.push('by-name');
    if (kinds.length) { const h = { ...at, kinds }; Object.defineProperty(h, 'entry', { value: e, enumerable: false }); out.push(h); }
  }
  return out;
}

// A directory on disk as a view: {entries, read(entry), head(entry, n), readRel(rel), isFile(rel)}. lstat only.
export function dirView(root) {
  const full = (rel) => path.join(root, rel);
  return {
    entries: walk(root),
    read: (e) => fs.readFileSync(full(e.rel)),
    head: (e, n) => { const b = Buffer.alloc(n); const fd = fs.openSync(full(e.rel), 'r'); try { return b.subarray(0, fs.readSync(fd, b, 0, n, 0)); } finally { fs.closeSync(fd); } },
    readRel: (rel) => fs.readFileSync(full(rel)),
    isFile: (rel) => { try { return fs.lstatSync(full(rel)).isFile(); } catch { return false; } },
  };
}
export const asView = (x) => (typeof x === 'string' ? dirView(x) : x);
const viewOf = (src, entries) => { const v = asView(src); return entries ? { ...v, entries } : v; };

export const SERVICE_ENTRYPOINT = ['/bin/bash', '-p', '/opt/mediator/mediator-entrypoint.sh'];

// Every entry under root (lstat; symlinks are listed, never followed). Returns {rel, kind, size}.
export function walk(root) {
  const out = [];
  const stack = [''];
  while (stack.length) {
    const rel = stack.pop();
    let ents;
    try { ents = fs.readdirSync(path.join(root, rel), { withFileTypes: true }); } catch { continue; }
    for (const e of ents) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) { out.push({ rel: r, kind: 'dir' }); stack.push(r); }
      else if (e.isSymbolicLink()) out.push({ rel: r, kind: 'link' });
      else if (e.isFile()) out.push({ rel: r, kind: 'file' });
      else out.push({ rel: r, kind: 'other' });
    }
  }
  return out.sort((a, b) => (a.rel < b.rel ? -1 : 1));
}

const base = (rel) => rel.split('/').pop();

// The searches, each a pure function of a view (or a root and its entries) → hits (paths, and for content the words;
// an added-layer view's hits carry their layer).
export function searches(src, entries, contentWords = STORE_WORDS) {
  const v = viewOf(src, entries);
  const es = v.entries;
  const at = (e) => ({ path: `/${e.rel}`, ...(e.layer !== undefined ? { layer: e.layer } : {}) });
  const named = (names) => es.filter((e) => e.kind !== 'dir' && names.includes(base(e.rel))).map((e) => `/${e.rel}`);
  const content = [];
  const words = contentWords.map((w) => Buffer.from(w));
  for (const e of es) {
    if (e.kind !== 'file') continue;
    let buf;
    try { buf = v.read(e); } catch { buf = null; }
    if (!buf) { content.push({ ...at(e), words: ['unreadable'] }); continue; }
    const hit = contentWords.filter((w, i) => buf.includes(words[i]));
    if (hit.length) content.push({ ...at(e), words: hit });
  }
  const busPaths = es.filter((e) => e.rel === 'run/dbus/system_bus_socket' || /^run\/user\/[^/]+\/bus$/.test(e.rel)).map((e) => `/${e.rel}`);
  return {
    setup_named: named(['mediator-setup']),
    store_named: named(['mediator-store.mjs']),
    store_words: content,
    dbus_bins: named(DBUS_BINS),
    bus_paths: busPaths,
  };
}

function inspectOf(file) {
  const j = JSON.parse(fs.readFileSync(file, 'utf8'));
  const c = (Array.isArray(j) ? j[0] : j)?.Config;
  if (!c) throw new Error('no Config in the inspect JSON');
  return c;
}
const envNames = (c) => (c.Env || []).map((kv) => kv.split('=')[0]);
const nonRoot = (u) => !!u && !/^(root|0)(:|$)/.test(u);
const P = (ok) => (ok ? 'PASS' : 'FAIL');

// layers: the added-layer view (Security 12430 (2)): the same (d), (e) and (b) name searches run over every regular file
// in every added layer's own tar. Optional for the units; the CLI always passes it in save mode.
export function serviceVerdict(root, config, planted, layers = null) {
  const v = asView(root);
  const s = searches(v);
  const p = searches(planted);
  const l = layers ? searches(layers) : null;
  const instrument = {
    planted_setup_found: p.setup_named.length > 0,
    planted_store_name_found: p.store_named.length > 0,
    planted_renamed_copy_found: p.store_words.some((h) => !h.path.endsWith('mediator-store.mjs') && h.words.length === STORE_WORDS.length),
    planted_dbus_found: p.dbus_bins.length > 0,
    planted_bus_path_found: p.bus_paths.length > 0,
  };
  const names = envNames(config);
  const env_dbus = names.filter((n) => /^DBUS_/.test(n) || n === 'XDG_RUNTIME_DIR');
  const has = (rel) => v.isFile(rel);
  const ep = config.Entrypoint || [];
  const checks = {
    instrument_bites: P(Object.values(instrument).every(Boolean)),
    d_no_mediator_setup: P(s.setup_named.length === 0),
    e_no_store_tool_by_name: P(s.store_named.length === 0),
    e_no_file_carries_the_store_words: P(s.store_words.length === 0),
    b_no_dbus_daemon_or_broker: P(s.dbus_bins.length === 0),
    b_no_bus_socket_paths: P(s.bus_paths.length === 0),
    b_image_env_names_no_bus: P(env_dbus.length === 0),
    user_not_root: P(nonRoot(config.User)),
    entrypoint_exec_form: P(JSON.stringify(ep) === JSON.stringify(SERVICE_ENTRYPOINT)),
    entrypoint_and_deny_sha_present: P(has('opt/mediator/mediator-entrypoint.sh') && has('opt/mediator/mediator-deny.sha256')),
    keyring_probe_present: P(has('opt/mediator/keyring-probe')),
    ...(l ? {
      added_layers_no_mediator_setup: P(l.setup_named.length === 0),
      added_layers_no_store_tool_by_name: P(l.store_named.length === 0),
      added_layers_no_file_carries_the_store_words: P(l.store_words.length === 0),
      added_layers_no_dbus_daemon_or_broker: P(l.dbus_bins.length === 0),
    } : {}),
  };
  return { checks, hits: s, added_layer_hits: l, added_layer_files: layers ? layers.entries.length : null, instrument, user: config.User || '', entrypoint: ep, env_names: names.sort(), env_bus_names: env_dbus };
}

// layers: the added-layer view (Security 12430 (e)): the removed-word search and the archive list also run over every
// regular file in every added layer's own tar; the shipped path is left out only where its bytes are the shipped tool's.
export function rekeyVerdict(root, config, shipped, planted, layers = null) {
  const v0 = asView(root);
  const s = searches(v0, null, REKEY_IMAGE_WORDS);
  const rel = shipped.replace(/^\/+/, '');
  // 12940 change 2: an instrument that can't hit can't pass. The planted tree holds a renamed copy of the full tool.
  const p = planted ? searches(planted, walk(planted), REKEY_IMAGE_WORDS) : null;
  const plantedRenamedHit = !!p && p.store_words.some((h) => !h.path.endsWith('mediator-store.mjs') && h.words.length === REKEY_IMAGE_WORDS.length);
  const contentHits = s.store_words.filter((h) => h.path !== `/${rel}`);
  // 13081.2: the archive list must first find the planted gzip of the full tool (named so only its bytes give it away)
  const plantedArchive = !!planted && archives(planted, walk(planted)).some((a) => a.kinds.includes('gzip') && !a.kinds.includes('by-name'));
  const archiveHits = archives(v0).filter((a) => a.path !== `/${rel}` && !allowedArchive(v0, a));
  const archivesAllowedRead = allowedRead(v0);
  let text = null;
  try { const b = v0.isFile(rel) ? v0.readRel(rel) : null; text = b ? b.toString('utf8') : null; } catch { /* checked below */ }
  const v = text === null ? null : shippedVerdict(text);
  const shippedSha = text === null ? null : sha256(Buffer.from(text));
  // an added-layer file at the shipped path is the shipped tool only when its bytes are the image's shipped bytes
  const isShipped = (h) => h.path === `/${rel}` && h.entry && shippedSha !== null && sha256(layers.read(h.entry)) === shippedSha;
  let layerContent = null, layerArchives = null;
  if (layers) {
    const ls = searches(layers, null, REKEY_IMAGE_WORDS);
    layerContent = ls.store_words.filter((h) => {
      if (h.path !== `/${rel}`) return true;
      const e = layers.entries.find((x) => x.layer === h.layer && `/${x.rel}` === h.path);
      return !(e && shippedSha !== null && sha256(layers.read(e)) === shippedSha);
    });
    layerArchives = archives(layers).filter((a) => !isShipped(a) && !allowedArchive(layers, a));
    layerContent.named = ls.store_named.filter((p) => p !== `/${rel}`);
    layerContent.setup = ls.setup_named;
  }
  const entries = v0.entries;
  const mediatorBins = entries.filter((e) => e.kind === 'file' && base(e.rel) === 'mediator').map((e) => `/${e.rel}`);
  const otherCopies = s.store_named.filter((p) => p !== `/${rel}`);
  const ports = Object.keys(config.ExposedPorts || {});
  const checks = {
    shipped_tool_present: P(v !== null),
    shipped_subcommands_within_rekey_opens_names_absent: P(!!v && v.extra_subcommands.length === 0 && v.subcommands.includes('rekey')),
    shipped_file_has_no_removed_words: P(!!v && v.forbidden_words.length === 0 && !v.markers_left),
    d_no_mediator_setup: P(s.setup_named.length === 0),
    no_mediator_binary: P(mediatorBins.length === 0),
    no_other_store_tool_copy: P(otherCopies.length === 0),
    content_search_bites: P(plantedRenamedHit),
    no_file_outside_the_shipped_path_carries_the_removed_words: P(contentHits.length === 0),
    archive_search_bites: P(plantedArchive),
    no_archive_outside_the_shipped_path: P(archiveHits.length === 0),
    no_exposed_port: P(ports.length === 0),
    user_not_root: P(nonRoot(config.User)),
    ...(layers ? {
      added_layers_no_file_carries_the_removed_words: P(layerContent.length === 0),
      added_layers_no_archive: P(layerArchives.length === 0),
      added_layers_no_other_store_tool_or_setup_by_name: P(layerContent.named.length === 0 && layerContent.setup.length === 0),
    } : {}),
  };
  return { checks, shipped: shipped, shipped_sha256: shippedSha, added_layer_files: layers ? layers.entries.length : null,
    added_layer_removed_word_hits: layerContent ? [...layerContent] : null, added_layer_archive_hits: layerArchives, subcommands: v?.subcommands ?? null,
    forbidden_words: v?.forbidden_words ?? null, mediator_bins: mediatorBins, other_copies: otherCopies,
    removed_word_hits: contentHits, planted_renamed_copy_found: plantedRenamedHit,
    archive_hits: archiveHits, archives_allowed: ARCHIVES_ALLOWED, archives_allowed_read: archivesAllowedRead, planted_archive_found: plantedArchive, exposed_ports: ports, user: config.User || '' };
}

// `save:<tree.json>` (mediator-image-save.mjs): the applied tree + the added-layer view; anything else is a directory.
async function sourceOf(arg) {
  if (!String(arg).startsWith('save:')) return { root: arg, layers: null };
  const { viewsFromJson } = await import('./mediator-image-save.mjs');
  const v = viewsFromJson(JSON.parse(fs.readFileSync(arg.slice(5), 'utf8')));
  return { root: v.tree, layers: v.layers };
}

if (process.argv[1]?.endsWith('mediator-image-check.mjs')) {
  const [mode, rootArg, inspect, third, out, fourth] = process.argv.slice(2);
  (async () => {
    const config = inspectOf(inspect);
    const { root, layers } = await sourceOf(rootArg);
    const r = mode === 'service' ? serviceVerdict(root, config, third, layers) : mode === 'rekey' && fourth ? rekeyVerdict(root, config, third, fourth, layers) : null;
    if (!r) { console.error('usage: mediator-image-check.mjs service <rootfs|save:tree.json> <config.json> <planted> <out.json> | rekey <rootfs|save:tree.json> <config.json> <shipped> <out.json> <planted>'); return 2; }
    const ok = Object.values(r.checks).every((x) => x === 'PASS');
    const rec = { what: `image check (${mode})`, read_from: layers ? 'saved layers' : 'a directory', ok, ...r };
    fs.writeFileSync(out, `${JSON.stringify(rec, null, 2)}\n`);
    console.log(JSON.stringify({ mode, ok, checks: r.checks }));
    return ok ? 0 : 1;
  })().then((c) => process.exit(c), (e) => { console.error(`mediator-image-check: ${e.message}`); process.exit(1); });
}
