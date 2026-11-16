#!/usr/bin/env node
// The base diff's base side, built from the pinned bytes (Security 12327, Railroad 12314; PAX/GNU names Security 12358,
// Railroad 12351). The base side used to be the local pull's `docker export`, tied to the pin only by the store's own
// report. Here it is built from the layers the pinned linux/amd64 manifest names, fetched by digest
// (mediator-base-fetch.mjs writes them, raw, judging nothing), so it is the pinned bytes by construction:
//
//   1. the manifest's sha256 = the pinned base_manifest_digest, the config blob's = the pinned base_config_digest and
//      the manifest's config.digest (rekey-config.json, Security 12278.2);
//   2. each layer: compressed sha256 + size = the manifest's entry; media type one of the manifest's own tar(+gzip)
//      types; layer count = the blob's rootfs.diff_ids count; decompressed sha256 = diff_ids[i], in order;
//   3. applied in order into an in-memory tree: an absolute name, a `..` component, or a write through a symlink an
//      earlier entry laid down is red; `.wh.<name>` deletes its path, `.wh..wh..opq` empties its directory of what the
//      layers below put there; hard links resolve inside the tree (to a file already in it), or are red. Every name is
//      the effective one (pax `path`/`linkpath`, GNU `L`/`K`), and a pax global path, an orphan or doubled header is
//      red (tarWalk in mediator-base-diff.mjs).
//
// The tree is written only when every check passes; mediator-base-diff.mjs reads a missing tree as red. A failed or
// rate-limited fetch leaves a layer missing, so it fails closed here too. Printed: per-layer digest verdicts and
// counts only, never a file's bytes.
//
//   mediator-base-layers.mjs <chain dir> <rekey-config.json> <out tree.json> <out verdict.json>
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { pipeline } from 'node:stream/promises';
import { Transform } from 'node:stream';
import { tarWalk, components } from './mediator-base-diff.mjs';

const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const OCI_MANIFEST = 'application/vnd.oci.image.manifest.v1+json';
const DOCKER_MANIFEST = 'application/vnd.docker.distribution.manifest.v2+json';
// The layer types each manifest type may name, and whether the bytes are gzip.
const LAYER_TYPES = {
  [OCI_MANIFEST]: { 'application/vnd.oci.image.layer.v1.tar+gzip': true, 'application/vnd.oci.image.layer.v1.tar': false },
  [DOCKER_MANIFEST]: { 'application/vnd.docker.image.rootfs.diff.tar.gzip': true },
};

// Where the fetch writes layer i (0-based): <chain>/layers/<i>.blob; the decompressed tar goes beside it as <i>.tar.
export const layerBlob = (chain, i) => path.join(chain, 'layers', `${i}.blob`);
export const layerTar = (chain, i) => path.join(chain, 'layers', `${i}.tar`);

// Step 2 on bytes already read, for ANY image (Security 12430 (c): the registry base side and every `docker save` read
// share this one function, not a copy). manifest + config: parsed objects; blobs: per layer Buffer|null;
// decompressedSha(buf, gzip, i) → hex | null. Each layer: compressed sha256 + size = the manifest's entry, media type
// one of the manifest's own tar(+gzip) types, count = rootfs.diff_ids count, decompressed sha256 = diff_ids[i] in order.
export function checkLayers({ manifest, config, blobs, decompressedSha }) {
  const checks = {};
  const P = (b) => (b ? 'PASS' : 'FAIL');
  const types = LAYER_TYPES[manifest?.mediaType] || null;
  checks.manifest_type_known = P(!!types);
  const ls = Array.isArray(manifest?.layers) ? manifest.layers : [];
  const diffIds = Array.isArray(config?.rootfs?.diff_ids) ? config.rootfs.diff_ids : [];
  checks.layer_count_equals_diff_ids = P(ls.length > 0 && ls.length === diffIds.length && blobs.length === ls.length && blobs.every(Boolean));
  const layers = ls.map((d, i) => {
    const b = blobs[i];
    const gz = types ? types[d?.mediaType] : undefined;
    const v = {
      i, digest: String(d?.digest ?? ''),
      compressed: P(!!b && /^sha256:[0-9a-f]{64}$/.test(String(d?.digest)) && `sha256:${sha(b)}` === d.digest && b.length === d.size),
      size: P(!!b && b.length === d?.size),
      media_type: P(gz !== undefined),
      diff_id: 'FAIL',
    };
    if (b && gz !== undefined) {
      const got = decompressedSha(b, gz, i);
      v.diff_id = P(got !== null && `sha256:${got}` === diffIds[i]);
    }
    return v;
  });
  checks.every_layer_checks = P(layers.length > 0 && layers.every((l) => l.compressed === 'PASS' && l.size === 'PASS' && l.media_type === 'PASS' && l.diff_id === 'PASS'));
  return { checks, layers, gzip: layers.map((l, i) => (types ? types[ls[i]?.mediaType] === true : false)), counts: { layers: ls.length, diff_ids: diffIds.length, blobs: blobs.filter(Boolean).length } };
}

// Whether layer i of a manifest is gzip (true), plain tar (false), or not one of its own types (undefined).
export const layerGzip = (manifest, i) => LAYER_TYPES[manifest?.mediaType]?.[manifest?.layers?.[i]?.mediaType];

// Steps 1-2 for the registry base: the pins, then checkLayers. Pure, so the units can feed it made-up chains.
// Returns {ok, checks, layers: [{i, digest, compressed, size, media_type, diff_id}], counts}.
export function layerVerdict({ manifestRaw, configRaw, pins, blobs, decompressedSha }) {
  const P = (b) => (b ? 'PASS' : 'FAIL');
  let manifest = null, config = null;
  try { manifest = JSON.parse(manifestRaw.toString('utf8')); } catch {}
  try { config = JSON.parse(configRaw.toString('utf8')); } catch {}
  const pinChecks = {
    manifest_is_the_pin: P(!!manifestRaw && `sha256:${sha(manifestRaw)}` === pins.base_manifest_digest),
    config_is_the_pin: P(!!configRaw && `sha256:${sha(configRaw)}` === pins.base_config_digest && manifest?.config?.digest === pins.base_config_digest),
  };
  const c = checkLayers({ manifest, config, blobs, decompressedSha });
  const checks = { ...pinChecks, ...c.checks };
  const ok = Object.values(checks).every((x) => x === 'PASS');
  return { ok, ...c, checks };
}

// Step 3: apply layer tars, in order, into a tree. tars: file paths. Returns {tree: Map path → entry, red: [...],
// whiteouts, opaque, layer_red, per_layer}. A whiteout of a path laid down earlier in the same layer is red (a malformed
// layer), and so is a whiteout or entry whose parent is a symlink or a non-directory.
//
// opts (Security 12430 (e), for a `docker save` read): bytes a later layer deletes still ship in the image, so from
// layer `addedFrom` on (the first layer past the pinned base prefix) the ADDED layers are judged one by one, not only
// the applied tree:
//   - a non-directory an added layer laid down, then overwritten or deleted (whiteout, opaque dir, or a directory
//     written over it) in a later added layer = red; so is an added directory re-stated with another mode, owner or
//     xattrs, or deleted;
//   - a whiteout in an added layer may delete only a BASE path (one the base prefix laid down; a base directory an
//     added layer merely re-states stays one), and only one named in opts.whiteouts (exact; a listed one that never comes is red too, so a stale list
//     never passes quietly); an opaque dir only a base dir named in opts.opaque, the same way;
//   - the same path written twice in ONE added layer (Security 12480, the one change before any rekey run) = red, `written_twice_in_one_layer`: the
//     applied tree keeps only the second, so the first entry's bytes ship unseen at tree level (the content searches
//     still read both, from addedLayerFiles). Any entry kind, a directory too; implicit parents don't count;
// opts.keepSource: each file entry keeps {layer, offset} (where its bytes sit in that layer's tar) so the image checks
// can read the applied tree straight from the layers, never through a container.
export function applyLayers(tars, opts = {}) {
  const addedFrom = Number.isInteger(opts.addedFrom) ? opts.addedFrom : Infinity;
  const allowWh = new Set((opts.whiteouts || []).map((x) => String(x).replace(/^\/+/, '')));
  const allowOpq = new Set((opts.opaque || []).map((x) => String(x).replace(/^\/+/, '')));
  const tree = new Map();
  const red = [];
  const layerRed = [];
  const perLayer = [];
  const seenWh = new Set(), seenOpq = new Set();
  // path → {layer, type, mode, uid, gid, xattrs} for what an ADDED layer wrote (implicit parents excluded)
  const addedBy = new Map();
  let whiteouts = 0, opaque = 0;
  // what the base prefix laid down, taken when the first added layer starts: a base directory an added layer
  // re-states (every COPY layer re-states its parents) stays a base directory
  let basePaths = new Set();
  const delTree = (p, keep = null) => {
    for (const k of [...tree.keys()]) if ((k === p || k.startsWith(`${p}/`)) && !(keep && keep.has(k))) tree.delete(k);
  };
  const under = (k, d) => d === '' || k === d || k.startsWith(`${d}/`);
  // An added layer li deletes everything at or under d (strictly under, for an opaque dir): any of it an earlier added
  // layer wrote is red.
  const addedGone = (li, d, why, at, strict = false) => {
    for (const [k, w] of addedBy) if (w.layer < li && (strict ? k !== d && under(k, d) : under(k, d))) layerRed.push({ kind: why, ...at, added_in_layer: w.layer, gone: `/${k}`.slice(0, 200) });
  };
  tars.forEach((file, li) => {
    const thisLayer = new Set();
    // the paths this layer's own entries named (never the implicit parents), for the written-twice rule
    const written = new Set();
    const added = li >= addedFrom;
    if (li === addedFrom) basePaths = new Set([...tree].filter(([, e]) => !e.implicit).map(([k]) => k));
    const pl = { layer: li, added, files: 0, dirs: 0, links: 0, hardlinks: 0, other: 0, whiteouts: 0, opaque: 0 };
    perLayer.push(pl);
    const anomalies = tarWalk(file, (e) => {
      const at = { layer: li, path: String(e.name).slice(0, 200) };
      const c = components(e.name);
      if (c.red) { red.push({ kind: c.red === 'absolute' ? 'absolute_name' : 'dotdot_name', ...at }); return; }
      if (!c.parts.length) return; // the root itself
      const parts = c.parts;
      // the parents: never a symlink, never a non-directory; a missing parent is made the way tar makes one
      for (let k = 1; k < parts.length; k++) {
        const pp = parts.slice(0, k).join('/');
        const t = tree.get(pp);
        if (!t) { tree.set(pp, { type: 'dir', mode: 0o755, uid: 0, gid: 0, implicit: true }); thisLayer.add(pp); continue; }
        if (t.type === 'link') { red.push({ kind: 'write_through_symlink', ...at, via: `/${pp}` }); return; }
        if (t.type !== 'dir') { red.push({ kind: 'parent_not_a_directory', ...at, via: `/${pp}` }); return; }
      }
      const base = parts[parts.length - 1];
      const dir = parts.slice(0, -1).join('/');
      if (base === '.wh..wh..opq') {
        opaque += 1; pl.opaque += 1;
        const d = dir;
        if (added) {
          seenOpq.add(d);
          const t = tree.get(d);
          if (!t || t.type !== 'dir' || !basePaths.has(d)) layerRed.push({ kind: 'opaque_dir_not_a_base_dir', ...at });
          else if (!allowOpq.has(d)) layerRed.push({ kind: 'opaque_dir_not_listed', ...at });
          addedGone(li, d, 'added_then_opaqued', at, true);
          for (const k of [...addedBy.keys()]) if (k !== d && under(k, d)) addedBy.delete(k);
        }
        for (const k of [...tree.keys()]) if (d === '' ? true : k.startsWith(`${d}/`)) if (!thisLayer.has(k)) tree.delete(k);
        return;
      }
      if (base.startsWith('.wh.')) {
        whiteouts += 1; pl.whiteouts += 1;
        const target = [dir, base.slice(4)].filter(Boolean).join('/');
        if (!base.slice(4) || base.slice(4) === '..' || base.slice(4) === '.') { red.push({ kind: 'whiteout_bad_name', ...at }); return; }
        if (thisLayer.has(target)) { red.push({ kind: 'whiteout_of_same_layer_entry', ...at }); return; }
        if (added) {
          seenWh.add(target);
          const before = layerRed.length;
          addedGone(li, target, 'added_then_whited_out', at);
          if (layerRed.length === before) {
            if (!tree.has(target)) layerRed.push({ kind: 'whiteout_of_nothing', ...at });
            else if (!allowWh.has(target)) layerRed.push({ kind: 'whiteout_not_listed', ...at });
          }
          for (const k of [...addedBy.keys()]) if (under(k, target)) addedBy.delete(k);
        }
        delTree(target);
        return;
      }
      const p = parts.join('/');
      const entry = { type: e.type, mode: e.mode, uid: e.uid, gid: e.gid };
      if (e.xattrs) entry.xattrs = e.xattrs;
      if (e.type === 'file') { entry.size = e.size; entry.sha256 = e.sha256; if (opts.keepSource) entry.src = { layer: li, offset: e.offset }; }
      if (e.type === 'link') entry.linkname = e.linkname;
      if (e.type === 'hardlink') {
        const lc = components(e.linkname);
        if (lc.red || !lc.parts.length) { red.push({ kind: 'hardlink_leaves_tree', ...at }); return; }
        const tp = lc.parts.join('/');
        for (let k = 1; k < lc.parts.length; k++) {
          const t = tree.get(lc.parts.slice(0, k).join('/'));
          if (t && t.type !== 'dir') { red.push({ kind: 'hardlink_through_non_directory', ...at }); return; }
        }
        const t = tree.get(tp);
        if (!t || (t.type !== 'file' && t.type !== 'hardlink')) { red.push({ kind: 'hardlink_target_not_a_file_in_the_tree', ...at }); return; }
        entry.linkname = tp; entry.size = t.size; entry.sha256 = t.sha256;
        if (opts.keepSource && t.src) entry.src = t.src;
      }
      pl[{ file: 'files', dir: 'dirs', link: 'links', hardlink: 'hardlinks' }[e.type] || 'other'] += 1;
      if (added && written.has(p)) layerRed.push({ kind: 'written_twice_in_one_layer', ...at });
      written.add(p);
      if (added) {
        const w = addedBy.get(p);
        if (w && w.layer < li) {
          if (w.type !== 'dir' || entry.type !== 'dir') layerRed.push({ kind: 'added_then_overwritten', ...at, added_in_layer: w.layer });
          else if (w.mode !== entry.mode || w.uid !== entry.uid || w.gid !== entry.gid || JSON.stringify(w.xattrs || {}) !== JSON.stringify(entry.xattrs || {}))
            layerRed.push({ kind: 'added_dir_restated_differently', ...at, added_in_layer: w.layer });
        }
        if (w && w.type === 'dir' && entry.type !== 'dir') {
          addedGone(li, p, 'added_then_overwritten', at, true);
          for (const k of [...addedBy.keys()]) if (k !== p && under(k, p)) addedBy.delete(k);
        }
        // a base directory re-stated as a directory carries no bytes of its own (its mode and owner are judged on the
        // applied tree); every other entry an added layer writes is tracked
        const old0 = tree.get(p);
        if (!(entry.type === 'dir' && basePaths.has(p) && old0?.type === 'dir' && !w)) addedBy.set(p, { layer: li, type: entry.type, mode: entry.mode, uid: entry.uid, gid: entry.gid, xattrs: entry.xattrs });
      }
      const old = tree.get(p);
      if (old && old.type === 'dir' && entry.type !== 'dir') delTree(p);
      tree.set(p, entry);
      thisLayer.add(p);
    });
    for (const a of anomalies) red.push({ ...a, layer: li });
  });
  if (addedFrom !== Infinity) {
    for (const w of allowWh) if (!seenWh.has(w)) layerRed.push({ kind: 'listed_whiteout_not_seen', path: `/${w}` });
    for (const d of allowOpq) if (!seenOpq.has(d)) layerRed.push({ kind: 'listed_opaque_dir_not_seen', path: `/${d}` });
  }
  return { tree, red, whiteouts, opaque, layer_red: layerRed, per_layer: perLayer, whiteouts_seen: [...seenWh].map((x) => `/${x}`).sort() };
}

// Every regular file each ADDED layer's own tar carries (Security 12430 (e): the content searches read these, so bytes a
// later layer deletes or overwrites are still searched). Returns [{layer, rel, size, offset}] in stream order; hard
// links and symlinks carry no bytes of their own. Effective names (pax/GNU); a red name is skipped here (apply reds it).
export function addedLayerFiles(tars, addedFrom) {
  const out = [];
  tars.forEach((file, li) => {
    if (li < addedFrom) return;
    tarWalk(file, (e) => {
      if (e.type !== 'file') return;
      const c = components(e.name);
      if (c.red || !c.parts.length) return;
      const base = c.parts[c.parts.length - 1];
      if (base.startsWith('.wh.')) return;
      out.push({ layer: li, rel: c.parts.join('/'), size: e.size, offset: e.offset });
    });
  });
  return out;
}

// Gunzip (or copy) a blob to a tar file, hashing the tar bytes; returns the hex sha256, or null on a bad stream.
export async function decompressToFile(blobFile, gz, outFile) {
  const h = crypto.createHash('sha256');
  const tap = new Transform({ transform(c, _e, cb) { h.update(c); cb(null, c); } });
  try {
    await pipeline(fs.createReadStream(blobFile), ...(gz ? [zlib.createGunzip()] : []), tap, fs.createWriteStream(outFile));
    return h.digest('hex');
  } catch { return null; }
}

async function main([chain, pinsFile, treeOut, verdictOut]) {
  if (!verdictOut) { console.error('usage: mediator-base-layers.mjs <chain dir> <rekey-config.json> <out tree.json> <out verdict.json>'); return 2; }
  const rd = (f) => { try { return fs.readFileSync(f); } catch { return null; } };
  const pins = JSON.parse(fs.readFileSync(pinsFile, 'utf8'));
  const manifestRaw = rd(path.join(chain, 'manifest.raw')), configRaw = rd(path.join(chain, 'config.raw'));
  let n = 0;
  try { n = JSON.parse(manifestRaw.toString('utf8')).layers.length; } catch {}
  const blobs = Array.from({ length: n }, (_, i) => rd(layerBlob(chain, i)));
  // the decompressed hashes, streamed to disk first (the verdict is sync and pure)
  const shas = [];
  let m = null;
  try { m = JSON.parse(manifestRaw.toString('utf8')); } catch {}
  for (let i = 0; i < n; i++) {
    const gz = layerGzip(m, i);
    shas[i] = blobs[i] && gz !== undefined ? await decompressToFile(layerBlob(chain, i), gz, layerTar(chain, i)) : null;
  }
  const v = layerVerdict({ manifestRaw, configRaw, pins, blobs, decompressedSha: (_b, _gz, i) => shas[i] });
  let applied = null;
  if (v.ok) applied = applyLayers(Array.from({ length: n }, (_, i) => layerTar(chain, i)));
  const applyOk = !!applied && applied.red.length === 0;
  const ok = v.ok && applyOk;
  if (ok) fs.writeFileSync(treeOut, JSON.stringify({ what: 'the base tree built from the pinned layers (Security 12327)', entries: [...applied.tree] }));
  const rec = {
    what: 'the base side from the pinned layers (Security 12327, 12358)', ok,
    checks: { ...v.checks, layers_apply_clean: v.ok ? (applyOk ? 'PASS' : 'FAIL') : 'FAIL' },
    layers: v.layers, counts: { ...v.counts, tree_entries: applied ? applied.tree.size : 0, whiteouts: applied?.whiteouts ?? 0, opaque_dirs: applied?.opaque ?? 0, apply_red: applied ? applied.red.length : null },
    apply_red: applied ? applied.red.slice(0, 50) : [],
  };
  fs.writeFileSync(verdictOut, `${JSON.stringify(rec, null, 2)}\n`);
  console.log(JSON.stringify({ ok, checks: rec.checks, layers: rec.layers, counts: rec.counts, apply_red: rec.apply_red.slice(0, 10) }));
  return ok ? 0 : 1;
}

if (process.argv[1]?.endsWith('mediator-base-layers.mjs')) {
  main(process.argv.slice(2)).then((c) => process.exit(c), (e) => { console.error(`mediator-base-layers: ${e.message}`); process.exit(1); });
}
