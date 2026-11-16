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

// Steps 1-2 on bytes already read: manifest + config raw buffers, pins, and per layer {blob: Buffer|null}. Pure, so
// the units can feed it made-up chains. decompress(buf, gzip) → Buffer of the tar (sync; fine for units and for the
// verdict, the CLI streams instead). Returns {ok, checks, layers: [{i, digest, compressed, size, media_type,
// diff_id}], counts}.
export function layerVerdict({ manifestRaw, configRaw, pins, blobs, decompressedSha }) {
  const checks = {};
  const P = (b) => (b ? 'PASS' : 'FAIL');
  let manifest = null, config = null;
  try { manifest = JSON.parse(manifestRaw.toString('utf8')); } catch {}
  try { config = JSON.parse(configRaw.toString('utf8')); } catch {}
  checks.manifest_is_the_pin = P(!!manifestRaw && `sha256:${sha(manifestRaw)}` === pins.base_manifest_digest);
  checks.config_is_the_pin = P(!!configRaw && `sha256:${sha(configRaw)}` === pins.base_config_digest && manifest?.config?.digest === pins.base_config_digest);
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
  const ok = Object.values(checks).every((x) => x === 'PASS');
  return { ok, checks, layers, gzip: layers.map((l, i) => (types ? types[ls[i]?.mediaType] === true : false)), counts: { layers: ls.length, diff_ids: diffIds.length, blobs: blobs.filter(Boolean).length } };
}

// Step 3: apply layer tars, in order, into a tree. tars: file paths. Returns {tree: Map path → entry, red: [...],
// whiteouts, opaque}. A whiteout of a path laid down earlier in the same layer is red (a malformed layer), and so is a
// whiteout or entry whose parent is a symlink or a non-directory.
export function applyLayers(tars) {
  const tree = new Map();
  const red = [];
  let whiteouts = 0, opaque = 0;
  const delTree = (p, keep = null) => {
    for (const k of [...tree.keys()]) if ((k === p || k.startsWith(`${p}/`)) && !(keep && keep.has(k))) tree.delete(k);
  };
  tars.forEach((file, li) => {
    const thisLayer = new Set();
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
        opaque += 1;
        const d = dir;
        for (const k of [...tree.keys()]) if (d === '' ? true : k.startsWith(`${d}/`)) if (!thisLayer.has(k)) tree.delete(k);
        return;
      }
      if (base.startsWith('.wh.')) {
        whiteouts += 1;
        const target = [dir, base.slice(4)].filter(Boolean).join('/');
        if (!base.slice(4) || base.slice(4) === '..' || base.slice(4) === '.') { red.push({ kind: 'whiteout_bad_name', ...at }); return; }
        if (thisLayer.has(target)) { red.push({ kind: 'whiteout_of_same_layer_entry', ...at }); return; }
        delTree(target);
        return;
      }
      const p = parts.join('/');
      const entry = { type: e.type, mode: e.mode, uid: e.uid, gid: e.gid };
      if (e.xattrs) entry.xattrs = e.xattrs;
      if (e.type === 'file') { entry.size = e.size; entry.sha256 = e.sha256; }
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
      }
      const old = tree.get(p);
      if (old && old.type === 'dir' && entry.type !== 'dir') delTree(p);
      tree.set(p, entry);
      thisLayer.add(p);
    });
    for (const a of anomalies) red.push({ ...a, layer: li });
  });
  return { tree, red, whiteouts, opaque };
}

// Gunzip (or copy) a blob to a tar file, hashing the tar bytes; returns the hex sha256, or null on a bad stream.
async function decompressToFile(blobFile, gz, outFile) {
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
  for (let i = 0; i < n; i++) {
    let gz = null;
    try { const m = JSON.parse(manifestRaw.toString('utf8')); gz = LAYER_TYPES[m.mediaType]?.[m.layers[i].mediaType]; } catch {}
    shas[i] = blobs[i] && gz !== undefined && gz !== null ? await decompressToFile(layerBlob(chain, i), gz, layerTar(chain, i)) : null;
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
