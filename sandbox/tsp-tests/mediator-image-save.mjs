#!/usr/bin/env node
// Every image the images step judges is read from its OWN layers, never through a container (Security 12430; WPI-BUILD
// 12400 proved a container's export shows the runtime's /etc/hosts, /etc/hostname, /etc/resolv.conf and /.dockerenv,
// whatever the image holds there). This reads one image's `docker save` (OCI layout, extracted to a scratch dir):
//
//   (b) exactly ONE image in the save, for linux/amd64: every index/manifest/config blob's sha256 (and size) is its
//       descriptor's; attestation manifests (no platform, in-toto layers only) are counted and set aside; a second
//       image, a missing one, or a descriptor whose platform disagrees with its config blob's is red. That config blob
//       is the image's config (the config record reads it, never inspect); inspect is compared to it as evidence, and a
//       disagreement is red.
//   (c) each layer: compressed sha256 + size = the manifest's, media type one of the manifest's own tar(+gzip) types,
//       count = diff_ids, decompressed sha256 = diff_ids[i] in order: checkLayers, the same function as the registry
//       base side (mediator-base-layers.mjs).
//   (d) base prefix, exact: the image's first diff_ids equal the pinned base config's, in order. The base config comes
//       from a registry chain tied by hash to the Dockerfile's FROM digest (index sha256 = the FROM digest, its one
//       linux/amd64 manifest, that manifest's config blob), and for the rekey side also equal to the L8 pins.
//   (e) the ADDED layers (past the prefix) one by one (applyLayers' added-layer rules), and every regular file in every
//       added layer's own tar is listed for the content searches (mediator-image-check.mjs), so bytes a later layer
//       deletes or overwrites are still searched.
//   (f) for the local base pull: its layers equal the registry chain's by digest, and (mediator-base-diff.mjs) its
//       applied tree equals the registry tree with zero exceptions.
//   (h) the scratch tree is the in-memory apply (each file's bytes read back from its layer tar at its offset; no link
//       is ever followed); the layout and the decompressed tars stay in the job's scratch dir, which the step deletes
//       and absence-checks at its end. Never an artifact.
// Printed: per-layer verdicts and counts per kind, red kinds and paths; never a file's bytes.
//
//   mediator-image-save.mjs --name <rekey|service|base|plant> --layout <dir> --work <dir> --base-chain <dir>
//     --from-digest <sha256:…> [--config-pin <sha256:…>] [--same-layers-as-chain] [--inspect <inspect.json>]
//     --out-tree <tree.json> --out-config <config.json> --out <verdict.json>
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { checkLayers, layerGzip, decompressToFile, applyLayers, addedLayerFiles } from './mediator-base-layers.mjs';
import { amd64Descriptor } from './mediator-base-fetch.mjs';
import { configFieldsDiffer } from './mediator-image-config.mjs';

const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const P = (b) => (b ? 'PASS' : 'FAIL');
const J = JSON.stringify;
const parse = (b) => { try { return JSON.parse(b.toString('utf8')); } catch { return null; } };
const INDEX_TYPES = ['application/vnd.oci.image.index.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json'];
const MANIFEST_TYPES = ['application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json'];
const ATTESTATION_LAYER = 'application/vnd.in-toto+json';

// The deletes an image's ADDED layers may make (Security 12430 (e)): whiteouts and opaque dirs, each of a BASE path,
// exact both ways. The rekey Dockerfile removes /var/log/apt (Security 11869.3 (a)); the service image deletes
// nothing. Widened only by a Security block, never in place. A plant built FROM the rekey image uses the rekey list.
export const ADDED_LAYER_DELETES = Object.freeze({
  rekey: Object.freeze({ whiteouts: Object.freeze(['/var/log/apt']), opaque: Object.freeze([]) }),
  plant: Object.freeze({ whiteouts: Object.freeze(['/var/log/apt']), opaque: Object.freeze([]) }),
  service: Object.freeze({ whiteouts: Object.freeze([]), opaque: Object.freeze([]) }),
  base: Object.freeze({ whiteouts: Object.freeze([]), opaque: Object.freeze([]) }),
});

// A layout's blob by digest: Buffer, or null when absent or not a sha256 digest.
export const layoutBlob = (layout, digest) => {
  const m = /^sha256:([0-9a-f]{64})$/.exec(String(digest));
  if (!m) return null;
  try { return fs.readFileSync(path.join(layout, 'blobs', 'sha256', m[1])); } catch { return null; }
};

// (b): walks index.json (nested indexes too), hash-checks every blob it reads, and returns the one image.
// readBlob(digest) → Buffer|null; indexRaw: index.json's bytes. Returns {checks, image|null, images, attestations, bad}.
export function selectImage(readBlob, indexRaw, platform = { os: 'linux', architecture: 'amd64' }) {
  const bad = [], images = [], attestations = [];
  const root = indexRaw ? parse(indexRaw) : null;
  const rootOk = !!root && INDEX_TYPES.includes(root.mediaType ?? 'application/vnd.oci.image.index.v1+json') && Array.isArray(root.manifests);
  const blobOf = (d, what) => {
    const b = readBlob(d?.digest);
    if (!b) { bad.push({ kind: `${what}_blob_missing`, digest: String(d?.digest ?? '') }); return null; }
    if (`sha256:${sha(b)}` !== d.digest || (d.size !== undefined && d.size !== b.length)) { bad.push({ kind: `${what}_blob_not_its_digest`, digest: d.digest }); return null; }
    return b;
  };
  const queue = rootOk ? root.manifests.map((d) => ({ d, depth: 0 })) : [];
  while (queue.length) {
    const { d, depth } = queue.shift();
    if (INDEX_TYPES.includes(d?.mediaType)) {
      if (depth > 3) { bad.push({ kind: 'index_too_deep', digest: d.digest }); continue; }
      const b = blobOf(d, 'index'); const j = b && parse(b);
      if (!j || !Array.isArray(j.manifests)) { if (b) bad.push({ kind: 'index_malformed', digest: d.digest }); continue; }
      for (const x of j.manifests) queue.push({ d: x, depth: depth + 1 });
      continue;
    }
    if (!MANIFEST_TYPES.includes(d?.mediaType)) { bad.push({ kind: 'descriptor_type_unknown', digest: String(d?.digest ?? ''), media_type: String(d?.mediaType ?? '') }); continue; }
    const mb = blobOf(d, 'manifest'); const m = mb && parse(mb);
    if (!m) { if (mb) bad.push({ kind: 'manifest_malformed', digest: d.digest }); continue; }
    const ls = Array.isArray(m.layers) ? m.layers : [];
    const noPlatform = !d.platform || d.platform.os === 'unknown';
    if (noPlatform && ls.length > 0 && ls.every((l) => l?.mediaType === ATTESTATION_LAYER)) { attestations.push({ digest: d.digest, layers: ls.length }); continue; }
    const cb = blobOf(m.config, 'config'); const c = cb && parse(cb);
    if (!c) { if (cb) bad.push({ kind: 'config_malformed', digest: d.digest }); continue; }
    images.push({ digest: d.digest, descriptor_platform: d.platform ?? null, config_platform: { os: c.os ?? null, architecture: c.architecture ?? null, variant: c.variant ?? null },
      manifestRaw: mb, manifest: m, configRaw: cb, config: c });
  }
  const one = images.length === 1 ? images[0] : null;
  const cp = one?.config_platform, dp = one?.descriptor_platform;
  const platformOk = !!one && cp.os === platform.os && cp.architecture === platform.architecture && !cp.variant
    && (!dp || (dp.os === platform.os && dp.architecture === platform.architecture && !dp.variant));
  const checks = {
    save_index_well_formed: P(rootOk),
    save_blobs_match_their_digests: P(rootOk && bad.length === 0),
    save_exactly_one_image: P(images.length === 1),
    save_image_is_linux_amd64: P(platformOk),
  };
  const strip = ({ manifestRaw: _a, manifest: _b, configRaw: _c, config: _d, ...rest }) => rest;
  return { checks, image: Object.values(checks).every((x) => x === 'PASS') ? one : null, images: images.map(strip), attestations, bad };
}

// (d)'s base: a registry chain (mediator-base-fetch.mjs's index.raw, manifest.raw, config.raw) tied by hash to the FROM
// digest. Returns {checks, config|null, manifest|null, manifest_digest_read, config_digest_read}.
export function chainBase(chain, fromDigest, configPin = null) {
  const c = chain ?? {};
  const indexOk = !!c.index && `sha256:${sha(c.index)}` === fromDigest;
  const desc = indexOk ? amd64Descriptor(parse(c.index)) : null;
  const manifestOk = !!desc && !!c.manifest && `sha256:${sha(c.manifest)}` === desc.digest && (desc.size === undefined || desc.size === c.manifest.length);
  const manifest = manifestOk ? parse(c.manifest) : null;
  const cd = manifest?.config?.digest;
  const configOk = !!cd && !!c.config && `sha256:${sha(c.config)}` === cd;
  const config = configOk ? parse(c.config) : null;
  const checks = { base_chain_is_the_from_digest: P(indexOk && manifestOk && configOk && config?.os === 'linux' && config?.architecture === 'amd64') };
  if (configPin !== null) checks.base_chain_config_is_the_l8_pin = P(configOk && cd === configPin);
  return { checks, config, manifest, manifest_digest_read: desc?.digest ?? null, config_digest_read: configOk ? cd : null };
}

// The whole read of one saved image. Async (layers are decompressed to the work dir). Returns the verdict, the tree
// (Map, files carrying src) and the added files; writes nothing.
export async function readSave({ layout, work, base, name, sameLayersAsChain = false, inspect = null }) {
  const rd = (f) => { try { return fs.readFileSync(f); } catch { return null; } };
  const sel = selectImage((d) => layoutBlob(layout, d), rd(path.join(layout, 'index.json')));
  const checks = { ...sel.checks, ...base.checks };
  const img = sel.image;
  const ls = img ? img.manifest.layers ?? [] : [];
  const diffIds = Array.isArray(img?.config?.rootfs?.diff_ids) ? img.config.rootfs.diff_ids : [];
  const baseIds = Array.isArray(base.config?.rootfs?.diff_ids) ? base.config.rootfs.diff_ids : null;
  checks.base_prefix_is_the_pinned_base = P(!!img && !!baseIds && baseIds.length > 0 && diffIds.length >= baseIds.length && J(diffIds.slice(0, baseIds.length)) === J(baseIds));
  if (sameLayersAsChain) checks.layers_equal_the_registry_layers_by_digest = P(!!img && !!base.manifest && J(ls.map((l) => [l.digest, l.size, l.mediaType])) === J((base.manifest.layers ?? []).map((l) => [l.digest, l.size, l.mediaType])));
  // (b) inspect is evidence only: printed, and red if it disagrees with the saved config blob
  let inspectDiffer = null;
  if (inspect) {
    const ic = (Array.isArray(inspect) ? inspect[0] : inspect) ?? {};
    inspectDiffer = img ? configFieldsDiffer(img.config.config, ic.Config) : ['no image'];
    if (img && J(ic.RootFS?.Layers ?? null) !== J(diffIds)) inspectDiffer.push('RootFS.Layers');
    checks.inspect_equals_the_saved_config_blob = P(!!img && inspectDiffer.length === 0);
  }
  // (c)
  fs.mkdirSync(work, { recursive: true });
  const blobs = ls.map((l) => layoutBlob(layout, l.digest));
  const tars = ls.map((_l, i) => path.join(work, `${i}.tar`));
  const shas = [];
  for (let i = 0; i < ls.length; i++) {
    const gz = layerGzip(img.manifest, i);
    shas[i] = blobs[i] && gz !== undefined ? await decompressToFile(path.join(layout, 'blobs', 'sha256', ls[i].digest.slice(7)), gz, tars[i]) : null;
  }
  const lc = img ? checkLayers({ manifest: img.manifest, config: img.config, blobs, decompressedSha: (_b, _g, i) => shas[i] }) : { checks: { every_layer_checks: 'FAIL' }, layers: [], counts: {} };
  Object.assign(checks, lc.checks);
  blobs.length = 0;
  const pre = Object.values(checks).every((x) => x === 'PASS');
  let applied = null, files = [];
  if (pre) {
    const del = ADDED_LAYER_DELETES[name] ?? { whiteouts: [], opaque: [] };
    applied = applyLayers(tars, { addedFrom: baseIds.length, whiteouts: del.whiteouts, opaque: del.opaque, keepSource: true });
    files = addedLayerFiles(tars, baseIds.length);
  }
  checks.layers_apply_clean = P(!!applied && applied.red.length === 0);
  checks.added_layers_clean = P(!!applied && applied.layer_red.length === 0);
  const ok = Object.values(checks).every((x) => x === 'PASS');
  const verdict = {
    what: `${name} image read from its own saved layers (Security 12430)`, ok, checks,
    image: img ? { manifest_digest: img.digest, config_digest: img.manifest.config?.digest ?? null, diff_ids: diffIds.length, base_prefix: baseIds ? baseIds.length : null } : null,
    images_in_save: sel.images, attestations_in_save: sel.attestations, save_bad: sel.bad,
    base_chain: { manifest_digest_read: base.manifest_digest_read, config_digest_read: base.config_digest_read },
    layers: lc.layers, per_layer: applied?.per_layer ?? [], counts: { ...lc.counts, tree_entries: applied ? applied.tree.size : 0, added_layer_files: files.length },
    apply_red: applied ? applied.red.slice(0, 50) : [], added_layer_red: applied ? applied.layer_red.slice(0, 50) : [],
    added_layer_whiteouts_seen: applied?.whiteouts_seen ?? [], inspect_vs_saved_config_differ: inspectDiffer,
  };
  return { verdict, tree: applied?.tree ?? null, tars, files, config: img?.config ?? null };
}

// A saved image's files as the image checks read them (mediator-image-check.mjs's view): the applied tree, each file's
// bytes read from its layer tar at its offset. Symlinks are listed, never followed; a hard link reads its target's bytes.
export function treeView(tree, tars) {
  const kind = (e) => (e.type === 'hardlink' ? 'file' : e.type === 'file' || e.type === 'dir' || e.type === 'link' ? e.type : 'other');
  const entries = [...tree].map(([rel, e]) => ({ rel, kind: kind(e), size: e.size, src: e.src })).sort((a, b) => (a.rel < b.rel ? -1 : 1));
  return fromSources(entries, tars, (rel) => { const e = tree.get(rel); return e && kind(e) === 'file' ? { rel, size: e.size, src: e.src } : null; });
}

// Every regular file in every added layer's own tar, as a view (duplicate paths across layers are each their own entry).
export function layerView(files, tars) {
  const entries = files.map((f) => ({ rel: f.rel, kind: 'file', size: f.size, src: { layer: f.layer, offset: f.offset }, layer: f.layer }));
  return fromSources(entries, tars, () => null);
}

function fromSources(entries, tars, byRel) {
  const readAt = (e, n) => {
    if (!e?.src) return null;
    const len = n === undefined ? e.size : Math.min(n, e.size);
    const buf = Buffer.alloc(len);
    const fd = fs.openSync(tars[e.src.layer], 'r');
    try { let got = 0; while (got < len) { const r = fs.readSync(fd, buf, got, len - got, e.src.offset + got); if (!r) break; got += r; } return buf.subarray(0, got); }
    finally { fs.closeSync(fd); }
  };
  return {
    entries,
    read: (e) => readAt(e),
    head: (e, n) => readAt(e, n),
    readRel: (rel) => readAt(byRel(rel)),
    isFile: (rel) => !!byRel(rel),
  };
}

// The tree as JSON: {entries, tars, added_files} so the image checks and the base diff read the same bytes.
export const saveJson = (r) => ({ what: 'a saved image applied from its own layers (Security 12430)', entries: [...r.tree], tars: r.tars, added_files: r.files });
export const viewsFromJson = (j) => {
  const tree = new Map(j.entries);
  return { tree: treeView(tree, j.tars), layers: layerView(j.added_files, j.tars) };
};

const arg = (argv, k) => { const i = argv.indexOf(k); return i >= 0 ? argv[i + 1] : undefined; };
async function main(argv) {
  const name = arg(argv, '--name'), layout = arg(argv, '--layout'), work = arg(argv, '--work'), chainDir = arg(argv, '--base-chain');
  const from = arg(argv, '--from-digest'), pin = arg(argv, '--config-pin') ?? null, insp = arg(argv, '--inspect');
  const outTree = arg(argv, '--out-tree'), outConfig = arg(argv, '--out-config'), out = arg(argv, '--out');
  if (!name || !layout || !work || !chainDir || !from || !outTree || !outConfig || !out || !(name in ADDED_LAYER_DELETES)) {
    console.error('usage: mediator-image-save.mjs --name <rekey|service|base|plant> --layout <dir> --work <dir> --base-chain <dir> --from-digest <sha256:…> [--config-pin <sha256:…>] [--same-layers-as-chain] [--inspect <f>] --out-tree <f> --out-config <f> --out <f>');
    return 2;
  }
  const raw = (n) => { try { return fs.readFileSync(path.join(chainDir, n)); } catch { return null; } };
  const base = chainBase({ index: raw('index.raw'), manifest: raw('manifest.raw'), config: raw('config.raw') }, from, pin);
  let inspect = null;
  if (insp) inspect = JSON.parse(fs.readFileSync(insp, 'utf8'));
  const r = await readSave({ layout, work, base, name, sameLayersAsChain: argv.includes('--same-layers-as-chain'), inspect });
  // The tree is written whenever the layers themselves check and apply (so every other line can still be judged and
  // printed); the save line itself is red on any added-layer rule. Without a clean apply, no tree: the lines that read
  // it go red.
  if (r.tree && r.verdict.checks.layers_apply_clean === 'PASS') fs.writeFileSync(outTree, J(saveJson(r)));
  // The saved config blob, inspect-shaped, for the image checks and the config record (never inspect itself).
  if (r.config) fs.writeFileSync(outConfig, J([{ from: 'the saved config blob (Security 12430 (b))', Architecture: r.config.architecture, Os: r.config.os, Config: r.config.config ?? {}, RootFS: { Type: 'layers', Layers: r.config.rootfs?.diff_ids ?? [] } }]));
  fs.writeFileSync(out, `${J(r.verdict, null, 2)}\n`);
  const v = r.verdict;
  console.log(J({ name, ok: v.ok, checks: v.checks, image: v.image, attestations: v.attestations_in_save.length, per_layer: v.per_layer, added_layer_red: v.added_layer_red, apply_red: v.apply_red.slice(0, 10), whiteouts_seen: v.added_layer_whiteouts_seen, inspect_differ: v.inspect_vs_saved_config_differ, save_bad: v.save_bad }));
  return v.ok ? 0 : 1;
}

if (process.argv[1]?.endsWith('mediator-image-save.mjs')) {
  main(process.argv.slice(2)).then((c) => process.exit(c), (e) => { console.error(`mediator-image-save: ${e.message}`); process.exit(1); });
}
