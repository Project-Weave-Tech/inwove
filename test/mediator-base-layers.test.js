// Security 12327 + 12358 (Railroad 12314, 12351): the base diff's base side built from the pinned layers. Every unit
// Security listed is red first, except the whiteout/opaque ones, which must delete their paths. Made-up layers only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import crypto from 'node:crypto';
import { gzipSync, gunzipSync } from 'node:zlib';
import { layerVerdict, applyLayers, checkLayers, addedLayerFiles } from '../sandbox/tsp-tests/mediator-base-layers.mjs';
import { tarWalk, tarList, crossCheck, crossCheckBites, baseDiff, redPaths } from '../sandbox/tsp-tests/mediator-base-diff.mjs';
import { selectImage, treeView, layerView, chainBase, chainPinVerdict } from '../sandbox/tsp-tests/mediator-image-save.mjs';
import { readFileSync } from 'node:fs';

const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const dirs = [];
const tmp = () => { const d = mkdtempSync(join(tmpdir(), 'blay-')); dirs.push(d); return d; };
test.after(() => dirs.forEach((d) => rmSync(d, { recursive: true, force: true })));

// A small tar writer. entries: [{name, type ('0' file | '1' hardlink | '2' symlink | '5' dir | 'x' | 'g' | 'L' | 'K'),
// mode, uid, body, linkname, pax: {key: value}}]. A pax: {} on a member writes an 'x' header before it.
function header(name, type, mode, size, linkname = '', uid = 0) {
  const h = Buffer.alloc(512);
  h.write(name.slice(0, 100), 0, 100); h.write(`${mode.toString(8).padStart(7, '0')}\0`, 100); h.write(`${uid.toString(8).padStart(7, '0')}\0`, 108); h.write('0000000\0', 116);
  h.write(`${size.toString(8).padStart(11, '0')}\0`, 124); h.write('00000000000\0', 136); h.write('        ', 148); h.write(type, 156);
  h.write(linkname.slice(0, 100), 157, 100); h.write('ustar\0', 257); h.write('00', 263);
  h.write(`${[...h].reduce((a, b) => a + b, 0).toString(8).padStart(6, '0')}\0 `, 148);
  return h;
}
const pad = (b) => Buffer.concat([b, Buffer.alloc((512 - (b.length % 512)) % 512)]);
const paxBody = (kv) => Buffer.concat(Object.entries(kv).map(([k, v]) => {
  const rest = Buffer.from(` ${k}=${v}\n`);
  let len = rest.length + 1; while (String(len).length + rest.length !== len) len = String(len).length + rest.length;
  return Buffer.concat([Buffer.from(String(len)), rest]);
}));
function tarBytes(entries, { end = true } = {}) {
  const parts = [];
  for (const e of entries) {
    const t = e.type ?? '0';
    if (t === 'x' || t === 'g') { const b = paxBody(e.pax); parts.push(header(e.name ?? 'PaxHeader', t, 0o644, b.length), pad(b)); continue; }
    if (t === 'L' || t === 'K') { const b = Buffer.from(`${e.body}\0`); parts.push(header('././@LongLink', t, 0o644, b.length), pad(b)); continue; }
    if (e.pax) { const b = paxBody(e.pax); parts.push(header(`PaxHeaders/${e.name}`.slice(0, 99), 'x', 0o644, b.length), pad(b)); }
    const body = Buffer.from(e.body ?? '');
    parts.push(header(e.name, t, e.mode ?? (t === '5' ? 0o755 : 0o644), t === '0' ? body.length : 0, e.linkname ?? '', e.uid ?? 0), t === '0' ? pad(body) : Buffer.alloc(0));
  }
  if (end) parts.push(Buffer.alloc(1024));
  return Buffer.concat(parts);
}
const tarFile = (entries, o) => { const f = join(tmp(), 'l.tar'); writeFileSync(f, tarBytes(entries, o)); return f; };

// A made-up chain: layer tars → {manifestRaw, configRaw, pins, blobs}
const OCI = 'application/vnd.oci.image.manifest.v1+json', GZ = 'application/vnd.oci.image.layer.v1.tar+gzip';
function chain(layerTars, { manifestLayers = null, diffIds = null } = {}) {
  const blobs = layerTars.map((t) => gzipSync(t));
  const ids = diffIds ?? layerTars.map((t) => `sha256:${sha(t)}`);
  const configRaw = Buffer.from(JSON.stringify({ architecture: 'amd64', os: 'linux', rootfs: { type: 'layers', diff_ids: ids } }));
  const layers = manifestLayers ?? blobs.map((b) => ({ mediaType: GZ, digest: `sha256:${sha(b)}`, size: b.length }));
  const manifestRaw = Buffer.from(JSON.stringify({ schemaVersion: 2, mediaType: OCI, config: { digest: `sha256:${sha(configRaw)}` }, layers }));
  return { manifestRaw, configRaw, blobs, pins: { base_manifest_digest: `sha256:${sha(manifestRaw)}`, base_config_digest: `sha256:${sha(configRaw)}` } };
}
const unzipSha = (b, gz) => { try { return sha(gz ? gunzipSync(b) : b); } catch { return null; } };
const verdict = (c) => layerVerdict({ ...c, decompressedSha: unzipSha });
const L1 = tarBytes([{ name: 'usr/', type: '5' }, { name: 'usr/bin/', type: '5' }, { name: 'usr/bin/node', body: 'ELF', mode: 0o755 }]);
const L2 = tarBytes([{ name: 'etc/', type: '5' }, { name: 'etc/os-release', body: 'debian' }]);

test('layers: the pinned chain passes every check; per-layer verdicts and counts only', () => {
  const v = verdict(chain([L1, L2]));
  assert.equal(v.ok, true, JSON.stringify(v));
  assert.deepEqual(v.counts, { layers: 2, diff_ids: 2, blobs: 2 });
  assert.ok(v.layers.every((l) => l.compressed === 'PASS' && l.diff_id === 'PASS'));
  assert.ok(!JSON.stringify(v).includes('ELF'));
});

test('layers: compressed digest right but uncompressed bytes wrong is red (Railroad 12314)', () => {
  // the manifest's digest is the blob's, the blob is what came, but it unpacks to other bytes than the diff_id
  const c = chain([L1, L2], { diffIds: [`sha256:${sha(L1)}`, `sha256:${sha(L1)}`] });
  const v = verdict(c);
  assert.equal(v.ok, false);
  assert.equal(v.layers[1].compressed, 'PASS');
  assert.equal(v.layers[1].diff_id, 'FAIL');
});

test('layers: two layers swapped, a layer missing, an extra layer, a wrong size, a type not the manifest\'s own: all red', () => {
  const good = chain([L1, L2]);
  // swapped: the blobs come in the other order
  assert.equal(verdict({ ...good, blobs: [good.blobs[1], good.blobs[0]] }).ok, false);
  // missing: the fetch stopped (a rate limit) and one file is absent
  const miss = verdict({ ...good, blobs: [good.blobs[0], null] });
  assert.equal(miss.ok, false); assert.equal(miss.checks.layer_count_equals_diff_ids, 'FAIL');
  // an extra layer in the manifest that the config's diff_ids don't list
  const L3 = tarBytes([{ name: 'x', body: 'x' }]);
  const three = chain([L1, L2, L3]);
  const extra = layerVerdict({ ...three, configRaw: good.configRaw, pins: { ...three.pins, base_config_digest: good.pins.base_config_digest }, decompressedSha: unzipSha });
  assert.equal(extra.ok, false);
  // size other than the manifest's
  const ml = JSON.parse(good.manifestRaw).layers; ml[0].size += 1;
  const sized = chain([L1, L2], { manifestLayers: ml });
  assert.equal(verdict(sized).layers[0].size, 'FAIL');
  // a layer type from the other manifest family
  const ml2 = JSON.parse(good.manifestRaw).layers; ml2[0].mediaType = 'application/vnd.docker.image.rootfs.diff.tar.gzip';
  const typed = verdict(chain([L1, L2], { manifestLayers: ml2 }));
  assert.equal(typed.ok, false); assert.equal(typed.layers[0].media_type, 'FAIL');
  // a manifest or config other than the pins
  assert.equal(verdict({ ...good, pins: { ...good.pins, base_manifest_digest: `sha256:${'0'.repeat(64)}` } }).checks.manifest_is_the_pin, 'FAIL');
  assert.equal(verdict({ ...good, pins: { ...good.pins, base_config_digest: `sha256:${'0'.repeat(64)}` } }).checks.config_is_the_pin, 'FAIL');
});

test('apply: a .. member, an absolute member, and a member written through an earlier symlink are red', () => {
  const lower = tarFile([{ name: 'usr/', type: '5' }, { name: 'usr/lib', type: '2', linkname: '/tmp' }]);
  for (const [name, entries, kind] of [
    ['dotdot', [{ name: 'usr/../../etc/x', body: 'x' }], 'dotdot_name'],
    ['absolute', [{ name: '/etc/x', body: 'x' }], 'absolute_name'],
    ['through symlink', [{ name: 'usr/lib/evil', body: 'x' }], 'write_through_symlink'],
  ]) {
    const a = applyLayers([lower, tarFile(entries)]);
    assert.ok(a.red.some((r) => r.kind === kind), `${name}: ${JSON.stringify(a.red)}`);
  }
});

test('apply: a whiteout in an upper layer deletes its path (and what is under it); an opaque dir empties what the layers below put there', () => {
  const lower = tarFile([{ name: 'etc/', type: '5' }, { name: 'etc/a', body: 'a' }, { name: 'etc/d/', type: '5' }, { name: 'etc/d/x', body: 'x' }, { name: 'opt/', type: '5' }, { name: 'opt/old', body: 'o' }]);
  const upper = tarFile([{ name: 'etc/.wh.d', body: '' }, { name: 'etc/.wh.a', body: '' }, { name: 'opt/new', body: 'n' }, { name: 'opt/.wh..wh..opq', body: '' }]);
  const a = applyLayers([lower, upper]);
  assert.deepEqual(a.red, []);
  assert.equal(a.tree.has('etc/a'), false);
  assert.equal(a.tree.has('etc/d'), false);
  assert.equal(a.tree.has('etc/d/x'), false);
  assert.equal(a.tree.has('opt/old'), false, 'opaque: the lower layer\'s child is gone');
  assert.equal(a.tree.has('opt/new'), true, 'opaque: the same layer\'s child stays');
  assert.equal(a.whiteouts, 2); assert.equal(a.opaque, 1);
  // a whiteout of what its own layer just wrote is a malformed layer
  const bad = applyLayers([lower, tarFile([{ name: 'etc/b', body: 'b' }, { name: 'etc/.wh.b', body: '' }])]);
  assert.ok(bad.red.some((r) => r.kind === 'whiteout_of_same_layer_entry'));
});

test('apply: a hard link resolves inside the tree, carrying its target\'s bytes; one to a missing target is red', () => {
  const a = applyLayers([tarFile([{ name: 'usr/', type: '5' }, { name: 'usr/a', body: 'same' }, { name: 'usr/b', type: '1', linkname: 'usr/a' }])]);
  assert.deepEqual(a.red, []);
  assert.equal(a.tree.get('usr/b').sha256, sha('same'));
  const m = applyLayers([tarFile([{ name: 'usr/b', type: '1', linkname: 'usr/none' }])]);
  assert.ok(m.red.some((r) => r.kind === 'hardlink_target_not_a_file_in_the_tree'));
});

// Security 12358 (Railroad 12351): the effective name, never the raw ustar field
test('pax/GNU: a plain ustar name with a pax path of ../x is red; so is a hard link whose pax linkpath leaves the tree', () => {
  const a = applyLayers([tarFile([{ name: 'plain', body: 'x', pax: { path: '../x' } }])]);
  assert.ok(a.red.some((r) => r.kind === 'dotdot_name'), JSON.stringify(a.red));
  const b = applyLayers([tarFile([{ name: 'usr/', type: '5' }, { name: 'usr/a', body: 'a' }, { name: 'usr/b', type: '1', linkname: 'usr/a', pax: { linkpath: '../../etc/shadow' } }])]);
  assert.ok(b.red.some((r) => r.kind === 'hardlink_leaves_tree'), JSON.stringify(b.red));
});

test('pax/GNU: a GNU L long name holding .. is red', () => {
  const a = applyLayers([tarFile([{ type: 'L', body: `${'a/'.repeat(60)}../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../x` }, { name: 'short', body: 'x' }])]);
  assert.ok(a.red.some((r) => r.kind === 'dotdot_name'), JSON.stringify(a.red));
  // and the effective name, not the ustar one, is what lands
  const ok = applyLayers([tarFile([{ type: 'L', body: `deep/${'n'.repeat(120)}` }, { name: 'short', body: 'x' }])]);
  assert.ok(ok.tree.has(`deep/${'n'.repeat(120)}`)); assert.equal(ok.tree.has('short'), false);
});

test('pax/GNU: a global header with path or linkpath, an orphan header, two of one kind before a member: all red', () => {
  const kinds = (entries, o) => tarWalk(tarFile(entries, o), () => {}).map((x) => x.kind);
  assert.ok(kinds([{ type: 'g', pax: { path: 'etc' } }, { name: 'a', body: 'a' }]).includes('pax_global_path'));
  assert.ok(kinds([{ type: 'g', pax: { linkpath: '/x' } }, { name: 'a', body: 'a' }]).includes('pax_global_linkpath'));
  assert.deepEqual(kinds([{ type: 'g', pax: { comment: 'fine' } }, { name: 'a', body: 'a' }]), []);
  assert.ok(kinds([{ name: 'a', body: 'a' }, { type: 'x', pax: { path: 'b' } }]).includes('header_without_member'));
  assert.ok(kinds([{ type: 'x', pax: { path: 'a' } }, { type: 'x', pax: { path: 'b' } }, { name: 'c', body: 'c' }]).includes('two_pax_headers'));
  assert.ok(kinds([{ type: 'L', body: 'a' }, { type: 'L', body: 'b' }, { name: 'c', body: 'c' }]).includes('two_long_names'));
  assert.ok(kinds([{ type: 'L', body: 'a' }, { name: 'c', body: 'c', pax: { path: 'b' } }]).includes('long_name_and_pax_path_disagree'));
  // in a layer, every one of these lands in the apply's red list
  const a = applyLayers([tarFile([{ type: 'g', pax: { path: 'etc' } }, { name: 'a', body: 'a' }])]);
  assert.ok(a.red.some((r) => r.kind === 'pax_global_path' && r.layer === 0));
  // and an export stream carrying one is not well formed
  assert.ok(tarList(tarFile([{ type: 'g', pax: { path: 'etc' } }, { name: 'a', body: 'a' }])).anomalies.length > 0);
});

// Security 12327.4 + 12430 (f): the local pull checked against the registry tree, not trusted, with ZERO exceptions
const REG = () => applyLayers([tarFile([{ name: 'etc/', type: '5' }, { name: 'etc/hostname', body: 'made-up-host\n' }, { name: 'etc/a', body: 'a' }, { name: 'usr/', type: '5' }, { name: 'usr/x', body: 'x' }])]).tree;
const SAME = () => applyLayers([tarFile([{ name: 'etc/', type: '5' }, { name: 'etc/hostname', body: 'made-up-host\n' }, { name: 'etc/a', body: 'a' }, { name: 'usr/', type: '5' }, { name: 'usr/x', body: 'x' }])]).tree;

test('cross-check (12430 f): the same tree passes; the runtime\'s placeholders are no longer an allowed difference; one changed file is red; the instrument bites', () => {
  const reg = REG();
  assert.equal(crossCheck(SAME(), reg).ok, true);
  // what an export used to show: an empty 0755 /etc/hostname and an /etc/hosts in no layer. Both red now, by name.
  const runtime = tarList(tarFile([{ name: 'etc/', type: '5' }, { name: 'etc/hostname', body: '', mode: 0o755 }, { name: 'etc/a', body: 'a' }, { name: 'etc/hosts', body: '', mode: 0o755 }, { name: 'usr/', type: '5' }, { name: 'usr/x', body: 'x' }]));
  const c = crossCheck(runtime, reg);
  assert.equal(c.ok, false);
  assert.deepEqual(c.only_local, [{ path: '/etc/hosts', type: 'file' }]);
  assert.deepEqual(c.differ, [{ path: '/etc/hostname', why: ['mode', 'bytes'] }]);
  const changed = new Map(SAME()); changed.set('etc/a', { ...changed.get('etc/a'), sha256: sha('A') });
  assert.deepEqual(crossCheck(changed, reg).differ, [{ path: '/etc/a', why: ['bytes'] }]);
  assert.equal(crossCheckBites(SAME(), reg).bites, true);
});

test('base diff on saved trees (12430 a): bytes at /etc/hosts, /etc/hostname, /etc/resolv.conf, /.dockerenv are red by name', () => {
  const base = applyLayers([tarFile([{ name: 'etc/', type: '5' }, { name: 'etc/hostname', body: '' }, { name: 'etc/resolv.conf', body: '' }])]).tree;
  const added = new Map([['opt/rekey/t.mjs', sha('tool')]]);
  const rekeyLayers = [{ name: 'opt/', type: '5' }, { name: 'opt/rekey/', type: '5' }, { name: 'opt/rekey/t.mjs', body: 'tool', mode: 0o444 }];
  const baseOpt = new Map(base); baseOpt.set('opt', { type: 'dir', mode: 0o755, uid: 0, gid: 0 });
  const lower = tarFile([{ name: 'etc/', type: '5' }, { name: 'etc/hostname', body: '' }, { name: 'etc/resolv.conf', body: '' }]);
  const ok = applyLayers([lower, tarFile(rekeyLayers)]).tree;
  assert.equal(baseDiff(ok, baseOpt, added).ok, true);
  const P22 = 'p'.repeat(22);
  const plant = applyLayers([lower, tarFile(rekeyLayers), tarFile([{ name: 'etc/', type: '5' }, { name: 'etc/hosts', body: P22 }, { name: 'etc/hostname', body: P22 }, { name: 'etc/resolv.conf', body: P22 }, { name: '.dockerenv', body: P22 }])]).tree;
  const v = baseDiff(plant, baseOpt, added);
  assert.equal(v.ok, false);
  for (const p of ['/etc/hosts', '/etc/hostname', '/etc/resolv.conf', '/.dockerenv']) assert.ok(redPaths(v).includes(p), p);
});

// Security 12430 (e): the added layers, one by one
const ADD = (o = {}) => ({ addedFrom: 1, whiteouts: ['/var/log/apt'], ...o });
const BASE_L = () => tarFile([{ name: 'var/', type: '5' }, { name: 'var/log/', type: '5' }, { name: 'var/log/apt/', type: '5' }, { name: 'var/log/apt/eipp.log.xz', body: 'xz' }, { name: 'usr/', type: '5' }, { name: 'usr/x', body: 'x' }]);
const WH_APT = () => tarFile([{ name: 'var/', type: '5' }, { name: 'var/log/', type: '5' }, { name: 'var/log/.wh.apt', body: '' }]);

test('added layers: a listed base whiteout passes; an added file deleted, overwritten or opaqued away later is red; the base layers are never judged this way', () => {
  const clean = applyLayers([BASE_L(), WH_APT(), tarFile([{ name: 'opt/', type: '5' }, { name: 'opt/a', body: 'a' }])], ADD());
  assert.deepEqual(clean.layer_red, []); assert.deepEqual(clean.whiteouts_seen, ['/var/log/apt']);
  const kinds = (a) => a.layer_red.map((r) => r.kind);
  const del = applyLayers([BASE_L(), WH_APT(), tarFile([{ name: 'opt/', type: '5' }, { name: 'opt/a', body: 'a' }]), tarFile([{ name: 'opt/', type: '5' }, { name: 'opt/.wh.a', body: '' }])], ADD());
  assert.deepEqual(kinds(del), ['added_then_whited_out']); assert.equal(del.layer_red[0].gone, '/opt/a');
  const dirDel = applyLayers([BASE_L(), WH_APT(), tarFile([{ name: 'opt/', type: '5' }, { name: 'opt/d/', type: '5' }, { name: 'opt/d/a', body: 'a' }]), tarFile([{ name: 'opt/', type: '5' }, { name: 'opt/.wh.d', body: '' }])], ADD());
  assert.ok(dirDel.layer_red.some((r) => r.kind === 'added_then_whited_out' && r.gone === '/opt/d/a'));
  const over = applyLayers([BASE_L(), WH_APT(), tarFile([{ name: 'opt/', type: '5' }, { name: 'opt/a', body: 'a' }]), tarFile([{ name: 'opt/', type: '5' }, { name: 'opt/a', body: 'b' }])], ADD());
  assert.deepEqual(kinds(over), ['added_then_overwritten']);
  // the same bytes again still count: the earlier layer's copy ships either way
  const same = applyLayers([BASE_L(), WH_APT(), tarFile([{ name: 'opt/', type: '5' }, { name: 'opt/a', body: 'a' }]), tarFile([{ name: 'opt/', type: '5' }, { name: 'opt/a', body: 'a' }])], ADD());
  assert.deepEqual(kinds(same), ['added_then_overwritten']);
  const dirOver = applyLayers([BASE_L(), WH_APT(), tarFile([{ name: 'opt/', type: '5' }, { name: 'opt/d/', type: '5' }, { name: 'opt/d/a', body: 'a' }]), tarFile([{ name: 'opt/', type: '5' }, { name: 'opt/d', body: 'f' }])], ADD());
  assert.ok(dirOver.layer_red.some((r) => r.kind === 'added_then_overwritten' && r.gone === '/opt/d/a'));
  const opq = applyLayers([BASE_L(), WH_APT(), tarFile([{ name: 'usr/', type: '5' }, { name: 'usr/y', body: 'y' }]), tarFile([{ name: 'usr/', type: '5' }, { name: 'usr/.wh..wh..opq', body: '' }])], ADD());
  assert.ok(kinds(opq).includes('added_then_opaqued')); assert.ok(kinds(opq).includes('opaque_dir_not_listed'));
  const restated = applyLayers([BASE_L(), WH_APT(), tarFile([{ name: 'opt/', type: '5' }, { name: 'opt/d/', type: '5', mode: 0o755 }]), tarFile([{ name: 'opt/', type: '5' }, { name: 'opt/d/', type: '5', mode: 0o777 }])], ADD());
  assert.deepEqual(kinds(restated), ['added_dir_restated_differently']);
  // re-stating a directory the same way (every COPY layer does) is not red
  const restatedSame = applyLayers([BASE_L(), WH_APT(), tarFile([{ name: 'opt/', type: '5' }, { name: 'opt/a', body: 'a' }]), tarFile([{ name: 'opt/', type: '5' }, { name: 'opt/b', body: 'b' }])], ADD());
  assert.deepEqual(restatedSame.layer_red, []);
  // without addedFrom (the registry base side) none of this applies
  assert.deepEqual(applyLayers([BASE_L(), tarFile([{ name: 'usr/', type: '5' }, { name: 'usr/.wh.x', body: '' }])]).layer_red, []);
});

test('added layers: a whiteout of an unlisted base path, of nothing, and a listed whiteout that never comes are red; an opaque dir only as a listed base dir', () => {
  const kinds = (a) => a.layer_red.map((r) => r.kind);
  const unlisted = applyLayers([BASE_L(), WH_APT(), tarFile([{ name: 'usr/', type: '5' }, { name: 'usr/.wh.x', body: '' }])], ADD());
  assert.deepEqual(kinds(unlisted), ['whiteout_not_listed']);
  const nothing = applyLayers([BASE_L(), WH_APT(), tarFile([{ name: 'usr/', type: '5' }, { name: 'usr/.wh.none', body: '' }])], ADD());
  assert.deepEqual(kinds(nothing), ['whiteout_of_nothing']);
  const stale = applyLayers([BASE_L(), tarFile([{ name: 'opt/', type: '5' }, { name: 'opt/a', body: 'a' }])], ADD());
  assert.deepEqual(kinds(stale), ['listed_whiteout_not_seen']);
  const listedOpq = applyLayers([BASE_L(), WH_APT(), tarFile([{ name: 'usr/', type: '5' }, { name: 'usr/.wh..wh..opq', body: '' }])], ADD({ opaque: ['/usr'] }));
  assert.deepEqual(listedOpq.layer_red, []);
  const addedOpq = applyLayers([BASE_L(), WH_APT(), tarFile([{ name: 'opt/', type: '5' }]), tarFile([{ name: 'opt/', type: '5' }, { name: 'opt/.wh..wh..opq', body: '' }])], ADD({ opaque: ['/opt'] }));
  assert.ok(kinds(addedOpq).includes('opaque_dir_not_a_base_dir'));
});

test('added layer files (12430 e): a file a later layer deletes is still listed, with where its bytes sit; the base layers are not', () => {
  const lt = [BASE_L(), tarFile([{ name: 'opt/', type: '5' }, { name: 'opt/a', body: 'secret-bytes' }]), tarFile([{ name: 'opt/', type: '5' }, { name: 'opt/.wh.a', body: '' }])];
  const files = addedLayerFiles(lt, 1);
  assert.deepEqual(files.map((f) => [f.layer, f.rel, f.size]), [[1, 'opt/a', 12]]);
  const v = layerView(files, lt);
  assert.equal(v.read(v.entries[0]).toString(), 'secret-bytes');
  // the applied tree no longer holds it, but the view over the tree reads the rest straight from the layers
  const a = applyLayers(lt, { addedFrom: 1, keepSource: true });
  const tv = treeView(a.tree, lt);
  assert.equal(tv.isFile('opt/a'), false);
  assert.equal(tv.readRel('usr/x').toString(), 'x');
  assert.equal(tv.head(tv.entries.find((e) => e.rel === 'var/log/apt/eipp.log.xz'), 1).toString(), 'x');
});

// Security 12430 (b): exactly one image for linux/amd64 in the save, every blob by its digest
function layout({ images = [{ arch: 'amd64' }], attest = false, nested = false, tamper = null } = {}) {
  const blobs = new Map();
  const put = (obj) => { const b = Buffer.isBuffer(obj) ? obj : Buffer.from(JSON.stringify(obj)); const d = `sha256:${sha(b)}`; blobs.set(d, b); return { digest: d, size: b.length }; };
  const descs = images.map((im) => {
    const cfg = put({ architecture: im.configArch ?? im.arch, os: 'linux', rootfs: { type: 'layers', diff_ids: [] }, config: {} });
    const m = put({ schemaVersion: 2, mediaType: OCI, config: { mediaType: 'application/vnd.oci.image.config.v1+json', ...cfg }, layers: [{ mediaType: GZ, digest: `sha256:${'0'.repeat(64)}`, size: 1 }] });
    return { mediaType: OCI, ...m, ...(im.noPlatform ? {} : { platform: { architecture: im.arch, os: 'linux' } }) };
  });
  if (attest) {
    const cfg = put({ architecture: 'unknown', os: 'unknown' });
    const m = put({ schemaVersion: 2, mediaType: OCI, config: cfg, layers: [{ mediaType: 'application/vnd.in-toto+json', digest: `sha256:${'1'.repeat(64)}`, size: 1 }] });
    descs.push({ mediaType: OCI, ...m, annotations: { 'vnd.docker.reference.type': 'attestation-manifest' } });
  }
  let top = descs;
  if (nested) { const ix = put({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.index.v1+json', manifests: descs }); top = [{ mediaType: 'application/vnd.oci.image.index.v1+json', ...ix }]; }
  if (tamper) { const d = descs[0].digest; blobs.set(d, Buffer.concat([blobs.get(d), Buffer.from(' ')])); }
  const index = Buffer.from(JSON.stringify({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.index.v1+json', manifests: top }));
  return selectImage((d) => blobs.get(d) ?? null, index);
}

test('save read (12430 b): one amd64 image passes (nested index and an attestation too); two, none, a platform disagreement or a blob not its digest are red', () => {
  const ok = layout();
  assert.equal(ok.image !== null, true); assert.deepEqual(Object.values(ok.checks), ['PASS', 'PASS', 'PASS', 'PASS']);
  const withAttest = layout({ attest: true, nested: true });
  assert.ok(withAttest.image); assert.equal(withAttest.attestations.length, 1);
  assert.equal(layout({ images: [{ arch: 'amd64' }, { arch: 'amd64' }] }).checks.save_exactly_one_image, 'FAIL');
  assert.equal(layout({ images: [{ arch: 'amd64' }, { arch: 'arm64' }] }).checks.save_exactly_one_image, 'FAIL');
  assert.equal(layout({ images: [] }).checks.save_exactly_one_image, 'FAIL');
  assert.equal(layout({ images: [{ arch: 'arm64' }] }).checks.save_image_is_linux_amd64, 'FAIL');
  // the index names amd64 but the config blob is another platform's image
  assert.equal(layout({ images: [{ arch: 'amd64', configArch: 'arm64' }] }).checks.save_image_is_linux_amd64, 'FAIL');
  const t = layout({ tamper: true });
  assert.equal(t.checks.save_blobs_match_their_digests, 'FAIL'); assert.equal(t.image, null);
});

test('checkLayers is the one function both sides use (12430 c): the save read and the registry verdict agree layer by layer', () => {
  const c = chain([L1, L2]);
  const fromSave = checkLayers({ manifest: JSON.parse(c.manifestRaw), config: JSON.parse(c.configRaw), blobs: c.blobs, decompressedSha: unzipSha });
  assert.deepEqual(fromSave.layers, verdict(c).layers);
  const swapped = checkLayers({ manifest: JSON.parse(c.manifestRaw), config: JSON.parse(c.configRaw), blobs: [c.blobs[1], c.blobs[0]], decompressedSha: unzipSha });
  assert.equal(swapped.checks.every_layer_checks, 'FAIL');
});

test('added-layer search (12430 e): the removed words and an archive in a file a later layer deletes are found, by layer', async () => {
  const { searches, archives, REKEY_IMAGE_WORDS } = await import('../sandbox/tsp-tests/mediator-image-check.mjs');
  const gz = gzipSync(Buffer.from('anything'));
  const lt = [BASE_L(), tarFile([{ name: 'usr/', type: '5' }, { name: 'usr/share/', type: '5' }, { name: 'usr/share/notes.txt', body: 'delete-admin admin-out seal-test encrypt-test' }]),
    tarFile([{ name: 'usr/', type: '5' }, { name: 'usr/share/', type: '5' }, { name: 'usr/share/.wh.notes.txt', body: '' }])];
  const v = layerView(addedLayerFiles(lt, 1), lt);
  const s = searches(v, null, REKEY_IMAGE_WORDS);
  assert.deepEqual(s.store_words, [{ path: '/usr/share/notes.txt', layer: 1, words: REKEY_IMAGE_WORDS }]);
  // the applied tree alone would have missed it
  const a = applyLayers(lt, { addedFrom: 1, keepSource: true });
  assert.deepEqual(searches(treeView(a.tree, lt), null, REKEY_IMAGE_WORDS).store_words, []);
  const f = join(tmp(), 'gz.tar'); writeFileSync(f, Buffer.concat([tarBytes([{ name: 'opt/', type: '5' }], { end: false }), header('opt/blob', '0', 0o644, gz.length), pad(gz), Buffer.alloc(1024)]));
  const lt2 = [BASE_L(), f];
  assert.deepEqual(archives(layerView(addedLayerFiles(lt2, 1), lt2)).map((h) => [h.path, h.layer, h.kinds]), [['/opt/blob', 1, ['gzip']]]);
});

// Security 12480: the same path written twice in one added layer ships the first entry's bytes unseen at tree level
test('added layers (12480): one path written twice in one added layer is red, any kind; across two layers it stays added_then_overwritten; the base layers are not judged', () => {
  const kinds = (a) => a.layer_red.map((r) => r.kind);
  const twice = tarFile([{ name: 'opt/', type: '5' }, { name: 'opt/x', body: 'fourteen bytes' }, { name: 'opt/x', body: 'five!' }]);
  const r = applyLayers([BASE_L(), WH_APT(), twice], ADD());
  assert.deepEqual(kinds(r), ['written_twice_in_one_layer']);
  assert.equal(r.layer_red[0].path, 'opt/x');
  // the tree keeps the second; addedLayerFiles still lists both, so the content searches read the hidden bytes
  assert.equal(r.tree.get('opt/x').size, 5);
  assert.equal(addedLayerFiles([BASE_L(), WH_APT(), twice], 1).filter((f) => f.rel === 'opt/x').length, 2);
  // the same bytes twice are red too (one entry is enough to hide; the rule is about the entry, not the bytes)
  const sameTwice = applyLayers([BASE_L(), WH_APT(), tarFile([{ name: 'opt/', type: '5' }, { name: 'opt/x', body: 'a' }, { name: 'opt/x', body: 'a' }])], ADD());
  assert.deepEqual(kinds(sameTwice), ['written_twice_in_one_layer']);
  // a directory, a symlink over a file, and a hard link over a file, each in one layer
  const dirTwice = applyLayers([BASE_L(), WH_APT(), tarFile([{ name: 'opt/', type: '5' }, { name: 'opt/d/', type: '5' }, { name: 'opt/d/', type: '5', mode: 0o700 }])], ADD());
  assert.ok(kinds(dirTwice).includes('written_twice_in_one_layer'));
  const linkOver = applyLayers([BASE_L(), WH_APT(), tarFile([{ name: 'opt/', type: '5' }, { name: 'opt/x', body: 'secret' }, { name: 'opt/x', type: '2', linkname: '/etc/os-release' }])], ADD());
  assert.ok(kinds(linkOver).includes('written_twice_in_one_layer'));
  const hardOver = applyLayers([BASE_L(), WH_APT(), tarFile([{ name: 'opt/', type: '5' }, { name: 'opt/y', body: 'y' }, { name: 'opt/x', body: 'secret' }, { name: 'opt/x', type: '1', linkname: 'opt/y' }])], ADD());
  assert.ok(kinds(hardOver).includes('written_twice_in_one_layer'));
  // a base dir re-stated once per added layer (every COPY layer does) is not red; an implicit parent then its own entry is not either
  const restate = applyLayers([BASE_L(), WH_APT(), tarFile([{ name: 'opt/a', body: 'a' }, { name: 'opt/', type: '5' }]), tarFile([{ name: 'opt/', type: '5' }, { name: 'opt/b', body: 'b' }])], ADD());
  assert.deepEqual(restate.layer_red, []);
  // across two layers: the existing rule, not this one
  const across = applyLayers([BASE_L(), WH_APT(), tarFile([{ name: 'opt/', type: '5' }, { name: 'opt/x', body: 'a' }]), tarFile([{ name: 'opt/', type: '5' }, { name: 'opt/x', body: 'b' }])], ADD());
  assert.deepEqual(kinds(across), ['added_then_overwritten']);
  // the base layers (before addedFrom) are not judged this way
  const inBase = applyLayers([tarFile([{ name: 'usr/', type: '5' }, { name: 'usr/x', body: '1' }, { name: 'usr/x', body: '2' }]), WH_APT()], { addedFrom: 1, whiteouts: [] });
  assert.ok(!kinds(inBase).includes('written_twice_in_one_layer'));
});

// Security 12480 (3): a BASE dir an added layer re-states with another mode, owner or xattr carries no bytes and is
// not tracked by applyLayers; the base diff judges it on the applied tree, and must go red
test('base diff (12480 (3)): a base dir re-stated in an added layer with another mode, owner or xattr is red in the base diff; re-stated the same is not', () => {
  const baseTar = () => tarFile([{ name: 'opt/', type: '5', mode: 0o755 }, { name: 'usr/', type: '5' }, { name: 'usr/x', body: 'x' }]);
  const base = applyLayers([baseTar()]).tree;
  const added = new Map([['opt/rekey/t.mjs', sha('tool')]]);
  const tool = (opt) => tarFile([opt, { name: 'opt/rekey/', type: '5' }, { name: 'opt/rekey/t.mjs', body: 'tool', mode: 0o444 }]);
  const same = applyLayers([baseTar(), tool({ name: 'opt/', type: '5', mode: 0o755 })], { addedFrom: 1 });
  assert.deepEqual(same.layer_red, []);
  assert.equal(baseDiff(same.tree, base, added).ok, true);
  for (const [why, opt] of [
    ['mode', { name: 'opt/', type: '5', mode: 0o700 }],
    ['owner', { name: 'opt/', type: '5', mode: 0o755, uid: 1000 }],
    ['xattr', { name: 'opt/', type: '5', mode: 0o755, pax: { 'SCHILY.xattr.user.x': '1' } }],
  ]) {
    const a = applyLayers([baseTar(), tool(opt)], { addedFrom: 1 });
    assert.deepEqual(a.layer_red, [], `${why}: applyLayers alone passes it (Security's probe)`);
    const v = baseDiff(a.tree, base, added);
    assert.equal(v.ok, false, why);
    assert.ok(redPaths(v).includes('/opt'), `${why}: /opt named`);
  }
});

// Security 12480 (2): the service base pinned as a triple, STOP while VERIFY, FAIL on any difference or a moved FROM
test('service base pin (12480 (2)): the triple passes only when all three equal the chain; VERIFY is STOP; a moved FROM, a wrong manifest or config, or an unread chain is FAIL', () => {
  const plat = { architecture: 'amd64', os: 'linux' };
  const configRaw = Buffer.from(JSON.stringify({ ...plat, rootfs: { type: 'layers', diff_ids: ['sha256:' + '1'.repeat(64)] } }));
  const manifestRaw = Buffer.from(JSON.stringify({ schemaVersion: 2, mediaType: OCI, config: { digest: `sha256:${sha(configRaw)}`, size: configRaw.length }, layers: [] }));
  const indexRaw = Buffer.from(JSON.stringify({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.index.v1+json', manifests: [{ mediaType: OCI, digest: `sha256:${sha(manifestRaw)}`, size: manifestRaw.length, platform: plat }] }));
  const from = `sha256:${sha(indexRaw)}`;
  const base = chainBase({ index: indexRaw, manifest: manifestRaw, config: configRaw }, from);
  assert.equal(base.checks.base_chain_is_the_from_digest, 'PASS');
  const good = { index_digest: from, manifest_digest: `sha256:${sha(manifestRaw)}`, config_digest: `sha256:${sha(configRaw)}` };
  assert.equal(chainPinVerdict(good, from, base).verdict, 'PASS');
  const stop = chainPinVerdict({ ...good, manifest_digest: 'VERIFY', config_digest: 'VERIFY' }, from, base);
  assert.equal(stop.verdict, 'STOP'); assert.equal(stop.checks.index_is_the_pin, 'PASS');
  assert.deepEqual(stop.read, good, 'the read digests are printed so they can be pinned');
  const other = 'sha256:' + 'a'.repeat(64);
  assert.equal(chainPinVerdict({ ...good, manifest_digest: other }, from, base).verdict, 'FAIL');
  assert.equal(chainPinVerdict({ ...good, config_digest: other }, from, base).verdict, 'FAIL');
  // FAIL wins over STOP
  assert.equal(chainPinVerdict({ ...good, manifest_digest: 'VERIFY', config_digest: other }, from, base).verdict, 'FAIL');
  // a moved FROM: the chain is read for the new digest, the pin file still names the old index
  const moved = chainBase({ index: indexRaw, manifest: manifestRaw, config: configRaw }, other);
  assert.equal(chainPinVerdict(good, other, moved).verdict, 'FAIL');
  // nothing read (the fetch failed), a missing or malformed pin file: FAIL, never a pass
  assert.equal(chainPinVerdict(good, from, chainBase({}, from)).verdict, 'FAIL');
  assert.equal(chainPinVerdict(null, from, base).verdict, 'FAIL');
  assert.equal(chainPinVerdict({ ...good, config_digest: 'sha256:short' }, from, base).verdict, 'FAIL');
  // the committed pin file names the service Dockerfile's FROM digest and is STOP until Security pins it
  const pinFile = JSON.parse(readFileSync(new URL('../sandbox/tsp-tests/service-base.json', import.meta.url), 'utf8'));
  const df = readFileSync(new URL('../sandbox/tsp-tests/mediator-service.Dockerfile', import.meta.url), 'utf8');
  assert.equal(pinFile.index_digest, /^FROM [^@\s]+@(sha256:[0-9a-f]{64})/m.exec(df)[1]);
  for (const k of ['manifest_digest', 'config_digest']) assert.ok(pinFile[k] === 'VERIFY' || /^sha256:[0-9a-f]{64}$/.test(pinFile[k]), k);
});
