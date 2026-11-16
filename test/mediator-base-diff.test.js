// Security 11869.4: the rekey image's base-diff line, on small made-up trees tarred the way an export is (pax, numeric
// owners). Every disguise Security probed passes the content and archive lines; each must be red here.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, chmodSync, chownSync, symlinkSync, cpSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import crypto from 'node:crypto';
import { gzipSync, deflateRawSync, brotliCompressSync } from 'node:zlib';
import { tarList, baseDiff, addedSet, instrument, dirList } from '../sandbox/tsp-tests/mediator-base-diff.mjs';

const DIR = new URL('../sandbox/tsp-tests/', import.meta.url).pathname;
const SRC = readFileSync(join(DIR, 'mediator-store.mjs'));
const tmp = () => mkdtempSync(join(tmpdir(), 'bdiff-'));
const put = (root, rel, body = '', mode = 0o644) => { mkdirSync(join(root, rel, '..'), { recursive: true }); writeFileSync(join(root, rel), body); chmodSync(join(root, rel), mode); };
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const TOOL = Buffer.from('#!/usr/bin/env node\n// the shipped tool, made up\n');
const NOBLE = Buffer.from('export const sha256 = 1;\n');
const ADDED = addedSet({ tool: { path: '/opt/rekey/mediator-store.mjs', sha256: sha(TOOL) }, noble: [{ path: '/opt/rekey/node_modules/@noble/hashes/sha2.js', sha256: sha(NOBLE) }] });
const tarOf = (root) => {
  const f = join(tmp(), 'x.tar');
  const r = spawnSync('tar', ['--numeric-owner', '--format=pax', '-cf', f, '-C', root, '.']);
  assert.equal(r.status, 0, r.stderr?.toString());
  return f;
};
function baseTree() {
  const r = tmp();
  put(r, 'usr/bin/node', 'ELF made-up', 0o755);
  put(r, 'usr/bin/su', 'ELF su', 0o4755);
  put(r, 'usr/share/doc/x/copyright', 'text');
  put(r, 'var/log/apt/eipp.log.xz', Buffer.from([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]));
  put(r, 'etc/a-long-directory-name-to-need-a-pax-path-record/and-another-long-segment-here/and-a-third-one-too/file.conf', 'x');
  symlinkSync('/usr/bin/node', join(r, 'usr/bin/nodejs'));
  mkdirSync(join(r, 'opt'), { recursive: true });
  return r;
}
function rekeyFrom(base) {
  const r = tmp();
  cpSync(base, r, { recursive: true, verbatimSymlinks: true });
  rmSync(join(r, 'var/log/apt'), { recursive: true, force: true });
  put(r, 'opt/rekey/mediator-store.mjs', TOOL, 0o444);
  put(r, 'opt/rekey/node_modules/@noble/hashes/sha2.js', NOBLE);
  return r;
}
const judge = (rek, base) => baseDiff(tarList(tarOf(rek)), tarList(tarOf(base)), ADDED);

test('base diff: the base plus the added set passes; deleted base files are listed, not red; pax long paths read', () => {
  const b = baseTree(), r = rekeyFrom(b);
  try {
    const bl = tarList(tarOf(b));
    assert.ok(bl.has('etc/a-long-directory-name-to-need-a-pax-path-record/and-another-long-segment-here/and-a-third-one-too/file.conf'));
    assert.equal(bl.get('usr/bin/su').mode, 0o4755);
    assert.equal(bl.get('usr/bin/nodejs').linkname, '/usr/bin/node');
    const v = judge(r, b);
    assert.equal(v.ok, true, JSON.stringify(v));
    assert.deepEqual(v.deleted_base_entries, ['/var/log/apt', '/var/log/apt/eipp.log.xz']);
  } finally { rmSync(b, { recursive: true, force: true }); rmSync(r, { recursive: true, force: true }); }
});

test('base diff: every disguise of the full tool Security probed is red at usr/share/<name>', () => {
  const b = baseTree();
  const gzOneIn = Buffer.concat([Buffer.from('x'), gzipSync(SRC)]);
  const tarDir = tmp(); put(tarDir, 'a.txt', SRC);
  const tarOfTool = readFileSync(tarOf(tarDir));
  const disguises = {
    base64: Buffer.from(SRC.toString('base64')), hex: Buffer.from(SRC.toString('hex')), rawdeflate: deflateRawSync(SRC),
    brotli: brotliCompressSync(SRC), gzip_one_byte_in: gzOneIn, tar_member: tarOfTool, reversed: Buffer.from([...SRC].reverse()),
  };
  try {
    for (const [name, body] of Object.entries(disguises)) {
      const r = rekeyFrom(b);
      try {
        put(r, `usr/share/${name}`, body);
        const v = judge(r, b);
        assert.equal(v.ok, false, name);
        assert.ok(v.added_file_not_in_set.some((h) => h.path === `/usr/share/${name}`), name);
      } finally { rmSync(r, { recursive: true, force: true }); }
    }
  } finally { rmSync(b, { recursive: true, force: true }); rmSync(tarDir, { recursive: true, force: true }); }
});

test('base diff: a changed base file (bytes, mode, setuid added, owner, link target) is red; so is an added-set file with other bytes', () => {
  const b = baseTree();
  const cases = [
    ['bytes', (r) => put(r, 'usr/share/doc/x/copyright', 'text plus the tool'), '/usr/share/doc/x/copyright', 'changed'],
    ['setuid added', (r) => chmodSync(join(r, 'usr/bin/node'), 0o4755), '/usr/bin/node', 'changed'],
    ['mode', (r) => chmodSync(join(r, 'usr/share/doc/x/copyright'), 0o666), '/usr/share/doc/x/copyright', 'changed'],
    ['owner', (r) => chownSync(join(r, 'usr/share/doc/x/copyright'), 1000, 1000), '/usr/share/doc/x/copyright', 'changed'],
    ['link target', (r) => { rmSync(join(r, 'usr/bin/nodejs')); symlinkSync('/opt/rekey/x', join(r, 'usr/bin/nodejs')); }, '/usr/bin/nodejs', 'changed'],
    ['tool other bytes', (r) => put(r, 'opt/rekey/mediator-store.mjs', SRC, 0o444), '/opt/rekey/mediator-store.mjs', 'added_file_not_in_set'],
    ['noble other bytes', (r) => put(r, 'opt/rekey/node_modules/@noble/hashes/sha2.js', 'x'), '/opt/rekey/node_modules/@noble/hashes/sha2.js', 'added_file_not_in_set'],
    ['a file added under /opt/rekey', (r) => put(r, 'opt/rekey/extra.js', 'x'), '/opt/rekey/extra.js', 'added_file_not_in_set'],
  ];
  try {
    for (const [name, change, p, kind] of cases) {
      const r = rekeyFrom(b);
      try {
        change(r);
        const v = judge(r, b);
        assert.equal(v.ok, false, name);
        assert.ok(v[kind].some((h) => (h.path ?? h) === p), `${name}: ${JSON.stringify(v[kind])}`);
      } finally { rmSync(r, { recursive: true, force: true }); }
    }
  } finally { rmSync(b, { recursive: true, force: true }); }
});

test('base diff: a dir added outside /opt/rekey, an added link, a setuid added file, or a missing added-set file is red', () => {
  const b = baseTree();
  const cases = [
    ['dir outside', (r) => mkdirSync(join(r, 'usr/share/hidden')), 'added_dir_outside', '/usr/share/hidden'],
    ['added link', (r) => symlinkSync('/opt/rekey/mediator-store.mjs', join(r, 'usr/bin/rk')), 'added_not_a_file', '/usr/bin/rk'],
    ['setuid tool', (r) => chmodSync(join(r, 'opt/rekey/mediator-store.mjs'), 0o4555), 'added_setuid', '/opt/rekey/mediator-store.mjs'],
    ['noble missing', (r) => rmSync(join(r, 'opt/rekey/node_modules/@noble/hashes/sha2.js')), 'added_set_missing', '/opt/rekey/node_modules/@noble/hashes/sha2.js'],
  ];
  try {
    for (const [name, change, kind, p] of cases) {
      const r = rekeyFrom(b);
      try {
        change(r);
        const v = judge(r, b);
        assert.equal(v.ok, false, name);
        assert.ok(v[kind].some((h) => (h.path ?? h) === p), `${name}: ${JSON.stringify(v[kind])}`);
      } finally { rmSync(r, { recursive: true, force: true }); }
    }
  } finally { rmSync(b, { recursive: true, force: true }); }
});

test('base diff instrument: bites on a planted tree plus a base64 copy of the tool; an empty planted tree, or one the base already holds, cannot bite', () => {
  const b = baseTree(), r = rekeyFrom(b), p = tmp();
  try {
    put(p, 'usr/lib/node/renamed-tool.js', SRC); put(p, 'usr/lib/node/renamed-tool.bin', gzipSync(SRC)); put(p, 'usr/local/bin/mediator-setup');
    const rek = tarList(tarOf(r)), base = tarList(tarOf(b));
    const ins = instrument(rek, base, ADDED, p, SRC);
    assert.equal(ins.bites, true, JSON.stringify(ins));
    assert.equal(ins.planted_files, 4);
    // the planted tree read from disk carries its files
    assert.ok(dirList(p).get('usr/lib/node/renamed-tool.js').sha256);
    // an empty planted tree can't bite: the line must hit the planted tree, not only the base64 copy
    const empty = tmp();
    try { assert.equal(instrument(rek, base, ADDED, empty, SRC).bites, false); } finally { rmSync(empty, { recursive: true, force: true }); }
    // planted files the base already holds byte for byte are not red, so the instrument reports them missed
    const same = tmp();
    try { put(same, 'usr/share/doc/x/copyright', 'text'); const m = instrument(rek, base, ADDED, same, SRC); assert.equal(m.bites, false); assert.deepEqual(m.missed.length >= 1, true); }
    finally { rmSync(same, { recursive: true, force: true }); }
  } finally { [b, r, p].forEach((d) => rmSync(d, { recursive: true, force: true })); }
});
