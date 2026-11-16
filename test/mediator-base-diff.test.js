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

// A small tar writer (ustar + a pax 'x' header per entry) so a test can plant SCHILY.xattr.* records, which a runner
// without xattr support can't write with tar itself. entries: [{name, type ('0' file | '5' dir), mode, body, xattrs: {name: Buffer}}]
function tarBytes(entries) {
  const field = (s, n) => { const b = Buffer.alloc(n); b.write(s, 0, 'utf8'); return b; };
  const header = (name, type, mode, size) => {
    const h = Buffer.alloc(512);
    h.write(name, 0, 100); h.write(`${mode.toString(8).padStart(7, '0')}\0`, 100); h.write('0000000\0', 108); h.write('0000000\0', 116);
    h.write(`${size.toString(8).padStart(11, '0')}\0`, 124); h.write('00000000000\0', 136); h.write('        ', 148); h.write(type, 156); h.write('ustar\0', 257); h.write('00', 263);
    h.write(`${[...h].reduce((a, b) => a + b, 0).toString(8).padStart(6, '0')}\0 `, 148);
    return h;
  };
  const pad = (b) => Buffer.concat([b, Buffer.alloc((512 - (b.length % 512)) % 512)]);
  const parts = [];
  for (const e of entries) {
    const body = e.body ?? Buffer.alloc(0);
    if (e.xattrs) {
      const recs = Object.entries(e.xattrs).map(([k, v]) => {
        const rest = Buffer.concat([Buffer.from(` SCHILY.xattr.${k}=`), v, Buffer.from('\n')]);
        let len = rest.length + 1; while (String(len).length + rest.length !== len) len = String(len).length + rest.length;
        return Buffer.concat([Buffer.from(String(len)), rest]);
      });
      const px = Buffer.concat(recs);
      parts.push(header(`PaxHeaders/${e.name}`, 'x', 0o644, px.length), pad(px));
    }
    parts.push(header(e.name, e.type ?? '0', e.mode ?? 0o644, body.length), pad(body));
  }
  parts.push(Buffer.alloc(1024));
  return Buffer.concat(parts);
}
const tarFile = (entries) => { const f = join(tmp(), 'w.tar'); writeFileSync(f, tarBytes(entries)); return f; };

test('base diff: a security.capability xattr added to a base binary (or any added file) is red, by name only; removed or changed too; equal xattrs pass', () => {
  const CAP = Buffer.from([1, 0, 0, 2, 0, 0, 0, 0, 0xff, 0, 0, 0]);
  const baseE = [{ name: 'usr/bin/', type: '5', mode: 0o755 }, { name: 'usr/bin/node', body: Buffer.from('ELF'), mode: 0o755 }, { name: 'usr/bin/ping', body: Buffer.from('ELF2'), mode: 0o755, xattrs: { 'security.capability': CAP } }];
  const base = tarList(tarFile(baseE));
  assert.deepEqual(Object.keys(base.get('usr/bin/ping').xattrs), ['security.capability']);
  assert.equal(base.get('usr/bin/ping').xattrs['security.capability'], sha(CAP));
  assert.equal(base.get('usr/bin/node').xattrs, undefined);
  assert.equal(baseDiff(tarList(tarFile(baseE)), base, new Map()).ok, true);
  const cases = {
    added: [baseE[0], { ...baseE[1], xattrs: { 'security.capability': CAP } }, baseE[2]],
    removed: [baseE[0], baseE[1], { ...baseE[2], xattrs: undefined }],
    changed: [baseE[0], baseE[1], { ...baseE[2], xattrs: { 'security.capability': Buffer.from('other') } }],
  };
  for (const [name, es] of Object.entries(cases)) {
    const v = baseDiff(tarList(tarFile(es)), base, new Map());
    assert.equal(v.ok, false, name);
    assert.equal(v.xattr_changed.length, 1, name);
    assert.deepEqual(v.xattr_changed[0].names, ['security.capability'], name);
    assert.ok(!JSON.stringify(v).includes(sha(CAP)), 'no value digest in the verdict');
  }
  // an added file and an added dir under /opt/rekey carrying an xattr are red too
  const withAdded = [...baseE, { name: 'opt/rekey/', type: '5', mode: 0o755, xattrs: { 'user.x': Buffer.from('1') } }, { name: 'opt/rekey/t.mjs', body: TOOL, xattrs: { 'security.capability': CAP } }];
  const v = baseDiff(tarList(tarFile(withAdded)), base, new Map([['opt/rekey/t.mjs', sha(TOOL)]]));
  assert.equal(v.ok, false);
  assert.deepEqual(v.xattr_changed.map((h) => h.path).sort(), ['/opt/rekey', '/opt/rekey/t.mjs']);
});

test('base diff: a base directory whose mode or owner changed is red', () => {
  const b = baseTree();
  try {
    for (const [name, change] of [['mode', (r) => chmodSync(join(r, 'usr/share/doc/x'), 0o777)], ['owner', (r) => chownSync(join(r, 'usr/share/doc/x'), 1000, 1000)], ['setuid dir', (r) => chmodSync(join(r, 'usr/share'), 0o4755)]]) {
      const r = rekeyFrom(b);
      try {
        change(r);
        const v = judge(r, b);
        assert.equal(v.ok, false, name);
        assert.ok(v.changed.some((h) => h.path.startsWith('/usr/share') && h.why.includes(name === 'owner' ? 'owner' : 'mode')), `${name}: ${JSON.stringify(v.changed)}`);
      } finally { rmSync(r, { recursive: true, force: true }); }
    }
  } finally { rmSync(b, { recursive: true, force: true }); }
});
