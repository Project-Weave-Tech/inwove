// The Dockerfile batch's judges (Security 12422 e + the rekey image, 12491 b, 12195.1 d), on made-up trees: the
// shipped store tool keeps only rekey/opens/names/absent and none of the removed words; the service-image search
// hits a planted renamed copy, a setup binary, a D-Bus daemon and a bus path, and passes a clean tree; the rekey-image
// check reads the shipped file, not the source. The images themselves are built and judged on the job.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, cpSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gzipSync, deflateSync } from 'node:zlib';
import { strip, shippedVerdict, subcommands } from '../sandbox/tsp-tests/mediator-store-ship.mjs';
import { serviceVerdict, rekeyVerdict, archives, walk, SERVICE_ENTRYPOINT, ARCHIVES_ALLOWED, allowedArchive } from '../sandbox/tsp-tests/mediator-image-check.mjs';

const DIR = new URL('../sandbox/tsp-tests/', import.meta.url).pathname;
const SRC = readFileSync(join(DIR, 'mediator-store.mjs'), 'utf8');
const tmp = () => mkdtempSync(join(tmpdir(), 'img-'));
const put = (root, rel, body = '') => { mkdirSync(join(root, rel, '..'), { recursive: true }); writeFileSync(join(root, rel), body); };
const SVC_CONFIG = { User: '10001:10001', Entrypoint: SERVICE_ENTRYPOINT, Env: ['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'] };

function cleanService() {
  const r = tmp();
  put(r, 'opt/mediator/mediator', 'ELF made-up');
  put(r, 'opt/mediator/mediator-entrypoint.sh', '#!/bin/bash -p\n');
  put(r, 'opt/mediator/mediator-deny.sha256', 'x\n');
  put(r, 'opt/mediator/keyring-probe', 'ELF made-up');
  put(r, 'usr/lib/x86_64-linux-gnu/libdbus-1.so.3', 'client library only');
  return r;
}
function planted() {
  const p = tmp();
  put(p, 'usr/lib/node/renamed-tool.js', SRC); put(p, 'opt/mediator-store.mjs', SRC);
  put(p, 'usr/lib/node/renamed-tool.bin', gzipSync(Buffer.from(SRC)));
  put(p, 'usr/local/bin/mediator-setup'); put(p, 'usr/bin/dbus-daemon'); put(p, 'run/dbus/system_bus_socket'); put(p, 'run/user/10001/bus');
  return p;
}

test('ship: the shipped tool has only rekey/opens/names/absent and none of the removed words; the source has all eight', () => {
  assert.deepEqual(subcommands(SRC), ['absent', 'admin-out', 'delete-admin', 'encrypt-test', 'names', 'opens', 'rekey', 'seal-test']);
  assert.equal(shippedVerdict(SRC).ok, false);
  const v = shippedVerdict(strip(SRC));
  assert.deepEqual(v, { ok: true, subcommands: ['absent', 'names', 'opens', 'rekey'], extra_subcommands: [], forbidden_words: [], markers_left: false });
});

test('ship: an unbalanced marker refuses; a subcommand added outside the markers is red', () => {
  assert.throws(() => strip('a\n// ship:drop-begin\nb\n'), /without an end/);
  assert.throws(() => strip('a\n// ship:drop-end\n'), /without a begin/);
  assert.throws(() => strip('// ship:drop-begin\n// ship:drop-begin\n// ship:drop-end\n'), /nested/);
  const leak = strip(SRC).replace("    case 'rekey': {", "    case 'dump': { return 0; }\n    case 'rekey': {");
  assert.deepEqual(shippedVerdict(leak).extra_subcommands, ['dump']);
  assert.equal(shippedVerdict(strip(SRC) + '\n// admin-out\n').ok, false);
  assert.equal(shippedVerdict(strip(SRC).replace("case 'rekey'", "case 'rekeyed'")).ok, false); // rekey must be there
});

test('ship: the shipped tool still runs: rekey refuses while the admin credential is present, then re-seals', () => {
  const d = tmp();
  try {
    mkdirSync(join(d, 'ship/node_modules/@noble'), { recursive: true });
    cpSync(join(DIR, 'node_modules/@noble/hashes'), join(d, 'ship/node_modules/@noble/hashes'), { recursive: true });
    writeFileSync(join(d, 'ship/mediator-store.mjs'), strip(SRC));
    writeFileSync(join(d, 'old'), 'made-up-old'); writeFileSync(join(d, 'new'), 'made-up-new');
    const full = (...a) => spawnSync(process.execPath, [join(DIR, 'mediator-store.mjs'), ...a], { encoding: 'utf8' });
    const ship = (...a) => spawnSync(process.execPath, [join(d, 'ship/mediator-store.mjs'), ...a], { encoding: 'utf8' });
    const s = join(d, 'secrets.json');
    assert.equal(full('seal-test', s, join(d, 'old'), JSON.stringify({ mediator_admin_credential: 'made-up', mediator_jwt_secret: 'made-up' })).status, 0);
    const r1 = ship('rekey', s, join(d, 'old'), join(d, 'new'));
    assert.notEqual(r1.status, 0); assert.match(r1.stderr, /mediator_admin_credential/);
    for (const c of ['admin-out', 'delete-admin', 'seal-test', 'encrypt-test']) assert.equal(ship(c, s, join(d, 'old')).status, 2, c);
    assert.equal(full('delete-admin', s, join(d, 'old')).status, 0);
    const r2 = ship('rekey', s, join(d, 'old'), join(d, 'new'));
    assert.equal(r2.status, 0, r2.stderr);
    assert.equal(ship('opens', s, join(d, 'old')).status, 4);
    assert.equal(ship('opens', s, join(d, 'new')).status, 0);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test('service image check: a clean tree passes, and the planted tree is hit on every search', () => {
  const r = cleanService(), p = planted();
  try {
    const v = serviceVerdict(r, SVC_CONFIG, p);
    assert.ok(Object.values(v.checks).every((x) => x === 'PASS'), JSON.stringify(v.checks));
    assert.ok(Object.values(v.instrument).every(Boolean));
    // the planted tree judged as if it were the image: every line that should bite does
    const bad = serviceVerdict(p, SVC_CONFIG, p).checks;
    for (const k of ['d_no_mediator_setup', 'e_no_store_tool_by_name', 'e_no_file_carries_the_store_words', 'b_no_dbus_daemon_or_broker', 'b_no_bus_socket_paths']) assert.equal(bad[k], 'FAIL', k);
  } finally { rmSync(r, { recursive: true, force: true }); rmSync(p, { recursive: true, force: true }); }
});

test('service image check: a renamed copy, one word in any file, a bus name in Env, root, a shell-form entrypoint each go red', () => {
  const p = planted();
  const cases = [
    ['e_no_file_carries_the_store_words', (r) => put(r, 'usr/share/x/tool.txt', SRC), SVC_CONFIG],
    ['e_no_file_carries_the_store_words', (r) => put(r, 'etc/notes', 'run encrypt-test here'), SVC_CONFIG],
    ['e_no_store_tool_by_name', (r) => put(r, 'srv/mediator-store.mjs', 'renamed inside'), SVC_CONFIG],
    ['d_no_mediator_setup', (r) => put(r, 'opt/mediator/mediator-setup'), SVC_CONFIG],
    ['b_no_dbus_daemon_or_broker', (r) => put(r, 'usr/bin/dbus-broker'), SVC_CONFIG],
    ['b_image_env_names_no_bus', () => {}, { ...SVC_CONFIG, Env: ['DBUS_SESSION_BUS_ADDRESS=unix:path=/x'] }],
    ['b_image_env_names_no_bus', () => {}, { ...SVC_CONFIG, Env: ['XDG_RUNTIME_DIR=/run/user/10001'] }],
    ['user_not_root', () => {}, { ...SVC_CONFIG, User: '' }],
    ['user_not_root', () => {}, { ...SVC_CONFIG, User: '0:0' }],
    ['entrypoint_exec_form', () => {}, { ...SVC_CONFIG, Entrypoint: ['/bin/sh', '-c', '/opt/mediator/mediator-entrypoint.sh'] }],
    ['keyring_probe_present', (r) => rmSync(join(r, 'opt/mediator/keyring-probe')), SVC_CONFIG],
  ];
  try {
    for (const [line, mutate, config] of cases) {
      const r = cleanService();
      try { mutate(r); assert.equal(serviceVerdict(r, config, p).checks[line], 'FAIL', line); } finally { rmSync(r, { recursive: true, force: true }); }
    }
    // an instrument that can't hit can't pass: an empty planted dir makes the image check red
    const r = cleanService(), empty = tmp();
    try { assert.equal(serviceVerdict(r, SVC_CONFIG, empty).checks.instrument_bites, 'FAIL'); } finally { rmSync(r, { recursive: true, force: true }); rmSync(empty, { recursive: true, force: true }); }
  } finally { rmSync(p, { recursive: true, force: true }); }
});

test('rekey image check: reads the shipped file in the image; the source shipped, a mediator binary, a port or a second copy are red', () => {
  const REK = { User: '1000:1000', Entrypoint: ['node', '/opt/rekey/mediator-store.mjs'] };
  const mk = (body) => { const r = tmp(); put(r, 'opt/rekey/mediator-store.mjs', body); put(r, 'usr/local/bin/node', 'ELF'); return r; };
  const p = planted();
  const ok = mk(strip(SRC));
  try {
    const v = rekeyVerdict(ok, REK, '/opt/rekey/mediator-store.mjs', p);
    assert.ok(Object.values(v.checks).every((x) => x === 'PASS'), JSON.stringify(v.checks));
    assert.deepEqual(v.subcommands, ['absent', 'names', 'opens', 'rekey']);
    assert.match(v.shipped_sha256, /^[0-9a-f]{64}$/);
    assert.equal(rekeyVerdict(ok, { ...REK, ExposedPorts: { '7037/tcp': {} } }, '/opt/rekey/mediator-store.mjs', p).checks.no_exposed_port, 'FAIL');
    assert.equal(rekeyVerdict(ok, REK, '/opt/rekey/missing.mjs', p).checks.shipped_tool_present, 'FAIL');
  } finally { rmSync(ok, { recursive: true, force: true }); }
  const src = mk(SRC);
  try {
    const c = rekeyVerdict(src, REK, '/opt/rekey/mediator-store.mjs', p).checks;
    assert.equal(c.shipped_subcommands_within_rekey_opens_names_absent, 'FAIL');
    assert.equal(c.shipped_file_has_no_removed_words, 'FAIL');
  } finally { rmSync(src, { recursive: true, force: true }); }
  for (const [line, extra] of [['no_mediator_binary', 'opt/mediator/mediator'], ['d_no_mediator_setup', 'usr/bin/mediator-setup'], ['no_other_store_tool_copy', 'tmp/mediator-store.mjs']]) {
    const r = mk(strip(SRC));
    try { put(r, extra, 'x'); assert.equal(rekeyVerdict(r, REK, '/opt/rekey/mediator-store.mjs', p).checks[line], 'FAIL', line); } finally { rmSync(r, { recursive: true, force: true }); }
  }
  // Security 12940 change 2: a renamed copy, or one removed word in any file outside the shipped path, is red; `rekey`
  // alone (node may carry it) is not; and a content search that can't hit its planted copy can't pass.
  for (const [body, red] of [[SRC, true], ['see admin-out', true], ['call encrypt-test', true], ['node: rekey of a buffer', false]]) {
    const r = mk(strip(SRC));
    try {
      put(r, 'usr/lib/node/renamed.js', body);
      const v = rekeyVerdict(r, REK, '/opt/rekey/mediator-store.mjs', p);
      assert.equal(v.checks.no_file_outside_the_shipped_path_carries_the_removed_words, red ? 'FAIL' : 'PASS', body.slice(0, 20));
      assert.equal(v.checks.content_search_bites, 'PASS');
    } finally { rmSync(r, { recursive: true, force: true }); }
  }
  const empty = tmp(), clean = mk(strip(SRC));
  try {
    assert.equal(rekeyVerdict(clean, REK, '/opt/rekey/mediator-store.mjs', empty).checks.content_search_bites, 'FAIL');
    assert.equal(rekeyVerdict(clean, REK, '/opt/rekey/mediator-store.mjs').checks.content_search_bites, 'FAIL');
  } finally { for (const d of [empty, clean, p]) rmSync(d, { recursive: true, force: true }); }
});

test('ship: getEntry (the one-value open) is dropped with admin-out, and a getEntry left outside a drop block is red (Security 12940 change 1)', () => {
  assert.ok(SRC.includes('export function getEntry'));
  assert.ok(!strip(SRC).includes('getEntry'));
  const leaked = strip(SRC).replace('function writeAtomic(', 'export function getEntry(j) { return j; }\n\nfunction writeAtomic(');
  assert.deepEqual(shippedVerdict(leaked).forbidden_words, ['getEntry']);
  assert.equal(shippedVerdict(leaked).ok, false);
});

test('rekey image check 13081.2: an archive outside the shipped path is red by its bytes (a renamed one too); the list must hit the planted gzip', () => {
  const REK = { User: '1000:1000', Entrypoint: ['node', '/opt/rekey/mediator-store.mjs'] };
  const mk = () => { const r = tmp(); put(r, 'opt/rekey/mediator-store.mjs', strip(SRC)); put(r, 'usr/local/bin/node', 'ELF'); return r; };
  const p = planted();
  const SHIP = '/opt/rekey/mediator-store.mjs';
  try {
    const clean = mk();
    try {
      const v = rekeyVerdict(clean, REK, SHIP, p);
      assert.equal(v.checks.archive_search_bites, 'PASS');
      assert.equal(v.checks.no_archive_outside_the_shipped_path, 'PASS');
      assert.deepEqual(v.archive_hits, []);
    } finally { rmSync(clean, { recursive: true, force: true }); }
    // the planted case Security named: a gzip of the full source passes the word search (compressed) but not this
    const zipLocal = Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.alloc(26)]);
    for (const [rel, body, kind] of [
      ['usr/lib/node/full.tgz', gzipSync(Buffer.from(SRC)), 'gzip'],
      ['usr/lib/node/innocent.js', gzipSync(Buffer.from(SRC)), 'gzip'],
      ['usr/share/x.zip', zipLocal, 'zip'],
      ['usr/share/x.dat', deflateSync(Buffer.from(SRC)), 'zlib'],
      ['usr/share/tool.js.br', 'brotli has no magic', 'by-name'],
    ]) {
      const r = mk();
      try {
        put(r, rel, body);
        const v = rekeyVerdict(r, REK, SHIP, p);
        assert.equal(v.checks.no_file_outside_the_shipped_path_carries_the_removed_words, 'PASS', `${rel}: the word search alone misses it`);
        assert.equal(v.checks.no_archive_outside_the_shipped_path, 'FAIL', rel);
        assert.ok(v.archive_hits.some((a) => a.path === `/${rel}` && a.kinds.includes(kind)), JSON.stringify(v.archive_hits));
        assert.equal(Object.values(v.checks).every((x) => x === 'PASS'), false);
      } finally { rmSync(r, { recursive: true, force: true }); }
    }
    // an instrument that can't hit can't pass: a planted dir with the renamed copy but no gzip
    const noGz = tmp();
    try {
      put(noGz, 'usr/lib/node/renamed-tool.js', SRC);
      const clean = mk();
      try { assert.equal(rekeyVerdict(clean, REK, SHIP, noGz).checks.archive_search_bites, 'FAIL'); } finally { rmSync(clean, { recursive: true, force: true }); }
    } finally { rmSync(noGz, { recursive: true, force: true }); }
    // plain text, a JS file starting with x, and an empty file are not archives
    const t = tmp();
    try {
      put(t, 'a.js', 'x = 1;\n'); put(t, 'b.txt', 'PK is just two letters here'); put(t, 'empty', '');
      assert.deepEqual(archives(t, walk(t)), []);
    } finally { rmSync(t, { recursive: true, force: true }); }
  } finally { rmSync(p, { recursive: true, force: true }); }
});

test('rekey image check 11869.3: the one allowed archive passes only as its pinned triple; gzip bytes, one byte changed, another size or path are red', () => {
  const REK = { User: '1000:1000', Entrypoint: ['node', '/opt/rekey/mediator-store.mjs'] };
  const SHIP = '/opt/rekey/mediator-store.mjs';
  const ALT = 'var/lib/dpkg/alternatives/builtins.7.gz';
  assert.equal(ARCHIVES_ALLOWED.length, 1);
  assert.deepEqual(ARCHIVES_ALLOWED[0].kinds, ['by-name']);
  assert.throws(() => { ARCHIVES_ALLOWED.push({ path: '/x.gz' }); });
  // a stand-in triple with bytes the test owns (the real one is the base's own 83-byte dpkg record)
  const body = Buffer.from('manual\n/usr/share/man/man7/builtins.7.gz\n\n/usr/share/man/man7/bash-builtins.7.gz\n10\n\n');
  const crypto = { sha: (b) => spawnSync('sha256sum', { input: b }).stdout.toString().split(' ')[0] };
  const allowed = [{ path: `/${ALT}`, sha256: crypto.sha(body), size: body.length, kinds: ['by-name'] }];
  const mk = (rel, b) => { const r = tmp(); put(r, 'opt/rekey/mediator-store.mjs', strip(SRC)); put(r, rel, b); return r; };
  const flip = Buffer.from(body); flip[3] ^= 1;
  for (const [name, rel, b, ok] of [
    ['the pinned bytes', ALT, body, true],
    ['the same name with gzip bytes', ALT, gzipSync(body), false],
    ['the same name with one byte changed', ALT, flip, false],
    ['another size', ALT, Buffer.concat([body, Buffer.from('\n')]), false],
    ['the pinned bytes at another path', 'var/lib/dpkg/alternatives/other.7.gz', body, false],
  ]) {
    const r = mk(rel, b);
    try {
      const hit = archives(r, walk(r)).find((a) => a.path === `/${rel}`);
      assert.ok(hit, name);
      assert.equal(!!allowedArchive(r, hit, allowed), ok, name);
    } finally { rmSync(r, { recursive: true, force: true }); }
  }
  // the shipped list itself: its own pinned path with other bytes is red in rekeyVerdict
  const p = planted();
  try {
    for (const b of [gzipSync(body), body]) {
      const r = mk(ALT, b);
      try {
        const v = rekeyVerdict(r, REK, SHIP, p);
        assert.equal(v.checks.no_archive_outside_the_shipped_path, 'FAIL');
        assert.ok(v.archive_hits.some((a) => a.path === `/${ALT}`));
        assert.equal(v.archives_allowed_read[0].path, `/${ALT}`);
      } finally { rmSync(r, { recursive: true, force: true }); }
    }
    // absent: nothing allowed, nothing red, and the read says absent
    const r = mk('usr/local/bin/node', 'ELF');
    try {
      const v = rekeyVerdict(r, REK, SHIP, p);
      assert.equal(v.checks.no_archive_outside_the_shipped_path, 'PASS');
      assert.deepEqual(v.archives_allowed_read, [{ path: `/${ALT}`, absent: true }]);
    } finally { rmSync(r, { recursive: true, force: true }); }
  } finally { rmSync(p, { recursive: true, force: true }); }
});
