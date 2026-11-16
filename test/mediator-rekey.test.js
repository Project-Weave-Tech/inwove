// The rekey run (Security 12024, shape B): the entrypoint's `env -i` and the tool's own environment check (1), and the
// three tool cases (2): a second run refuses and writes nothing, a run killed at any point leaves exactly one whole
// store, a second writer between the read and the rename refuses. Made-up stores and passphrases only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, readdirSync, copyFileSync, symlinkSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const DIR = new URL('../sandbox/tsp-tests/', import.meta.url).pathname;
const SRC = join(DIR, 'mediator-store.mjs');
const NODE = '/usr/local/bin/node';
const MARKERS = { DATABASE_URL: 'postgres://u:marker-db-7f3a@h/db', REDIS_PASSWORD: 'marker-redis-91c2', MARK_SERVICE_VAR: 'marker-svc-44e0' };
const OLD = 'made-up-old-passphrase-1', NEW = 'made-up-new-passphrase-2';

// A rekey "image" in a temp dir: the entrypoint and the SHIPPED tool side by side, an empty HOME, @noble beside them.
function rig() {
  const d = mkdtempSync(join(tmpdir(), 'rekey-'));
  const img = join(d, 'opt'); mkdirSync(img); mkdirSync(join(img, 'home'));
  copyFileSync(join(DIR, 'mediator-rekey-entrypoint.sh'), join(img, 'rekey-entrypoint.sh'));
  const s = spawnSync(process.execPath, [join(DIR, 'mediator-store-ship.mjs'), SRC, join(img, 'mediator-store.mjs')], { encoding: 'utf8' });
  assert.equal(s.status, 0, s.stderr);
  symlinkSync(join(DIR, 'node_modules'), join(img, 'node_modules'));
  chmodSync(join(img, 'home'), 0o555);
  const vol = join(d, 'vol'); mkdirSync(vol, { mode: 0o700 });
  const store = join(vol, 'secrets.json');
  const pp = mkdtempSync('/dev/shm/rekey-test-');
  writeFileSync(join(pp, 'old'), OLD); writeFileSync(join(pp, 'new'), NEW);
  const tool = (args, env = process.env, pre = []) => spawnSync(NODE, [...pre, SRC, ...args], { encoding: 'utf8', env });
  assert.equal(tool(['seal-test', store, join(pp, 'old'), JSON.stringify({ mediator_jwt_secret: 'made-up-jwt', mediator_secrets: 'made-up-ops' })]).status, 0);
  const opensWith = (f) => tool(['opens', store, f]).status === 0;
  const exactEnv = { REKEY_STORE: store, REKEY_OLD_PASSPHRASE_FILE: join(pp, 'old'), REKEY_NEW_PASSPHRASE_FILE: join(pp, 'new'), PATH: '/usr/local/bin:/usr/bin:/bin', HOME: join(img, 'home') };
  const entry = (env, args = ['--volume', vol, '--tmpfs', '/dev/shm']) =>
    spawnSync('/bin/bash', ['-p', join(img, 'rekey-entrypoint.sh'), ...args], { encoding: 'utf8', env: { PATH: '/usr/bin:/bin', ...env } });
  const done = () => {
    rmSync(d, { recursive: true, force: true }); rmSync(pp, { recursive: true, force: true });
    for (const n of readdirSync('/dev/shm')) if (n.startsWith('rekey.')) { try { rmSync(join('/dev/shm', n), { recursive: true, force: true }); } catch { /* not ours */ } }
  };
  return { d, img, vol, store, pp, tool, opensWith, exactEnv, entry, done };
}
const last = (out) => { try { return JSON.parse(out.trim().split('\n').pop()); } catch { return null; } };
const temps = (vol) => readdirSync(vol).filter((n) => n.startsWith('.secrets.json.'));

test('rekey 12024.1: through the entrypoint, planted service variables never reach the tool and no marker is printed', () => {
  const r = rig();
  try {
    const x = r.entry({ ...MARKERS, ENKARA_MEDIATOR_BACKEND_PASSPHRASE: OLD, ENKARA_MEDIATOR_BACKEND_PASSPHRASE_NEW: NEW });
    assert.equal(x.status, 0, x.stderr);
    const j = last(x.stdout);
    assert.equal(j.values_unchanged, true); assert.equal(j.old_opens, false); assert.equal(j.new_opens, true); assert.equal(j.salt_changed, true);
    for (const v of [...Object.values(MARKERS), OLD, NEW]) assert.ok(!x.stdout.includes(v) && !x.stderr.includes(v), 'no value is printed');
    assert.match(x.stderr, /env -i dropped \d+ host names: .*DATABASE_URL/);
    assert.ok(!r.opensWith(join(r.pp, 'old')) && r.opensWith(join(r.pp, 'new')), 'read-back: new opens, old refuses');
  } finally { r.done(); }
});

test('rekey 12024.1: the tool refuses (6) on any name beyond the allow list, a missing one, or a path that is not its argument, and writes nothing', () => {
  const r = rig();
  try {
    const before = readFileSync(r.store);
    const args = ['rekey', r.store, join(r.pp, 'old'), join(r.pp, 'new')];
    for (const env of [{ ...r.exactEnv, DATABASE_URL: MARKERS.DATABASE_URL }, { ...r.exactEnv, NODE_OPTIONS: '' }, (({ HOME, ...e }) => e)(r.exactEnv),
      { ...r.exactEnv, REKEY_NEW_PASSPHRASE_FILE: join(r.pp, 'old') }]) {
      const x = r.tool(args, env);
      assert.equal(x.status, 6, JSON.stringify(Object.keys(env)));
      assert.ok(!x.stdout.includes(MARKERS.DATABASE_URL), 'names only');
      assert.deepEqual(readFileSync(r.store), before);
    }
    assert.deepEqual(last(r.tool(args, { ...r.exactEnv, DATABASE_URL: 'x' }).stdout).extra, ['DATABASE_URL']);
    assert.equal(r.tool(args, r.exactEnv).status, 0, 'exactly the allow list runs');
  } finally { r.done(); }
});

test('rekey 12024.2 (a): a second run refuses (the old passphrase no longer opens) and leaves the store byte-identical', () => {
  const r = rig();
  try {
    const env = { ENKARA_MEDIATOR_BACKEND_PASSPHRASE: OLD, ENKARA_MEDIATOR_BACKEND_PASSPHRASE_NEW: NEW };
    assert.equal(r.entry(env).status, 0);
    const after = readFileSync(r.store);
    const x = r.entry(env);
    assert.equal(x.status, 1); assert.match(x.stderr, /the old passphrase does not open the store/);
    assert.deepEqual(readFileSync(r.store), after); assert.deepEqual(temps(r.vol), []);
  } finally { r.done(); }
});

// A preload that kills the tool (SIGKILL, no cleanup) at one point of the write.
const KILL = {
  'during the temp write': "const w = fs.writeSync; fs.writeSync = (...a) => { if (a[0] !== 1 && a[0] !== 2) process.kill(process.pid, 'SIGKILL'); return w(...a); };",
  'after fsync, before the rename': "fs.renameSync = () => process.kill(process.pid, 'SIGKILL');",
  'after the rename, before the directory fsync': "const rn = fs.renameSync; fs.renameSync = (...a) => { rn(...a); process.kill(process.pid, 'SIGKILL'); };",
};
for (const [where, patch] of Object.entries(KILL)) {
  test(`rekey 12024.2 (b): killed ${where}, the store opens with exactly one of the two passphrases`, () => {
    const r = rig();
    try {
      const pre = join(r.d, 'kill.mjs'); writeFileSync(pre, `import fs from 'node:fs';\n${patch}\n`);
      const x = r.tool(['rekey', r.store, join(r.pp, 'old'), join(r.pp, 'new')], r.exactEnv, ['--import', pre]);
      assert.equal(x.signal, 'SIGKILL', x.stderr);
      const o = r.opensWith(join(r.pp, 'old')), n = r.opensWith(join(r.pp, 'new'));
      assert.ok(o !== n, `exactly one opens (old ${o}, new ${n})`);
      assert.equal(n, where.startsWith('after the rename'));
      // A killed run's temp is removed by the next run, which then completes (or refuses if it already went through).
      const y = r.tool(['rekey', r.store, join(r.pp, o ? 'old' : 'new'), join(r.pp, o ? 'new' : 'old')], o ? r.exactEnv
        : { ...r.exactEnv, REKEY_OLD_PASSPHRASE_FILE: join(r.pp, 'new'), REKEY_NEW_PASSPHRASE_FILE: join(r.pp, 'old') });
      assert.equal(y.status, 0, y.stderr); assert.deepEqual(temps(r.vol), []);
      assert.equal(last(y.stdout).stale_temps_removed, where === 'after the rename, before the directory fsync' ? 0 : 1);
    } finally { r.done(); }
  });
}

test('rekey 12024.2 (c): a second writer between the read and the rename refuses; the temp is removed and the store left as it was', () => {
  const r = rig();
  try {
    const pre = join(r.d, 'writer.mjs');
    // the "other writer": touches the store's mtime when the tool chmods its temp file (just before the guard)
    writeFileSync(pre, `import fs from 'node:fs';\nconst c = fs.chmodSync; fs.chmodSync = (p, m) => { c(p, m); const t = new Date(Date.now() + 5000); fs.utimesSync(${JSON.stringify(r.store)}, t, t); };\n`);
    const before = readFileSync(r.store);
    const x = r.tool(['rekey', r.store, join(r.pp, 'old'), join(r.pp, 'new')], r.exactEnv, ['--import', pre]);
    assert.equal(x.status, 1); assert.match(x.stderr, /second writer/);
    assert.deepEqual(readFileSync(r.store), before); assert.deepEqual(temps(r.vol), []);
    assert.ok(r.opensWith(join(r.pp, 'old')));
  } finally { r.done(); }
});

test('rekey entrypoint: refuses by name, before any tool runs', () => {
  const r = rig();
  try {
    const both = { ENKARA_MEDIATOR_BACKEND_PASSPHRASE: OLD, ENKARA_MEDIATOR_BACKEND_PASSPHRASE_NEW: NEW };
    const before = readFileSync(r.store);
    const cases = [
      [{ ENKARA_MEDIATOR_BACKEND_PASSPHRASE: OLD }, undefined, /ENKARA_MEDIATOR_BACKEND_PASSPHRASE_NEW is missing/],
      [{ ...both, ENKARA_MEDIATOR_BACKEND_PASSPHRASE_NEW: OLD }, undefined, /equals/],
      [{ ...both, LD_PRELOAD: '/x.so' }, undefined, /shell or the loader: LD_PRELOAD/],
      [{ ...both, BASH_ENV: '/x' }, undefined, /shell or the loader: BASH_ENV/],
      [both, ['--volume', r.vol, '--tmpfs', '/dev/shm', '--extra'], /unknown argument/],
      [both, ['--volume', r.vol, '--tmpfs', r.d], /not tmpfs/],
      [both, ['--volume', join(r.d, 'nope'), '--tmpfs', '/dev/shm'], /volume is not a directory/],
    ];
    for (const [env, args, want] of cases) {
      const x = r.entry(env, args);
      assert.equal(x.status, 78, `${want}: ${x.stderr}`); assert.match(x.stderr, want);
      assert.ok(!x.stderr.includes(OLD) && !x.stderr.includes(NEW));
    }
    assert.deepEqual(readFileSync(r.store), before);
  } finally { r.done(); }
});
