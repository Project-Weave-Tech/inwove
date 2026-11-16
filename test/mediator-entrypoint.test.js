// Condition 16.4 refuse cases on the mediator's entrypoint (Security 11984 §2-3, 12079.2). A fake mediator prints the
// NAMES in its environment (never a value) and whether the passphrase file reads back; no real mediator, no real key.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync, symlinkSync, existsSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const EP = new URL('../sandbox/tsp-tests/mediator-entrypoint.sh', import.meta.url).pathname;
const SHM = '/dev/shm';
const haveTmpfs = existsSync(SHM) && spawnSync('stat', ['-f', '-c', '%T', SHM], { encoding: 'utf8' }).stdout.trim() === 'tmpfs';

function rig() {
  const disk = mkdtempSync(join(tmpdir(), 'ep-'));
  const shm = mkdtempSync(join(SHM, 'ep-'));
  const bin = join(disk, 'bin'); mkdirSync(bin);
  const med = join(bin, 'mediator');
  writeFileSync(med, '#!/bin/sh\nfor kv in $(/usr/bin/env | /usr/bin/cut -d= -f1 | /usr/bin/sort); do echo "name $kv"; done\n'
    + 'if [ "$(/bin/cat "$MEDIATOR_FILE_BACKEND_PASSPHRASE_FILE")" = "test-only-marker" ]; then echo "passfile ok"; fi\necho "cwd $(pwd)"\n');
  chmodSync(med, 0o755);
  const volume = join(disk, 'volume'); mkdirSync(volume);
  const workdir = join(disk, 'work'); mkdirSync(workdir);
  const deny = join(disk, 'deny.txt'); writeFileSync(deny, 'MEDIATOR_ACL_MODE\nBLOCK_REMOTE_ADMIN_MSGS\nLOG_LEVEL\n');
  return { disk, shm, med, volume, workdir, deny, done: () => { rmSync(disk, { recursive: true, force: true }); rmSync(shm, { recursive: true, force: true }); } };
}
const baseEnv = { PATH: '/usr/bin:/bin', DATABASE_URL: 'redis://test-only', ENKARA_MEDIATOR_BACKEND_PASSPHRASE: 'test-only-marker' };
function run(r, { env = {}, tmpfs = r.shm, volume = r.volume, workdir = r.workdir, extra = [] } = {}) {
  const res = spawnSync('bash', [EP, '--bin', r.med, '--volume', volume, '--tmpfs', tmpfs, '--workdir', workdir, '--deny-file', r.deny, ...extra, '--', '-c', 'mediator.toml'],
    { encoding: 'utf8', env: { ...baseEnv, ...env } });
  return { code: res.status, out: res.stdout, err: res.stderr };
}
const refused = (x, what) => { assert.equal(x.code, 78, x.err); assert.match(x.err, new RegExp(`refused: .*${what}`)); };

test('entrypoint: green case: only the allow list reaches the mediator, the passphrase file is 0400 on tmpfs', { skip: !haveTmpfs && 'no tmpfs at /dev/shm' }, () => {
  const r = rig();
  try {
    const x = run(r, { env: { PORT: '8080', SOME_PLATFORM_VAR: '1' } });
    assert.equal(x.code, 0, x.err);
    const names = x.out.split('\n').filter((l) => l.startsWith('name ')).map((l) => l.slice(5)).filter((n) => n !== 'PWD');
    assert.deepEqual(names, ['DATABASE_URL', 'MEDIATOR_FILE_BACKEND_PASSPHRASE_FILE', 'RUST_LOG']);
    assert.match(x.out, /passfile ok/);
    assert.match(x.out, new RegExp(`cwd ${r.workdir}`));
    assert.equal((statSync(join(r.shm, 'backend-passphrase')).mode & 0o777).toString(8), '400');
    assert.ok(!x.out.includes('test-only-marker') && !x.err.includes('test-only-marker'), 'the value is never printed');
  } finally { r.done(); }
});

test('entrypoint: refuses the plain passphrase, any MEDIATOR_TAG_*, and a deny-list name on the host', { skip: !haveTmpfs && 'no tmpfs' }, () => {
  const r = rig();
  try {
    refused(run(r, { env: { MEDIATOR_FILE_BACKEND_PASSPHRASE: 'x' } }), 'MEDIATOR_FILE_BACKEND_PASSPHRASE is set');
    refused(run(r, { env: { MEDIATOR_TAG_REGION: 'x' } }), 'MEDIATOR_TAG_\\* present');
    refused(run(r, { env: { MEDIATOR_ACL_MODE: 'explicit_deny' } }), 'MEDIATOR_ACL_MODE is set');
    refused(run(r, { env: { LOG_LEVEL: 'debug' } }), 'LOG_LEVEL is set');
  } finally { r.done(); }
});

test('entrypoint: a missing required value fails loudly', { skip: !haveTmpfs && 'no tmpfs' }, () => {
  const r = rig();
  try {
    refused(run(r, { env: { DATABASE_URL: '' } }), 'DATABASE_URL is missing');
    refused(run(r, { env: { ENKARA_MEDIATOR_BACKEND_PASSPHRASE: '' } }), 'ENKARA_MEDIATOR_BACKEND_PASSPHRASE is missing');
  } finally { r.done(); }
});

test('entrypoint: refuses a non-tmpfs dir, one on the volume\'s filesystem, a symlinked dir or file', { skip: !haveTmpfs && 'no tmpfs' }, () => {
  const r = rig();
  try {
    const plain = join(r.disk, 'plain'); mkdirSync(plain);
    refused(run(r, { tmpfs: plain }), 'not tmpfs');
    const vol2 = join(r.shm, 'vol'); mkdirSync(vol2);
    refused(run(r, { volume: vol2 }), "on the volume's filesystem");
    const link = join(r.disk, 'link'); symlinkSync(r.shm, link);
    refused(run(r, { tmpfs: link }), 'tmpfs dir is a symlink');
    symlinkSync(join(r.disk, 'elsewhere'), join(r.shm, 'backend-passphrase'));
    refused(run(r), 'passphrase file is a symlink');
  } finally { r.done(); }
});

test('entrypoint: refuses mediator-setup in the image and a non-empty working directory', { skip: !haveTmpfs && 'no tmpfs' }, () => {
  const r = rig();
  try {
    writeFileSync(join(r.workdir, 'mediator.toml'), '');
    refused(run(r), 'working directory is not empty');
    rmSync(join(r.workdir, 'mediator.toml'));
    writeFileSync(join(r.disk, 'bin', 'mediator-setup'), '#!/bin/sh\n'); chmodSync(join(r.disk, 'bin', 'mediator-setup'), 0o755);
    refused(run(r), 'mediator-setup is in the image');
  } finally { r.done(); }
});
