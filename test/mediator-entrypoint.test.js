// Condition 16.4 refuse cases on the mediator's entrypoint (Security 11984 §2-3, 12079.2). A fake mediator prints the
// NAMES in its environment (never a value) and whether the passphrase file reads back; no real mediator, no real key.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync, symlinkSync, existsSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readFileSync } from 'node:fs';
import { denyFileText, sha256 } from '../sandbox/tsp-tests/mediator-deny-file.mjs';

const EP = new URL('../sandbox/tsp-tests/mediator-entrypoint.sh', import.meta.url).pathname;
const RECORD = JSON.parse(readFileSync(new URL('../sandbox/tsp-tests/mediator-env-lists.json', import.meta.url), 'utf8'));
const BAKED = readFileSync(new URL('../sandbox/tsp-tests/mediator-deny.sha256', import.meta.url), 'utf8').trim();
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
  writeFileSync(join(volume, 'secrets.json'), JSON.stringify({ entries: { mediator_jwt_secret: 'dGVzdA', mediator_operating_secrets: 'dGVzdA' } }));
  const workdir = join(disk, 'work'); mkdirSync(workdir);
  const deny = join(disk, 'deny.txt'); writeFileSync(deny, denyFileText(RECORD));
  return { disk, shm, med, volume, workdir, deny, done: () => { rmSync(disk, { recursive: true, force: true }); rmSync(shm, { recursive: true, force: true }); } };
}
const baseEnv = { PATH: '/usr/bin:/bin', DATABASE_URL: 'redis://test-only', ENKARA_MEDIATOR_BACKEND_PASSPHRASE: 'test-only-marker' };
function run(r, { env = {}, tmpfs = r.shm, volume = r.volume, workdir = r.workdir, deny = r.deny, extra = [] } = {}) {
  const res = spawnSync('bash', [EP, '--bin', r.med, '--volume', volume, '--tmpfs', tmpfs, '--workdir', workdir, '--deny-file', deny, ...extra, '--', '-c', 'mediator.toml'],
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
    const vol2 = join(r.shm, 'vol'); mkdirSync(vol2); writeFileSync(join(vol2, 'secrets.json'), JSON.stringify({ entries: {} }));
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

test('entrypoint: the baked deny sha256 is the deny side of the committed record (12144.3a)', () => {
  assert.equal(BAKED, sha256(denyFileText(RECORD)));
  for (const n of RECORD.floor.deny) assert.ok(n in RECORD.deny, `floor name ${n} on the deny side`);
  const script = readFileSync(EP, 'utf8');
  for (const n of RECORD.floor.deny) assert.ok(script.includes(n), `the entrypoint holds floor name ${n}`);
});

test('entrypoint: refuses an empty deny file, one missing ADMIN_DID, and one that differs from the record (12144.3a)', { skip: !haveTmpfs && 'no tmpfs' }, () => {
  const r = rig();
  try {
    const empty = join(r.disk, 'empty.txt'); writeFileSync(empty, '');
    refused(run(r, { deny: empty }), 'missing the floor name');
    const cut = join(r.disk, 'cut.txt'); writeFileSync(cut, denyFileText(RECORD).replace('ADMIN_DID\n', ''));
    refused(run(r, { deny: cut }), 'missing the floor name ADMIN_DID');
    const short = join(r.disk, 'short.txt'); writeFileSync(short, denyFileText(RECORD).replace('LOG_LEVEL\n', ''));
    refused(run(r, { deny: short }), "deny file's sha256 is not the record's");
  } finally { r.done(); }
});

test('entrypoint: refuses unlisted MEDIATOR_/VAULT_/AWS_ host names, not the allow list (12144.2)', { skip: !haveTmpfs && 'no tmpfs' }, () => {
  const r = rig();
  try {
    refused(run(r, { env: { MEDIATOR_NEW_KNOB: '1' } }), 'MEDIATOR_/VAULT_/AWS_ families.*MEDIATOR_NEW_KNOB');
    refused(run(r, { env: { VAULT_ADDR: 'x' } }), 'families.*VAULT_ADDR');
    refused(run(r, { env: { AWS_ACCESS_KEY_ID: 'x' } }), 'families.*AWS_ACCESS_KEY_ID');
    const ok = run(r, { env: { MEDIATOR_FILE_BACKEND_PASSPHRASE_FILE: '/elsewhere', RUST_LOG: 'trace' } });
    assert.equal(ok.code, 0, ok.err);
    assert.match(ok.out, new RegExp(`name MEDIATOR_FILE_BACKEND_PASSPHRASE_FILE`));
  } finally { r.done(); }
});

test('entrypoint: refuses a tmpfs dir wider than 0700 (12144.3b)', { skip: !haveTmpfs && 'no tmpfs' }, () => {
  const r = rig();
  try {
    chmodSync(r.shm, 0o777);
    refused(run(r), "tmpfs dir's mode is 777");
    chmodSync(r.shm, 0o750);
    refused(run(r), "tmpfs dir's mode is 750");
    chmodSync(r.shm, 0o700);
    assert.equal(run(r).code, 0);
  } finally { r.done(); }
});

test('entrypoint: one start line names what env -i dropped, never a value (12144.3c, Railroad 12137)', { skip: !haveTmpfs && 'no tmpfs' }, () => {
  const r = rig();
  try {
    const x = run(r, { env: { WPI_HOST_EXTRA: 'planted-value-7f3', PORT: '8080' } });
    assert.equal(x.code, 0, x.err);
    const line = x.err.split('\n').filter((l) => l.startsWith('entrypoint: env -i dropped'));
    assert.equal(line.length, 1, x.err);
    for (const n of ['WPI_HOST_EXTRA', 'PORT', 'ENKARA_MEDIATOR_BACKEND_PASSPHRASE', 'PATH']) assert.match(line[0], new RegExp(`\\b${n}\\b`));
    assert.doesNotMatch(line[0], /\bDATABASE_URL\b/);
    const count = Number(line[0].match(/dropped (\d+) host names/)[1]);
    assert.equal(count, line[0].split('host names: ')[1].trim().split(/\s+/).length);
    for (const v of ['planted-value-7f3', 'test-only-marker', 'redis://test-only', '8080']) {
      assert.ok(!x.out.includes(v) && !x.err.includes(v), `value ${v} never printed`);
    }
  } finally { r.done(); }
});

test('entrypoint: 16.3(b) refuses a store that names mediator_admin_credential, and a missing or linked store', { skip: !haveTmpfs && 'no tmpfs' }, () => {
  const r = rig();
  try {
    const store = join(r.volume, 'secrets.json');
    writeFileSync(store, JSON.stringify({ entries: { mediator_admin_credential: 'dGVzdA', mediator_jwt_secret: 'dGVzdA' } }));
    refused(run(r), 'mediator_admin_credential is in the secret backend');
    // the encrypted shape names it in plaintext too: no passphrase needed to see it
    writeFileSync(store, JSON.stringify({ version: 1, kdf: {}, verifier_b64: 'x', verifier_nonce_b64: 'x', entries: { mediator_admin_credential: { nonce_b64: 'x', ciphertext_b64: 'x' } } }));
    refused(run(r), 'mediator_admin_credential is in the secret backend');
    rmSync(store);
    refused(run(r), 'no secret store on the volume');
    writeFileSync(join(r.disk, 'real.json'), JSON.stringify({ entries: {} }));
    symlinkSync(join(r.disk, 'real.json'), store);
    refused(run(r), 'the secret store is a symlink');
  } finally { r.done(); }
});
