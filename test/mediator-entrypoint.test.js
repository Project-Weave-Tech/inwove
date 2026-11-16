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
  const conf = join(disk, 'mediator.toml');
  writeFileSync(conf, `[security]\ntrust_task_verification = "enforce"\n[secrets]\nbackend = "file://${volume}/secrets.json?encrypt=1"\n[storage]\nbackend = "redis"\n`);
  return { disk, shm, med, volume, workdir, deny, conf, done: () => { rmSync(disk, { recursive: true, force: true }); rmSync(shm, { recursive: true, force: true }); } };
}
const baseEnv = { PATH: '/usr/bin:/bin', DATABASE_URL: 'redis://test-only', ENKARA_MEDIATOR_BACKEND_PASSPHRASE: 'test-only-marker' };
function run(r, { env = {}, tmpfs = r.shm, volume = r.volume, workdir = r.workdir, deny = r.deny, extra = [], medArgs = ['-c', r.conf] } = {}) {
  const res = spawnSync('/bin/bash', ['-p', EP, '--bin', r.med, '--volume', volume, '--tmpfs', tmpfs, '--workdir', workdir, '--deny-file', deny, ...extra, '--', ...medArgs],
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

test('entrypoint 12491(b): refuses a D-Bus session or system bus handed in by the host, by name', { skip: !haveTmpfs && 'no tmpfs' }, () => {
  const r = rig();
  try {
    refused(run(r, { env: { DBUS_SESSION_BUS_ADDRESS: 'unix:path=/run/user/1000/bus' } }), 'D-Bus bus names on the host: DBUS_SESSION_BUS_ADDRESS');
    refused(run(r, { env: { DBUS_SYSTEM_BUS_ADDRESS: 'unix:path=/run/dbus/system_bus_socket' } }), 'D-Bus bus names on the host: DBUS_SYSTEM_BUS_ADDRESS');
    // An unrelated DBUS_ name is not a bus address: env -i drops it like any other platform name.
    const ok = run(r, { env: { DBUS_STARTER_BUS_TYPE: 'session' } });
    assert.ok(!/refused: D-Bus/.test(ok.err), 'only the bus-address names refuse');
    // Security 12640: the starter (activation) bus address refuses too; with the type beside it, the address is named.
    refused(run(r, { env: { DBUS_STARTER_ADDRESS: 'unix:path=/run/dbus/system_bus_socket' } }), 'D-Bus bus names on the host: DBUS_STARTER_ADDRESS');
    refused(run(r, { env: { DBUS_STARTER_BUS_TYPE: 'system', DBUS_STARTER_ADDRESS: 'unix:path=/run/dbus/system_bus_socket' } }), 'D-Bus bus names on the host: DBUS_STARTER_ADDRESS');
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
    const conf2 = join(r.disk, 'vol2.toml'); writeFileSync(conf2, `[security]\ntrust_task_verification = "enforce"\n[secrets]\nbackend = "file://${vol2}/secrets.json?encrypt=1"\n`);
    refused(run(r, { volume: vol2, medArgs: ['-c', conf2] }), "on the volume's filesystem");
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

// 12180 (Security): the entrypoint must not trust its own shell. Proven on 1aafa86 with a fake `env` first on PATH,
// BASH_ENV and exported functions; these hold the fix.
function fakeBin(r) {
  const fb = join(r.disk, 'fakebin'); mkdirSync(fb);
  // a fake env that drops -i and execs the rest; fakes of the check tools that always "pass"
  writeFileSync(join(fb, 'env'), '#!/bin/sh\n[ "$1" = -i ] && shift\nexec /usr/bin/env "$@"\n');
  writeFileSync(join(fb, 'sha256sum'), `#!/bin/sh\necho "${BAKED}  -"\n`);
  writeFileSync(join(fb, 'grep'), '#!/bin/sh\nexit 0\n');
  writeFileSync(join(fb, 'stat'), '#!/bin/sh\necho tmpfs\n');
  for (const f of ['env', 'sha256sum', 'grep', 'stat']) chmodSync(join(fb, f), 0o755);
  return fb;
}

test('entrypoint 12180: a fake env (and fake check tools) first on the host PATH changes nothing', { skip: !haveTmpfs && 'no tmpfs' }, () => {
  const r = rig();
  try {
    const fb = fakeBin(r);
    const x = run(r, { env: { PATH: `${fb}:/usr/bin:/bin`, WPI_HOST_EXTRA: 'planted-value-7f3', RUST_LOG: 'trace' } });
    assert.equal(x.code, 0, x.err);
    const names = x.out.split('\n').filter((l) => l.startsWith('name ')).map((l) => l.slice(5)).filter((n) => n !== 'PWD');
    assert.deepEqual(names, ['DATABASE_URL', 'MEDIATOR_FILE_BACKEND_PASSPHRASE_FILE', 'RUST_LOG']);
    assert.match(x.err, /env -i dropped .*\bPATH\b/);
    // the fake tools would pass a cut deny file; the real ones refuse it
    const cut = join(r.disk, 'cut.txt'); writeFileSync(cut, denyFileText(RECORD).replace('LOG_LEVEL\n', ''));
    refused(run(r, { env: { PATH: `${fb}:/usr/bin:/bin` }, deny: cut }), "deny file's sha256 is not the record's");
  } finally { r.done(); }
});

test('entrypoint 12180: refuses BASH_ENV, ENV, SHELLOPTS, BASHOPTS, any BASH_FUNC_* and any LD_* by name', { skip: !haveTmpfs && 'no tmpfs' }, () => {
  const r = rig();
  try {
    const hook = join(r.disk, 'hook.sh'); writeFileSync(hook, 'echo HOOKED >&2\n');
    for (const n of ['BASH_ENV', 'ENV']) {
      const x = run(r, { env: { [n]: hook } });
      refused(x, `change the shell or the loader: ${n}`);
      assert.doesNotMatch(x.err, /HOOKED/);
    }
    refused(run(r, { env: { SHELLOPTS: 'xtrace' } }), 'change the shell or the loader: SHELLOPTS');
    refused(run(r, { env: { BASHOPTS: 'extglob' } }), 'change the shell or the loader: BASHOPTS');
    // an exported function standing in for sha256sum, with a cut deny file: refused by name, never "passed"
    const cut = join(r.disk, 'cut.txt'); writeFileSync(cut, denyFileText(RECORD).replace('LOG_LEVEL\n', ''));
    const fn = run(r, { env: { 'BASH_FUNC_sha256sum%%': `() { echo "${BAKED}  -"; }` }, deny: cut });
    refused(fn, 'change the shell or the loader: BASH_FUNC_sha256sum%%');
    refused(run(r, { env: { 'BASH_FUNC_grep%%': '() { return 0; }' } }), 'BASH_FUNC_grep%%');
    refused(run(r, { env: { LD_PRELOAD: '' } }), 'change the shell or the loader: LD_PRELOAD');
    refused(run(r, { env: { LD_LIBRARY_PATH: '/nowhere' } }), 'LD_LIBRARY_PATH');
  } finally { r.done(); }
});

test('entrypoint 12180: run without -p, a BASH_ENV still never reaches a start (refused by name)', { skip: !haveTmpfs && 'no tmpfs' }, () => {
  // the shebang and the image's exec-form ENTRYPOINT carry -p; this is the belt if someone starts it as `bash <script>`
  const r = rig();
  try {
    const res = spawnSync('bash', [EP, '--bin', r.med, '--volume', r.volume, '--tmpfs', r.shm, '--workdir', r.workdir, '--deny-file', r.deny, '--', '-c', 'x'],
      { encoding: 'utf8', env: { ...baseEnv, BASH_ENV: '/dev/null' } });
    assert.equal(res.status, 78, res.stderr);
    assert.match(res.stderr, /refused: .*BASH_ENV/);
  } finally { r.done(); }
});

test('entrypoint 12180: the script starts as bash -p, sets PATH first, and calls env -i by absolute path', () => {
  const lines = readFileSync(EP, 'utf8').split('\n');
  assert.equal(lines[0], '#!/bin/bash -p');
  const firstStatement = lines.slice(1).find((l) => l.trim() && !l.trim().startsWith('#'));
  assert.equal(firstStatement, 'PATH=/usr/bin:/bin; export PATH');
  const execs = lines.filter((l) => /^\s*exec\b/.test(l));
  assert.equal(execs.length, 1);
  assert.match(execs[0], /^exec \/usr\/bin\/env -i /);
  assert.ok(!lines.some((l) => !l.trim().startsWith('#') && /compgen -e/.test(l)), 'host names come from /proc, not compgen -e');
});

test('entrypoint 12247.1: a store key spelled with a \\u escape is refused, though JSON.parse reads it as the admin credential', { skip: !haveTmpfs && 'no tmpfs' }, () => {
  const r = rig();
  try {
    const raw = '{"entries":{"\\u006dediator_admin_credential":"eA","mediator_jwt_secret":"dGVzdA"}}';
    assert.ok(Object.keys(JSON.parse(raw).entries).includes('mediator_admin_credential'), 'the escape decodes to the real name');
    assert.ok(!raw.includes('"mediator_admin_credential"'), 'and the plain name is not in the file');
    writeFileSync(join(r.volume, 'secrets.json'), raw);
    refused(run(r), 'u escape');
    writeFileSync(join(r.volume, 'secrets.json'), '{"entries":{"mediator_jwt_secret":"dGVzdA","x":"\\u0041"}}');
    refused(run(r), 'u escape');
  } finally { r.done(); }
});

test('entrypoint 12247.4: the conf must point the backend at exactly file://<volume>/secrets.json?encrypt=1', { skip: !haveTmpfs && 'no tmpfs' }, () => {
  const r = rig();
  try {
    refused(run(r, { medArgs: [] }), 'no mediator conf');
    const other = join(r.disk, 'other.toml');
    const bad = (body) => { writeFileSync(other, body); return run(r, { medArgs: ['-c', other] }); };
    refused(bad(`backend = "file://${r.disk}/decoy/secrets.json?encrypt=1"\n`), "conf's backend is not");
    refused(bad(`backend = "file://${r.volume}/secrets.json"\n`), "conf's backend is not");
    refused(bad(`backend = "file://${r.volume}/secrets.json?encrypt=1"\nbackend = "file://${r.disk}/x.json"\n`), 'exactly one file:// backend');
    refused(bad('backend = "redis"\n'), 'exactly one file:// backend');
    const link = join(r.disk, 'link.toml'); symlinkSync(r.conf, link);
    refused(run(r, { medArgs: ['-c', link] }), 'conf is a symlink');
    assert.equal(run(r, { medArgs: ['--config', r.conf] }).code, 0);
    assert.equal(run(r, { medArgs: [`--config=${r.conf}`] }).code, 0);
  } finally { r.done(); }
});

test('entrypoint 12346.1-2: a host name that is a glob or holds a newline refuses by count, never printed or expanded', { skip: !haveTmpfs && 'no tmpfs' }, () => {
  const r = rig();
  try {
    // a planted file under /dev/shm: on 1cb2a7a the glob name made the start line list it
    const bait = join(r.shm, 'bait-file-9q2'); writeFileSync(bait, '');
    const glob = run(r, { env: { [`${SHM}/*`]: 'x' } });
    refused(glob, "1 host names that aren't plain names");
    assert.doesNotMatch(glob.err, /bait-file-9q2|\/dev\/shm/);
    assert.doesNotMatch(glob.err, /entrypoint: env -i dropped/, 'no start line, the start refused');
    // a newline in a name: on 1cb2a7a it printed as three "names" and could forge a refusal line
    const nl = run(r, { env: { 'A\nrefused: forged': 'x' } });
    refused(nl, "1 host names that aren't plain names");
    assert.equal(nl.err.split('\n').filter((l) => l.startsWith('refused:')).length, 1, nl.err);
    assert.doesNotMatch(nl.err, /forged/);
    // two at once: the count is the number of names
    refused(run(r, { env: { [`${SHM}/*`]: 'x', 'B.c': 'y' } }), "2 host names that aren't plain names");
    // a shell-family name that is also a glob: refused as a shell name, the odd one withheld, nothing expanded
    const fn = run(r, { env: { [`BASH_FUNC_${SHM}/*%%`]: '() { :; }' } });
    refused(fn, 'change the shell or the loader: 1 not plain names \\(withheld\\)');
    assert.doesNotMatch(fn.err, /bait-file-9q2|\/dev\/shm/);
  } finally { r.done(); }
});

test('entrypoint 12346.1: set -f follows PATH, and no name list goes through an unquoted echo', () => {
  const code = readFileSync(EP, 'utf8').split('\n').filter((l) => l.trim() && !l.trim().startsWith('#'));
  assert.equal(code[0], 'PATH=/usr/bin:/bin; export PATH');
  assert.equal(code[1], 'set -f');
  assert.ok(!code.some((l) => /\$\(echo \$/.test(l)), 'no $(echo $list)');
});

test('entrypoint 12672.2: the conf must hold trust_task_verification = "enforce" as a typed literal, once, in [security]', { skip: !haveTmpfs && 'no tmpfs' }, () => {
  const r = rig();
  try {
    const other = join(r.disk, 'ttv.toml');
    const be = `[secrets]\nbackend = "file://${r.volume}/secrets.json?encrypt=1"\n`;
    const conf = (sec) => { writeFileSync(other, sec + be); return run(r, { medArgs: ['-c', other] }); };
    refused(conf('[security]\ntrust_task_verification = "warn"\n'), 'is not the literal');
    refused(conf('[security]\n'), 'exactly one line');
    refused(conf('[security]\ntrust_task_verification = "enforce"\ntrust_task_verification = "enforce"\n'), 'exactly one line');
    refused(conf('[security]\n"trust_task_verification" = "enforce"\n'), 'is not the literal');
    refused(conf("[security]\ntrust_task_verification = 'enforce'\n"), 'is not the literal');
    refused(conf('[security]\ntrust_task_verification = "${TRUST_TASK_VERIFICATION:enforce}"\n'), 'is not the literal');
    refused(conf('[security]\ntrust_task_verification = "enforce" # on\n'), 'is not the literal');
    refused(conf('[security]\nTrust_Task_Verification = "warn"\ntrust_task_verification = "enforce"\n'), 'exactly one line');
    refused(conf('security.trust_task_verification = "enforce"\n'), 'is not the literal');
    refused(conf('security = { trust_task_verification = "enforce" }\n'), 'is not the literal');
    refused(conf('[other]\ntrust_task_verification = "enforce"\n'), 'is not under \\[security\\]');
    refused(conf('[security.sub]\ntrust_task_verification = "enforce"\n'), 'is not under \\[security\\]');
    // a host TRUST_TASK_VERIFICATION refuses by the deny list, whatever the conf says
    refused(conf('[security]\ntrust_task_verification = "enforce"\n') && run(r, { env: { TRUST_TASK_VERIFICATION: 'warn' }, medArgs: ['-c', other] }), 'TRUST_TASK_VERIFICATION is set on the host');
    // green: setup's own shape at the pin (the template's comment names it, conf/mediator.toml:283)
    assert.equal(conf('[security]\n### Env: TRUST_TASK_VERIFICATION\n### warn | enforce\ntrust_task_verification = "enforce"\n').code, 0);
    // a commented-out second value still changes nothing; a comment can't hide a real second line
    refused(conf('[security]\n# trust_task_verification = "warn"\ntrust_task_verification = "enforce"\n[other]\ntrust_task_verification = "warn"\n'), 'exactly one');
    // green: the literal under [security], with spacing and other keys around it
    assert.equal(conf('[security]\nssl = "none"\n  trust_task_verification   =   "enforce"  \n').code, 0);
  } finally { r.done(); }
});

test('entrypoint 12892.3: a brace outside a comment refuses (a TOML 1.1 multi-line inline table can hide the key)', { skip: !haveTmpfs && 'no tmpfs' }, () => {
  const r = rig();
  try {
    const other = join(r.disk, 'brace.toml');
    const be = `[secrets]\nbackend = "file://${r.volume}/secrets.json?encrypt=1"\n`;
    const conf = (sec) => { writeFileSync(other, sec + be); return run(r, { medArgs: ['-c', other] }); };
    // Security's probe: the mediator reads security.x.trust_task_verification (unknown, ignored) and runs `warn`
    refused(conf('[security]\nx = {\ntrust_task_verification = "enforce"\n}\n'), 'brace outside a comment');
    // the real key present, an inline table elsewhere: still refused (fails closed)
    refused(conf('[security]\ntrust_task_verification = "enforce"\nextra = { a = 1 }\n'), 'brace outside a comment');
    refused(conf('[security]\ntrust_task_verification = "enforce"\n[other]\nt = {\n}\n'), 'brace outside a comment');
    // a brace in a trailing comment on a value line counts too
    refused(conf('[security]\ntrust_task_verification = "enforce"\nssl = "none" # {x}\n'), 'brace outside a comment');
    // green: braces in whole-line comments change nothing
    assert.equal(conf('[security]\n### e.g. ${TRUST_TASK_VERIFICATION:warn} or { a = 1 }\ntrust_task_verification = "enforce"\n').code, 0);
  } finally { r.done(); }
});

test('entrypoint 12795.2: a TOML multi-line string anywhere in the conf refuses (it can hide a line that reads as the key)', { skip: !haveTmpfs && 'no tmpfs' }, () => {
  const r = rig();
  try {
    const other = join(r.disk, 'ml.toml');
    const be = `[secrets]\nbackend = "file://${r.volume}/secrets.json?encrypt=1"\n`;
    const conf = (sec) => { writeFileSync(other, sec + be); return run(r, { medArgs: ['-c', other] }); };
    const DQ = '"""', SQ = "'''";
    // Security's probe: the real key absent, a string body that reads as it (accepted before this check)
    refused(conf(`[security]\nnote = ${DQ}\ntrust_task_verification = "enforce"\n${DQ}\n`), 'multi-line string \\(three double quotes\\)');
    refused(conf(`[security]\nnote = ${SQ}\ntrust_task_verification = "enforce"\n${SQ}\n`), 'multi-line string \\(three single quotes\\)');
    // the real key present too: still refused (fails closed)
    refused(conf(`[security]\ntrust_task_verification = "enforce"\nnote = ${DQ}x${DQ}\n`), 'multi-line string');
    refused(conf(`[security]\ntrust_task_verification = "enforce"\nnote = ${SQ}x${SQ}\n`), 'multi-line string');
    // in a comment line too
    refused(conf(`[security]\n# see ${DQ}\ntrust_task_verification = "enforce"\n`), 'multi-line string');
    // green: one or two quotes in a row are not caught
    assert.equal(conf(`[security]\nnote = "a \\"b\\" c"\nempty = ""\nlit = 'x'\nnone = ''\ntrust_task_verification = "enforce"\n`).code, 0);
  } finally { r.done(); }
});

// Security 12940 / 12519 (e): the kernel-keyring probe is the first stderr line of every start past the shell guards,
// one JSON line, under env -i and a short timeout, and it never gates the start. Run from a copy of the entrypoint
// with a fake probe beside it (the real probe is judged in the image on the job; its verdict there depends on the
// host's syscall filter, which is the thing measured).
function probeRig(r, body) {
  const d = join(r.disk, 'ep'); mkdirSync(d, { recursive: true });
  writeFileSync(join(d, 'mediator-entrypoint.sh'), readFileSync(EP)); chmodSync(join(d, 'mediator-entrypoint.sh'), 0o755);
  writeFileSync(join(d, 'mediator-deny.sha256'), `${BAKED}\n`);
  rmSync(join(d, 'keyring-probe'), { force: true });
  if (body !== null) { writeFileSync(join(d, 'keyring-probe'), body); chmodSync(join(d, 'keyring-probe'), 0o755); }
  return join(d, 'mediator-entrypoint.sh');
}
function runAt(ep, r, env = {}) {
  const res = spawnSync('/bin/bash', ['-p', ep, '--bin', r.med, '--volume', r.volume, '--tmpfs', r.shm, '--workdir', r.workdir, '--deny-file', r.deny, '--', '-c', r.conf],
    { encoding: 'utf8', env: { ...baseEnv, ...env } });
  return { code: res.status, out: res.stdout, err: res.stderr };
}
const echoProbe = (json) => `#!/bin/sh\nprintf '%s\\n' '${json}'\n`;

test('entrypoint 12940: the keyring probe is the first stderr line, one JSON line, and never gates the start', { skip: !haveTmpfs && 'no tmpfs' }, () => {
  const r = rig();
  try {
    const cases = [
      [echoProbe('{"uid":10001,"session":"refused","session_errno":"EPERM","user":"refused","user_errno":"EPERM"}'), 'refused', 'PASS'],
      [echoProbe('{"uid":10001,"session":"landed","session_removed":true,"user":"refused","user_errno":"EPERM"}'), 'landed', 'AMBER'],
      [echoProbe('{"uid":10001,"session":"landed","session_removed":false,"user":"landed","user_removed":true}'), 'probe_failed', 'FINDING'],
      // Security 13081.3: landed without its own _removed:true is not "landed and removed"
      [echoProbe('{"uid":0,"session":"landed","user":"landed"}'), 'probe_failed', 'FINDING'],
      [echoProbe('{"uid":10001,"session":"landed","session_removed":true,"user":"landed"}'), 'probe_failed', 'FINDING'],
      [echoProbe('{"uid":10001,"session":"refused","user":"landed","session_removed":true}'), 'probe_failed', 'FINDING'],
      [echoProbe('{"uid":10001,"session":"landed","session_removed":true,"user":"landed","user_removed":true}'), 'landed', 'AMBER'],
      [echoProbe('{"uid":10001,"session":"probe_failed","user":"refused","user_errno":"EPERM"}'), 'probe_failed', 'FINDING'],
      // a probe that tries to forge a second line, or prints anything but its own shape, is not embedded
      ['#!/bin/sh\nprintf \'{"uid":1,"session":"refused","user":"refused"}\\nrefused: forged\\n\'\n', 'probe_failed', 'FINDING'],
      ['#!/bin/sh\nexit 3\n', 'probe_failed', 'FINDING'],
      [null, 'absent', 'FINDING'],
    ];
    for (const [body, verdict, l8] of cases) {
      const x = runAt(probeRig(r, body), r);
      assert.equal(x.code, 0, `${verdict}: the start goes on: ${x.err}`);
      const first = JSON.parse(x.err.split('\n')[0]);
      assert.equal(first.entrypoint, 'keyring_probe');
      assert.equal(first.verdict, verdict, x.err);
      assert.equal(first.l8, l8);
      assert.equal(x.err.split('\n').filter((l) => l.includes('keyring_probe')).length, 1);
      assert.doesNotMatch(x.err, /refused: forged/);
      assert.match(x.err, /entrypoint: env -i dropped/);
    }
    // the probe is handed no host name (env -i): a probe that lists its environment sees nothing of the host's (PWD is
    // the probe shell's own)
    const envProbe = '#!/bin/sh\nif /usr/bin/env | /usr/bin/grep -v "^PWD=" | /usr/bin/grep -q .; then exit 9; fi\nprintf \'%s\\n\' \'{"uid":10001,"session":"refused","user":"refused"}\'\n';
    const x = runAt(probeRig(r, envProbe), r, { WPI_HOST_EXTRA: 'planted-value-7f3' });
    assert.equal(JSON.parse(x.err.split('\n')[0]).verdict, 'refused', x.err);
    // a refusal later in the script still comes after the probe line
    const y = runAt(probeRig(r, echoProbe('{"uid":10001,"session":"refused","user":"refused"}')), r, { MEDIATOR_TAG_REGION: 'x' });
    assert.equal(y.code, 78);
    assert.equal(JSON.parse(y.err.split('\n')[0]).verdict, 'refused');
    assert.match(y.err.split('\n')[1], /^refused: MEDIATOR_TAG_/);
  } finally { r.done(); }
});

test('entrypoint 12940: a probe that hangs is cut by the timeout and reads probe_failed; the start goes on', { skip: !haveTmpfs && 'no tmpfs' }, () => {
  const r = rig();
  try {
    const t0 = Date.now();
    const x = runAt(probeRig(r, '#!/bin/sh\nexec /usr/bin/sleep 60\n'), r);
    assert.ok(Date.now() - t0 < 15000, 'cut by the timeout');
    assert.equal(x.code, 0, x.err);
    const first = JSON.parse(x.err.split('\n')[0]);
    assert.equal(first.verdict, 'probe_failed'); assert.equal(first.exit, 124);
  } finally { r.done(); }
});
