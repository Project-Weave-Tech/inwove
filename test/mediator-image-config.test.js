// Security 11935: the rekey image's config record, on made-up `docker image inspect` records. The rekey image's Env,
// Entrypoint, Cmd, User and WorkingDir must be the pinned base's plus the hand half (the Dockerfile's own lines), exact
// both ways; nothing is inherited that a Dockerfile line could hide. Each disguise must turn the named line red.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { configVerdict, instrument } from '../sandbox/tsp-tests/mediator-image-config.mjs';

const DIR = new URL('../sandbox/tsp-tests/', import.meta.url).pathname;
const ID = 'sha256:' + 'ab'.repeat(32);
const ENV = ['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'NODE_VERSION=22.11.0', 'YARN_VERSION=1.22.22'];
const EP = ['/bin/bash', '-p', '/opt/rekey/rekey-entrypoint.sh'];
const baseRec = (over = {}, top = {}) => [{ Id: ID, Architecture: 'amd64', Os: 'linux', Config: { Env: [...ENV], Entrypoint: ['docker-entrypoint.sh'], Cmd: ['node'], User: '', WorkingDir: '', ...over }, ...top }];
const rekeyRec = (over = {}) => [{ Config: { Env: [...ENV], Entrypoint: EP, Cmd: null, User: '1000:1000', WorkingDir: '', ...over } }];
const HAND = { base_config_digest: 'VERIFY', user: '1000:1000', entrypoint: EP, cmd: null, env: {} };
const DF = ['# a comment', 'FROM node:22-bookworm-slim@sha256:e9f5', 'USER 1000:1000', `ENTRYPOINT ${JSON.stringify(EP)}`, ''].join('\n');
const run = (o = {}) => configVerdict(o.rekey ?? rekeyRec(), o.base ?? baseRec(), o.hand ?? HAND, o.df ?? DF);
const lines = (v) => Object.fromEntries(Object.entries(v.checks).filter(([, x]) => x !== 'PASS'));

test('config: a clean pair passes every line except the digest pin, which is STOP while VERIFY and carries the read Id', () => {
  const v = run();
  assert.deepEqual(lines(v), { base_config_digest_pinned: 'STOP' });
  assert.equal(v.ok, false);
  assert.equal(v.base_config_digest_read, ID);
  assert.deepEqual(v.base_platform, { Architecture: 'amd64', Os: 'linux' });
  assert.deepEqual(v.base_half, { Env: ENV, Entrypoint: ['docker-entrypoint.sh'], Cmd: ['node'], User: '', WorkingDir: '' });
});

test('config: the pin equal to the read Id passes every line; a different pin is FAIL', () => {
  const v = run({ hand: { ...HAND, base_config_digest: ID } });
  assert.deepEqual(lines(v), {});
  assert.equal(v.ok, true);
  assert.equal(run({ hand: { ...HAND, base_config_digest: 'sha256:other' } }).checks.base_config_digest_pinned, 'FAIL');
});

test('config: an extra base variable the rekey Env lacks, and an extra rekey variable, are red (names only)', () => {
  const v = run({ base: baseRec({ Env: [...ENV, 'EXTRA_BASE=secretish'] }) });
  assert.equal(v.checks.env_exact_both_ways, 'FAIL');
  assert.deepEqual(v.details.env_missing, ['EXTRA_BASE']);
  assert.ok(!JSON.stringify(v.details).includes('secretish'));
  const w = run({ rekey: rekeyRec({ Env: [...ENV, 'FOO=bar'] }) });
  assert.equal(w.checks.env_exact_both_ways, 'FAIL');
  assert.deepEqual(w.details.env_extra, ['FOO']);
});

test('config: NODE_OPTIONS added without the hand half is red, and the built-in instrument bites on both planted cases', () => {
  const v = run({ rekey: rekeyRec({ Env: [...ENV, 'NODE_OPTIONS=--require /x'] }) });
  assert.equal(v.checks.env_exact_both_ways, 'FAIL');
  assert.deepEqual(v.details.env_extra, ['NODE_OPTIONS']);
  assert.ok(!JSON.stringify(v).includes('/x'));
  assert.deepEqual(instrument(), { bites: true, extra_base_variable_red: true, node_options_red: true });
});

test('config: a base variable whose value changed without the hand half (PATH) is red; a duplicate name is red', () => {
  const v = run({ rekey: rekeyRec({ Env: ['PATH=/tmp:/usr/bin', ENV[1], ENV[2]] }) });
  assert.equal(v.checks.env_exact_both_ways, 'FAIL');
  assert.deepEqual(v.details.env_changed, ['PATH']);
  const d = run({ rekey: rekeyRec({ Env: [...ENV, 'NODE_VERSION=1'] }) });
  assert.equal(d.checks.env_exact_both_ways, 'FAIL');
  assert.deepEqual(d.details.env_duplicate, ['NODE_VERSION']);
});

test('config: a hand-half env override applied on top passes when an ENV line backs it; one with no ENV line is red', () => {
  const hand = { ...HAND, env: { NODE_ENV: 'production' } };
  const rekey = rekeyRec({ Env: [...ENV, 'NODE_ENV=production'] });
  const ok = run({ hand, rekey, df: `${DF}ENV NODE_ENV=production\n` });
  assert.equal(ok.checks.env_exact_both_ways, 'PASS');
  assert.equal(ok.checks.hand_half_backed_by_dockerfile, 'PASS');
  assert.equal(run({ hand, rekey, df: `${DF}ENV NODE_ENV production\n` }).checks.hand_half_backed_by_dockerfile, 'PASS');
  const no = run({ hand, rekey });
  assert.equal(no.checks.hand_half_backed_by_dockerfile, 'FAIL');
  assert.deepEqual(no.details.hand_not_backed, ['env:NODE_ENV']);
  assert.equal(run({ hand, rekey, df: `${DF}# ENV NODE_ENV=production\n` }).checks.hand_half_backed_by_dockerfile, 'FAIL');
  // a changed base value named by the hand half is fine on the env line
  const path = run({ hand: { ...HAND, env: { PATH: '/x' } }, rekey: rekeyRec({ Env: ['PATH=/x', ENV[1], ENV[2]] }), df: `${DF}ENV PATH=/x\n` });
  assert.equal(path.checks.env_exact_both_ways, 'PASS');
});

test('config: a hand-half entry that restates a base value unchanged is red', () => {
  const env = run({ hand: { ...HAND, env: { NODE_VERSION: '22.11.0' } }, df: `${DF}ENV NODE_VERSION=22.11.0\n` });
  assert.equal(env.checks.hand_half_restates_no_base_value, 'FAIL');
  assert.deepEqual(env.details.hand_restates_base, ['env:NODE_VERSION']);
  const user = run({ base: baseRec({ User: '1000:1000' }) });
  assert.equal(user.checks.hand_half_restates_no_base_value, 'FAIL');
  const ep = run({ base: baseRec({ Entrypoint: EP }) });
  assert.equal(ep.checks.hand_half_restates_no_base_value, 'FAIL');
  const wd = run({ hand: { ...HAND, workdir: '/app' }, base: baseRec({ WorkingDir: '/app' }), rekey: rekeyRec({ WorkingDir: '/app' }), df: `${DF}WORKDIR /app\n` });
  assert.equal(wd.checks.hand_half_restates_no_base_value, 'FAIL');
});

test('config: Entrypoint, Cmd, User and WorkingDir equal the base unless overridden; null and [] differ', () => {
  assert.equal(run({ rekey: rekeyRec({ Entrypoint: ['docker-entrypoint.sh'] }) }).checks.entrypoint_exact, 'FAIL');
  assert.equal(run({ rekey: rekeyRec({ Cmd: [] }) }).checks.cmd_exact, 'FAIL');
  assert.equal(run({ rekey: rekeyRec({ Cmd: ['node'] }) }).checks.cmd_exact, 'FAIL');
  assert.equal(run({ rekey: rekeyRec({ User: '' }) }).checks.user_exact, 'FAIL');
  assert.equal(run({ rekey: rekeyRec({ WorkingDir: '/tmp' }) }).checks.workdir_exact, 'FAIL');
  // no override for a key: it must equal the base (here the hand half has no workdir, base ''), and a cmd with no override inherits ['node']
  const { cmd: _c, ...noCmd } = HAND;
  const inherit = run({ hand: noCmd, df: `FROM x\nUSER 1000:1000\nENTRYPOINT ${JSON.stringify(EP)}\n`, rekey: rekeyRec({ Cmd: ['node'] }) });
  assert.equal(inherit.checks.cmd_exact, 'PASS');
});

test('config: ExposedPorts, Healthcheck, OnBuild or Volumes on the rekey image, or on the base, is red', () => {
  const bad = { ExposedPorts: { '80/tcp': {} }, Healthcheck: { Test: ['CMD', 'true'] }, OnBuild: ['RUN x'], Volumes: { '/v': {} } };
  for (const [k, val] of Object.entries(bad)) {
    assert.equal(run({ rekey: rekeyRec({ [k]: val }) }).checks.rekey_has_no_volumes_ports_healthcheck_onbuild, 'FAIL', `rekey ${k}`);
    const b = run({ base: baseRec({ [k]: val }) });
    assert.equal(b.checks.base_has_no_volumes_ports_healthcheck_onbuild, 'FAIL', `base ${k}`);
    assert.deepEqual(b.details.base_has, [k]);
  }
  for (const empty of [null, {}, []]) assert.equal(run({ rekey: rekeyRec({ Volumes: empty, OnBuild: empty }) }).checks.rekey_has_no_volumes_ports_healthcheck_onbuild, 'PASS');
});

test('config: a base that is not linux/amd64 is red', () => {
  assert.equal(run({ base: baseRec({}, { Architecture: 'arm64' }) }).checks.base_platform_linux_amd64, 'FAIL');
  assert.equal(run({ base: baseRec({}, { Os: 'windows' }) }).checks.base_platform_linux_amd64, 'FAIL');
});

test('config: hand-half user, workdir, entrypoint and cmd need their Dockerfile lines; cmd null needs ENTRYPOINT and no CMD', () => {
  const bk = (df, hand = HAND, rekey) => run({ df, hand, rekey }).checks.hand_half_backed_by_dockerfile;
  assert.equal(bk('FROM x\n'), 'FAIL');
  assert.equal(bk(`FROM x\nUSER 1000:1000\nENTRYPOINT ${JSON.stringify(EP)}\n`), 'PASS');
  assert.equal(bk(`FROM x\nUSER 1001\nENTRYPOINT ${JSON.stringify(EP)}\n`), 'FAIL');
  assert.equal(bk(`FROM x\nUSER 1000:1000\nENTRYPOINT /bin/bash -p x\n`), 'FAIL'); // shell form is not exec form
  assert.equal(bk(`FROM x\nUSER 1000:1000\nENTRYPOINT ${JSON.stringify(EP)}\nCMD ["x"]\n`), 'FAIL'); // cmd null, but a CMD line exists
  // cmd override: not backed by CMD while ENTRYPOINT is absent
  const noEp = { user: '1000:1000', cmd: null, env: {} };
  const v = run({ hand: noEp, df: 'FROM x\nUSER 1000:1000\n', rekey: rekeyRec({ Entrypoint: ['docker-entrypoint.sh'], Cmd: null }) });
  assert.equal(v.checks.hand_half_backed_by_dockerfile, 'FAIL');
  assert.deepEqual(v.details.hand_not_backed, ['cmd']);
  // cmd override with its CMD line
  const withCmd = run({ hand: { ...noEp, cmd: ['sh'] }, df: 'FROM x\nUSER 1000:1000\nCMD ["sh"]\n', rekey: rekeyRec({ Entrypoint: ['docker-entrypoint.sh'], Cmd: ['sh'] }) });
  assert.equal(withCmd.checks.hand_half_backed_by_dockerfile, 'PASS');
  // a workdir override
  const w = run({ hand: { ...HAND, workdir: '/opt/rekey' }, rekey: rekeyRec({ WorkingDir: '/opt/rekey' }), df: `${DF}WORKDIR /opt/rekey\n` });
  assert.equal(w.checks.hand_half_backed_by_dockerfile, 'PASS');
  assert.equal(w.checks.workdir_exact, 'PASS');
  // an unknown hand key is not a Dockerfile line
  assert.equal(bk(DF, { ...HAND, labels: {} }), 'FAIL');
});

test('config CLI: the real rekey-config.json is the VERIFY half; the run prints STOP, carries the read Id, and exits nonzero until pinned', () => {
  const d = mkdtempSync(join(tmpdir(), 'cfg-'));
  try {
    const hand = JSON.parse(readFileSync(join(DIR, 'rekey-config.json'), 'utf8'));
    assert.equal(hand.base_config_digest, 'VERIFY');
    const w = (n, o) => { const f = join(d, n); writeFileSync(f, typeof o === 'string' ? o : JSON.stringify(o)); return f; };
    const args = (h) => [join(DIR, 'mediator-image-config.mjs'), w('rk.json', rekeyRec()), w('b.json', baseRec()), w('h.json', h), w('Dockerfile', DF), join(d, 'out.json')];
    let r = spawnSync('node', args(hand), { encoding: 'utf8' });
    assert.equal(r.status, 1, r.stderr);
    let out = JSON.parse(readFileSync(join(d, 'out.json'), 'utf8'));
    assert.equal(out.checks.instrument_bites, 'PASS');
    assert.equal(out.checks.base_config_digest_pinned, 'STOP');
    assert.equal(out.base_config_digest_read, ID);
    r = spawnSync('node', args({ ...hand, base_config_digest: ID }), { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    out = JSON.parse(readFileSync(join(d, 'out.json'), 'utf8'));
    assert.equal(out.ok, true);
    assert.deepEqual(Object.keys(out), ['what', 'ok', 'checks', 'instrument', 'base_config_digest_read', 'base_platform', 'base_half', 'hand_keys', 'details']);
  } finally { rmSync(d, { recursive: true, force: true }); }
});
