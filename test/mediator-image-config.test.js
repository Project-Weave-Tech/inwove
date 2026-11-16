// Security 11935: the rekey image's config record, on made-up `docker image inspect` records. The rekey image's Env,
// Entrypoint, Cmd, User and WorkingDir must be the pinned base's plus the hand half (the Dockerfile's own lines), exact
// both ways; nothing is inherited that a Dockerfile line could hide. Each disguise must turn the named line red.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { configVerdict, instrument, makeChain, chainVerdict, BLOB_FIELDS, PLANT_LAYERS } from '../sandbox/tsp-tests/mediator-image-config.mjs';
import { parseRef, amd64Descriptor } from '../sandbox/tsp-tests/mediator-base-fetch.mjs';

const DIR = new URL('../sandbox/tsp-tests/', import.meta.url).pathname;
const ID = 'sha256:' + 'ab'.repeat(32);
const ENV = ['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'NODE_VERSION=22.11.0', 'YARN_VERSION=1.22.22'];
const EP = ['/bin/bash', '-p', '/opt/rekey/rekey-entrypoint.sh'];
const baseRec = (over = {}, top = {}) => [{ Id: ID, Architecture: 'amd64', Os: 'linux', RootFS: { Type: 'layers', Layers: [...PLANT_LAYERS] }, Config: { Env: [...ENV], Entrypoint: ['docker-entrypoint.sh'], Cmd: ['node'], User: '', WorkingDir: '', ...over }, ...top }];
const rekeyRec = (over = {}) => [{ Config: { Env: [...ENV], Entrypoint: EP, Cmd: null, User: '1000:1000', WorkingDir: '', ...over } }];
const HAND = { base_manifest_digest: 'VERIFY', base_config_digest: 'VERIFY', user: '1000:1000', entrypoint: EP, cmd: null, env: {} };
// The registry chain is made from the base record's own Config unless a test hands one in; the FROM line names its index.
const DFT = (idx) => ['# a comment', `FROM node:22-bookworm-slim@${idx}`, 'USER 1000:1000', `ENTRYPOINT ${JSON.stringify(EP)}`, ''].join('\n');
const C0 = makeChain(baseRec()[0].Config);
const DF = DFT(C0.indexDigest);
const run = (o = {}) => {
  const base = o.base ?? baseRec();
  const c = o.chain ?? makeChain(base[0].Config);
  const df = (o.df ?? DF).replace(C0.indexDigest, c.indexDigest);
  return configVerdict(o.rekey ?? rekeyRec(), base, o.hand ?? HAND, df, c.chain);
};
const PINNED = { ...HAND, base_manifest_digest: C0.manifestDigest, base_config_digest: C0.configDigest };
const lines = (v) => Object.fromEntries(Object.entries(v.checks).filter(([, x]) => x !== 'PASS'));

test('config: a clean pair passes every line except the two digest pins, STOP while VERIFY, carrying the chain\'s digests (never inspect\'s Id)', () => {
  const v = run();
  assert.deepEqual(lines(v), { base_manifest_digest_pinned: 'STOP', base_config_digest_pinned: 'STOP' });
  assert.equal(v.ok, false);
  assert.equal(v.base_manifest_digest_read, C0.manifestDigest);
  assert.equal(v.base_config_digest_read, C0.configDigest);
  assert.equal(v.base_inspect_id, ID, 'inspect Id is printed as evidence only');
  assert.deepEqual(v.base_platform, { Architecture: 'amd64', Os: 'linux' });
  assert.deepEqual(v.base_half, { Env: ENV, Entrypoint: ['docker-entrypoint.sh'], Cmd: ['node'], User: '', WorkingDir: '' });
});

test('config: pins equal to the chain\'s digests pass every line; a different pin, or the inspect Id as the config pin, is FAIL', () => {
  const v = run({ hand: PINNED });
  assert.deepEqual(lines(v), {});
  assert.equal(v.ok, true);
  assert.equal(run({ hand: { ...PINNED, base_config_digest: 'sha256:other' } }).checks.base_config_digest_pinned, 'FAIL');
  assert.equal(run({ hand: { ...PINNED, base_config_digest: ID } }).checks.base_config_digest_pinned, 'FAIL');
  assert.equal(run({ hand: { ...PINNED, base_manifest_digest: C0.indexDigest } }).checks.base_manifest_digest_pinned, 'FAIL');
  assert.deepEqual(v.hand_keys, ['cmd', 'entrypoint', 'env', 'user'], 'the pins are not hand-half config lines');
});

// Security 12197.2 (a)-(b), Railroad 12183.1: every hash in the chain is checked here, and inspect is tied to the blob.
test('chain: index bytes that are not the FROM pin, or a missing index, are red', () => {
  const c = makeChain(baseRec()[0].Config);
  const other = makeChain({ ...baseRec()[0].Config, Cmd: ['x'] });
  assert.equal(chainVerdict(c.chain, other.indexDigest, baseRec()[0].Config).checks.base_index_is_the_from_pin, 'FAIL');
  assert.equal(chainVerdict({ ...c.chain, index: null }, c.indexDigest, baseRec()[0].Config).checks.base_index_is_the_from_pin, 'FAIL');
  assert.equal(chainVerdict(c.chain, null, baseRec()[0].Config).checks.base_index_is_the_from_pin, 'FAIL');
  // a Dockerfile whose FROM line carries no digest has no pin to check against
  assert.equal(run({ df: DF.replace(/@sha256:[0-9a-f]+/, '') }).checks.base_index_is_the_from_pin, 'FAIL');
});

test('chain: no linux/amd64 manifest, two of them, or only a variant one, is red', () => {
  assert.equal(amd64Descriptor({ manifests: [{ platform: { os: 'linux', architecture: 'arm64' } }] }), null);
  assert.equal(amd64Descriptor({ manifests: [{ platform: { os: 'linux', architecture: 'amd64', variant: 'v3' } }] }), null);
  const two = makeChain(baseRec()[0].Config, { extraManifests: [{ digest: 'sha256:' + 'cd'.repeat(32), platform: { os: 'linux', architecture: 'amd64' } }] });
  const v = chainVerdict(two.chain, two.indexDigest, baseRec()[0].Config);
  assert.equal(v.checks.base_one_linux_amd64_manifest_matches_its_descriptor, 'FAIL');
  assert.equal(v.config_digest_read, null);
  // attestation manifests (platform unknown/unknown) beside the one amd64 manifest are fine
  const att = makeChain(baseRec()[0].Config, { extraManifests: [{ digest: 'sha256:' + 'ef'.repeat(32), platform: { os: 'unknown', architecture: 'unknown' } }] });
  assert.deepEqual(Object.values(chainVerdict(att.chain, att.indexDigest, baseRec()[0].Config, PLANT_LAYERS).checks), ['PASS', 'PASS', 'PASS', 'PASS', 'PASS']);
});

test('chain: a manifest or config blob whose bytes differ from what names it is red', () => {
  const c = makeChain(baseRec()[0].Config);
  const flip = (b) => { const x = Buffer.from(b); x[x.length - 2] ^= 1; return x; };
  const m = chainVerdict({ ...c.chain, manifest: flip(c.chain.manifest) }, c.indexDigest, baseRec()[0].Config);
  assert.equal(m.checks.base_one_linux_amd64_manifest_matches_its_descriptor, 'FAIL');
  const b = chainVerdict({ ...c.chain, config: flip(c.chain.config) }, c.indexDigest, baseRec()[0].Config);
  assert.equal(b.checks.base_config_blob_matches_the_manifest, 'FAIL');
  assert.equal(b.checks.base_inspect_equals_the_config_blob, 'FAIL', 'no blob, no tie');
  const none = chainVerdict({ ...c.chain, config: null }, c.indexDigest, baseRec()[0].Config);
  assert.equal(none.checks.base_config_blob_matches_the_manifest, 'FAIL');
  const arm = makeChain(baseRec()[0].Config, { arch: 'arm64' });
  assert.equal(chainVerdict(arm.chain, arm.indexDigest, baseRec()[0].Config).checks.base_config_blob_matches_the_manifest, 'FAIL');
});

test('chain: inspect that differs from the pinned blob in any one field is red, naming the field; absent and null read alike', () => {
  const blobCfg = { ...baseRec()[0].Config };
  const c = makeChain(blobCfg);
  const diff = { Env: [...ENV, 'X=1'], Entrypoint: ['x'], Cmd: [], User: 'root', WorkingDir: '/w', ExposedPorts: { '80/tcp': {} },
    Healthcheck: { Test: ['NONE'] }, OnBuild: ['RUN x'], Volumes: { '/v': {} } };
  assert.deepEqual(Object.keys(diff).sort(), [...BLOB_FIELDS].sort());
  for (const [k, val] of Object.entries(diff)) {
    const v = chainVerdict(c.chain, c.indexDigest, { ...blobCfg, [k]: val });
    assert.equal(v.checks.base_inspect_equals_the_config_blob, 'FAIL', k);
    assert.deepEqual(v.inspect_vs_blob_differ, [k]);
  }
  const loose = chainVerdict(c.chain, c.indexDigest, { ...blobCfg, Volumes: null, OnBuild: null, User: undefined });
  assert.equal(loose.checks.base_inspect_equals_the_config_blob, 'PASS');
  const emptyList = makeChain({ ...blobCfg, Cmd: null });
  assert.equal(chainVerdict(emptyList.chain, emptyList.indexDigest, { ...blobCfg, Cmd: [] }).checks.base_inspect_equals_the_config_blob, 'FAIL', 'null and [] differ');
});

// Security 12278.5 (change C): inspect's RootFS.Layers is tied to the pinned blob's rootfs.diff_ids, same values,
// same order, so base.tar (the base side of the file-by-file diff) comes from the pinned bytes too.
test('chain: inspect layers that differ from the blob\'s diff_ids in one digest, in order, in count, or are absent, are red', () => {
  const c = makeChain(baseRec()[0].Config);
  const lay = (layers) => chainVerdict(c.chain, c.indexDigest, baseRec()[0].Config, layers).checks.base_inspect_layers_equal_the_blob;
  assert.equal(lay([...PLANT_LAYERS]), 'PASS');
  assert.equal(lay([PLANT_LAYERS[0], 'sha256:' + '33'.repeat(32)]), 'FAIL', 'one diff_id changed');
  assert.equal(lay([...PLANT_LAYERS].reverse()), 'FAIL', 'same values, other order');
  assert.equal(lay([PLANT_LAYERS[0]]), 'FAIL', 'a layer missing');
  assert.equal(lay([...PLANT_LAYERS, 'sha256:' + '44'.repeat(32)]), 'FAIL', 'a layer extra');
  assert.equal(lay(undefined), 'FAIL', 'inspect without RootFS');
  const empty = makeChain(baseRec()[0].Config, { diffIds: [] });
  assert.equal(chainVerdict(empty.chain, empty.indexDigest, baseRec()[0].Config, []).checks.base_inspect_layers_equal_the_blob, 'FAIL', 'no layers on either side is no tie');
  const flip = (b) => { const x = Buffer.from(b); x[x.length - 2] ^= 1; return x; };
  assert.equal(chainVerdict({ ...c.chain, config: flip(c.chain.config) }, c.indexDigest, baseRec()[0].Config, PLANT_LAYERS).checks.base_inspect_layers_equal_the_blob, 'FAIL', 'no blob, no tie');
  // through configVerdict: the base record's RootFS.Layers is what is compared, and only the layers line goes red
  const v = run({ hand: PINNED, base: baseRec({}, { RootFS: { Type: 'layers', Layers: [PLANT_LAYERS[0], 'sha256:' + '33'.repeat(32)] } }) });
  assert.deepEqual(lines(v), { base_inspect_layers_equal_the_blob: 'FAIL' });
  assert.equal(v.details.inspect_layers, 2);
  assert.equal(v.details.blob_diff_ids, 2);
  assert.equal(instrument().store_answers_other_layers_red, true);
});

test('fetch: the base ref parses to a Docker Hub repository and its index digest; anything else is refused', () => {
  const d = 'sha256:' + 'e9'.repeat(32);
  assert.deepEqual(parseRef(`node:22-bookworm-slim@${d}`), { repo: 'library/node', digest: d });
  assert.deepEqual(parseRef(`docker.io/library/node@${d}`), { repo: 'library/node', digest: d });
  assert.equal(parseRef('node:22-bookworm-slim'), null);
  assert.equal(parseRef(`ghcr.io:443/x@${d}`), null);
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
  assert.deepEqual(instrument(), { bites: true, extra_base_variable_red: true, node_options_red: true, store_answers_other_config_red: true, store_answers_other_layers_red: true });
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

test('config CLI: the real rekey-config.json carries Security 12278.2\'s pins; a VERIFY half prints STOP twice, carries the chain\'s digests, and exits nonzero until pinned', () => {
  const d = mkdtempSync(join(tmpdir(), 'cfg-'));
  try {
    const real = JSON.parse(readFileSync(join(DIR, 'rekey-config.json'), 'utf8'));
    assert.equal(real.base_manifest_digest, 'sha256:47725aca53d3295ec2d3be8f62726599b3033cc262edc2c7e429909b3ac599fc');
    assert.equal(real.base_config_digest, 'sha256:b774d993885c47eca14db241ba8cc7e5789235142f76e4a2a6a65ec350a1bac0');
    const hand = { ...real, base_manifest_digest: 'VERIFY', base_config_digest: 'VERIFY' };
    const w = (n, o) => { const f = join(d, n); writeFileSync(f, typeof o === 'string' || Buffer.isBuffer(o) ? o : JSON.stringify(o)); return f; };
    const ch = join(d, 'chain'); mkdirSync(ch);
    for (const [n, b] of [['index.raw', C0.chain.index], ['manifest.raw', C0.chain.manifest], ['config.raw', C0.chain.config]]) writeFileSync(join(ch, n), b);
    const args = (h, chainDir = ch) => [join(DIR, 'mediator-image-config.mjs'), w('rk.json', rekeyRec()), w('b.json', baseRec()), w('h.json', h), w('Dockerfile', DF), chainDir, join(d, 'out.json')];
    let r = spawnSync('node', args(hand), { encoding: 'utf8' });
    assert.equal(r.status, 1, r.stderr);
    let out = JSON.parse(readFileSync(join(d, 'out.json'), 'utf8'));
    assert.equal(out.checks.instrument_bites, 'PASS');
    assert.equal(out.checks.base_config_digest_pinned, 'STOP');
    assert.equal(out.checks.base_manifest_digest_pinned, 'STOP');
    assert.equal(out.base_config_digest_read, C0.configDigest);
    assert.equal(out.base_manifest_digest_read, C0.manifestDigest);
    r = spawnSync('node', args({ ...hand, base_manifest_digest: C0.manifestDigest, base_config_digest: C0.configDigest }), { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    out = JSON.parse(readFileSync(join(d, 'out.json'), 'utf8'));
    assert.equal(out.ok, true);
    assert.deepEqual(Object.keys(out), ['what', 'ok', 'checks', 'instrument', 'base_manifest_digest_read', 'base_config_digest_read', 'base_inspect_id', 'base_platform', 'base_half', 'hand_keys', 'details']);
    // a chain dir the fetch never filled: red, never a pass
    r = spawnSync('node', args({ ...hand, base_manifest_digest: C0.manifestDigest, base_config_digest: C0.configDigest }, join(d, 'nope')), { encoding: 'utf8' });
    assert.equal(r.status, 1);
    assert.equal(JSON.parse(readFileSync(join(d, 'out.json'), 'utf8')).checks.base_index_is_the_from_pin, 'FAIL');
  } finally { rmSync(d, { recursive: true, force: true }); }
});
