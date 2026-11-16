#!/usr/bin/env node
// The rekey image's config record (Security 11935). The filesystem lines judge what the image holds; this one judges
// what it RUNS WITH: the Env, Entrypoint, Cmd, User and WorkingDir `docker image inspect` reports, which a Dockerfile
// can change with one line (NODE_OPTIONS=--require /x, a new ENTRYPOINT) without touching a single file. So the rekey
// image's config is judged against the pinned base image's config, exact both ways, and the only difference allowed is
// the hand half (rekey-config.json), which must itself be nothing but the Dockerfile's own lines:
//
//   (a) by digest and platform (Security 12197.2, Railroad 12183.1, Security 12232.1): the base's config digest is read
//       from the registry chain the pin names, never from inspect's `.Id` (on this runner's containerd store that is
//       the INDEX digest; it is printed as base_inspect_id, evidence only). mediator-base-fetch.mjs writes the raw
//       index, the one linux/amd64 manifest and its config blob; chainVerdict checks the index's sha256 is the FROM
//       line's digest, picks the one linux/amd64 manifest (no variant), checks that manifest's own sha256 (and size)
//       against its descriptor, takes its config.digest, checks the config blob's sha256 against it, and ties the
//       inspect read to those bytes: the blob's config Env/Entrypoint/Cmd/User/WorkingDir/ExposedPorts/Healthcheck/
//       OnBuild/Volumes must equal inspect's (absent and null read alike; null and [] differ). Any mismatch, or a
//       blob that was not fetched, is FAIL. `base_manifest_digest` and `base_config_digest` in rekey-config.json are
//       pinned by Security from the first run it reads; while either is "VERIFY" its line reads STOP (neither PASS nor
//       FAIL) and the verdict carries base_manifest_digest_read / base_config_digest_read so it can be pinned. The base
//       must be linux/amd64 (pulled with --platform linux/amd64 by digest; the blob's own architecture/os too).
//   (b) exact both ways: the rekey Env, as a set of NAME=value strings with no duplicate name, must equal the base's Env
//       as read with each hand-half env entry applied on top (override or add). An extra variable, a missing one, or a
//       base variable whose value changed without the hand half naming it is FAIL (names listed, never values).
//       Entrypoint, Cmd, User and WorkingDir must equal the base's, or the hand half's override (entrypoint, cmd, user,
//       workdir) exactly, compared as JSON (null and [] differ).
//   (c) the hand half is only the Dockerfile's lines: every key must be backed by a matching instruction in the
//       Dockerfile text (ENV NAME=.. / ENV NAME .., USER, WORKDIR, exec-form ENTRYPOINT [..], CMD [..]; Docker semantics:
//       with an ENTRYPOINT line and no CMD line, `cmd: null` is allowed, since setting ENTRYPOINT resets the inherited
//       CMD), and must not restate a base value unchanged. Comment lines are ignored.
//   (d) Volumes, ExposedPorts, Healthcheck and OnBuild must be empty in the rekey config, and the BASE must have none
//       either (never inherited: a re-pinned base that gains one goes red).
//   (e) visible: the verdict carries base_half = {Env, Entrypoint, Cmd, User, WorkingDir} as read from the base (the base
//       image is public, so it is printed in full), beside the lines.
// The CLI first runs configVerdict on two planted cases (an extra variable in the base that the rekey Env lacks; a rekey
// Env that adds NODE_OPTIONS=--require /x that the hand half omits); both must FAIL on the env line, else the run fails
// (instrument_bites). Names, digests and verdicts only; the rekey image's own variable values are never printed.
//
//   mediator-image-config.mjs <rekey-inspect.json> <base-inspect.json> <rekey-config.json> <rekey Dockerfile> <base chain dir> <out.json>
// (<base chain dir> holds mediator-base-fetch.mjs's index.raw, manifest.raw and config.raw; the index pin is read from
// the Dockerfile's FROM line.)
// Exit 0 only when every line is PASS.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { amd64Descriptor } from './mediator-base-fetch.mjs';

const J = JSON.stringify;
const P = (ok) => (ok ? 'PASS' : 'FAIL');
const EMPTY_KEYS = ['Volumes', 'ExposedPorts', 'Healthcheck', 'OnBuild'];
const HAND_KEYS = ['what', 'base_manifest_digest', 'base_config_digest', 'env', 'user', 'workdir', 'entrypoint', 'cmd'];
const isEmpty = (v) => v == null || (Array.isArray(v) ? v.length === 0 : typeof v === 'object' ? Object.keys(v).length === 0 : v === '');
const cfg = (inspect) => (Array.isArray(inspect) ? inspect[0] : inspect) ?? {};
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

// The hand half's env as a Map NAME → value; accepts {NAME: value} or a list of such objects.
function handEnv(hand) {
  const m = new Map();
  for (const o of Array.isArray(hand.env) ? hand.env : [hand.env ?? {}]) for (const [k, v] of Object.entries(o)) m.set(k, String(v));
  return m;
}
const envMap = (list) => { const m = new Map(), dup = []; for (const kv of list || []) { const i = kv.indexOf('='); const k = i < 0 ? kv : kv.slice(0, i); if (m.has(k)) dup.push(k); m.set(k, i < 0 ? '' : kv.slice(i + 1)); } return { m, dup }; };

// The Dockerfile's instructions with comment lines dropped and continuation lines joined: [{op, args}].
export function instructions(text) {
  const lines = String(text).split(/\r?\n/).filter((l) => !/^\s*#/.test(l));
  const out = [];
  let cur = '';
  for (const l of lines) {
    cur += cur ? ` ${l.trim()}` : l.trim();
    if (/\\$/.test(cur)) { cur = cur.slice(0, -1).trimEnd(); continue; }
    const m = /^([A-Za-z]+)\s+([\s\S]*)$/.exec(cur);
    if (m) out.push({ op: m[1].toUpperCase(), args: m[2].trim() });
    cur = '';
  }
  return out;
}
const unquote = (s) => (/^"(.*)"$/s.test(s) ? s.slice(1, -1).replace(/\\(.)/g, '$1') : /^'(.*)'$/s.test(s) ? s.slice(1, -1) : s);
// NAME → value for every ENV instruction (both `ENV A=b C=d` and `ENV A b c`).
function dockerfileEnv(ins) {
  const m = new Map();
  for (const { op, args } of ins) {
    if (op !== 'ENV') continue;
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(args)) for (const x of args.matchAll(/([A-Za-z_][A-Za-z0-9_]*)=("(?:[^"\\]|\\.)*"|'[^']*'|\S*)/g)) m.set(x[1], unquote(x[2]));
    else { const x = /^(\S+)\s+([\s\S]*)$/.exec(args); if (x) m.set(x[1], unquote(x[2].trim())); }
  }
  return m;
}
const execForm = (args) => { try { const v = JSON.parse(args); return Array.isArray(v) && v.every((x) => typeof x === 'string') ? v : null; } catch { return null; } };

const sha = (b) => `sha256:${crypto.createHash('sha256').update(b).digest('hex')}`;
const parse = (b) => { try { return JSON.parse(Buffer.from(b).toString('utf8')); } catch { return null; } };
// The digest on the Dockerfile's first FROM line, or null.
export function fromDigest(dockerfileText) {
  const f = instructions(dockerfileText).find((i) => i.op === 'FROM');
  const m = f && /@(sha256:[0-9a-f]{64})(?:\s|$)/.exec(f.args);
  return m ? m[1] : null;
}
export const BLOB_FIELDS = ['Env', 'Entrypoint', 'Cmd', 'User', 'WorkingDir', 'ExposedPorts', 'Healthcheck', 'OnBuild', 'Volumes'];
const STR_FIELDS = ['User', 'WorkingDir'];
const blobNorm = (k, v) => (STR_FIELDS.includes(k) ? (v ?? '') : (v === undefined ? null : v));

// The registry chain (Security 12197.2 a-c). chain: {index, manifest, config} as Buffers (any may be missing);
// indexPin: the FROM line's digest; inspectConfig: base inspect's Config. Returns {checks, manifest_digest_read,
// config_digest_read, blob_platform, inspect_vs_blob_differ}.
export function chainVerdict(chain, indexPin, inspectConfig) {
  const c = chain ?? {};
  const indexOk = !!c.index && indexPin !== null && sha(c.index) === indexPin;
  const desc = indexOk ? amd64Descriptor(parse(c.index)) : null;
  const manifestOk = !!desc && !!c.manifest && sha(c.manifest) === desc.digest && (desc.size === undefined || desc.size === c.manifest.length);
  const cdesc = manifestOk ? parse(c.manifest)?.config : null;
  const configDigest = cdesc && /^sha256:[0-9a-f]{64}$/.test(String(cdesc.digest)) ? cdesc.digest : null;
  const blobOk = !!configDigest && !!c.config && sha(c.config) === configDigest && (cdesc.size === undefined || cdesc.size === c.config.length);
  const blob = blobOk ? parse(c.config) : null;
  const bc = blob?.config ?? {};
  const ic = inspectConfig ?? {};
  const differ = blob ? BLOB_FIELDS.filter((k) => J(blobNorm(k, bc[k])) !== J(blobNorm(k, ic[k]))) : BLOB_FIELDS;
  return {
    checks: {
      base_index_is_the_from_pin: P(indexOk),
      base_one_linux_amd64_manifest_matches_its_descriptor: P(manifestOk),
      base_config_blob_matches_the_manifest: P(blobOk && blob?.architecture === 'amd64' && blob?.os === 'linux'),
      base_inspect_equals_the_config_blob: P(!!blob && !differ.length),
    },
    manifest_digest_read: desc?.digest ?? null, config_digest_read: configDigest,
    blob_platform: blob ? { architecture: blob.architecture ?? null, os: blob.os ?? null } : null,
    inspect_vs_blob_differ: differ,
  };
}

// Returns {ok, checks, base_manifest_digest_read, base_config_digest_read, base_inspect_id, base_platform, base_half, hand_keys, details}.
export function configVerdict(rekeyInspect, baseInspect, hand, dockerfileText, chain = null) {
  const rb = baseInspect?.[0] ?? {}, rr = rekeyInspect?.[0] ?? {};
  const bc = rb.Config ?? {}, rc = rr.Config ?? {};
  hand = hand ?? {};
  const base_half = { Env: bc.Env ?? null, Entrypoint: bc.Entrypoint ?? null, Cmd: bc.Cmd ?? null, User: bc.User ?? '', WorkingDir: bc.WorkingDir ?? '' };
  // (a) the config digest is the chain's, never inspect's Id
  const ch = chainVerdict(chain, fromDigest(dockerfileText), bc);
  const pinned = (pin, read) => (pin === 'VERIFY' ? 'STOP' : P(typeof pin === 'string' && read !== null && pin === read));
  // (b) env
  const hEnv = handEnv(hand);
  const base = envMap(bc.Env), rek = envMap(rc.Env);
  const want = new Map(base.m); for (const [k, v] of hEnv) want.set(k, v);
  const extra = [...rek.m.keys()].filter((k) => !want.has(k)).sort();
  const missing = [...want.keys()].filter((k) => !rek.m.has(k)).sort();
  const changed = [...rek.m.keys()].filter((k) => want.has(k) && want.get(k) !== rek.m.get(k)).sort();
  const dup = [...new Set(rek.dup)].sort();
  const envOk = !extra.length && !missing.length && !changed.length && !dup.length;
  const field = (key, handKey, norm) => {
    const exp = has(hand, handKey) ? hand[handKey] : norm(bc[key]);
    return J(norm(rc[key])) === J(exp);
  };
  const nul = (v) => (v === undefined ? null : v);
  const str = (v) => v ?? '';
  // (c)
  const ins = instructions(dockerfileText);
  const ops = (op) => ins.filter((i) => i.op === op);
  const dfEnv = dockerfileEnv(ins);
  const problems = [];
  for (const k of Object.keys(hand)) if (!HAND_KEYS.includes(k)) problems.push(`unknown:${k}`);
  for (const [k, v] of hEnv) if (!dfEnv.has(k) || dfEnv.get(k) !== v) problems.push(`env:${k}`);
  if (has(hand, 'user') && !ops('USER').some((i) => i.args === hand.user)) problems.push('user');
  if (has(hand, 'workdir') && !ops('WORKDIR').some((i) => i.args === hand.workdir)) problems.push('workdir');
  if (has(hand, 'entrypoint') && !ops('ENTRYPOINT').some((i) => execForm(i.args) && J(execForm(i.args)) === J(hand.entrypoint))) problems.push('entrypoint');
  if (has(hand, 'cmd')) {
    const backed = hand.cmd === null ? ops('ENTRYPOINT').length > 0 && ops('CMD').length === 0 : ops('CMD').some((i) => execForm(i.args) && J(execForm(i.args)) === J(hand.cmd));
    if (!backed) problems.push('cmd');
  }
  const restated = [];
  for (const [k, v] of hEnv) if (base.m.get(k) === v) restated.push(`env:${k}`);
  if (has(hand, 'user') && J(hand.user) === J(str(bc.User))) restated.push('user');
  if (has(hand, 'workdir') && J(hand.workdir) === J(str(bc.WorkingDir))) restated.push('workdir');
  if (has(hand, 'entrypoint') && J(hand.entrypoint) === J(nul(bc.Entrypoint))) restated.push('entrypoint');
  if (has(hand, 'cmd') && J(hand.cmd) === J(nul(bc.Cmd))) restated.push('cmd');
  // (d)
  const rekeyHas = EMPTY_KEYS.filter((k) => !isEmpty(rc[k]));
  const baseHas = EMPTY_KEYS.filter((k) => !isEmpty(bc[k]));
  const checks = {
    ...ch.checks,
    base_manifest_digest_pinned: pinned(hand.base_manifest_digest, ch.manifest_digest_read),
    base_config_digest_pinned: pinned(hand.base_config_digest, ch.config_digest_read),
    base_platform_linux_amd64: P(rb.Architecture === 'amd64' && rb.Os === 'linux'),
    env_exact_both_ways: P(envOk),
    entrypoint_exact: P(field('Entrypoint', 'entrypoint', nul)),
    cmd_exact: P(field('Cmd', 'cmd', nul)),
    user_exact: P(field('User', 'user', str)),
    workdir_exact: P(field('WorkingDir', 'workdir', str)),
    hand_half_backed_by_dockerfile: P(!problems.length),
    hand_half_restates_no_base_value: P(!restated.length),
    rekey_has_no_volumes_ports_healthcheck_onbuild: P(!rekeyHas.length),
    base_has_no_volumes_ports_healthcheck_onbuild: P(!baseHas.length),
  };
  return {
    ok: Object.values(checks).every((x) => x === 'PASS'), checks,
    base_manifest_digest_read: ch.manifest_digest_read, base_config_digest_read: ch.config_digest_read, base_inspect_id: rb.Id ?? null, base_platform: { Architecture: rb.Architecture ?? null, Os: rb.Os ?? null },
    base_half, hand_keys: Object.keys(hand).filter((k) => HAND_KEYS.includes(k) && !['what', 'base_manifest_digest', 'base_config_digest'].includes(k)).sort(),
    details: { inspect_vs_blob_differ: ch.inspect_vs_blob_differ, blob_platform: ch.blob_platform, env_extra: extra, env_missing: missing, env_changed: changed, env_duplicate: dup, hand_not_backed: problems, hand_restates_base: restated, rekey_has: rekeyHas, base_has: baseHas },
  };
}

// The two planted cases. Each must come back red on the env line.
const PATH = 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';
const fakeBase = (env) => [{ Id: 'sha256:planted', Architecture: 'amd64', Os: 'linux', Config: { Env: env, Entrypoint: ['docker-entrypoint.sh'], Cmd: ['node'], User: '', WorkingDir: '' } }];
const fakeRekey = (env) => [{ Config: { Env: env, Entrypoint: ['/bin/bash', '-p', '/opt/rekey/rekey-entrypoint.sh'], Cmd: null, User: '1000:1000', WorkingDir: '' } }];
const PLANT_HAND = { user: '1000:1000', entrypoint: ['/bin/bash', '-p', '/opt/rekey/rekey-entrypoint.sh'], cmd: null, env: {} };
const PLANT_DF = 'FROM x\nUSER 1000:1000\nENTRYPOINT ["/bin/bash", "-p", "/opt/rekey/rekey-entrypoint.sh"]\n';
// A made-up registry chain whose config blob carries `config` (an inspect-shaped Config), consistent end to end:
// {chain, indexDigest, manifestDigest, configDigest}. Exported for the units; the instrument plants from it too.
export function makeChain(config, { arch = 'amd64', os = 'linux', extraManifests = [] } = {}) {
  const cfgBytes = Buffer.from(JSON.stringify({ architecture: arch, os, config, rootfs: { type: 'layers', diff_ids: [] } }));
  const configDigest = sha(cfgBytes);
  const manBytes = Buffer.from(JSON.stringify({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.manifest.v1+json',
    config: { mediaType: 'application/vnd.oci.image.config.v1+json', digest: configDigest, size: cfgBytes.length }, layers: [] }));
  const manifestDigest = sha(manBytes);
  const idxBytes = Buffer.from(JSON.stringify({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.index.v1+json', manifests: [
    { mediaType: 'application/vnd.oci.image.manifest.v1+json', digest: manifestDigest, size: manBytes.length, platform: { architecture: 'amd64', os: 'linux' } },
    ...extraManifests] }));
  return { chain: { index: idxBytes, manifest: manBytes, config: cfgBytes }, indexDigest: sha(idxBytes), manifestDigest, configDigest };
}

export function instrument() {
  const v = (rekeyEnv, baseEnv) => {
    const b = fakeBase(baseEnv), c = makeChain(b[0].Config);
    return configVerdict(fakeRekey(rekeyEnv), b, PLANT_HAND, PLANT_DF.replace('FROM x', `FROM x@${c.indexDigest}`), c.chain);
  };
  const extraInBase = v([PATH, 'NODE_VERSION=22'], [PATH, 'NODE_VERSION=22', 'EXTRA_BASE_VAR=1']);
  const nodeOptions = v([PATH, 'NODE_VERSION=22', 'NODE_OPTIONS=--require /x'], [PATH, 'NODE_VERSION=22']);
  const red = (x) => !x.ok && x.checks.env_exact_both_ways === 'FAIL';
  // Security 12197.2 (b): a local store that answers with a config other than the pinned blob's (inspect shows an
  // Env the blob lacks) must turn the tie-to-the-blob line red, with every hash in the chain still good.
  const b = fakeBase([PATH, 'NODE_VERSION=22']), c = makeChain(fakeBase([PATH])[0].Config);
  const store = configVerdict(fakeRekey([PATH, 'NODE_VERSION=22']), b, PLANT_HAND, PLANT_DF.replace('FROM x', `FROM x@${c.indexDigest}`), c.chain);
  const storeRed = !store.ok && store.checks.base_inspect_equals_the_config_blob === 'FAIL' && store.checks.base_config_blob_matches_the_manifest === 'PASS';
  return { bites: red(extraInBase) && red(nodeOptions) && storeRed, extra_base_variable_red: red(extraInBase), node_options_red: red(nodeOptions), store_answers_other_config_red: storeRed };
}

if (process.argv[1]?.endsWith('mediator-image-config.mjs')) {
  const [rekeyF, baseF, handF, dockerfile, chainDir, out] = process.argv.slice(2);
  try {
    if (!out) { console.error('usage: mediator-image-config.mjs <rekey-inspect.json> <base-inspect.json> <rekey-config.json> <rekey Dockerfile> <base chain dir> <out.json>'); process.exit(2); }
    const rd = (f) => JSON.parse(fs.readFileSync(f, 'utf8'));
    const raw = (n) => { try { return fs.readFileSync(path.join(chainDir, n)); } catch { return null; } };
    const chain = { index: raw('index.raw'), manifest: raw('manifest.raw'), config: raw('config.raw') };
    const v = configVerdict(rd(rekeyF), rd(baseF), rd(handF), fs.readFileSync(dockerfile, 'utf8'), chain);
    const ins = instrument();
    const checks = { instrument_bites: P(ins.bites), ...v.checks };
    const ok = Object.values(checks).every((x) => x === 'PASS');
    const { ok: _o, checks: _c, ...rest } = v;
    fs.writeFileSync(out, `${JSON.stringify({ what: 'rekey image config record (Security 11935, 12197.2, 12232.1)', ok, checks, instrument: ins, ...rest }, null, 2)}\n`);
    console.log(JSON.stringify({ ok, checks, base_manifest_digest_read: v.base_manifest_digest_read, base_config_digest_read: v.base_config_digest_read, base_inspect_id: v.base_inspect_id, base_platform: v.base_platform, details: v.details }));
    process.exit(ok ? 0 : 1);
  } catch (e) { console.error(`mediator-image-config: ${e.message}`); process.exit(1); }
}
