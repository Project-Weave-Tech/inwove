#!/usr/bin/env node
// The rekey image's config record (Security 11935). The filesystem lines judge what the image holds; this one judges
// what it RUNS WITH: the Env, Entrypoint, Cmd, User and WorkingDir `docker image inspect` reports, which a Dockerfile
// can change with one line (NODE_OPTIONS=--require /x, a new ENTRYPOINT) without touching a single file. So the rekey
// image's config is judged against the pinned base image's config, exact both ways, and the only difference allowed is
// the hand half (rekey-config.json), which must itself be nothing but the Dockerfile's own lines:
//
//   (a) by digest and platform: the base's config digest (inspect Id) and Architecture/Os are printed. `base_config_digest`
//       in rekey-config.json is pinned by Security; while it is "VERIFY" the line reads STOP (neither PASS nor FAIL) and
//       the verdict carries base_config_digest_read so it can be pinned. The base must be linux/amd64 (pulled with
//       --platform linux/amd64 by digest); any other platform is FAIL.
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
//   mediator-image-config.mjs <rekey-inspect.json> <base-inspect.json> <rekey-config.json> <rekey Dockerfile> <out.json>
// Exit 0 only when every line is PASS.
import fs from 'node:fs';

const J = JSON.stringify;
const P = (ok) => (ok ? 'PASS' : 'FAIL');
const EMPTY_KEYS = ['Volumes', 'ExposedPorts', 'Healthcheck', 'OnBuild'];
const HAND_KEYS = ['what', 'base_config_digest', 'env', 'user', 'workdir', 'entrypoint', 'cmd'];
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

// Returns {ok, checks, base_config_digest_read, base_platform, base_half, hand_keys, details}.
export function configVerdict(rekeyInspect, baseInspect, hand, dockerfileText) {
  const rb = baseInspect?.[0] ?? {}, rr = rekeyInspect?.[0] ?? {};
  const bc = rb.Config ?? {}, rc = rr.Config ?? {};
  hand = hand ?? {};
  const base_half = { Env: bc.Env ?? null, Entrypoint: bc.Entrypoint ?? null, Cmd: bc.Cmd ?? null, User: bc.User ?? '', WorkingDir: bc.WorkingDir ?? '' };
  const read = rb.Id ?? null;
  // (a)
  const pin = hand.base_config_digest;
  const digest = pin === 'VERIFY' ? 'STOP' : P(typeof pin === 'string' && read !== null && pin === read);
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
    base_config_digest_pinned: digest,
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
    base_config_digest_read: read, base_platform: { Architecture: rb.Architecture ?? null, Os: rb.Os ?? null },
    base_half, hand_keys: Object.keys(hand).filter((k) => HAND_KEYS.includes(k) && k !== 'what').sort(),
    details: { env_extra: extra, env_missing: missing, env_changed: changed, env_duplicate: dup, hand_not_backed: problems, hand_restates_base: restated, rekey_has: rekeyHas, base_has: baseHas },
  };
}

// The two planted cases. Each must come back red on the env line.
const PATH = 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';
const fakeBase = (env) => [{ Id: 'sha256:planted', Architecture: 'amd64', Os: 'linux', Config: { Env: env, Entrypoint: ['docker-entrypoint.sh'], Cmd: ['node'], User: '', WorkingDir: '' } }];
const fakeRekey = (env) => [{ Config: { Env: env, Entrypoint: ['/bin/bash', '-p', '/opt/rekey/rekey-entrypoint.sh'], Cmd: null, User: '1000:1000', WorkingDir: '' } }];
const PLANT_HAND = { user: '1000:1000', entrypoint: ['/bin/bash', '-p', '/opt/rekey/rekey-entrypoint.sh'], cmd: null, env: {} };
const PLANT_DF = 'FROM x\nUSER 1000:1000\nENTRYPOINT ["/bin/bash", "-p", "/opt/rekey/rekey-entrypoint.sh"]\n';
export function instrument() {
  const extraInBase = configVerdict(fakeRekey([PATH, 'NODE_VERSION=22']), fakeBase([PATH, 'NODE_VERSION=22', 'EXTRA_BASE_VAR=1']), PLANT_HAND, PLANT_DF);
  const nodeOptions = configVerdict(fakeRekey([PATH, 'NODE_VERSION=22', 'NODE_OPTIONS=--require /x']), fakeBase([PATH, 'NODE_VERSION=22']), PLANT_HAND, PLANT_DF);
  const red = (v) => !v.ok && v.checks.env_exact_both_ways === 'FAIL';
  return { bites: red(extraInBase) && red(nodeOptions), extra_base_variable_red: red(extraInBase), node_options_red: red(nodeOptions) };
}

if (process.argv[1]?.endsWith('mediator-image-config.mjs')) {
  const [rekeyF, baseF, handF, dockerfile, out] = process.argv.slice(2);
  try {
    if (!out) { console.error('usage: mediator-image-config.mjs <rekey-inspect.json> <base-inspect.json> <rekey-config.json> <rekey Dockerfile> <out.json>'); process.exit(2); }
    const rd = (f) => JSON.parse(fs.readFileSync(f, 'utf8'));
    const v = configVerdict(rd(rekeyF), rd(baseF), rd(handF), fs.readFileSync(dockerfile, 'utf8'));
    const ins = instrument();
    const checks = { instrument_bites: P(ins.bites), ...v.checks };
    const ok = Object.values(checks).every((x) => x === 'PASS');
    const { ok: _o, checks: _c, ...rest } = v;
    fs.writeFileSync(out, `${JSON.stringify({ what: 'rekey image config record (Security 11935)', ok, checks, instrument: ins, ...rest }, null, 2)}\n`);
    console.log(JSON.stringify({ ok, checks, base_config_digest_read: v.base_config_digest_read, base_platform: v.base_platform, details: v.details }));
    process.exit(ok ? 0 : 1);
  } catch (e) { console.error(`mediator-image-config: ${e.message}`); process.exit(1); }
}
