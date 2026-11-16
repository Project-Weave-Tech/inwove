#!/usr/bin/env node
// The image checks (Security 12195.1 d, 12422 e + the rekey image, 12491 b's image half), run on an image's whole
// filesystem as `docker export` writes it, plus its `docker image inspect` JSON. Names, paths and verdicts only.
//
//   service <rootfs> <inspect.json> <planted dir> <out.json>
//     (d) no file named mediator-setup anywhere;
//     (e) no file named mediator-store.mjs, and no regular file whose bytes carry rekey, delete-admin, admin-out,
//         seal-test or encrypt-test (a name search alone misses a renamed copy);
//     (b) no dbus-daemon / dbus-broker / dbus-launch anywhere, no /run/dbus/system_bus_socket, no /run/user/*/bus, and
//         the image's own Env names no DBUS_* and no XDG_RUNTIME_DIR;
//     the image: a non-root User, the exec-form entrypoint `/bin/bash -p /opt/mediator/mediator-entrypoint.sh`, the
//         baked deny sha256 beside it, and the keyring probe (12519 e).
//     Every search first runs on <planted dir> (a renamed copy of the store tool, a mediator-setup, a dbus-daemon,
//     a bus socket path) and must hit each, so a search that can't hit can't pass.
//   rekey <rootfs> <inspect.json> <shipped tool path in the image> <out.json>
//     the shipped tool's subcommands are within rekey/opens/names/absent (rekey present), none of the removed words
//     is in it, its sha256 for L8; (d) no mediator-setup; no mediator binary; no other copy of the store tool by
//     name; no exposed port; a non-root User.
// Exit 0 only when every line is PASS.
import fs from 'node:fs';
import path from 'node:path';
import { shippedVerdict, sha256 } from './mediator-store-ship.mjs';

export const STORE_WORDS = ['rekey', 'delete-admin', 'admin-out', 'seal-test', 'encrypt-test'];
const DBUS_BINS = ['dbus-daemon', 'dbus-broker', 'dbus-launch'];
export const SERVICE_ENTRYPOINT = ['/bin/bash', '-p', '/opt/mediator/mediator-entrypoint.sh'];

// Every entry under root (lstat; symlinks are listed, never followed). Returns {rel, kind, size}.
export function walk(root) {
  const out = [];
  const stack = [''];
  while (stack.length) {
    const rel = stack.pop();
    let ents;
    try { ents = fs.readdirSync(path.join(root, rel), { withFileTypes: true }); } catch { continue; }
    for (const e of ents) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) { out.push({ rel: r, kind: 'dir' }); stack.push(r); }
      else if (e.isSymbolicLink()) out.push({ rel: r, kind: 'link' });
      else if (e.isFile()) out.push({ rel: r, kind: 'file' });
      else out.push({ rel: r, kind: 'other' });
    }
  }
  return out.sort((a, b) => (a.rel < b.rel ? -1 : 1));
}

const base = (rel) => rel.split('/').pop();

// The searches, each a pure function of (root, entries) → hits (paths, and for content the words).
export function searches(root, entries) {
  const named = (names) => entries.filter((e) => e.kind !== 'dir' && names.includes(base(e.rel))).map((e) => `/${e.rel}`);
  const content = [];
  const words = STORE_WORDS.map((w) => Buffer.from(w));
  for (const e of entries) {
    if (e.kind !== 'file') continue;
    let buf;
    try { buf = fs.readFileSync(path.join(root, e.rel)); } catch { content.push({ path: `/${e.rel}`, words: ['unreadable'] }); continue; }
    const hit = STORE_WORDS.filter((w, i) => buf.includes(words[i]));
    if (hit.length) content.push({ path: `/${e.rel}`, words: hit });
  }
  const busPaths = entries.filter((e) => e.rel === 'run/dbus/system_bus_socket' || /^run\/user\/[^/]+\/bus$/.test(e.rel)).map((e) => `/${e.rel}`);
  return {
    setup_named: named(['mediator-setup']),
    store_named: named(['mediator-store.mjs']),
    store_words: content,
    dbus_bins: named(DBUS_BINS),
    bus_paths: busPaths,
  };
}

function inspectOf(file) {
  const j = JSON.parse(fs.readFileSync(file, 'utf8'));
  const c = (Array.isArray(j) ? j[0] : j)?.Config;
  if (!c) throw new Error('no Config in the inspect JSON');
  return c;
}
const envNames = (c) => (c.Env || []).map((kv) => kv.split('=')[0]);
const nonRoot = (u) => !!u && !/^(root|0)(:|$)/.test(u);
const P = (ok) => (ok ? 'PASS' : 'FAIL');

export function serviceVerdict(root, config, planted) {
  const s = searches(root, walk(root));
  const p = searches(planted, walk(planted));
  const instrument = {
    planted_setup_found: p.setup_named.length > 0,
    planted_store_name_found: p.store_named.length > 0,
    planted_renamed_copy_found: p.store_words.some((h) => !h.path.endsWith('mediator-store.mjs') && h.words.length === STORE_WORDS.length),
    planted_dbus_found: p.dbus_bins.length > 0,
    planted_bus_path_found: p.bus_paths.length > 0,
  };
  const names = envNames(config);
  const env_dbus = names.filter((n) => /^DBUS_/.test(n) || n === 'XDG_RUNTIME_DIR');
  const has = (rel) => { try { return fs.lstatSync(path.join(root, rel)).isFile(); } catch { return false; } };
  const ep = config.Entrypoint || [];
  const checks = {
    instrument_bites: P(Object.values(instrument).every(Boolean)),
    d_no_mediator_setup: P(s.setup_named.length === 0),
    e_no_store_tool_by_name: P(s.store_named.length === 0),
    e_no_file_carries_the_store_words: P(s.store_words.length === 0),
    b_no_dbus_daemon_or_broker: P(s.dbus_bins.length === 0),
    b_no_bus_socket_paths: P(s.bus_paths.length === 0),
    b_image_env_names_no_bus: P(env_dbus.length === 0),
    user_not_root: P(nonRoot(config.User)),
    entrypoint_exec_form: P(JSON.stringify(ep) === JSON.stringify(SERVICE_ENTRYPOINT)),
    entrypoint_and_deny_sha_present: P(has('opt/mediator/mediator-entrypoint.sh') && has('opt/mediator/mediator-deny.sha256')),
    keyring_probe_present: P(has('opt/mediator/keyring-probe')),
  };
  return { checks, hits: s, instrument, user: config.User || '', entrypoint: ep, env_names: names.sort(), env_bus_names: env_dbus };
}

export function rekeyVerdict(root, config, shipped) {
  const entries = walk(root);
  const s = searches(root, entries);
  const rel = shipped.replace(/^\/+/, '');
  let text = null;
  try { text = fs.readFileSync(path.join(root, rel), 'utf8'); } catch { /* checked below */ }
  const v = text === null ? null : shippedVerdict(text);
  const mediatorBins = entries.filter((e) => e.kind === 'file' && base(e.rel) === 'mediator').map((e) => `/${e.rel}`);
  const otherCopies = s.store_named.filter((p) => p !== `/${rel}`);
  const ports = Object.keys(config.ExposedPorts || {});
  const checks = {
    shipped_tool_present: P(v !== null),
    shipped_subcommands_within_rekey_opens_names_absent: P(!!v && v.extra_subcommands.length === 0 && v.subcommands.includes('rekey')),
    shipped_file_has_no_removed_words: P(!!v && v.forbidden_words.length === 0 && !v.markers_left),
    d_no_mediator_setup: P(s.setup_named.length === 0),
    no_mediator_binary: P(mediatorBins.length === 0),
    no_other_store_tool_copy: P(otherCopies.length === 0),
    no_exposed_port: P(ports.length === 0),
    user_not_root: P(nonRoot(config.User)),
  };
  return { checks, shipped: shipped, shipped_sha256: text === null ? null : sha256(Buffer.from(text)), subcommands: v?.subcommands ?? null,
    forbidden_words: v?.forbidden_words ?? null, mediator_bins: mediatorBins, other_copies: otherCopies, exposed_ports: ports, user: config.User || '' };
}

if (process.argv[1]?.endsWith('mediator-image-check.mjs')) {
  const [mode, root, inspect, third, out] = process.argv.slice(2);
  try {
    const config = inspectOf(inspect);
    const r = mode === 'service' ? serviceVerdict(root, config, third) : mode === 'rekey' ? rekeyVerdict(root, config, third) : null;
    if (!r) { console.error('usage: mediator-image-check.mjs service|rekey <rootfs> <inspect.json> <planted|shipped> <out.json>'); process.exit(2); }
    const ok = Object.values(r.checks).every((x) => x === 'PASS');
    const rec = { what: `image check (${mode})`, ok, ...r };
    fs.writeFileSync(out, `${JSON.stringify(rec, null, 2)}\n`);
    console.log(JSON.stringify({ mode, ok, checks: r.checks }));
    process.exit(ok ? 0 : 1);
  } catch (e) { console.error(`mediator-image-check: ${e.message}`); process.exit(1); }
}
