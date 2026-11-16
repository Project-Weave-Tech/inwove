#!/usr/bin/env node
// Condition 16, tightening 1(a) (Security, bus 11984): check the RESOLVED feature set, not just the flags we pass.
// Feature unification can switch a feature back on from inside the dependency graph, so the job records
// `cargo tree -e features ...` and fails if `vta`, any `secrets-*` feature or `aws` (the gate on AWS_REGION, bus 12079.5)
// shows up anywhere in it.
//
// `cargo tree` does not print the root crate's own features on its root line, so a default build (which has `vta`)
// shows no `feature "vta"` line at all: what shows is the `vta-sdk` crate that feature pulls in. The check therefore
// fails on either sign: a `feature "vta"` / `feature "secrets-..."` edge, or a crate in the tree that is a `vta*`
// crate or a secret-store backend crate. The job also runs this on the default build as a control, which must FAIL
// (a check that can't fail isn't evidence).
//
// Secret-store backend crates (Security 12391.2), both modes: (i) the crates each `secrets-*` feature of
// mediator-common pulls at the pin (BACKEND_CRATES), and (ii) any crate whose name holds `secret`, unless it is one
// of the exact names in SECRET_NAMED_OK (which also holds `keyring-core`, see there), each read at 34bbdea4 with
// `cargo tree -i` and found not to be a store backend. A literal `*-secrets-*` glob can't be used:
// `affinidi-secrets-resolver` is a plain dependency of every build. A new secret-named crate at a future pin goes
// red until it is read and named there.
//
// The setup binary (Security 12277, the setup binary row): `vta-sdk` is a plain dependency of mediator-setup at this
// pin, so that one crate is expected and does not count, while any other `vta*` crate does (Security 12391.1: a new
// `vta-*` backend crate arriving at a future pin goes red); what fails there is the setup crate's own `vta*`/`secrets-*`/
// `publish-aws` feature (read from its root line, `cargo tree --depth 0 -f '{p}|{f}'`, since the tree itself never
// shows the root's features), any `feature "vta*"`/`"secrets-*"`/`"aws"` edge, or an `aws-config`/`aws-sdk-*` crate:
// the admin credential must never have a cloud road out of the setup binary. Its control is the setup crate's
// default build, which carries every `secrets-*` backend and `publish-aws` and must fail.
//
// Usage: node mediator-features.mjs <tree.txt> <checkout path> <out.json> [--expect-fail]
//                                   [--setup <root line file>] [--bin <binary, for its sha256>]
// The record's sha256 is of the tree with the checkout's absolute path replaced by `<checkout>`, so it is the same on
// any runner. Prints counts and the matched feature/crate names only.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

export function normalise(tree, checkout) {
  return checkout ? tree.split(checkout).join('<checkout>') : tree;
}

export function rootFeatures(line) {
  const f = String(line || '').trim().split('\n')[0].split('|')[1] ?? '';
  return f.split(',').map((x) => x.trim()).filter(Boolean).sort();
}

// Read at 34bbdea4 with `cargo tree -i <name>` on the lean and setup builds. Exact names only; each says why it isn't a store.
export const SECRET_NAMED_OK = new Map([
  ['affinidi-secrets-resolver', 'the in-memory DID key resolver every affinidi crate (and vta-sdk) uses; holds no store'],
  ['crypto_secretbox', 'XSalsa20-Poly1305, used by affinidi-tsp and affinidi-messaging-didcomm-v1 for sealing messages'],
  ['dbus-secret-service', 'pulled only by dbus-secret-service-keyring-store (next line)'],
  ['dbus-secret-service-keyring-store', "affinidi-tdk-common's default client keyring, via affinidi-messaging-sdk; not mediator-common's secrets-keyring backend"],
  // keyring-core has no `secret` in its name but is also in BACKEND_CRATES' list (secrets-keyring pulls it). At the pin
  // it is in EVERY build, lean included, through affinidi-tdk-common's default features (with the dbus store above),
  // so it can't be the sign of the backend; the backend is told apart by its own two store crates and its feature edge.
  ['keyring-core', 'affinidi-tdk-common default (client keyring) in every build at the pin; secrets-keyring is caught by linux-keyutils-/apple-native-keyring-store and `feature "secrets-keyring"`'],
]);
// The crates mediator-common's `secrets-keyring|aws|gcp|azure|vault|k8s` features pull at the pin (its Cargo.toml).
export const BACKEND_CRATES = /^(?:apple-native-keyring-store|linux-keyutils-keyring-store|aws-sdk-secretsmanager|google-cloud-secretmanager[\w-]*|google-cloud-gax|azure_[\w-]+|vaultrs|rustify|kube(?:-[\w-]+)?|k8s-openapi)$/;

export function crateHit(name, { setup = false } = {}) {
  if (/^vta[\w-]*$/.test(name)) return !(setup && name === 'vta-sdk');
  // `aws` gates the mediator's AWS_REGION read (config/mod.rs, bus 12079.5): its sign is the feature edge or the AWS
  // SDK crates it pulls in. (`aws-lc-rs` is rustls' crypto, not the SDK, and doesn't count.)
  if (/^(?:aws-config|aws-sdk-[\w-]+)$/.test(name)) return true;
  // Security w-1116-0355 (d): the Linux kernel keyring needs no D-Bus, so any keyutils crate is a store that could land
  // a write even with no bus. None is in the lean or setup tree at 34bbdea4; one arriving is red, never excused by name.
  if (/keyutils/i.test(name)) return true;
  if (SECRET_NAMED_OK.has(name)) return false;
  return BACKEND_CRATES.test(name) || /secret/i.test(name);
}

export function verdict(tree, { setup = false, root = [] } = {}) {
  const hits = new Map();
  const add = (k) => hits.set(k, (hits.get(k) ?? 0) + 1);
  for (const m of tree.matchAll(/feature "(vta[^"]*|secrets-[^"]*|aws)"/g)) add(`feature ${m[1]}`);
  for (const m of tree.matchAll(/(?:^|[\s│├└─])([A-Za-z0-9_][\w-]*) v\d/gm)) if (crateHit(m[1], { setup })) add(`crate ${m[1]}`);
  for (const f of root) if (/^(vta|secrets-|publish-aws$|aws$)/.test(f)) add(`root feature ${f}`);
  const lines = tree.split('\n').filter((l) => l.trim()).length;
  return { lines, hits: Object.fromEntries([...hits].sort()), clean: hits.size === 0 && lines > 0 };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [treePath, checkout, outPath, ...rest] = process.argv.slice(2);
  if (!treePath || !checkout || !outPath) { console.error('usage: mediator-features.mjs <tree.txt> <checkout> <out.json> [--expect-fail] [--setup <root line>] [--bin <binary>]'); process.exit(2); }
  const opt = (n) => { const i = rest.indexOf(n); return i >= 0 ? rest[i + 1] : null; };
  const expectFail = rest.includes('--expect-fail');
  const setupRoot = opt('--setup'), bin = opt('--bin');
  const tree = normalise(readFileSync(treePath, 'utf8'), checkout);
  const root = setupRoot ? rootFeatures(readFileSync(setupRoot, 'utf8')) : [];
  const v = verdict(tree, { setup: !!setupRoot, root });
  const sha256 = createHash('sha256').update(tree).digest('hex');
  const binSha = bin ? createHash('sha256').update(readFileSync(bin)).digest('hex') : undefined;
  const pass = expectFail ? !v.clean && v.lines > 0 : v.clean;
  const role = setupRoot ? (expectFail ? 'setup control (default build, must show secrets-*/aws)' : 'setup binary (Security 12277)')
    : (expectFail ? 'control (default build, must show vta)' : 'lean build');
  writeFileSync(outPath, JSON.stringify({ role, sha256, ...(setupRoot ? { root_features: root } : {}), ...(binSha ? { binary_sha256: binSha } : {}), ...v, pass }, null, 2) + '\n');
  console.log(`${role}: ${v.lines} lines, sha256 ${sha256}${binSha ? `, binary ${binSha}` : ''}, hits ${JSON.stringify(v.hits)}: ${pass ? 'PASS' : 'FAIL'}`);
  process.exit(pass ? 0 : 1);
}
