#!/usr/bin/env node
// Condition 16, tightening 1(a) (Security, bus 11984): check the RESOLVED feature set, not just the flags we pass.
// Feature unification can switch a feature back on from inside the dependency graph, so the job records
// `cargo tree -e features ...` and fails if `vta`, any `secrets-*` feature or `aws` (the gate on AWS_REGION, bus 12079.5)
// shows up anywhere in it.
//
// `cargo tree` does not print the root crate's own features on its root line, so a default build (which has `vta`)
// shows no `feature "vta"` line at all: what shows is the `vta-sdk` crate that feature pulls in. The check therefore
// fails on either sign: a `feature "vta"` / `feature "secrets-..."` edge, or a crate named `vta-*` / `*-secrets-*`
// backend crate in the tree. The job also runs this on the default build as a control, which must FAIL (a check that
// can't fail isn't evidence).
//
// The setup binary (Security 12277, the setup binary row): `vta-sdk` is a plain dependency of mediator-setup at this
// pin, so its crate is expected and does not count; what fails there is the setup crate's own `vta*`/`secrets-*`/
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

export function verdict(tree, { setup = false, root = [] } = {}) {
  const hits = new Map();
  const add = (k) => hits.set(k, (hits.get(k) ?? 0) + 1);
  for (const m of tree.matchAll(/feature "(vta[^"]*|secrets-[^"]*)"/g)) add(`feature ${m[1]}`);
  if (!setup) for (const m of tree.matchAll(/(?:^|[\s│├└─])(vta[\w-]*) v\d/gm)) add(`crate ${m[1]}`);
  for (const f of root) if (/^(vta|secrets-|publish-aws$|aws$)/.test(f)) add(`root feature ${f}`);
  // `aws` gates the mediator's AWS_REGION read (config/mod.rs, bus 12079.5): its sign is the feature edge or the AWS
  // SDK crates it pulls in. (`aws-lc-rs` is rustls' crypto, not the SDK, and doesn't count.)
  for (const m of tree.matchAll(/feature "(aws)"/g)) add(`feature ${m[1]}`);
  for (const m of tree.matchAll(/(?:^|[\s│├└─])(aws-config|aws-sdk-[\w-]+) v\d/gm)) add(`crate ${m[1]}`);
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
