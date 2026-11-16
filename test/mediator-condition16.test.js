// Condition 16 checks on the ref/09 mediator job (Security, bus 11984): the resolved-feature check (1a) and the
// 16.2(b) environment-read grep. Made-up Rust and made-up `cargo tree` text only; the job runs the same code on the
// real mediator at the pin.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readsOf, constsOf, stripTestModules, wrapperCalls, classify, closureCallers, derive, compare, rawCount, scan, planted, DOES_NOT_COVER } from '../sandbox/tsp-tests/mediator-env-reads.mjs';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { verdict, normalise, rootFeatures } from '../sandbox/tsp-tests/mediator-features.mjs';
import { pathVerdict } from '../sandbox/tsp-tests/mediator-keyring-paths.mjs';

const lists = {
  allow: ['DATABASE_URL', 'RUST_LOG'],
  deny: { flips: ['MEDIATOR_ACL_MODE'], adjacent: ['ADMIN_DID'] },
};
const at = (rs) => rs.map((r, i) => ({ ...r, at: `x.rs:${r.line ?? i}` }));

test('env reads: a rustfmt-split env_override! call is found, with its line', () => {
  const src = 'fn f() {\n    env_override!(\n        config.security.mediator_acl_mode,\n        "MEDIATOR_ACL_MODE"\n    );\n}\n';
  const r = readsOf(src);
  assert.deepEqual(r.map((x) => [x.kind, x.name, x.line]), [['runtime', 'MEDIATOR_ACL_MODE', 2]]);
});

test('env reads: the macro definitions themselves are not reads; a const name resolves', () => {
  const src = 'macro_rules! env_override {\n ($f:expr, $env_var:expr) => { if let Ok(v) = std::env::var($env_var) { $f = v; } };\n}\n'
    + 'pub const P: &str = "MEDIATOR_FILE_BACKEND_PASSPHRASE";\nfn g() { let _ = std::env::var(P); }\n';
  assert.deepEqual(readsOf(src, constsOf(src)).map((x) => x.name), ['MEDIATOR_FILE_BACKEND_PASSPHRASE']);
});

test('env reads: an allowed, a denied, an unlisted, a prefix read and an unresolved name are each sorted right', () => {
  const src = 'fn a() { env_override!(c.d, "DATABASE_URL"); env_override!(c.a, "ADMIN_DID"); env_override!(c.l, "LOG_LEVEL"); }\n'
    + 'fn b() { for (k, _) in env::vars() { if k.starts_with("MEDIATOR_TAG_") {} } }\n'
    + 'fn c(v: String) { let _ = env::var_os(v); }\n';
  const c = classify(at(readsOf(src)), lists);
  assert.deepEqual([...c.onAllow], ['DATABASE_URL']);
  assert.deepEqual([...c.onDeny], ['ADMIN_DID']);
  assert.deepEqual([...c.unlisted.keys()], ['runtime:LOG_LEVEL']);
  assert.equal(c.prefix.length, 1);
  assert.equal(c.unresolved.length, 1);
});

test('env reads: build-time env!/option_env! are listed too (they bake the build environment in)', () => {
  const src = 'const V: &str = env!("CARGO_PKG_VERSION");\nfn f() { let _ = option_env!("SOME_BUILD_VAR"); }\n';
  const c = classify(at(readsOf(src)), lists);
  assert.deepEqual([...c.unlisted.keys()].sort(), ['build:CARGO_PKG_VERSION', 'build:SOME_BUILD_VAR']);
});

test('env reads: a #[cfg(test)] module is skipped, line numbers after it kept', () => {
  const src = 'fn a() {}\n#[cfg(test)]\nmod tests {\n  fn t() { let _ = std::env::var("MEDIATOR_TEST_URL"); let s = "}"; }\n}\nfn b() { env_override!(c.x, "RUST_LOG"); }\n';
  const s = stripTestModules(src);
  const r = readsOf(s.text);
  assert.deepEqual(r.map((x) => [x.name, x.line]), [['RUST_LOG', 6]]);
  assert.ok(s.skipped >= 3);
});

test('env reads: a wrapper like require_env(var) is read at its call sites', () => {
  const src = 'const T: &str = "VAULT_TOKEN";\nfn require_env(var: &str) -> R { let value = std::env::var(var).map_err(|_| e)?; Ok(value) }\nfn f() { let t = require_env(T)?; }\n';
  const w = wrapperCalls(src, constsOf(src));
  assert.deepEqual(w.names, ['require_env']);
  assert.deepEqual(w.reads.map((x) => x.name), ['VAULT_TOKEN']);
});

test('features: the lean tree passes; a vta feature edge, a vta crate or a secrets-* feature fails', () => {
  const lean = 'affinidi-messaging-mediator v0.50.0 (/w/med/crates/x)\n├── tokio feature "default"\n│   └── tokio v1.0.0\n';
  assert.equal(verdict(lean).clean, true);
  assert.equal(verdict(lean + '├── vta-sdk v0.77.1\n').clean, false);
  assert.equal(verdict(lean + '├── affinidi-messaging-mediator feature "vta"\n').clean, false);
  assert.equal(verdict(lean + '│   ├── affinidi-messaging-mediator-common feature "secrets-aws"\n').clean, false);
  assert.equal(verdict(lean + '├── affinidi-messaging-mediator feature "aws"\n').clean, false, 'aws gates AWS_REGION (12079.5)');
  assert.equal(verdict(lean + '│   ├── aws-config v1.8.0\n').clean, false);
  assert.equal(verdict(lean + '│   ├── rustls feature "aws-lc-rs"\n│   │   └── aws-lc-rs v1.13.0\n').clean, true, 'rustls crypto is not the AWS SDK');
  assert.equal(verdict('').clean, false, 'an empty tree is not a clean one');
});

test('features, setup binary (Security 12277): vta-sdk is expected; its own vta/secrets-*/publish-aws, an aws edge or an AWS SDK crate fails', () => {
  const tree = 'affinidi-messaging-mediator-setup v0.50.0 (/w/med/tools/mediator-setup)\n├── vta-sdk feature "provision-client"\n│   └── vta-sdk v0.77.1\n├── tokio v1.0.0\n';
  const clean = (t, root = []) => verdict(t, { setup: true, root }).clean;
  assert.equal(clean(tree), true, 'the vta-sdk crate alone is expected in the setup binary');
  assert.equal(verdict(tree).clean, false, 'but it still fails the running image check');
  assert.deepEqual(rootFeatures('affinidi-messaging-mediator-setup v0.50.0 (/w)|secrets-aws,publish-aws\n'), ['publish-aws', 'secrets-aws']);
  assert.deepEqual(rootFeatures('affinidi-messaging-mediator-setup v0.50.0 (/w)|\n'), []);
  assert.equal(clean(tree, ['secrets-vault']), false);
  assert.equal(clean(tree, ['publish-aws']), false);
  assert.equal(clean(tree, ['vta']), false);
  assert.equal(clean(tree + '│   ├── affinidi-messaging-mediator-common feature "secrets-k8s"\n'), false);
  assert.equal(clean(tree + '├── some-crate feature "vta"\n'), false);
  assert.equal(clean(tree + '├── x feature "aws"\n'), false);
  assert.equal(clean(tree + '│   ├── aws-sdk-ssm v1.0.0\n'), false);
  assert.equal(clean(tree + '│   ├── aws-config v1.8.0\n'), false);
  assert.equal(clean(tree + '│   ├── rcgen feature "aws_lc_rs"\n│   │   └── aws-lc-rs v1.13.0\n'), true, 'rcgen/rustls crypto is not the AWS SDK');
});

test('features (Security 12391.1): in setup mode only vta-sdk is expected; any other vta* crate fails', () => {
  const tree = 'affinidi-messaging-mediator-setup v0.50.0 (/w/med/tools/mediator-setup)\n├── vta-sdk v0.77.1\n├── tokio v1.0.0\n';
  const v = (t) => verdict(t, { setup: true, root: [] });
  assert.equal(v(tree).clean, true);
  assert.equal(v(tree + '│   ├── vta-secrets v0.1.0\n').clean, false, 'a new vta-* backend crate goes red');
  assert.deepEqual(v(tree + '│   ├── vta-secrets v0.1.0\n').hits, { 'crate vta-secrets': 1 });
  assert.equal(v(tree + '├── vta v0.1.0\n').clean, false);
  assert.equal(v(tree.replace('vta-sdk', 'vta-sdk-extra')).clean, false, 'setup mode: only exactly vta-sdk is expected');
});

test('features (Security 12391.2): secret-store backend crates fail in both modes; the named non-store crates pass', () => {
  const lean = 'affinidi-messaging-mediator v0.50.0 (/w/med/crates/x)\n├── affinidi-secrets-resolver v0.5.4\n├── crypto_secretbox v0.1.1\n'
    + '├── dbus-secret-service-keyring-store v1.0.1\n│   ├── dbus-secret-service v4.1.0\n│   └── keyring-core v1.0.1\n';
  const setup = lean.replace('affinidi-messaging-mediator v0.50.0', 'affinidi-messaging-mediator-setup v0.50.0') + '├── vta-sdk v0.77.1\n';
  for (const [name, t, o] of [['lean', lean, {}], ['setup', setup, { setup: true }]]) {
    assert.equal(verdict(t, o).clean, true, `${name}: the crates read at 34bbdea4 and named are not stores`);
    for (const c of ['foo-secrets-bar v1.0.0', 'vta-secrets v0.1.0', 'some_secret_store v2.0.0', 'vaultrs v0.7.0', 'rustify v0.6.0',
      'kube v0.99.0', 'kube-client v0.99.0', 'k8s-openapi v0.25.0', 'azure_identity v0.27.0', 'azure_security_keyvault_secrets v0.6.0',
      'google-cloud-secretmanager-v1 v1.0.0', 'google-cloud-gax v1.0.0', 'aws-sdk-secretsmanager v1.0.0',
      'linux-keyutils-keyring-store v1.0.0', 'apple-native-keyring-store v1.0.0']) {
      assert.equal(verdict(t + `│   ├── ${c}\n`, o).clean, false, `${name}: ${c}`);
    }
  }
  assert.equal(verdict(lean + '│   ├── affinidi-messaging-mediator-common feature "secrets-keyring"\n').clean, false);
  assert.deepEqual(verdict(lean + '│   ├── aws-sdk-secretsmanager v1.0.0\n').hits, { 'crate aws-sdk-secretsmanager': 1 }, 'counted once');
});

test('features (Security w-1116-0355 d): any keyutils crate fails in both modes, today\'s trees have none', () => {
  const lean = 'affinidi-messaging-mediator v0.50.0 (/w/med/crates/x)\n├── keyring-core v1.0.1\n├── tokio v1.0.0\n';
  const setup = lean.replace('affinidi-messaging-mediator v0.50.0', 'affinidi-messaging-mediator-setup v0.50.0') + '├── vta-sdk v0.77.1\n';
  for (const [name, t, o] of [['lean', lean, {}], ['setup', setup, { setup: true, root: [] }]]) {
    assert.equal(verdict(t, o).clean, true, `${name}: no keyutils crate, clean`);
    for (const c of ['linux-keyutils v0.2.5', 'linux-keyutils-keyring-store v1.0.0', 'keyutils v0.4.0', 'some-keyutils-store v0.1.0']) {
      assert.equal(verdict(t + `│   ├── ${c}\n`, o).clean, false, `${name}: ${c}`);
    }
  }
});

// Made-up `cargo tree -i <crate> -e normal` text, the shapes seen at 34bbdea4 (lean and setup).
const INV_LEAN = 'keyring-core v1.0.1\n├── affinidi-tdk-common v0.7.0\n│   └── affinidi-messaging-sdk v0.45.0\n│       └── affinidi-messaging-mediator v0.50.0 (/w/med)\n'
  + '└── dbus-secret-service-keyring-store v1.0.1\n    └── affinidi-tdk-common v0.7.0 (*)\n';
const INV_SETUP = 'dbus-secret-service-keyring-store v1.0.1\n└── affinidi-tdk-common v0.7.0\n    ├── affinidi-meeting-place v0.5.0\n    │   └── affinidi-tdk v0.36.0\n'
  + '    │       └── vta-sdk v0.77.1\n    │           └── affinidi-messaging-mediator-setup v0.50.0 (/w/setup)\n    ├── affinidi-tdk v0.36.0 (*)\n    └── affinidi-tdk v0.37.0\n'
  + '        └── affinidi-messaging-mediator-setup v0.50.0 (/w/setup)\n';
test('keyring paths (Security 12491 a): the exception holds only while every path runs through affinidi-tdk-common', () => {
  assert.equal(pathVerdict(INV_LEAN, 'keyring-core').pass, true, 'lean at the pin');
  assert.equal(pathVerdict(INV_SETUP, 'dbus-secret-service-keyring-store').pass, true, 'setup at the pin');
  // mediator-common pulls the store directly (a future pin): red, by the forbidden crate and by the bypass.
  const viaCommon = INV_LEAN + '└── affinidi-messaging-mediator-common v0.50.0\n    └── affinidi-messaging-mediator v0.50.0 (/w/med)\n';
  const v = pathVerdict(viaCommon.replace('└── dbus-secret-service-keyring-store', '├── dbus-secret-service-keyring-store'), 'keyring-core');
  assert.equal(v.pass, false); assert.equal(v.forbidden_in_tree, true); assert.equal(v.paths_bypassing.length, 1);
  // Any other crate reaching the root without tdk-common: red, and the path is named.
  const bypass = 'keyring-core v1.0.1\n├── affinidi-tdk-common v0.7.0\n│   └── affinidi-messaging-mediator v0.50.0 (/w/med)\n└── some-new-crate v0.1.0\n    └── affinidi-messaging-mediator v0.50.0 (/w/med)\n';
  assert.deepEqual(pathVerdict(bypass, 'keyring-core').paths_bypassing, ['keyring-core <- some-new-crate <- affinidi-messaging-mediator']);
  // The target straight on the root (no tdk-common at all): red.
  assert.equal(pathVerdict('keyring-core v1.0.1\n└── affinidi-messaging-mediator v0.50.0 (/w/med)\n', 'keyring-core').pass, false);
  // Absent from the build: nothing to land, passes and says so. Anything unreadable fails closed.
  assert.deepEqual(pathVerdict('error: package ID specification `keyring-core` did not match any packages\n', 'keyring-core'), { pass: true, absent: true });
  assert.equal(pathVerdict('error: failed to download from crates.io\n', 'keyring-core').pass, false);
  assert.equal(pathVerdict('', 'keyring-core').pass, false, 'an empty tree is not an absent crate');
});

test('keyring paths (Security 12615): "absent" must name the crate asked for, and be the only thing there', () => {
  const absent = (c) => `error: package ID specification \`${c}\` did not match any packages\n`;
  // 12615.1: cargo's absent words about some OTHER name (a renamed or missing root) are not this crate's absence.
  assert.deepEqual(pathVerdict(absent('affinidi-messaging-mediator'), 'keyring-core'), { pass: false, error: 'absent words for another crate' });
  assert.deepEqual(pathVerdict(absent('keyring-core'), 'dbus-secret-service-keyring-store'), { pass: false, error: 'absent words for another crate' });
  assert.deepEqual(pathVerdict(absent('dbus-secret-service-keyring-store'), 'dbus-secret-service-keyring-store'), { pass: true, absent: true });
  // 12615.2 (Security's probe): a real tree with the absent sentence added to it is not absent.
  assert.deepEqual(pathVerdict(INV_LEAN + absent('keyring-core'), 'keyring-core'), { pass: false, error: 'absent words beside a tree' });
  assert.deepEqual(pathVerdict(absent('keyring-core') + INV_LEAN, 'keyring-core'), { pass: false, error: 'absent words beside a tree' });
  // A tree for a different crate than the one asked for fails closed; no crate named fails closed.
  assert.deepEqual(pathVerdict(INV_SETUP, 'keyring-core'), { pass: false, error: 'tree for another crate' });
  assert.equal(pathVerdict(INV_LEAN).pass, false, 'no crate named');
});

test('features: the record hash does not depend on where the checkout sits', () => {
  const t = (p) => `affinidi-messaging-mediator v0.50.0 (${p}/crates/x)\n`;
  assert.equal(normalise(t('/a/med'), '/a/med'), normalise(t('/b/other'), '/b/other'));
});

// ── 16.2(b) at the pin (Security 12079): compare against a committed record, never a rebuild ──
const SRC = [
  'fn a() {',
  '    env_override!(c.d, "DATABASE_URL");',
  '    env_override!(c.a, "ADMIN_DID");',
  '    env_override!(c.l, "LOG_LEVEL");',
  '    let v = env!("CARGO_PKG_VERSION");',
  '    for (k, _) in env::vars() { if k.get(..13) == Some("MEDIATOR_TAG_") {} }',
  '}',
  'fn r(c: &mut C) {',
  '    let resolve = |label: &str, env_var: &str, raw: &str| -> String {',
  '        if env::var_os(env_var).is_some() { return raw.to_string(); }',
  '        raw.to_string()',
  '    };',
  '    c.f = resolve("functions_file", "DATABASE_FUNCTIONS_FILE", &c.f);',
  '}',
  '',
].join('\n');

function tree(src = SRC) {
  const root = mkdtempSync(join(tmpdir(), 'c16-'));
  mkdirSync(join(root, 'crate/src'), { recursive: true });
  writeFileSync(join(root, 'crate/src/lib.rs'), src);
  return root;
}
const record = () => ({
  pin: 'x', crates: ['crate/src'],
  floor: { allow: ['DATABASE_URL'], deny: ['ADMIN_DID'] },
  allow: ['DATABASE_URL'],
  deny: { ADMIN_DID: 'ungated', LOG_LEVEL: 'ungated', DATABASE_FUNCTIONS_FILE: 'ungated' },
  exceptions: [
    { kind: 'prefix', at: 'crate/src/lib.rs:6', read: 'env::vars()', prefix: 'MEDIATOR_TAG_' },
    { kind: 'unresolved', at: 'crate/src/lib.rs:10', read: 'env::var_os(env_var)', callers: [{ at: 'crate/src/lib.rs:13', name: 'DATABASE_FUNCTIONS_FILE' }] },
  ],
  build_time: ['CARGO_PKG_VERSION'],
  does_not_cover: DOES_NOT_COVER,
});
const run = (src, rec = record()) => { const root = tree(src); try { const s = scan(root, rec); return { s, p: compare(derive(s.reads), rec, s.recall) }; } finally { rmSync(root, { recursive: true, force: true }); } };

test('16.2(b): the grep matching the committed record passes, with recall accounted', () => {
  const { s, p } = run(SRC);
  assert.deepEqual(p, []);
  assert.equal(s.recall.raw_total, s.recall.accounted);
});

test('16.2(b): a closure-parameter read lists its call sites and the names they pass (12079.3)', () => {
  const c = closureCallers(SRC, 10);
  assert.equal(c.closure, 'resolve');
  assert.deepEqual(c.callers.map((x) => x.name), ['DATABASE_FUNCTIONS_FILE']);
});

test('16.2(b): it fails in either direction: a new name, a gone name', () => {
  assert.ok(run(SRC.replace('"LOG_LEVEL"', '"LOG_FORMAT"')).p.some((x) => x.includes('new name') && x.includes('LOG_FORMAT')));
  assert.ok(run(SRC.replace('"LOG_LEVEL"', '"LOG_FORMAT"')).p.some((x) => x.includes('gone') && x.includes('LOG_LEVEL')));
});

test('16.2(b): a moved exception, a second prefix scan, a new caller name each fail', () => {
  assert.ok(run('\n' + SRC).p.some((x) => x.startsWith('exception new, moved or changed')), 'moved by a line');
  assert.ok(run(SRC.replace('fn r(', 'fn z() { for (k, _) in std::env::vars() { if k.starts_with("OTHER_") {} } }\nfn r(')).p.some((x) => /exception new.*prefix/.test(x)));
  assert.ok(run(SRC.replace('&c.f);', '&c.f);\n    c.g = resolve("x", "SECRET_PATH", &c.g);')).p.some((x) => x.includes('exception new')));
});

test('16.2(b): the floor cannot be dropped, a deny name needs a gate, a new build-time read fails', () => {
  const r1 = record(); delete r1.deny.ADMIN_DID; r1.allow = ['DATABASE_URL', 'ADMIN_DID'];
  assert.ok(run(SRC, r1).p.some((x) => x.includes('floor name off the deny list: ADMIN_DID')));
  const r2 = record(); r2.deny.LOG_LEVEL = 'unread';
  assert.ok(run(SRC, r2).p.some((x) => x.includes('no gate written: LOG_LEVEL')));
  assert.ok(run(SRC.replace('let v = env!("CARGO_PKG_VERSION");', 'let v = env!("CARGO_PKG_VERSION"); let w = option_env!("GITHUB_SHA");')).p.some((x) => x.includes('new build-time read') && x.includes('GITHUB_SHA')));
});

test('16.2(b): recall counts disagree when a read site is written in a shape the resolver misses (12079.7)', () => {
  const c = rawCount('fn a() { std::env::var("A"); env::var_os(x); let _ = option_env!("B"); env!("C"); my_env!("D"); }');
  assert.equal(c['env::var('], 1); assert.equal(c['env::var_os('], 1); assert.equal(c['option_env!('], 1); assert.equal(c['env!('], 1);
});

test('16.2(b): the planted instrument test catches all three plants (12079.6)', () => {
  const root = tree();
  const tmp = mkdtempSync(join(tmpdir(), 'c16p-'));
  try {
    const p = planted(root, record(), join(tmp, 'p'));
    assert.deepEqual(p.caught, { plain_read: true, env_override: true, second_prefix_scan: true });
    assert.equal(p.pass, true);
  } finally { rmSync(root, { recursive: true, force: true }); rmSync(tmp, { recursive: true, force: true }); }
});
