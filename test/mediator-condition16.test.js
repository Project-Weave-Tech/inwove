// Condition 16 checks on the ref/09 mediator job (Security, bus 11984): the resolved-feature check (1a) and the
// 16.2(b) environment-read grep. Made-up Rust and made-up `cargo tree` text only; the job runs the same code on the
// real mediator at the pin.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readsOf, constsOf, stripTestModules, wrapperCalls, classify } from '../sandbox/tsp-tests/mediator-env-reads.mjs';
import { verdict, normalise } from '../sandbox/tsp-tests/mediator-features.mjs';

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
  assert.equal(verdict('').clean, false, 'an empty tree is not a clean one');
});

test('features: the record hash does not depend on where the checkout sits', () => {
  const t = (p) => `affinidi-messaging-mediator v0.50.0 (${p}/crates/x)\n`;
  assert.equal(normalise(t('/a/med'), '/a/med'), normalise(t('/b/other'), '/b/other'));
});
