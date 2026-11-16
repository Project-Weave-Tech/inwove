// The mediator's file secret store from outside (condition 16.3, Railroad note ii): presence check without a
// passphrase, the open check, and the surgical delete that must leave every other entry byte-identical and opening.
// Test values only; the encrypted store is written in the mediator's 0.50.0 format by the tool's own seal-test.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const TOOL = new URL('../sandbox/tsp-tests/mediator-store.mjs', import.meta.url).pathname;
const run = (...a) => { const r = spawnSync(process.execPath, [TOOL, ...a], { encoding: 'utf8' }); return { code: r.status, out: r.stdout, err: r.stderr, j: r.stdout ? JSON.parse(r.stdout.trim().split('\n').pop()) : null }; };
function rig() {
  const d = mkdtempSync(join(tmpdir(), 'store-'));
  writeFileSync(join(d, 'p1'), 'test-pass-one\n'); writeFileSync(join(d, 'p2'), 'test-pass-two');
  return { d, done: () => rmSync(d, { recursive: true, force: true }) };
}
const VALUES = JSON.stringify({ mediator_admin_credential: '{"did":"did:key:zTEST","private_key_multibase":"zTESTONLY"}', mediator_jwt_secret: 'test-jwt', mediator_operating_secrets: 'test-ops' });

test('store: encrypted presence check needs no passphrase; open check tells the right passphrase from the wrong one', () => {
  const r = rig();
  try {
    const s = join(r.d, 'secrets.json');
    assert.equal(run('seal-test', s, join(r.d, 'p1'), VALUES).code, 0);
    assert.equal(run('absent', s).code, 3);
    assert.deepEqual(run('names', s).j.entries, ['mediator_admin_credential', 'mediator_jwt_secret', 'mediator_operating_secrets']);
    assert.equal(run('opens', s, join(r.d, 'p1')).code, 0);
    assert.equal(run('opens', s, join(r.d, 'p2')).code, 4);
    assert.ok(!readFileSync(s, 'utf8').includes('test-jwt'), 'values are sealed on disk');
  } finally { r.done(); }
});

test('store: surgical delete removes only the admin credential; the rest byte-identical and still opening', () => {
  const r = rig();
  try {
    const s = join(r.d, 'secrets.json');
    run('seal-test', s, join(r.d, 'p1'), VALUES);
    const before = JSON.parse(readFileSync(s, 'utf8'));
    const x = run('delete-admin', s, join(r.d, 'p1'));
    assert.equal(x.code, 0, x.err);
    assert.equal(x.j.removed[0], 'mediator_admin_credential');
    assert.equal(x.j.entries_after, 2); assert.equal(x.j.others_unchanged, true); assert.equal(x.j.still_opens, true);
    const after = JSON.parse(readFileSync(s, 'utf8'));
    delete before.entries.mediator_admin_credential;
    assert.deepEqual(after, before);
    assert.equal((statSync(s).mode & 0o777).toString(8), '600');
    assert.equal(run('absent', s).code, 0);
    assert.ok(!x.out.includes('zTESTONLY') && !x.out.includes('test-jwt'), 'no value printed');
  } finally { r.done(); }
});

test('store: delete with the wrong passphrase refuses and writes nothing; the plain shape deletes too', () => {
  const r = rig();
  try {
    const s = join(r.d, 'secrets.json');
    run('seal-test', s, join(r.d, 'p1'), VALUES);
    const raw = readFileSync(s, 'utf8');
    assert.notEqual(run('delete-admin', s, join(r.d, 'p2')).code, 0);
    assert.equal(readFileSync(s, 'utf8'), raw);
    const p = join(r.d, 'plain.json');
    writeFileSync(p, JSON.stringify({ entries: { mediator_admin_credential: 'eA', mediator_jwt_secret: 'eQ' } }));
    const y = run('delete-admin', p);
    assert.equal(y.code, 0, y.err); assert.deepEqual(JSON.parse(readFileSync(p, 'utf8')), { entries: { mediator_jwt_secret: 'eQ' } });
  } finally { r.done(); }
});

test('store: admin-out writes the credential 0600 and prints only its shape; rotation: the old passphrase fails a re-sealed store', () => {
  const r = rig();
  try {
    const s = join(r.d, 'secrets.json');
    run('seal-test', s, join(r.d, 'p1'), VALUES);
    const o = join(r.d, 'admin.json');
    const x = run('admin-out', s, join(r.d, 'p1'), o);
    assert.equal(x.code, 0, x.err); assert.equal(x.j.did_method, 'did:key');
    assert.equal(JSON.parse(readFileSync(o, 'utf8')).did, 'did:key:zTEST');
    assert.equal((statSync(o).mode & 0o777).toString(8), '600');
    assert.ok(!x.out.includes('zTESTONLY'));
    const s2 = join(r.d, 'rotated.json');
    run('seal-test', s2, join(r.d, 'p2'), VALUES);
    assert.equal(run('opens', s2, join(r.d, 'p1')).code, 4);
    assert.equal(run('opens', s2, join(r.d, 'p2')).code, 0);
  } finally { r.done(); }
});

test('store: rekey (v) re-seals every entry under the new passphrase in place; the old one no longer opens', () => {
  const r = rig();
  try {
    const s = join(r.d, 'secrets.json');
    run('seal-test', s, join(r.d, 'p1'), VALUES);
    const x = run('rekey', s, join(r.d, 'p1'), join(r.d, 'p2'));
    assert.equal(x.code, 0, x.err);
    assert.deepEqual(x.j, { entries: ['mediator_admin_credential', 'mediator_jwt_secret', 'mediator_operating_secrets'], values_unchanged: true, salt_changed: true, old_opens: false, new_opens: true, mode: '600' });
    assert.equal(run('opens', s, join(r.d, 'p1')).code, 4);
    assert.notEqual(run('rekey', s, join(r.d, 'p1'), join(r.d, 'p2')).code, 0, 'the old passphrase can no longer rekey');
  } finally { r.done(); }
});
