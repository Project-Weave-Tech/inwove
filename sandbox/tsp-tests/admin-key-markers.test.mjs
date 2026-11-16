// Every private key of the admin DID as one admin key (Security 12582.2(b)/(c)). Made-up test keys only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { ed25519 } from '@noble/curves/ed25519.js';
import { b58 } from './lib.mjs';
import { seedOf, adminKeys, markers, encodings, profileSecrets } from './admin-key-markers.mjs';

const fresh = () => {
  const sk = ed25519.utils.randomSecretKey();
  const did = 'did:key:z' + b58(Uint8Array.from([0xed, 0x01, ...ed25519.getPublicKey(sk)]));
  return { sk, did, cred: { did, private_key_multibase: 'z' + b58(Uint8Array.from([0x80, 0x26, ...sk])) } };
};

test('admin keys: a did:key admin names two keys, and the credential holds both (X25519 derived from the seed)', () => {
  const { cred } = fresh();
  const k = adminKeys(cred);
  assert.equal(k.did_method, 'did:key');
  assert.deepEqual(k.keys.map((x) => [x.kind, x.held_by_credential, x.derived]).sort(), [['ed25519', true, false], ['x25519', true, true]]);
});

test('admin keys: a credential whose key is not the DID\'s holds none of its keys → not every key held (red)', () => {
  const a = fresh(), b = fresh();
  const m = markers({ did: a.did, private_key_multibase: b.cred.private_key_multibase });
  assert.equal(m.every_document_key_held, false);
  assert.equal(m.markers.length, 0);
});

test('admin keys: seedOf reads the key with or without the multicodec prefix, 32 or 64 bytes; refuses other shapes', () => {
  const { sk } = fresh();
  const full = Uint8Array.from([...sk, ...ed25519.getPublicKey(sk)]);
  for (const mb of ['z' + b58(Uint8Array.from([0x80, 0x26, ...sk])), 'z' + b58(sk), 'z' + b58(Uint8Array.from([0x80, 0x26, ...full])), 'z' + b58(full)])
    assert.deepEqual([...seedOf(mb)], [...sk]);
  assert.throws(() => seedOf('u' + Buffer.from(sk).toString('base64url')));
  assert.throws(() => seedOf('z' + b58(sk.slice(0, 20))));
});

test('admin keys: markers cover both key types in every encoding, and each planted copy is found by a fixed-string scan', () => {
  const { cred } = fresh();
  const m = markers(cred);
  const kinds = new Set(m.planted.map((p) => p.kind));
  assert.deepEqual([...kinds].sort(), ['ed25519', 'x25519']);
  for (const kind of ['ed25519', 'x25519']) for (const enc of ['multibase', 'multibase_no_prefix', 'jwk_d', 'base64', 'hex'])
    assert.ok(m.planted.some((p) => p.kind === kind && p.encoding === enc), `${kind} ${enc}`);
  for (const p of m.planted) assert.ok(m.markers.some((x) => `noise ${p.value} noise`.includes(x)));
});

test('admin keys: the profile setup writes (admin-monitor.json) gives its own secret values, at any depth', () => {
  const { sk, did } = fresh();
  const d = Buffer.from(sk).toString('base64url');
  const prof = { alias: 'admin', did, mediator: 'did:peer:x', secrets: [{ id: did + '#k', type: 'JsonWebKey2020', privateKeyJwk: { kty: 'OKP', crv: 'Ed25519', d, x: 'short' } }, { privateKeyMultibase: 'z' + b58(sk) }] };
  assert.deepEqual(profileSecrets(prof).sort(), [d, 'z' + b58(sk)].sort());
  assert.deepEqual(profileSecrets({ did: 'did:key:z6Mkverylongbutpublicvalue', alias: 'admin' }), []);
});

test('admin keys: the X25519 JWK d marker equals the derived Montgomery secret', () => {
  const { sk, cred } = fresh();
  const x = adminKeys(cred).keys.find((k) => k.kind === 'x25519');
  assert.equal(encodings('x25519', x.priv).jwk_d, Buffer.from(ed25519.utils.toMontgomerySecret(sk)).toString('base64url'));
});

test('admin keys: the CLI writes markers + one planted file per marker kind, and prints counts, never a value', () => {
  const dir = mkdtempSync(join(tmpdir(), 'admkeys-'));
  try {
    const { cred } = fresh();
    writeFileSync(join(dir, 'cred.json'), JSON.stringify(cred));
    const out = execFileSync(process.execPath, [new URL('./admin-key-markers.mjs', import.meta.url).pathname, 'markers', join(dir, 'cred.json'), join(dir, 'marks'), join(dir, 'plant'), join(dir, 'no-profile.json')], { encoding: 'utf8' });
    const s = JSON.parse(out);
    assert.equal(s.ok, true); assert.equal(s.every_document_key_held, true); assert.deepEqual(s.kinds, ['ed25519', 'x25519']);
    assert.equal(readdirSync(join(dir, 'plant')).length, s.planted);
    const marks = readFileSync(join(dir, 'marks'), 'utf8').split('\n').filter(Boolean);
    for (const v of marks) assert.ok(!out.includes(v), 'a marker value was printed');
    assert.ok(!out.includes(cred.private_key_multibase));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
