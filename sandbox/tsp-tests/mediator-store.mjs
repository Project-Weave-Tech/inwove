#!/usr/bin/env node
// ship:drop-begin (Security 12422: the rekey image ships this file with every ship:drop block removed; mediator-store-ship.mjs)
// The mediator's `file://` secret store, read and changed from outside the mediator (condition 16.3, Security 11984
// §2, Railroad note ii). Format at 0.50.0 @ 34bbdea4: `affinidi-messaging-mediator-common/src/secrets/backends/`
// `file.rs` (plain: {"entries": {<key>: <base64url value>}}) and `file_encrypted.rs` (`?encrypt=1`: {"version":1,"kdf":{argon2id,
// salt_b64,memory_kib,iterations,parallelism},"verifier_nonce_b64","verifier_b64","entries":{<key>:{nonce_b64,
// ciphertext_b64}}}, AES-256-GCM under an Argon2id key, each entry's AAD "mediator-file-encrypted-v1|entry|<key>",
// the verifier a seal of 32 zero bytes with AAD "mediator-file-encrypted-v1|verifier").
//
// Entry NAMES are plaintext in both shapes, so 16.3(b)'s presence check needs no passphrase. Because each entry is
// sealed with its own name as AAD, removing one entry leaves every other entry opening exactly as before: that is
// what makes the setup job's last step a surgical delete (Railroad note ii: never the operating secrets or the JWT
// secret in the same backend).
//
// Prints names, counts and verdicts only. Never a value, a passphrase or a key.
//
//   names <store>                          {"shape","entries":[names],"admin_credential_present"}; exit 0
//   absent <store>                         exit 0 if mediator_admin_credential is absent, 3 if present (16.3(b))
//   opens <store> <passphrase file>        exit 0 if the passphrase opens the verifier and every entry, 4 if not
//   delete-admin <store> [<passphrase file>]
//                                          removes mediator_admin_credential only; proves the other entries are
//                                          byte-identical and (encrypted) still open; atomic write, mode 0600
//   admin-out <store> <passphrase file> <out>
//                                          writes the admin credential JSON to <out> (0600) for the setup job's
//                                          admin client; prints only its DID's method and fragment count. Refuses
//                                          (exit 5) an <out> not under /dev/shm or under any results/ path (12247.3)
//   rekey <store> <old passphrase file> <new passphrase file>
//                                          (v) rotation in place: every entry opened with the old passphrase and
//                                          re-sealed under the new one with a fresh salt; same entry names, same
//                                          values (so the mediator keeps its DID); proves old no longer opens.
//                                          Refuses while mediator_admin_credential is in the store (12247 i(a)).
//                                          Security 12024: refuses (exit 6) unless its own /proc/self/environ holds
//                                          exactly REKEY_STORE, REKEY_OLD_PASSPHRASE_FILE, REKEY_NEW_PASSPHRASE_FILE
//                                          (each equal to its argument), PATH and HOME, nothing else (the rekey
//                                          entrypoint's `env -i`); temp + fsync + rename + directory fsync, and
//                                          refuses if the store changed between the read and the rename
//   seal-test <store> <passphrase file> <json of {key: utf8 value}>
//                                          TEST ONLY: writes an encrypted store in the mediator's format (unit tests)
//   encrypt-test <plain store> <passphrase file>
//                                          TEST ONLY: re-seals a plain store in place in the ?encrypt=1 shape, same
//                                          entry names and values (upstream's test store, for the entrypoint run)
// ship:drop-end
// The mediator's `file://` secret store, read from outside the mediator. Prints names, counts and verdicts only.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { argon2id } from '@noble/hashes/argon2.js';

export const ADMIN_CREDENTIAL = 'mediator_admin_credential';
const KEY_BYTES = 32;
const b64u = (s) => Buffer.from(s, 'base64url');
const entryAad = (k) => Buffer.from(`mediator-file-encrypted-v1|entry|${k}`);
const VERIFIER_AAD = Buffer.from('mediator-file-encrypted-v1|verifier');

export function readStore(file) {
  const raw = fs.readFileSync(file, 'utf8');
  const j = JSON.parse(raw);
  if (!j || typeof j !== 'object' || typeof j.entries !== 'object' || j.entries === null) throw new Error('not a store');
  const shape = 'kdf' in j || 'verifier_b64' in j ? 'encrypted' : 'plain';
  return { j, shape };
}

// Security 12247 nit: the KDF parameters come from the file, so a planted store could make our own tool hang. Cap
// them at what upstream writes (file_encrypted.rs:86-88 at 34bbdea4: KDF_MEMORY_KIB 64*1024, KDF_ITERATIONS 3,
// KDF_PARALLELISM 4); anything above, or not a positive integer, refuses before Argon2 runs.
export const KDF_CAP = { memory_kib: 65536, iterations: 3, parallelism: 4 };
export function checkKdf(kdf) {
  if (!kdf || kdf.algo !== 'argon2id') throw new Error('unsupported kdf');
  for (const [k, max] of Object.entries(KDF_CAP)) {
    const v = kdf[k];
    if (!Number.isInteger(v) || v < 1 || v > max) throw new Error(`kdf ${k} outside 1..${max}`);
  }
}

export function deriveKey(passphrase, kdf) {
  checkKdf(kdf);
  return Buffer.from(argon2id(Buffer.from(passphrase), b64u(kdf.salt_b64), {
    t: kdf.iterations, m: kdf.memory_kib, p: kdf.parallelism, dkLen: KEY_BYTES, version: 0x13,
  }));
}

function openAead(key, nonce, ct, aad) {
  if (ct.length < 16) throw new Error('short ciphertext');
  const d = crypto.createDecipheriv('aes-256-gcm', key, nonce);
  d.setAAD(aad);
  d.setAuthTag(ct.subarray(ct.length - 16));
  return Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]);
}

function seal(key, pt, aad) {
  const nonce = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, nonce);
  c.setAAD(aad);
  const ct = Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]);
  return { nonce_b64: nonce.toString('base64url'), ciphertext_b64: ct.toString('base64url') };
}

// The passphrase as the mediator reads it from MEDIATOR_FILE_BACKEND_PASSPHRASE_FILE: whole file, trimmed.
export function readPassphrase(file) {
  const p = fs.readFileSync(file, 'utf8').trim();
  if (!p) throw new Error('empty passphrase file');
  return p;
}

// true when the passphrase opens the verifier (the mediator's own wrong-passphrase check) and every entry.
export function opens(j, passphrase) {
  try {
    const key = deriveKey(passphrase, j.kdf);
    const v = openAead(key, b64u(j.verifier_nonce_b64), b64u(j.verifier_b64), VERIFIER_AAD);
    if (!v.equals(Buffer.alloc(32))) return false;
    for (const [k, e] of Object.entries(j.entries)) openAead(key, b64u(e.nonce_b64), b64u(e.ciphertext_b64), entryAad(k));
    return true;
  } catch { return false; }
}

// ship:drop-begin (Security 12940 change 1: the one-value open, used only by admin-out; never in the shipped tool)
export function getEntry(j, shape, passphrase, name) {
  const e = j.entries[name];
  if (e === undefined) return null;
  if (shape === 'plain') return b64u(String(e)); // file.rs: values base64url-encoded
  const key = deriveKey(passphrase, j.kdf);
  return openAead(key, b64u(e.nonce_b64), b64u(e.ciphertext_b64), entryAad(name));
}
// ship:drop-end

// Security 12024.2 (b): the new store is written to a temp file in the SAME directory (so the same volume), fsynced,
// renamed over the store, then the directory is fsynced so the rename itself is durable. A run killed at any point
// leaves exactly one whole store: the old one up to the rename, the new one from it. `guard`, when given, runs just
// before the rename; if it throws, the temp file is removed and the store is left as it was.
const TEMP_NAME = (base) => new RegExp(`^\\.${base.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\.[0-9]+\\.[0-9a-f]{8}$`);
function writeAtomic(file, obj, guard = null) {
  const dir = path.dirname(file);
  const tmp = path.join(dir, `.${path.basename(file)}.${process.pid}.${crypto.randomBytes(4).toString('hex')}`);
  const fd = fs.openSync(tmp, 'wx', 0o600);
  try { fs.writeSync(fd, JSON.stringify(obj, null, 2)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  try {
    fs.chmodSync(tmp, 0o600);
    if (guard) guard();
  } catch (e) { fs.rmSync(tmp, { force: true }); throw e; }
  // Security 12197 change B: a second run removes a stale temp before it reads, so it can remove ours in flight. The
  // store is then still the old one, whole; say so in words rather than a raw ENOENT.
  try { fs.renameSync(tmp, file); } catch (e) {
    if (e?.code === 'ENOENT' && !fs.existsSync(tmp)) throw new Error('the temp was removed under us (a second run?); nothing written');
    throw e;
  }
  const dfd = fs.openSync(dir, 'r');
  try { fs.fsyncSync(dfd); } finally { fs.closeSync(dfd); }
}

// What identifies the store's bytes on disk between the read and the rename (Security 12024.2 (c)): a second writer
// changes at least one of these. Railway's one-deployment-per-volume lock is the real guard; this is the tripwire.
const storeStamp = (file) => { const st = fs.statSync(file, { bigint: true }); return `${st.dev}:${st.ino}:${st.size}:${st.mtimeNs}:${st.ctimeNs}`; };

// Security 12024.1: the rekey run's environment, exact. The entrypoint `exec env -i`s the tool with only these; the
// tool reads the kernel's copy of its own environment (never process.env, which node can be told to shape) and
// refuses on any other name, a missing one, or a path that isn't the argument it was given. Names only, never values.
// Security 12197 change A: "exactly" covers the two fixed values too: PATH is the entrypoint's own, HOME is the image's
// empty <the tool's dir>/home (args.home); any other value refuses (named in value_not_allowed, never printed).
export const REKEY_ENV = ['HOME', 'PATH', 'REKEY_NEW_PASSPHRASE_FILE', 'REKEY_OLD_PASSPHRASE_FILE', 'REKEY_STORE'];
export const REKEY_PATH = '/usr/local/bin:/usr/bin:/bin';
export const rekeyHome = () => path.join(path.dirname(fs.realpathSync(fileURLToPath(import.meta.url))), 'home');
export function rekeyEnvironVerdict(environ, args) {
  const pairs = environ.split('\0').filter(Boolean).map((kv) => { const i = kv.indexOf('='); return i < 0 ? [kv, ''] : [kv.slice(0, i), kv.slice(i + 1)]; });
  const names = pairs.map(([k]) => k);
  const plain = (n) => /^[A-Za-z_][A-Za-z0-9_]*$/.test(n);
  const extra = names.filter((n) => !REKEY_ENV.includes(n));
  const missing = REKEY_ENV.filter((n) => !names.includes(n));
  const dup = names.filter((n, i) => names.indexOf(n) !== i);
  const val = Object.fromEntries(pairs);
  const mismatch = [['REKEY_STORE', args.store], ['REKEY_OLD_PASSPHRASE_FILE', args.old], ['REKEY_NEW_PASSPHRASE_FILE', args.new]]
    .filter(([k, v]) => names.includes(k) && val[k] !== v).map(([k]) => k);
  const fixed = [['HOME', args.home], ['PATH', REKEY_PATH]].filter(([k, v]) => names.includes(k) && (typeof v !== 'string' || val[k] !== v)).map(([k]) => k);
  return { ok: !extra.length && !missing.length && !dup.length && !mismatch.length && !fixed.length,
    extra: extra.filter(plain).sort(), extra_not_plain: extra.filter((n) => !plain(n)).length, missing, duplicated: [...new Set(dup)], not_the_argument: mismatch, value_not_allowed: fixed };
}

// ship:drop-begin
// Removes ADMIN_CREDENTIAL and nothing else. Returns a names-only record. Throws (and writes nothing) if the result
// would differ from the original in anything but that one entry, or if an encrypted store no longer opens.
export function deleteAdmin(file, passphrase) {
  const { j, shape } = readStore(file);
  const before = Object.keys(j.entries).sort();
  const had = before.includes(ADMIN_CREDENTIAL);
  if (shape === 'encrypted' && !opens(j, passphrase)) throw new Error('the passphrase does not open the store');
  const next = JSON.parse(JSON.stringify(j));
  delete next.entries[ADMIN_CREDENTIAL];
  // Everything but the one entry byte-identical (header, kdf, verifier, every other sealed entry).
  const strip = (o) => { const c = JSON.parse(JSON.stringify(o)); delete c.entries[ADMIN_CREDENTIAL]; return JSON.stringify(c); };
  if (strip(j) !== JSON.stringify(next)) throw new Error('delete would change more than the admin credential');
  if (shape === 'encrypted' && !opens(next, passphrase)) throw new Error('the store would no longer open');
  if (had) writeAtomic(file, next);
  const after = readStore(file);
  const afterNames = Object.keys(after.j.entries).sort();
  const others = before.filter((n) => n !== ADMIN_CREDENTIAL);
  const othersUnchanged = others.every((n) => JSON.stringify(after.j.entries[n]) === JSON.stringify(j.entries[n]));
  return {
    shape, had_admin_credential: had, entries_before: before.length, entries_after: afterNames.length,
    removed: had ? [ADMIN_CREDENTIAL] : [], others_unchanged: othersUnchanged,
    admin_credential_present: afterNames.includes(ADMIN_CREDENTIAL),
    still_opens: shape === 'encrypted' ? opens(after.j, passphrase) : null,
    mode: (fs.statSync(file).mode & 0o777).toString(8),
  };
}

// ship:drop-end
export function rekey(file, oldPass, newPass) {
  // A temp left by a run killed before its rename is ours (same directory, our exact name shape) and holds the store
  // re-sealed under a passphrase that never went live: remove it before anything else, and say how many.
  const re = TEMP_NAME(path.basename(file));
  let staleTemps = 0;
  for (const n of fs.readdirSync(path.dirname(file))) {
    if (!re.test(n)) continue;
    const p = path.join(path.dirname(file), n);
    if (!fs.lstatSync(p).isFile()) throw new Error('a non-file with the temp name sits beside the store');
    fs.rmSync(p); staleTemps += 1;
  }
  const stamp = storeStamp(file);
  const { j, shape } = readStore(file);
  if (shape !== 'encrypted') throw new Error('not an encrypted store');
  // Security 12247 (i)(a): a rotation must never re-seal the one entry we delete.
  if (Object.prototype.hasOwnProperty.call(j.entries, ADMIN_CREDENTIAL)) throw new Error('mediator_admin_credential is still in the store; delete it first');
  if (!opens(j, oldPass)) throw new Error('the old passphrase does not open the store');
  const oldKey = deriveKey(oldPass, j.kdf);
  const values = {};
  for (const [k, e] of Object.entries(j.entries)) values[k] = openAead(oldKey, b64u(e.nonce_b64), b64u(e.ciphertext_b64), entryAad(k));
  sealStore(file, newPass, values, j.kdf, () => {
    if (storeStamp(file) !== stamp) throw new Error('the store changed between the read and the rename (a second writer?); nothing written');
  });
  const after = readStore(file).j;
  const newKey = deriveKey(newPass, after.kdf);
  const same = Object.keys(values).length === Object.keys(after.entries).length && Object.entries(values).every(([k, v]) => {
    const e = after.entries[k]; return e && openAead(newKey, b64u(e.nonce_b64), b64u(e.ciphertext_b64), entryAad(k)).equals(v);
  });
  return { entries: Object.keys(after.entries).sort(), values_unchanged: same, salt_changed: after.kdf.salt_b64 !== j.kdf.salt_b64,
    old_opens: opens(after, oldPass), new_opens: opens(after, newPass), mode: (fs.statSync(file).mode & 0o777).toString(8), stale_temps_removed: staleTemps };
}

function sealStore(file, passphrase, values, like = null, guard = null) {
  const salt = crypto.randomBytes(16);
  const kdf = { algo: 'argon2id', salt_b64: salt.toString('base64url'), memory_kib: like?.memory_kib ?? KDF_CAP.memory_kib,
    iterations: like?.iterations ?? KDF_CAP.iterations, parallelism: like?.parallelism ?? KDF_CAP.parallelism };
  const key = deriveKey(passphrase, kdf);
  const v = seal(key, Buffer.alloc(32), VERIFIER_AAD);
  const entries = {};
  for (const [k, val] of Object.entries(values)) entries[k] = seal(key, Buffer.isBuffer(val) ? val : Buffer.from(val), entryAad(k));
  writeAtomic(file, { version: 1, kdf, verifier_nonce_b64: v.nonce_b64, verifier_b64: v.ciphertext_b64, entries }, guard);
}

// ship:drop-begin
export const sealTest = sealStore;
// ship:drop-end

async function main(argv) {
  const [cmd, store, a, b] = argv;
  const say = (o) => console.log(JSON.stringify(o));
  switch (cmd) {
    case 'names': {
      const { j, shape } = readStore(store);
      const entries = Object.keys(j.entries).sort();
      say({ shape, entries, admin_credential_present: entries.includes(ADMIN_CREDENTIAL) });
      return 0;
    }
    case 'absent': {
      const { j } = readStore(store);
      const present = Object.prototype.hasOwnProperty.call(j.entries, ADMIN_CREDENTIAL);
      say({ admin_credential_present: present });
      return present ? 3 : 0;
    }
    case 'opens': {
      const { j, shape } = readStore(store);
      if (shape !== 'encrypted') { say({ shape, opens: false, why: 'not an encrypted store' }); return 4; }
      const ok = opens(j, readPassphrase(a));
      say({ shape, opens: ok });
      return ok ? 0 : 4;
    }
      // ship:drop-begin
    case 'delete-admin': {
      const { shape } = readStore(store);
      const r = deleteAdmin(store, shape === 'encrypted' ? readPassphrase(a) : null);
      say(r);
      return !r.admin_credential_present && r.others_unchanged && r.still_opens !== false ? 0 : 1;
    }
    case 'admin-out': {
      // Security 12247 change 3: <out> only on tmpfs under /dev/shm, never under a results/ (artifact) path; the
      // setup job removes it right after the admin calls and fails if it is still there at the end.
      const outAbs = path.resolve(b || '');
      const real = fs.realpathSync(path.dirname(outAbs));
      if (!b || !real.startsWith('/dev/shm/') || real.split('/').includes('results') || outAbs.split('/').includes('results')) {
        say({ refused: 'admin-out goes only under /dev/shm, never under results/' }); return 5;
      }
      const { j, shape } = readStore(store);
      const v = getEntry(j, shape, shape === 'encrypted' ? readPassphrase(a) : null, ADMIN_CREDENTIAL);
      if (!v) { say({ admin_credential_present: false }); return 3; }
      const fd = fs.openSync(b, 'wx', 0o600);
      try { fs.writeSync(fd, v); } finally { fs.closeSync(fd); }
      let method = null, fragments = 0;
      try { const c = JSON.parse(v.toString('utf8')); method = String(c.did || '').split(':').slice(0, 2).join(':'); fragments = (String(c.did || '').match(/#/g) || []).length; } catch { /* names only */ }
      say({ admin_credential_present: true, did_method: method, did_fragments: fragments });
      return 0;
    }
      // ship:drop-end
    case 'rekey': {
      let environ;
      try { environ = fs.readFileSync('/proc/self/environ', 'latin1'); } catch { say({ refused: 'cannot read /proc/self/environ' }); return 6; }
      const ev = rekeyEnvironVerdict(environ, { store, old: a, new: b, home: rekeyHome() });
      if (!ev.ok) { say({ refused: 'the rekey environment is not exactly the allow list', ...ev }); return 6; }
      const r = rekey(store, readPassphrase(a), readPassphrase(b));
      say(r);
      return r.values_unchanged && r.salt_changed && !r.old_opens && r.new_opens ? 0 : 1;
    }
      // ship:drop-begin
    case 'encrypt-test': {
      const { j, shape } = readStore(store);
      if (shape !== 'plain') { say({ refused: 'not a plain store' }); return 1; }
      const values = Object.fromEntries(Object.entries(j.entries).map(([k, v]) => [k, b64u(String(v))]));
      sealTest(store, readPassphrase(a), values);
      const after = readStore(store);
      say({ shape: after.shape, entries: Object.keys(after.j.entries).sort(), opens: opens(after.j, readPassphrase(a)) });
      return after.shape === 'encrypted' && opens(after.j, readPassphrase(a)) ? 0 : 1;
    }
    case 'seal-test': {
      sealTest(store, readPassphrase(a), JSON.parse(b));
      say({ written: true });
      return 0;
    }
      // ship:drop-end
    default:
      console.error('usage: mediator-store.mjs <subcommand> <store> …');
      return 2;
  }
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('mediator-store.mjs')) {
  main(process.argv.slice(2)).then((c) => process.exit(c), (e) => { console.error(`mediator-store: ${e.message}`); process.exit(1); });
}
