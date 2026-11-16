#!/usr/bin/env node
// Every private key of the admin DID, taken as one admin key (Security 12582.2(b)/(c); Railroad 12567.2).
// Read at 0.50.0 @ 34bbdea4: `mediator_admin_credential` is AdminCredential { did, private_key_multibase, … }
// (affinidi-messaging-mediator-common/src/secrets/well_known.rs:109-128): ONE private key. On the self-hosted path
// (`admin = "generate"`, tools/mediator-setup/src/main.rs:1650-1665) the admin is a freshly minted did:key:z6Mk…
// (Ed25519; admin_monitor_profile.rs:6-8), whose document also names an X25519 keyAgreement key. That X25519 key is
// not stored anywhere else: it is derived from the same Ed25519 seed. So the credential holds every private key the
// document names, once this module proves each public key in the document comes out of the credential's key.
// Setup ALSO writes `admin-monitor.json` (the admin's secret, 0600) beside the conf (main.rs:1786-1822,
// admin_monitor_profile.rs:58-80): a second place the admin key lives. It joins the surgical delete and the absence
// check; its own secret values become markers too, in whatever encoding it wrote them.
//
//   markers <admin-out credential.json> <out markers file> <out planted dir> [admin-monitor.json] → JSON summary
// The summary carries names and counts only: key ids' fragments are public, values and hash prefixes never printed.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import * as dc from '@openvtc/vti-didcomm-js'
import { b58 } from './lib.mjs'

const ED_PRIV = [0x80, 0x26] // multicodec ed25519-priv 0x1300
const X_PRIV = [0x82, 0x26] // multicodec x25519-priv 0x1302
const b64u = (b) => Buffer.from(b).toString('base64url')
const b64 = (b) => Buffer.from(b).toString('base64')
const hexOf = (b) => Buffer.from(b).toString('hex')
const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i])

// The Ed25519 seed out of a private_key_multibase: z + base58btc, with or without the ed25519-priv prefix,
// 32 bytes (seed) or 64 (seed ‖ public).
// Errors carry a fixed code and shape facts only (never a value: a JSON.parse message quotes the text it read).
export class KeyError extends Error { constructor(code, shape = {}) { super(code); this.code = code; this.shape = shape } }
export function seedOf(mb) {
  if (typeof mb !== 'string') throw new KeyError('key-not-a-string', { type: typeof mb })
  if (!mb.startsWith('z')) throw new KeyError('key-not-base58btc-multibase', { first_char_class: /[A-Za-z]/.test(mb[0] ?? '') ? 'letter' : 'other', length: mb.length })
  let raw
  try { raw = dc.multibase.base58btcDecode(mb.slice(1)) } catch { throw new KeyError('key-not-base58', { length: mb.length }) }
  const prefixed = raw[0] === ED_PRIV[0] && raw[1] === ED_PRIV[1]
  if (prefixed) raw = raw.slice(2)
  if (raw.length !== 32 && raw.length !== 64) throw new KeyError('key-wrong-length', { decoded_bytes: raw.length, ed25519_priv_prefix: prefixed, first_two_bytes_are_varint: (raw[1] & 0x80) === 0 && ((raw[0] ?? 0) & 0x80) !== 0 })
  return raw.slice(0, 32)
}

const docOf = (did) => {
  try { return (did.startsWith('did:peer:') ? dc.didPeer.resolve(did) : dc.didKey.resolve(did)).didDocument }
  catch { throw new KeyError('did-unresolvable', { did_method: did.split(':').slice(0, 2).join(':') }) }
}
const pubOf = (vm) => {
  const raw = dc.multibase.base58btcDecode(String(vm.publicKeyMultibase ?? '').slice(1))
  return raw.slice(2) // drop the 2-byte multicodec (0xed01 Ed25519, 0xec01 X25519)
}
const kindOf = (vm) => { const mb = String(vm.publicKeyMultibase ?? ''); return mb.startsWith('z6Mk') ? 'ed25519' : mb.startsWith('z6LS') ? 'x25519' : 'unknown' }

// The encodings a store, an SDK or a profile writes a private key in. Each is a marker; each must self-hit.
export function encodings(kind, priv) {
  const pre = kind === 'ed25519' ? ED_PRIV : X_PRIV
  const mb = 'z' + b58(Uint8Array.from([...pre, ...priv]))
  const out = { multibase: mb, multibase_no_prefix: mb.slice(1), multibase_bare: 'z' + b58(priv), jwk_d: b64u(priv), base64: b64(priv), hex: hexOf(priv) }
  if (kind === 'ed25519') {
    const full = Uint8Array.from([...priv, ...ed25519.getPublicKey(priv)])
    out.multibase_64 = 'z' + b58(Uint8Array.from([...pre, ...full]))
    out.base64_64 = b64(full)
  }
  return out
}

// Every string value under a key-material member of a profile JSON (d, privateKeyMultibase, …), at any depth.
const SECRET_NAMES = /^(d|privateKeyMultibase|private_key_multibase|privateKey|secret|secret_material|privateKeyJwk|privateKeyBase58|privateKeyHex)$/i
export function profileSecrets(v, out = []) {
  if (Array.isArray(v)) for (const x of v) profileSecrets(x, out)
  else if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) {
    if (typeof x === 'string') { if (SECRET_NAMES.test(k) && x.length >= 16) out.push(x) }
    else profileSecrets(x, out) // privateKeyJwk: { d } is caught one level down
  }
  return out
}

export const unwrap = (c) => (c && typeof c === 'object' && c.kind === 'admin-credential' && c.data && typeof c.data === 'object' ? c.data : c)

// The admin DID's keys, each matched to a private key the credential yields. Red when a key in the document
// matches none: then a private key lives somewhere the credential doesn't, and the job is red until it's found.
export function adminKeys(cred) {
  cred = unwrap(cred)
  const did = String(cred?.did ?? '')
  const seed = seedOf(cred?.private_key_multibase)
  const doc = docOf(did)
  const ids = new Set([...(doc.verificationMethod ?? []).map((m) => m.id), ...['authentication', 'assertionMethod', 'keyAgreement', 'capabilityInvocation', 'capabilityDelegation'].flatMap((r) => (doc[r] ?? []).map((x) => (typeof x === 'string' ? x : x.id)))])
  const byId = new Map((doc.verificationMethod ?? []).map((m) => [m.id, m]))
  const edPub = ed25519.getPublicKey(seed), xPriv = ed25519.utils.toMontgomerySecret(seed), xPub = x25519.getPublicKey(xPriv)
  const keys = []
  for (const id of ids) {
    const vm = byId.get(id); const kind = vm ? kindOf(vm) : 'unknown'
    const pub = vm ? pubOf(vm) : new Uint8Array()
    const priv = kind === 'ed25519' && same(pub, edPub) ? seed : kind === 'x25519' && same(pub, xPub) ? xPriv : null
    keys.push({ fragment: id.split('#')[1] ?? '', kind, held_by_credential: !!priv, derived: kind === 'x25519' && !!priv, priv })
  }
  return { did_method: did.split(':').slice(0, 2).join(':'), keys }
}

export function markers(cred, profile = null) {
  const { did_method, keys } = adminKeys(cred)
  const list = [], planted = []
  for (const k of keys) if (k.priv) for (const [enc, value] of Object.entries(encodings(k.kind, k.priv))) { list.push(value); planted.push({ kind: k.kind, encoding: enc, value }) }
  const fromProfile = profile ? profileSecrets(profile) : []
  for (const value of fromProfile) { list.push(value); planted.push({ kind: 'profile', encoding: 'as written', value }) }
  return {
    did_method,
    keys: keys.map(({ priv, ...k }) => k),
    every_document_key_held: keys.length > 0 && keys.every((k) => k.held_by_credential),
    kinds: [...new Set(keys.map((k) => k.kind))].sort(),
    profile_values: fromProfile.length,
    markers: [...new Set(list)],
    planted,
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const [cmd, credPath, marksOut, plantDir, profilePath] = process.argv.slice(2)
  if (cmd !== 'markers' || !credPath || !marksOut || !plantDir) { console.error('usage: admin-key-markers.mjs markers <credential.json> <markers out> <planted dir> [admin-monitor.json]'); process.exit(2) }
  let summary
  try {
    let text, cred
    try { text = readFileSync(credPath, 'utf8') } catch { throw new KeyError('credential-unreadable') }
    try { cred = JSON.parse(text) } catch { throw new KeyError('credential-not-json', { bytes: text.length }) }
    if (!cred || typeof cred !== 'object') throw new KeyError('credential-not-an-object')
    // admin-out writes the store's entry as sealed: Envelope { version, kind: "admin-credential", data, created_at }
    // (secrets/envelope.rs:25-36, well_known.rs:85,454); the AdminCredential is its `data`.
    cred = unwrap(cred)
    const fields = Object.keys(cred).sort()
    if (typeof cred.did !== 'string' || !('private_key_multibase' in cred)) throw new KeyError('credential-shape', { fields })
    let profile = null
    if (profilePath) { try { profile = JSON.parse(readFileSync(profilePath, 'utf8')) } catch {} }
    const m = markers(cred, profile)
    writeFileSync(marksOut, m.markers.join('\n') + (m.markers.length ? '\n' : ''), { mode: 0o600 })
    mkdirSync(plantDir, { recursive: true, mode: 0o700 })
    m.planted.forEach((p, i) => writeFileSync(join(plantDir, `planted-${i}-${p.kind}-${p.encoding.replace(/\W+/g, '_')}.txt`), `noise before ${p.value} noise after\n`, { mode: 0o600 }))
    summary = { ok: true, did_method: m.did_method, keys: m.keys, every_document_key_held: m.every_document_key_held, kinds: m.kinds, markers: m.markers.length, planted: m.planted.length, profile_values: m.profile_values }
  } catch (e) {
    summary = e instanceof KeyError ? { ok: false, error: e.code, shape: e.shape } : { ok: false, error: 'internal', where: String(e?.name ?? 'Error') }
  }
  console.log(JSON.stringify(summary))
  process.exit(summary.ok ? 0 : 1)
}
