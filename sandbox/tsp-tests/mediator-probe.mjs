#!/usr/bin/env node
// ref/09 §2.4 steps 1-2, first cut (open mode only): B sends A a routed frame through the local mediator over
// POST /inbound; A signs in over TSP and collects by REST (no websocket), opens it, then deletes it.
// Usage: node mediator-probe.mjs <mediator base url, e.g. http://127.0.0.1:7037/mediator/v1> <mediator VID>
// Test keys only: A and B are made here and die with the process.
import * as tsp from '@openvtc/vti-tsp-js'
import { ed25519 } from '@noble/curves/ed25519.js'
import { b58, utf8, eq } from './lib.mjs'

const [base, mediatorVid] = process.argv.slice(2)
const ALPHA = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
const unb58 = (s) => { let n = 0n; for (const c of s) n = n * 58n + BigInt(ALPHA.indexOf(c)); let h = n.toString(16); if (h.length % 2) h = '0' + h; return new Uint8Array(Buffer.from(h, 'hex')) }
// did:peer:2: .V = Ed25519 (0xed01), .E = X25519 (0xec01)
function peer2Keys(did) {
  const parts = did.replace(/^did:peer:2/, '').split('.').filter(Boolean)
  const pick = (p, code) => { const m = parts.find((x) => x.startsWith(p)); if (!m) return null; const b = unb58(m.slice(2)); if (b[0] !== code || b[1] !== 0x01) throw new Error('unexpected multikey ' + m.slice(0, 8)); return b.slice(2) }
  return { spk: pick('Vz', 0xed), epk: pick('Ez', 0xec) }
}
// A did:key VID whose X25519 key is the one did:key derives from its Ed25519 key (what the mediator will resolve).
function keyVid() {
  const sk = ed25519.utils.randomSecretKey(); const spk = ed25519.getPublicKey(sk)
  return { id: 'did:key:z' + b58(new Uint8Array([0xed, 0x01, ...spk])), sk, spk, dk: ed25519.utils.toMontgomerySecret(sk), epk: ed25519.utils.toMontgomery(spk) }
}
async function post(path, body, token, type = 'application/json') {
  const r = await fetch(base + path, { method: 'POST', headers: { 'content-type': type, ...(token ? { authorization: 'Bearer ' + token } : {}) }, body })
  const text = await r.text(); let json = null; try { json = JSON.parse(text) } catch {}
  return { status: r.status, json, text }
}
async function signIn(v) {
  const t0 = performance.now()
  const c = await post('/authenticate/challenge', JSON.stringify({ did: v.id }))
  if (c.status !== 200) return { ok: false, step: 'challenge', status: c.status, body: c.text.slice(0, 300) }
  const { challenge, session_id } = c.json.data
  const sig = Buffer.from(ed25519.sign(utf8(challenge), v.sk)).toString('base64url')
  const a = await post('/tsp/authenticate', JSON.stringify({ vid: v.id, session_id, signature: sig }))
  if (a.status !== 200) return { ok: false, step: 'tsp/authenticate', status: a.status, body: a.text.slice(0, 300) }
  return { ok: true, token: a.json.data.access_token, ms: Math.round(performance.now() - t0) }
}

const med = peer2Keys(mediatorVid)
const A = keyVid(); const B = keyVid()
const log = (k, v) => console.log(k.padEnd(28), typeof v === 'string' ? v : JSON.stringify(v))
const sb = await signIn(B); log('B sign-in', sb.ok ? `ok ${sb.ms} ms` : sb)
const sa = await signIn(A); log('A sign-in (registers A)', sa.ok ? `ok ${sa.ms} ms` : sa)
if (!sb.ok || !sa.ok) process.exit(1)

const body = utf8(JSON.stringify({ type: 'https://trusttasks.org/messaging/ping/0.2', id: 'urn:uuid:' + crypto.randomUUID() }))
const inner = await tsp.pack(body, B.id, A.id, { senderSigningKey: B.sk, receiverEncryptionKey: A.epk })
const outer = await tsp.packRouted(inner.bytes, [A.id], B.id, mediatorVid, { senderSigningKey: B.sk, receiverEncryptionKey: med.epk })
const sent = await post('/inbound', outer.bytes, sb.token, 'application/tsp')
log('B → /inbound (routed)', { status: sent.status, body: sent.text.slice(0, 300) })

const t1 = performance.now()
const got = await post('/fetch', JSON.stringify({ limit: 10, delete_policy: 'DoNotDelete' }), sa.token)
log('A /fetch', { status: got.status, ms: Math.round(performance.now() - t1), body: got.text.slice(0, 600) })
const list = got.json?.data?.success ?? []
for (const m of list) {
  const raw = m.msg ?? ''
  let bytes = null
  for (const dec of [(s) => Buffer.from(s, 'base64url'), (s) => Buffer.from(s, 'base64'), (s) => Buffer.from(s, 'latin1')]) { try { const b = new Uint8Array(dec(raw)); if (tsp.isTsp(b)) { bytes = b; break } } catch {} }
  if (!bytes) { log('A opens', `not a TSP frame in msg (${raw.slice(0, 40)}…)`); continue }
  try {
    const u = await tsp.unpack(bytes, { receiverDecryptionKey: A.dk, senderSigningKey: B.spk })
    log('A opens', { type: u.messageType, sender: u.sender === B.id, bodyUnchanged: eq(u.payload, body) })
  } catch (e) { log('A opens', 'refused: ' + e.message) }
}

// Acknowledge: delete what was collected (REST `DELETE /delete`), then fetch again: it must be gone.
const ids = list.map((m) => m.msg_id)
if (ids.length) {
  const r = await fetch(base + '/delete', { method: 'DELETE', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + sa.token }, body: JSON.stringify({ message_ids: ids }) })
  log('A /delete', { status: r.status, body: (await r.text()).slice(0, 300) })
  const again = await post('/fetch', JSON.stringify({ limit: 10, delete_policy: 'DoNotDelete' }), sa.token)
  log('A /fetch after delete', { status: again.status, left: (again.json?.data?.success ?? []).filter((m) => ids.includes(m.msg_id)).length })
}
