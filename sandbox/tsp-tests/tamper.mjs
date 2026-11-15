#!/usr/bin/env node
// ref/09 §2.5 `tamper`: broken frames offered to both implementations. Reads <resultsdir>/frames.json from `roundtrip`.
// (a)-(f): every implementation must refuse. (g)-(j): the library may open the frame; we record what it returns, because
// Enkara's own handler must refuse those (its suite asserts it). Usage: node tamper.mjs <resultsdir>
import { join } from 'node:path'
import * as tsp from '@openvtc/vti-tsp-js'
import * as rev3 from 'vti-tsp-js-rev3'
import { makeVid, signedPing, utf8, envelope, openEnvelope, verifyProof, b64, unb64, hex, rustPeer, recorder, readJson } from './lib.mjs'

const results = process.argv[2] ?? 'results'
const R = recorder('tamper')
const fr = readJson(join(results, 'frames.json'))
const k = (o) => Object.fromEntries(Object.entries(o).map(([n, v]) => [n, n === 'id' ? v : new Uint8Array(Buffer.from(v, 'hex'))]))
const ts = k(fr.keys.ts); const ru = k(fr.keys.ru)
const rs = rustPeer(); await rs.private(ru); await rs.remote(ts)
const table = []

// Offer bytes to TS (as receiver ts, from ru) or Rust (as receiver ru, from ts). Returns 'refused: …' or 'opened'.
async function tsOpen(bytes, from = ru) { try { const u = await tsp.unpack(bytes, { receiverDecryptionKey: ts.dk, senderSigningKey: from.spk }); return { opened: true, u } } catch (e) { return { opened: false, why: `${e.code ?? e.name}: ${e.message}`.slice(0, 160) } } }
async function rsOpen(bytes, from = ts) { const r = await rs.call({ op: 'unpack', bytes: b64(bytes), dk: hex(ru.dk), spk: hex(from.spk) }); return r.ok ? { opened: true, r: r.r } : { opened: false, why: r.error.slice(0, 160) } }
const flip = (bytes, i) => { const c = new Uint8Array(bytes); c[i] ^= 0x01; return c }
function mustRefuse(name, impl, res) { table.push({ case: name, impl, result: res.opened ? 'OPENED' : 'refused', detail: res.why ?? '' }); R.check(`${name} — ${impl} refuses`, !res.opened, res.why ?? 'it opened') }
function record(name, impl, res, note) { table.push({ case: name, impl, result: res.opened ? 'opened' : 'refused', detail: note ?? res.why ?? '' }); R.answer(`${name} — ${impl}`, (res.opened ? 'opened; ' : 'refused; ') + (note ?? res.why ?? '')) }

const toRust = unb64(fr.tsToRust.bytes) // ts -> ru
const toTs = unb64(fr.rustToTs.bytes)   // ru -> ts
const at = (bytes, s) => { const n = utf8(s); for (let i = 0; i + n.length <= bytes.length; i++) if (n.every((x, j) => bytes[i + j] === x)) return i; return -1 }

// (a) one byte in the sender VID (the last character of the did:key, inside the frame's clear envelope)
{
  const i1 = at(toRust, ts.id); const i2 = at(toTs, ru.id)
  R.check('(a) sender VID found in the clear envelope', i1 >= 0 && i2 >= 0, `offsets ${i1}, ${i2}`)
  mustRefuse('(a) one byte in the sender VID', 'Rust', await rsOpen(flip(toRust, i1 + ts.id.length - 1)))
  mustRefuse('(a) one byte in the sender VID', 'TS', await tsOpen(flip(toTs, i2 + ru.id.length - 1)))
}
// (b) one byte in the sealed payload (well inside the ciphertext: 40 bytes before the 64-byte signature and its code)
mustRefuse('(b) one byte in the sealed payload', 'Rust', await rsOpen(flip(toRust, toRust.length - 64 - 40)))
mustRefuse('(b) one byte in the sealed payload', 'TS', await tsOpen(flip(toTs, toTs.length - 64 - 40)))
// (c) one byte in the signature (the last byte of the frame)
mustRefuse('(c) one byte in the signature', 'Rust', await rsOpen(flip(toRust, toRust.length - 1)))
mustRefuse('(c) one byte in the signature', 'TS', await tsOpen(flip(toTs, toTs.length - 1)))
// (d) a valid frame addressed to a different receiver, offered with our keys
{
  const other = makeVid()
  const p = await tsp.pack(utf8('for someone else'), ts.id, other.id, { senderSigningKey: ts.sk, receiverEncryptionKey: other.epk })
  mustRefuse('(d) addressed to a different receiver', 'Rust (codec)', await rsOpen(p.bytes))
  const ag = await rs.call({ op: 'receive', our: ru.id, bytes: b64(p.bytes) })
  mustRefuse('(d) addressed to a different receiver', 'Rust (agent)', ag.ok ? { opened: true } : { opened: false, why: ag.error })
  const q = await rs.call({ op: 'pack', payload: b64(utf8('for someone else')), from: ru.id, to: other.id, sk: hex(ru.sk), epk: hex(other.epk) })
  mustRefuse('(d) addressed to a different receiver', 'TS', await tsOpen(unb64(q.r.bytes)))
}
// (e) the same frame twice: does the library catch the replay, or leave it to us? (Enkara guards either way.)
{
  const inv = await tsp.packInvite(ts.id, ru.id, { senderSigningKey: ts.sk, receiverEncryptionKey: ru.epk })
  await rs.ok({ op: 'receive', our: ru.id, bytes: b64(inv.bytes) }); await rs.ok({ op: 'accept', from: ru.id, to: ts.id })
  const app = await tsp.pack(utf8('once'), ts.id, ru.id, { senderSigningKey: ts.sk, receiverEncryptionKey: ru.epk })
  const r1 = await rs.call({ op: 'receive', our: ru.id, bytes: b64(app.bytes) }); const r2 = await rs.call({ op: 'receive', our: ru.id, bytes: b64(app.bytes) })
  record('(e) the same frame twice', 'Rust (agent)', r2.ok ? { opened: true } : { opened: false, why: r2.error }, `first ${r1.ok ? 'opened' : 'refused'}, second ${r2.ok ? 'opened: the library leaves replay to the caller' : 'refused: ' + r2.error}`)
  const t1 = await tsOpen(toTs); const t2 = await tsOpen(toTs)
  record('(e) the same frame twice', 'TS (codec)', t2, `first ${t1.opened ? 'opened' : 'refused'}, second ${t2.opened ? 'opened: the codec leaves replay to the caller' : 'refused: ' + t2.why}`)
}
// (f) a real Rev 3 frame (packed by @openvtc/vti-tsp-js 0.3.0, which packs Rev 3) offered to the 1.0 unpackers
{
  const r3toRu = await rev3.pack(utf8('rev 3'), ts.id, ru.id, { senderSigningKey: ts.sk, receiverEncryptionKey: ru.epk })
  const r3toTs = await rev3.pack(utf8('rev 3'), ru.id, ts.id, { senderSigningKey: ru.sk, receiverEncryptionKey: ts.epk })
  const code = Buffer.from(r3toRu.bytes.slice(0, 12)).toString('base64url').match(/YTSP-[A-Za-z0-9_-]{3}/)?.[0]
  R.check('(f) the Rev 3 frame carries YTSP-AAC', code === 'YTSP-AAC', String(code))
  mustRefuse('(f) a Rev 3 frame', 'Rust', await rsOpen(r3toRu.bytes))
  mustRefuse('(f) a Rev 3 frame', 'TS', await tsOpen(r3toTs.bytes))
}
// (g)-(j): frames that open, carrying documents Enkara must refuse. Check what the library returns and that the
// harness's own envelope/proof checks (the shape Enkara's handler will take) catch each one.
async function both(name, body, enkaraWouldRefuse) {
  const a = await tsp.pack(body, ts.id, ru.id, { senderSigningKey: ts.sk, receiverEncryptionKey: ru.epk })
  const b = await rs.call({ op: 'pack', payload: b64(body), from: ru.id, to: ts.id, sk: hex(ru.sk), epk: hex(ts.epk) })
  const rr = await rsOpen(a.bytes); const tt = await tsOpen(unb64(b.r.bytes))
  record(name, 'Rust', rr, rr.opened ? `returns ${rr.r.type} payload, ${unb64(rr.r.payload).length} bytes, sender ${rr.r.sender === ts.id ? 'as framed' : 'other'}` : undefined)
  record(name, 'TS', tt, tt.opened ? `returns ${tt.u.messageType} payload, ${tt.u.payload.length} bytes` : undefined)
  R.check(`${name} — the harness's envelope/proof checks refuse it (Enkara's handler must too)`, enkaraWouldRefuse(rr.opened ? unb64(rr.r.payload) : body, ts))
}
const handlerRefuses = (payload, sender) => { // the shape Enkara's door takes: envelope type, issuer = frame sender, proof verifies
  const env = (() => { try { return openEnvelope(payload) } catch { return { docBytes: null } } })()
  if (!env.docBytes) return true
  const doc = JSON.parse(new TextDecoder().decode(env.docBytes))
  return doc.issuer !== sender.id || !verifyProof(doc, sender.spk)
}
// control: the same checks accept a good document, so a refusal below means something
R.check('control — the harness accepts a well-formed, well-signed envelope from the frame sender', !handlerRefuses(envelope(utf8(JSON.stringify(signedPing(ts)))), ts))
const third = makeVid()
await both('(g) inner issuer differs from the frame sender', envelope(utf8(JSON.stringify(signedPing(third)))), handlerRefuses)
{ const d = signedPing(ts); d.proof.proofValue = d.proof.proofValue.slice(0, -2) + (d.proof.proofValue.endsWith('1') ? '22' : '11')
  await both('(h) inner document proof broken', envelope(utf8(JSON.stringify(d))), handlerRefuses) }
await both('(i) a bare Trust Task, no binding envelope', utf8(JSON.stringify(signedPing(ts))), handlerRefuses)
await both('(j) a DIDComm binding envelope inside a TSP frame', envelope(utf8(JSON.stringify(signedPing(ts))), 'https://trusttasks.org/binding/didcomm/0.1/envelope'), handlerRefuses)
await rs.close()
console.table(table)
process.exit(R.finish(results, { table, note: 'mediator frames are added to this job when the mediator job lands' }) ? 0 : 1)
