#!/usr/bin/env node
// ref/09 §2.3 `roundtrip`: @openvtc/vti-tsp-js 0.4.0 <-> affinidi-tsp 0.3.0, both ways, local only, test VIDs.
// Usage: node roundtrip.mjs <resultsdir>. Also writes <resultsdir>/frames.json for `tamper`.
import { join } from 'node:path'
import * as tsp from '@openvtc/vti-tsp-js'
import { makeVid, signedPing, utf8, envelope, openEnvelope, verifyProof, eq, b64, unb64, hex, rustPeer, recorder, writeJson } from './lib.mjs'

const results = process.argv[2] ?? 'results'
const R = recorder('roundtrip')
const rs = rustPeer()
const ts = makeVid() // the TS side ("Enkara")
const ru = makeVid() // the Rust side ("an agent")
await rs.private(ru); await rs.remote(ts)
const frames = {}
// The qb2 frame read as qb64 text: its version code sits right after the -E count code.
const version = (bytes) => { const t = Buffer.from(bytes.slice(0, 12)).toString('base64url'); let peek; try { const p = tsp.peekRevision(bytes); peek = `major ${p.major} minor ${p.minor}${p.recognised ? '' : ' (unrecognised)'}` } catch (e) { peek = 'peek refused: ' + e.message } return `${t.match(/YTSP-[A-Za-z0-9_-]{3}/)?.[0] ?? 'no YTSP code in ' + t} (${peek})` }

// 1. TS packs a direct sealed frame carrying the binding envelope; Rust unpacks it.
{
  const doc = signedPing(ts); const docBytes = utf8(JSON.stringify(doc))
  const body = envelope(docBytes)
  const p = await tsp.pack(body, ts.id, ru.id, { senderSigningKey: ts.sk, receiverEncryptionKey: ru.epk })
  frames.tsToRust = { bytes: b64(p.bytes), body: b64(body), sender: ts.id, receiver: ru.id }
  R.check('1 TS frame version code', String(version(p.bytes)).includes('YTSP-BAA'), String(version(p.bytes)))
  const u = await rs.call({ op: 'unpack', bytes: b64(p.bytes), dk: hex(ru.dk), spk: hex(ts.spk) })
  R.check('1 Rust opens the TS frame', u.ok, u.ok ? u.r.type : u.error)
  if (u.ok) {
    const got = unb64(u.r.payload); const env = openEnvelope(got)
    R.check('1 sender VID as sent', u.r.sender === ts.id)
    R.check('1 envelope bytes unchanged', eq(got, body), `${got.length} bytes`)
    R.check('1 inner document bytes unchanged', env.docBytes && eq(env.docBytes, docBytes))
    R.check('1 inner document proof verifies', env.docBytes && verifyProof(JSON.parse(new TextDecoder().decode(env.docBytes)), ts.spk))
  }
}

// 2. Reverse: Rust packs, TS unpacks.
{
  const doc = signedPing(ru); const docBytes = utf8(JSON.stringify(doc)); const body = envelope(docBytes)
  const p = await rs.call({ op: 'pack', payload: b64(body), from: ru.id, to: ts.id, sk: hex(ru.sk), epk: hex(ts.epk) })
  R.check('2 Rust packs', p.ok, p.ok ? '' : p.error)
  if (p.ok) {
    const bytes = unb64(p.r.bytes)
    frames.rustToTs = { bytes: p.r.bytes, body: b64(body), sender: ru.id, receiver: ts.id }
    R.check('2 Rust frame version code', String(version(bytes)).includes('YTSP-BAA'), String(version(bytes)))
    try {
      const u = await tsp.unpack(bytes, { receiverDecryptionKey: ts.dk, senderSigningKey: ru.spk })
      const env = openEnvelope(u.payload)
      R.check('2 TS opens the Rust frame', true, u.messageType?.kind ?? JSON.stringify(u.messageType))
      R.check('2 sender VID as sent', u.sender === ru.id)
      R.check('2 envelope bytes unchanged', eq(u.payload, body))
      R.check('2 inner document bytes unchanged', env.docBytes && eq(env.docBytes, docBytes))
      R.check('2 inner document proof verifies', env.docBytes && verifyProof(JSON.parse(new TextDecoder().decode(env.docBytes)), ru.spk))
    } catch (e) { R.check('2 TS opens the Rust frame', false, `${e.code ?? ''} ${e.message}`) }
  }
}

// 3. Relationship: TS invites, Rust accepts, TS records it; then one application frame each way.
const relationship = {}
{
  const keysTs = { senderSigningKey: ts.sk, receiverEncryptionKey: ru.epk }
  const inv = await tsp.packInvite(ts.id, ru.id, keysTs)
  let state = tsp.transition('none', 'sendInvite')
  const got = await rs.call({ op: 'receive', our: ru.id, bytes: b64(inv.bytes) })
  R.check('3 Rust receives the TS invite', got.ok, got.ok ? `${got.r.type} ${got.r.control ?? ''}`.slice(0, 160) : got.error)
  R.check('3 invite digest agrees', got.ok && got.r.digest === hex(inv.threadDigest), got.ok ? `${got.r.digest.slice(0, 16)}… vs ${hex(inv.threadDigest).slice(0, 16)}…` : '')
  const acc = await rs.call({ op: 'accept', from: ru.id, to: ts.id })
  R.check('3 Rust packs an accept', acc.ok, acc.ok ? '' : acc.error)
  if (acc.ok) {
    try {
      const u = await tsp.unpack(unb64(acc.r.bytes), { receiverDecryptionKey: ts.dk, senderSigningKey: ru.spk })
      R.check('3 TS opens the accept; inReplyTo = the invite digest', u.control && eq(u.control.inReplyTo ?? new Uint8Array(), inv.threadDigest), JSON.stringify({ type: u.control?.type }))
      state = tsp.transition(state, 'receiveAccept'); relationship.tsState = state
      R.check('3 TS state machine: none -> pending -> bidirectional', state === 'bidirectional' && tsp.canSend(state), state)
    } catch (e) { R.check('3 TS opens the accept', false, e.message) }
  }
  relationship.rustState = (await rs.ok({ op: 'state', our: ru.id, their: ts.id })).state
  R.check('3 Rust holds the relationship as Bidirectional', relationship.rustState === 'Bidirectional', relationship.rustState)
  // one application frame each way, inside the relationship
  const a = await tsp.pack(utf8('hello from TS'), ts.id, ru.id, keysTs)
  const ra = await rs.call({ op: 'receive', our: ru.id, bytes: b64(a.bytes) })
  R.check('3 TS -> Rust application frame inside the relationship', ra.ok && Buffer.from(ra.r.payload, 'base64').toString() === 'hello from TS', ra.ok ? '' : ra.error)
  const b = await rs.call({ op: 'send', from: ru.id, to: ts.id, payload: b64(utf8('hello from Rust')) })
  R.check('3 Rust sends inside the relationship', b.ok, b.ok ? '' : b.error)
  if (b.ok) {
    try { const u = await tsp.unpack(unb64(b.r.bytes), { receiverDecryptionKey: ts.dk, senderSigningKey: ru.spk }); R.check('3 Rust -> TS application frame inside the relationship', new TextDecoder().decode(u.payload) === 'hello from Rust') }
    catch (e) { R.check('3 Rust -> TS application frame', false, e.message) }
  }
}
// 3b. An application frame WITHOUT a prior relationship: record what each side does.
{
  const stranger = makeVid(); await rs.remote(stranger)
  const p = await tsp.pack(utf8('no relationship'), stranger.id, ru.id, { senderSigningKey: stranger.sk, receiverEncryptionKey: ru.epk })
  const r = await rs.call({ op: 'receive', our: ru.id, bytes: b64(p.bytes) })
  relationship.rustWithoutRelationship = r.ok ? `delivered (${r.r.type}, outcome ${r.r.outcome})` : `refused: ${r.error}`
  R.answer('3b Rust, application frame with no relationship', relationship.rustWithoutRelationship)
  const q = await rs.call({ op: 'pack', payload: b64(utf8('no relationship')), from: ru.id, to: stranger.id, sk: hex(ru.sk), epk: hex(stranger.epk) })
  try { const u = await tsp.unpack(unb64(q.r.bytes), { receiverDecryptionKey: stranger.dk, senderSigningKey: ru.spk }); relationship.tsWithoutRelationship = `opened by unpack (the codec does not gate; admitsApplicationMessage is the client's to apply), payload ${u.payload.length} bytes` }
  catch (e) { relationship.tsWithoutRelationship = `refused: ${e.code ?? ''} ${e.message}` }
  R.answer('3b TS, application frame with no relationship', relationship.tsWithoutRelationship)
  const sends = await rs.call({ op: 'send', from: ru.id, to: stranger.id, payload: b64(utf8('x')) })
  R.answer('3b Rust agent.send with no relationship', sends.ok ? 'packed' : `refused: ${sends.error}`)
}
// keys the tamper job needs (test keys, made above, thrown away with the run)
frames.keys = { ts: { id: ts.id, sk: hex(ts.sk), spk: hex(ts.spk), dk: hex(ts.dk), epk: hex(ts.epk) }, ru: { id: ru.id, sk: hex(ru.sk), spk: hex(ru.spk), dk: hex(ru.dk), epk: hex(ru.epk) } }
writeJson(join(results, 'frames.json'), frames)
await rs.close()
process.exit(R.finish(results, { relationship }) ? 0 : 1)
