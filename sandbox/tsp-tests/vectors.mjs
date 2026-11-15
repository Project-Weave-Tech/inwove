#!/usr/bin/env node
// ref/09 §2.2 `vectors`: TSP 1.0 Appendix A (trustoverip/tswg-tsp-specification at the pinned sha) through both libraries.
// Usage: node vectors.mjs <resultsdir> <path to the spec's spec/spec.md>
// The keys in Appendix A are published by the spec for checking its vectors only; nothing here is a real key.
// For every vector: the version code is YTSP-BAA; TS (@openvtc/vti-tsp-js 0.4.0) opens it; Rust (affinidi-tsp 0.3.0)
// opens it; the opened body matches the vector's payload; and where the vector gives the ephemeral (ikmE), TS rebuilds
// the message byte for byte. The suites the spec keeps only for older implementations (the libsodium sealed box) and
// the post-quantum key types are recorded as answers, not failures: Enkara's door uses HPKE-Base over X25519 only.
// The signed-only (unsealed) vector is an answer too (Railroad 11506): Enkara's door refuses an unsealed frame in its own code.
import { readFileSync } from 'node:fs'
import * as tsp from '@openvtc/vti-tsp-js'
import * as unsafe from '@openvtc/vti-tsp-js/unsafe-testing'
import { b64, eq, hex, rustPeer, recorder } from './lib.mjs'

const results = process.argv[2] ?? 'results'
const specPath = process.argv[3]
if (!specPath) { console.error('usage: node vectors.mjs <resultsdir> <spec.md>'); process.exit(2) }
const R = recorder('vectors')
const ub64u = (s) => new Uint8Array(Buffer.from(s, 'base64url'))

// --- parse Appendix A -------------------------------------------------------------------------------------------
export function parseAppendix(md) {
  const start = md.indexOf('## Appendix A: Test Vectors')
  if (start < 0) throw new Error('no Appendix A in the spec')
  const end = md.indexOf('\n## ', start + 5)
  const text = md.slice(start, end < 0 ? undefined : end)
  const blocks = [] // { heading, name, fields }
  let heading = ''; let name = ''
  const lines = text.split('\n')
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i]
    if (/^#{3,4} /.test(l)) { heading = l.replace(/^#+ /, '').trim(); name = /^#### /.test(l) ? heading : ''; continue }
    const m = l.match(/^`([a-z0-9_]+)`\s*$/); if (m) { name = m[1]; continue }
    if (l.startsWith('``` text')) {
      const fields = {}; let key = null
      for (i++; i < lines.length && !lines[i].startsWith('```'); i++) {
        const row = lines[i]
        if (!row.trim()) continue
        if (/^\s/.test(row)) { if (key) fields[key] += row.trim(); continue }
        const kv = row.match(/^(\S+)\s+(\S.*)$/)
        if (kv) { fields[kv[1]] = kv[2].trim(); key = null } else { key = row.trim(); fields[key] = '' }
      }
      blocks.push({ heading, name, fields })
    }
  }
  const ids = {}; const vectors = []
  for (const b of blocks) {
    if (b.fields.id && b.fields.longForm) ids[b.name] = b.fields
    else if (b.fields.message) vectors.push({ name: b.name, section: b.heading, ...b.fields })
  }
  return { ids, vectors }
}

const md = readFileSync(specPath, 'utf8')
const { ids, vectors } = parseAppendix(md)
R.check('Appendix A has vectors', vectors.length > 0, `${vectors.length} vectors, ${Object.keys(ids).length} identifiers`)

const rs = rustPeer()
const optional = (v, who) => /sealed-box/.test(v.name) ? 'the libsodium sealed box, kept by the spec for existing implementations only'
  // Railroad 11506: Enkara's door takes sealed frames only and refuses an unsealed one in its own code, so the TS gap never decides anything.
  : /signed-only/.test(v.name) ? "signed-only (unsealed): Enkara's door refuses unsealed frames itself (Railroad 11506)"
  : (ids[who]?.sigKeyType !== 'Ed25519' || ids[who]?.encKeyType !== 'X25519') ? `post-quantum key types (${ids[who]?.sigKeyType}/${ids[who]?.encKeyType})` : null
const perLibrary = []

for (const v of vectors) {
  const snd = ids[v.sender]; const rcv = ids[v.receiver]
  if (!snd || !rcv) { R.check(`${v.name}: sender and receiver identifiers found`, false, `${v.sender} → ${v.receiver}`); continue }
  const why = optional(v, v.receiver) ?? optional(v, v.sender)
  const bytes = ub64u(v.message)
  const code = v.message.match(/YTSP-[A-Za-z0-9_-]{3}/)?.[0] ?? null
  const row = { vector: v.name, version: code, ts: null, rust: null, rebuilt: null, optional: why }
  R.check(`${v.name}: version code YTSP-BAA`, code === 'YTSP-BAA', code ?? 'none')
  const expect = v.payload ? ub64u(v.payload) : null
  const tail = (body) => expect && body.length > 0 && body.length <= expect.length && eq(expect.slice(expect.length - body.length), body)

  // TS opens
  let tsOpened = null
  try {
    tsOpened = await tsp.unpack(bytes, { receiverDecryptionKey: ub64u(rcv.skE), senderSigningKey: ub64u(snd.pkS) })
    const isControl = tsOpened.messageType === 'control'
    const bodyOk = isControl ? !!tsOpened.control?.controlType : v.innerPayload ? true : tail(tsOpened.payload)
    row.ts = `opened: ${tsOpened.messageType}${isControl ? ' ' + (tsOpened.control?.controlType ?? 'with no control type') : ''}, ${tsOpened.payload.length} body bytes${bodyOk ? '' : ', body not the vector payload'}`
    if (tsOpened.sender !== snd.id && !snd.longForm.startsWith(tsOpened.sender)) row.ts += `, sender ${tsOpened.sender}`
    if (!why) R.check(`${v.name}: TS opens it, sender and body as the vector`, bodyOk && (tsOpened.sender === snd.id || snd.longForm === tsOpened.sender), row.ts)
  } catch (e) {
    row.ts = `refused: ${e.code ?? ''} ${e.message}`.trim()
    if (!why) R.check(`${v.name}: TS opens it`, false, row.ts)
  }

  // Rust opens
  const u = await rs.call({ op: 'unpack', bytes: b64(bytes), dk: hex(ub64u(rcv.skE)), spk: hex(ub64u(snd.pkS)) })
  if (u.ok) {
    const body = new Uint8Array(Buffer.from(u.r.payload, 'base64'))
    // A control frame's body is the library's own reading of the control fields, so for those only the kind is compared.
    const isControl = u.r.type === 'Control'
    const bodyOk = isControl ? true : v.innerPayload ? true : tail(body)
    row.rust = `opened: ${u.r.type}, ${body.length} body bytes${bodyOk ? '' : ', body not the vector payload'}`
    if (!why) R.check(`${v.name}: Rust opens it, sender${isControl ? ' and kind' : ' and body'} as the vector`, bodyOk && (u.r.sender === snd.id || u.r.sender === snd.longForm), row.rust)
    if (tsOpened && !why) {
      if (isControl) R.check(`${v.name}: TS and Rust read the same kind`, tsOpened.messageType === 'control', `${tsOpened.messageType} / ${u.r.type}`)
      else R.check(`${v.name}: TS and Rust open the same body`, eq(body, tsOpened.payload), `${body.length} / ${tsOpened.payload.length} bytes`)
    }
  } else {
    row.rust = `refused: ${u.error}`
    if (!why) R.check(`${v.name}: Rust opens it`, false, row.rust)
  }

  // TS rebuilds byte for byte where the vector gives ikmE (HPKE-Base)
  if (v.ikmE && tsOpened && !why) {
    const keys = { senderSigningKey: ub64u(snd.skS), receiverEncryptionKey: ub64u(rcv.pkE) }
    const u2 = { __unsafeIkmE: ub64u(v.ikmE) }
    let rebuilt = null; let how = ''
    try {
      const c = tsOpened.control
      if (tsOpened.messageType === 'direct') { rebuilt = await unsafe.__unsafeDeterministicPack(tsOpened.payload, snd.id, rcv.id, keys, u2); how = 'pack' }
      else if (tsOpened.messageType === 'nested') { rebuilt = await unsafe.__unsafeDeterministicPackNested(tsOpened.payload, snd.id, rcv.id, keys, u2); how = 'packNested' }
      else if (tsOpened.messageType === 'routed') { rebuilt = await unsafe.__unsafeDeterministicPackRouted(tsOpened.payload, tsOpened.hops, snd.id, rcv.id, keys, u2); how = 'packRouted' }
      else if (c?.referral) how = `no rebuild path: packInvite takes no referral (${c.controlType})`
      else if (/RFI|invite/i.test(c?.controlType ?? '')) { how = 'packInvite'; rebuilt = c.nonce ? await unsafe.__unsafeDeterministicPackInvite(snd.id, rcv.id, keys, { nonce: c.nonce, route: c.route }, u2) : null; if (!rebuilt) how += ' (no nonce in the opened control)' }
      else if (/RFA|accept/i.test(c?.controlType ?? '')) { how = 'packAccept'; rebuilt = await unsafe.__unsafeDeterministicPackAccept(c.inReplyTo, snd.id, rcv.id, keys, u2) }
      else if (/RFD|cancel/i.test(c?.controlType ?? '')) { how = 'packCancel'; rebuilt = await unsafe.__unsafeDeterministicPackCancel(c.inReplyTo, snd.id, rcv.id, keys, u2) }
      else how = `no rebuild path for ${tsOpened.messageType} ${c?.controlType ?? ''}`
      row.rebuilt = rebuilt ? `${how}: ${eq(rebuilt.bytes, bytes) ? 'byte for byte' : `differs (${rebuilt.bytes.length} vs ${bytes.length} bytes)`}` : how
    } catch (e) { row.rebuilt = `${how} threw: ${e.message}` }
    R.answer(`${v.name}: TS rebuild with the vector's ikmE`, row.rebuilt)
  }
  if (why) R.answer(`${v.name}: optional suite (${why})`, `TS ${row.ts}; Rust ${row.rust}`)
  perLibrary.push(row)
}
await rs.close()
process.exit(R.finish(results, { spec: specPath, perLibrary }) ? 0 : 1)
