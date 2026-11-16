// The DIDComm admin path (Railroad 11606 (a), binding 1; the read is didcomm-admin-read.md, 0.50.0 @ 34bbdea4).
// Over TSP a sender carries a bare VID with no `#fragment`, so check_admin_signature (common/authz.rs:189-196) is
// false and, with block_remote_admin_msgs = true (the guard, upstream's default), an ADMIN session is refused on every
// task that goes through check_permissions (access-list/update, acl, account/get|remove|update-acl). Over DIDComm the
// authcrypt skid is `<admin DID>#<X25519 key>`, so the same tasks pass with the guard on. This module is that path:
//   signIn    POST /authenticate/challenge, then POST /authenticate with an authcrypt JWE of the atm authenticate message
//   task      the same Trust Task document the TSP path sends (eddsa-jcs-2022 proof), wrapped in the DIDComm binding
//             envelope (`body` = the whole document), authcrypt to the mediator's keyAgreement kid, POST /inbound
//   collect   POST /fetch, open each stored authcrypt JWE from the mediator DID, keep the ones threaded to the request
// Test keys only. Prints nothing; the caller records statuses and problem codes, never a key or a token.
import * as dc from '@openvtc/vti-didcomm-js'
import { attachProof } from './lib.mjs'

export const AUTH_TYPE = 'https://affinidi.com/atm/1.0/authenticate'
export const ENVELOPE = dc.TRUST_TASK_ENVELOPE_TYPE // https://trusttasks.org/binding/didcomm/0.1/envelope

const docOf = (did) => (did.startsWith('did:peer:') ? dc.didPeer.resolve(did) : dc.didKey.resolve(did)).didDocument
// The X25519 keyAgreement kid of a DID. The mediator routes a JWE to itself only when the recipient kid's DID part is
// exactly its own DID (inbound.rs:1071), and check_admin_signature needs the sender kid's DID = the session DID.
export function keyAgreementKid(did) {
  const ka = docOf(did).keyAgreement
  if (!ka?.length) throw new Error('no keyAgreement key')
  const kid = typeof ka[0] === 'string' ? ka[0] : ka[0].id
  if (!kid.startsWith(did + '#')) throw new Error('keyAgreement kid is not on the DID itself')
  return kid
}
// who: { id, dk, epk } (X25519 secret/public, the did:key's own Montgomery pair); med: { id, epk }.
export function parties(who, med) {
  const kid = keyAgreementKid(who.id), medKid = keyAgreementKid(med.id)
  return {
    me: { kid, privateJwk: dc.jwk.privateJwk('X25519', who.dk, who.epk, kid) },
    medRecipient: { kid: medKid, publicJwk: dc.jwk.publicJwk('X25519', med.epk, medKid) },
    medSender: { publicJwk: dc.jwk.publicJwk('X25519', med.epk, medKid) },
    kid, medKid,
  }
}
const plain = (type, from, to, body, extra = {}) => {
  const now = Math.floor(Date.now() / 1000)
  return { id: crypto.randomUUID(), typ: 'application/didcomm-plain+json', type, from, to: [to], created_time: now, expires_time: now + 300, body, ...extra }
}

// post(path, body, token?, contentType?) -> { status, json, text }; the caller's own fetch wrapper.
export async function signIn(post, who, med) {
  const p = parties(who, med)
  const c = await post('/authenticate/challenge', JSON.stringify({ did: who.id }))
  if (c.status !== 200) return { ok: false, step: 'challenge', status: c.status, problem: problemOf(c) }
  const { challenge, session_id } = c.json.data
  const jwe = await dc.pack({ message: plain(AUTH_TYPE, who.id, med.id, { challenge, session_id }), sender: p.me, recipient: p.medRecipient })
  const a = await post('/authenticate', jwe)
  if (a.status !== 200) return { ok: false, step: 'authenticate (didcomm)', status: a.status, problem: problemOf(a), kind: (a.text.match(/authentication\.[a-z.]+[a-z]/) || [null])[0] }
  return { ok: true, token: a.json.data.access_token, via: 'didcomm', sender_kid_has_fragment: p.kid.includes('#') }
}

export function envelopeFor(who, med, doc) {
  return plain(ENVELOPE, who.id, med.id, doc)
}
export function trustTaskDoc(who, med, typeUri, payload) {
  return attachProof({ id: 'urn:uuid:' + crypto.randomUUID(), type: typeUri, issuer: who.id, recipient: med.id, issuedAt: new Date().toISOString(), payload }, who)
}

// One Trust Task over DIDComm. Same return shape as the TSP path's task(): { status, answerType, answer, problem? }.
export async function task(post, who, token, med, typeUri, payload) {
  const p = parties(who, med)
  const doc = trustTaskDoc(who, med, typeUri, payload)
  const msg = envelopeFor(who, med, doc)
  const jwe = await dc.pack({ message: msg, sender: p.me, recipient: p.medRecipient })
  const sent = await post('/inbound', jwe, token)
  if (sent.status >= 300) return { status: sent.status, problem: problemOf(sent), via: 'didcomm' }
  const replies = await collect(post, who, token, med)
  const r = replies.find((m) => m.thid === msg.id) ?? null
  const body = r?.body ?? null
  // The answer is a Trust Task response document in an envelope (body.type …#response, body.payload), or a
  // DIDComm problem report (type …/report-problem/2.0/problem-report, body.code).
  const answerType = body?.type ?? (r ? r.type : null)
  return { status: sent.status, answerType, answer: body?.payload ?? null, problem: r && !body?.type ? (body?.code ?? r.type) : undefined, via: 'didcomm', replies: replies.length }
}

export async function collect(post, who, token, med, del = true) {
  const p = parties(who, med)
  const got = await post('/fetch', JSON.stringify({ limit: 20, delete_policy: del ? 'Optimistic' : 'DoNotDelete' }), token)
  const out = []
  for (const m of got.json?.data?.success ?? []) {
    const s = typeof m.msg === 'string' ? m.msg : ''
    if (!s.trimStart().startsWith('{')) continue
    try {
      const u = await dc.unpack(s, p.me, p.medSender)
      // Only an authenticated reply from the mediator DID itself counts as its answer.
      if (!u.authenticated || u.senderDid !== med.id) continue
      out.push({ thid: u.message.thid ?? null, type: u.message.type, body: u.message.body ?? null, senderKid: u.senderKid })
    } catch {}
  }
  return out
}

export function problemOf(r) {
  return r.json?.errorCode ?? r.json?.error?.code ?? r.json?.code ?? r.json?.error_code_str ?? r.json?.message ?? String(r.text ?? '').slice(0, 160)
}
