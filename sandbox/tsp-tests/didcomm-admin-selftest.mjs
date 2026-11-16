#!/usr/bin/env node
// Self-test of didcomm-admin.mjs against a fake mediator in this process (no network, test keys only). It checks the
// shapes the source read says the real mediator needs, so a red run on the real one is about the mediator, not the client:
//   1 sign-in JWE is authcrypt (alg has 1PU), skid = <admin DID>#<X25519 key>, recipient kid = <mediator DID>#..., opens
//     to the atm authenticate type with from = admin DID, to = [mediator DID], the challenge + session_id and expires_time
//   2 the admin task is the binding envelope whose body is the whole signed Trust Task document, recipient = mediator DID
//   3 a reply from the mediator DID threaded to the request is read back as the answer
//   4 a reply sealed by someone else (right thid, wrong sender) is NOT taken as the answer
// Usage: node didcomm-admin-selftest.mjs [out.json]
import * as dc from '@openvtc/vti-didcomm-js'
import { ed25519 } from '@noble/curves/ed25519.js'
import { writeFileSync } from 'node:fs'
import { b58, verifyProof } from './lib.mjs'
import * as admin from './didcomm-admin.mjs'

const keyVid = () => { const sk = ed25519.utils.randomSecretKey(), spk = ed25519.getPublicKey(sk); return { id: 'did:key:z' + b58(new Uint8Array([0xed, 0x01, ...spk])), sk, spk, dk: ed25519.utils.toMontgomerySecret(sk), epk: ed25519.utils.toMontgomery(spk) } }
const peerVid = () => { const v = keyVid(); v.id = 'did:peer:2.Vz' + b58(new Uint8Array([0xed, 0x01, ...v.spk])) + '.Ez' + b58(new Uint8Array([0xec, 0x01, ...v.epk])); return v }
const MED = peerVid(), ADMIN = keyVid(), OTHER = peerVid()
const medP = admin.parties(MED, ADMIN) // the mediator's own view: its private key, the admin as the other side
const checks = {}
const ok = (k, pass, detail = {}) => { checks[k] = { pass: !!pass, ...detail }; console.log((pass ? 'ok  ' : 'FAIL') + '  ' + k) }
const hdr = (jwe) => JSON.parse(Buffer.from(JSON.parse(jwe).protected, 'base64url').toString())

let stored = [], lastTask = null
async function fakePost(path, body, token) {
  const r = (status, json) => ({ status, json, text: JSON.stringify(json) })
  if (path === '/authenticate/challenge') return r(200, { data: { challenge: 'C'.repeat(32), session_id: 'S'.repeat(12) } })
  if (path === '/authenticate') {
    const h = hdr(body), rk = JSON.parse(body).recipients[0].header.kid
    const u = await dc.unpack(body, medP.me, { publicJwk: dc.jwk.publicJwk('X25519', ADMIN.epk) })
    const m = u.message
    ok('1_signin_authcrypt_shape', /1PU/.test(h.alg) && h.skid === admin.keyAgreementKid(ADMIN.id) && h.skid.startsWith(ADMIN.id + '#') && rk.startsWith(MED.id + '#') && u.authenticated
      && m.type === admin.AUTH_TYPE && m.from === ADMIN.id && m.to?.[0] === MED.id && m.body?.challenge === 'C'.repeat(32) && m.body?.session_id === 'S'.repeat(12) && m.expires_time > Date.now() / 1000,
      { alg: h.alg, skid_is_admin_keyagreement: h.skid === admin.keyAgreementKid(ADMIN.id), recipient_on_mediator: rk.startsWith(MED.id + '#') })
    return r(200, { data: { access_token: 'T' } })
  }
  if (path === '/inbound') {
    const u = await dc.unpack(body, medP.me, { publicJwk: dc.jwk.publicJwk('X25519', ADMIN.epk) })
    const m = u.message, doc = m.body
    lastTask = m
    ok('2_task_is_envelope_with_whole_signed_doc', token === 'T' && m.type === admin.ENVELOPE && doc?.recipient === MED.id && doc?.issuer === ADMIN.id && doc?.proof?.cryptosuite === 'eddsa-jcs-2022' && verifyProof(doc, ADMIN.spk),
      { type: m.type, proof_verifies: verifyProof(doc, ADMIN.spk) })
    const answer = { type: doc.type + '#response', threadId: doc.id, payload: { accessListCount: 1 } }
    // One forged reply (right thread, sealed by OTHER, claiming nothing) and the mediator's real one.
    const forged = await dc.pack({ message: { id: crypto.randomUUID(), typ: 'application/didcomm-plain+json', type: admin.ENVELOPE, from: OTHER.id, to: [ADMIN.id], thid: m.id, body: { type: doc.type + '#response', payload: { accessListCount: 99 } } },
      sender: admin.parties(OTHER, ADMIN).me, recipient: { kid: admin.keyAgreementKid(ADMIN.id), publicJwk: dc.jwk.publicJwk('X25519', ADMIN.epk) } })
    const real = await dc.pack({ message: { id: crypto.randomUUID(), typ: 'application/didcomm-plain+json', type: admin.ENVELOPE, from: MED.id, to: [ADMIN.id], thid: m.id, body: answer },
      sender: medP.me, recipient: { kid: admin.keyAgreementKid(ADMIN.id), publicJwk: dc.jwk.publicJwk('X25519', ADMIN.epk) } })
    stored = [{ msg: forged }, { msg: real }]
    return r(200, { data: {} })
  }
  if (path === '/fetch') { const s = stored; stored = []; return r(200, { data: { success: s } }) }
  return r(404, {})
}

const s = await admin.signIn(fakePost, ADMIN, MED)
ok('1b_signin_returns_token', s.ok && s.token === 'T')
const t = await admin.task(fakePost, ADMIN, 'T', MED, 'https://trusttasks.org/spec/messaging/access-list/list/0.1', { did: 'x' })
ok('3_mediator_reply_read_as_answer', t.answerType?.endsWith('#response') && t.answer?.accessListCount === 1, { answerType: t.answerType })
ok('4_forged_reply_not_taken', t.answer?.accessListCount !== 99 && t.replies === 1, { replies_accepted: t.replies })
const pass = Object.values(checks).every((c) => c.pass) && Object.keys(checks).length === 5
if (process.argv[2]) writeFileSync(process.argv[2], JSON.stringify({ job: 'didcomm-admin-selftest', pass, checks }, null, 2) + '\n')
console.log('didcomm-admin selftest:', pass ? 'PASS' : 'FAIL')
process.exit(pass ? 0 : 1)
