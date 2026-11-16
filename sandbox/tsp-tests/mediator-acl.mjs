#!/usr/bin/env node
// ref/09 §2.4 line C + the inbox-mode pair (Railroad 11542), against a local mediator started here.
//   Closed mode (mediator_acl_mode = explicit_allow), forwarding off. The admin (the pinned mediator's upstream
//   TEST-ONLY admin key, docker/test/conf/admin-monitor.json) registers A, B and D with `messaging/account/add`
//   over TSP; A's account is made with accessListMode explicitDeny + selfManageList (an open inbox with a deny list,
//   Enkara's shape). A then puts D on its own deny list with `messaging/access-list/update` over TSP.
//   C1  an unknown DID can't sign in (refused at the challenge)
//   C2  a frame routed to a DID that is not local is refused (forwarding off)
//   C3  B (registered, never met by A, not on the list) → A: lands, A collects and opens it
//   C4  D (on A's deny list) → A: refused
// Every Trust Task carries an eddsa-jcs-2022 proof and the mediator runs trust_task_verification = "enforce".
//   A   (Railroad 11506) a did:peer with an Ed25519 key and no X25519 keyAgreement can't sign in
//   Z1/Z2 (Railroad 11606 step 0) account/add over TSP from a non-admin / a DID with no account is refused
//   Z3  (finding) account/add on an existing hash overwrites its role and ACLs
//   R1  (Railroad 11571, setup fact 1) a deliberate plain-DID account/add: the add's answer is not trusted; the
//       setup check (a real sign-in + an empty /fetch) must turn it red
// --closed-default (Railroad 11571, setup fact 2): the mediator's default for new accounts is explicit-allow (closed),
//   and the admin account is set to explicit-allow with exactly the mediator's own DID (hashed) on its list, then read
//   back with access-list/list, before any account/add. Without the flag the run is the 2026-11-15 shape (explicit-deny
//   default, the upstream test conf's), so the two can be compared.
// Usage: node mediator-acl.mjs <mediator binary> <conf dir> <redis-server> <out.json> [--closed-default] [--admin-didcomm]
// Test keys only; A, B, D, U are made here and die with the process. Prints statuses and problem codes, no keys.
import { spawn } from 'node:child_process'
import { mkdtempSync, cpSync, readFileSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import * as tsp from '@openvtc/vti-tsp-js'
import { ed25519 } from '@noble/curves/ed25519.js'
import { b58, utf8, eq, attachProof } from './lib.mjs'
import * as didcommAdmin from './didcomm-admin.mjs'

const [binArg, confArg, redisBin, outFile] = process.argv.slice(2).filter((a) => !a.startsWith('--'))
const CLOSED = process.argv.includes('--closed-default')
// --admin-didcomm (Railroad 11606 (a), binding 1): the admin signs in over DIDComm (/authenticate, authcrypt) and every
// admin Trust Task rides the DIDComm binding envelope, so its sender kid is <admin DID>#<key> and check_admin_signature
// can pass with the guard on. Everyone else (A, B, D, the strangers) stays on TSP, as the door will run.
const ADMIN_DIDCOMM = process.argv.includes('--admin-didcomm')
const BIN = resolve(binArg), CONF = resolve(confArg)
const work = mkdtempSync(join(process.env.RUNNER_TEMP || tmpdir(), 'medacl-'))
const RPORT = 20000 + Math.floor(Math.random() * 20000), MPORT = 40000 + Math.floor(Math.random() * 20000)
const PW = Buffer.from(crypto.getRandomValues(new Uint8Array(24))).toString('hex')
const procs = []
const stop = () => { for (const p of procs) try { p.kill('SIGTERM') } catch {}; rmSync(work, { recursive: true, force: true }) }
process.on('exit', stop)
const results = { line: 'C + inbox mode', setup: {}, checks: {} }
const log = (k, v) => console.log(k.padEnd(34), typeof v === 'string' ? v : JSON.stringify(v))

// ---- start Redis (with a password) and the mediator, closed mode, forwarding off ----
cpSync(CONF, join(work, 'conf'), { recursive: true })
const tomlPath = join(work, 'conf', 'mediator.toml')
let toml = readFileSync(tomlPath, 'utf8')
const set = (key, val) => { const re = new RegExp(`^${key} = .*$`, 'm'); if (!re.test(toml)) throw new Error('no ' + key + ' in mediator.toml'); toml = toml.replace(re, `${key} = "${val}"`) }
set('database_url', `redis://:${PW}@127.0.0.1:${RPORT}/`)
set('listen_address', `127.0.0.1:${MPORT}`)
set('mediator_acl_mode', 'explicit_allow')
// MODE_EXPLICIT_DENY in the default too: the mediator seals each Trust Task's answer into the sender's own inbox, and
// with an explicit-allow default the admin's empty list refuses the mediator's answer (73), so the add is never confirmed.
// With --closed-default the admin's own list is set first (below), so its answers get through.
const DEFAULT_ACL = CLOSED ? 'DENY_ALL,LOCAL,SEND_MESSAGES,RECEIVE_MESSAGES,MODE_EXPLICIT_ALLOW' : 'DENY_ALL,LOCAL,SEND_MESSAGES,RECEIVE_MESSAGES,MODE_EXPLICIT_DENY'
set('global_acl_default', DEFAULT_ACL)
set('local_direct_delivery_allowed', 'true')
set('enable_inter_mediator_relay', 'false')
set('external_forwarding', 'false')
toml = toml.replace(/^backend = "file:\/\/.*$/m, `backend = "file://${join(work, 'conf', 'secrets.json')}"`)
if (/^trust_task_verification = .*$/m.test(toml)) set('trust_task_verification', 'enforce')
else toml = toml.replace(/^\[security\]$/m, '[security]\ntrust_task_verification = "enforce"')
// The guard: written on, never left to the default, so a run can't pass because an upstream conf turned it off.
// Quoted like every other value the upstream conf carries (its values are strings with ${VAR:default} expansion).
if (/^block_remote_admin_msgs = .*$/m.test(toml)) set('block_remote_admin_msgs', 'true')
else toml = toml.replace(/^\[security\]$/m, '[security]\nblock_remote_admin_msgs = "true"')
if (!/^block_remote_admin_msgs = "true"$/m.test(toml)) throw new Error('could not set block_remote_admin_msgs = true')
writeFileSync(tomlPath, toml)
results.setup = { mediator_acl_mode: 'explicit_allow', global_acl_default: DEFAULT_ACL, external_forwarding: false, enable_inter_mediator_relay: false, trust_task_verification: 'enforce', block_remote_admin_msgs: true, admin_transport: ADMIN_DIDCOMM ? 'didcomm' : 'tsp' }

procs.push(spawn(redisBin, ['--port', String(RPORT), '--bind', '127.0.0.1', '--requirepass', PW, '--save', '', '--appendonly', 'no'], { stdio: 'ignore' }))
// Wait until Redis takes connections (a container start can take longer than a local binary), up to ~15 s.
{ const { connect } = await import('node:net'); let open = false
  for (let i = 0; i < 75 && !open; i++) { open = await new Promise((r) => { const c = connect(RPORT, '127.0.0.1'); c.once('connect', () => { c.end(); r(true) }); c.once('error', () => r(false)) }); if (!open) await new Promise((r) => setTimeout(r, 200)) }
  if (!open) { console.error('redis did not start on its port'); process.exit(1) } }
const env = { ...process.env, RUST_LOG: 'info,affinidi_messaging_mediator::common::config=warn' }
const med = spawn(BIN, ['--config', 'conf/mediator.toml'], { cwd: work, env, stdio: ['ignore', 'pipe', 'pipe'] })
procs.push(med)
let medLog = ''; med.stdout.on('data', (d) => { medLog += d }); med.stderr.on('data', (d) => { medLog += d })
const base = `http://127.0.0.1:${MPORT}/mediator/v1`
let up = false
for (let i = 0; i < 150 && med.exitCode === null; i++) { try { if ((await fetch(base + '/healthchecker')).ok) { up = true; break } } catch {} await new Promise((r) => setTimeout(r, 200)) }
if (!up) { console.error('mediator did not start; exit', med.exitCode); console.error(medLog.split('\n').filter((l) => !l.includes(PW)).slice(-15).join('\n')); process.exit(1) }

// ---- identities ----
const ALPHA = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
const unb58 = (s) => { let n = 0n; for (const c of s) n = n * 58n + BigInt(ALPHA.indexOf(c)); let h = n.toString(16); if (h.length % 2) h = '0' + h; return new Uint8Array(Buffer.from(h, 'hex')) }
function peer2Keys(did) {
  const parts = did.replace(/^did:peer:2/, '').split('.').filter(Boolean)
  const pick = (p, code) => { const m = parts.find((x) => x.startsWith(p)); const b = unb58(m.slice(2)); if (b[0] !== code || b[1] !== 0x01) throw new Error('unexpected multikey'); return b.slice(2) }
  return { spk: pick('Vz', 0xed), epk: pick('Ez', 0xec) }
}
function keyVid(sk = ed25519.utils.randomSecretKey()) {
  const spk = ed25519.getPublicKey(sk)
  return { id: 'did:key:z' + b58(new Uint8Array([0xed, 0x01, ...spk])), sk, spk, dk: ed25519.utils.toMontgomerySecret(sk), epk: ed25519.utils.toMontgomery(spk) }
}
const medVid = toml.match(/^mediator_did = "did:\/\/(.*)"$/m)[1]
const M = peer2Keys(medVid)
const adminJwk = JSON.parse(readFileSync(join(CONF, 'admin-monitor.json'), 'utf8')).secrets[0].privateKeyJwk
const ADMIN = keyVid(new Uint8Array(Buffer.from(adminJwk.d, 'base64url')))
const adminDid = toml.match(/^admin_did = "did:\/\/(.*)"$/m)[1]
if (ADMIN.id !== adminDid) throw new Error('admin key does not match admin_did')
const A = keyVid(), B = keyVid(), D = keyVid(), U = keyVid()

async function post(path, body, token, type = 'application/json') {
  const r = await fetch(base + path, { method: 'POST', headers: { 'content-type': type, ...(token ? { authorization: 'Bearer ' + token } : {}) }, body })
  const text = await r.text(); let json = null; try { json = JSON.parse(text) } catch {}
  return { status: r.status, json, text }
}
const problem = (r) => r.json?.errorCode ?? r.json?.error?.code ?? r.json?.code ?? r.json?.message ?? r.text.slice(0, 160)
async function signIn(v) {
  const c = await post('/authenticate/challenge', JSON.stringify({ did: v.id }))
  if (c.status !== 200) return { ok: false, step: 'challenge', status: c.status, problem: problem(c) }
  const { challenge, session_id } = c.json.data
  const a = await post('/tsp/authenticate', JSON.stringify({ vid: v.id, session_id, signature: Buffer.from(ed25519.sign(utf8(challenge), v.sk)).toString('base64url') }))
  if (a.status !== 200) return { ok: false, step: 'tsp/authenticate', status: a.status, problem: problem(a), kind: (a.text.match(/authentication\.[a-z.]+[a-z]/) || [null])[0] }
  return { ok: true, token: a.json.data.access_token }
}
// A Trust Task to the mediator, signed, sent as a direct TSP frame; the answer is sealed back to the sender's inbox.
async function task(who, token, typeUri, payload) {
  const doc = attachProof({ id: 'urn:uuid:' + crypto.randomUUID(), type: typeUri, issuer: who.id, recipient: medVid, issuedAt: new Date().toISOString(), payload }, who)
  const frame = await tsp.pack(utf8(JSON.stringify(doc)), who.id, medVid, { senderSigningKey: who.sk, receiverEncryptionKey: M.epk })
  const sent = await post('/inbound', frame.bytes, token, 'application/tsp')
  if (sent.status >= 300) return { status: sent.status, problem: problem(sent) }
  const reply = await collect(who, token, M.spk, true)
  const answer = reply.map((r) => r.json).find((j) => j?.threadId === doc.id || j?.id) ?? null
  return { status: sent.status, answerType: answer?.type ?? null, answer: answer?.payload ?? null }
}
// One request in flight at a time (Security 12552): Optimistic delete of up to 20 means a reply to a later request
// fetched in the same batch would be lost unread. Every caller here awaits each task() before the next.
async function collect(who, token, senderSpk, del = true) {
  const got = await post('/fetch', JSON.stringify({ limit: 20, delete_policy: del ? 'Optimistic' : 'DoNotDelete' }), token)
  const out = []
  for (const m of got.json?.data?.success ?? []) {
    let bytes = null
    for (const dec of [(s) => Buffer.from(s, 'base64url'), (s) => Buffer.from(s, 'base64')]) { try { const b = new Uint8Array(dec(m.msg ?? '')); if (tsp.isTsp(b)) { bytes = b; break } } catch {} }
    if (!bytes) continue
    try { const u = await tsp.unpack(bytes, { receiverDecryptionKey: who.dk, senderSigningKey: senderSpk }); let json = null; try { json = JSON.parse(new TextDecoder().decode(u.payload)) } catch {} out.push({ sender: u.sender, payload: u.payload, json }) } catch {}
  }
  return out
}
const ACCOUNT_ADD = 'https://trusttasks.org/spec/messaging/account/add/0.1'
const LIST_UPDATE = 'https://trusttasks.org/spec/messaging/access-list/update/0.1'
// Accounts and access lists are keyed by the DID's SHA-256 (hex). An account/add naming the plain DID is answered
// as a success and echoes the DID, but registers a key no sign-in ever looks up (found 2026-11-15: A then can't sign in).
const sha256hex = async (s) => Buffer.from(await crypto.subtle.digest('SHA-256', utf8(s))).toString('hex')
const LIST_LIST = 'https://trusttasks.org/spec/messaging/access-list/list/0.1'
// The setup check: an account exists only when its DID really signs in and an empty /fetch answers; never the add's answer.
async function accountReal(v) {
  const s = await signIn(v)
  if (!s.ok) return { real: false, refused_at: s.step, status: s.status, problem: s.problem }
  const f = await post('/fetch', JSON.stringify({ limit: 1, delete_policy: 'DoNotDelete' }), s.token)
  return { real: f.status === 200 && (f.json?.data?.success ?? []).length === 0, fetch_status: f.status }
}

// The admin's own calls: over DIDComm with --admin-didcomm, else the TSP task() above.
const MED = { id: medVid, epk: M.epk }
const adminSignIn = () => ADMIN_DIDCOMM ? didcommAdmin.signIn(post, ADMIN, MED) : signIn(ADMIN)
const adminTask = (typeUri, payload) => ADMIN_DIDCOMM ? didcommAdmin.task(post, ADMIN, sAdm.token, MED, typeUri, payload) : task(ADMIN, sAdm.token, typeUri, payload)

// ---- C1: closed mode refuses an unknown DID ----
const su = await signIn(U)
results.checks.C1_unknown_did_cannot_sign_in = { pass: !su.ok, ...su, token: undefined }
log('C1 unknown DID signs in', su.ok ? 'ALLOWED (fail)' : { refused_at: su.step, status: su.status, problem: su.problem })

// ---- the admin registers A (open inbox with a deny list), B and D ----
const sAdm = await adminSignIn(); log('admin sign-in', sAdm.ok ? (sAdm.via ?? 'tsp') : { ...sAdm, token: undefined })
results.setup.admin_sign_in = { ok: sAdm.ok, via: ADMIN_DIDCOMM ? 'didcomm' : 'tsp', ...(sAdm.ok ? {} : { step: sAdm.step, status: sAdm.status, problem: sAdm.problem }) }
if (!sAdm.ok) { results.error = 'admin could not sign in'; writeFileSync(outFile, JSON.stringify(results, null, 2) + '\n'); process.exit(1) }
// ---- --closed-default: the admin account gets exactly the mediator's own DID on its explicit-allow list ----
if (CLOSED) {
  const medHash = await sha256hex(medVid), admHash = await sha256hex(ADMIN.id)
  // The answer to this update is the mediator's, into an inbox whose list is still empty, so none is expected.
  const u = await adminTask(LIST_UPDATE, { did: admHash, clear: true, add: [medHash] })
  const l = await adminTask(LIST_LIST, { did: admHash, entries: [medHash] })
  const listed = (l.answer?.entries ?? []).map(String)
  results.setup.admin_list = { update_status: u.status, update_answer: u.answerType, update_problem: u.problem ?? null, list_status: l.status, list_answer: l.answerType, list_problem: l.problem ?? null, accessListCount: l.answer?.accessListCount ?? null, mediator_listed: listed.includes(medHash), only_entry: l.answer?.accessListCount === 1 && listed.includes(medHash) }
  results.checks.S2_admin_allow_list_is_mediator_only = { pass: results.setup.admin_list.only_entry, ...results.setup.admin_list }
  log('admin list = mediator only', results.setup.admin_list)
  // The read-back is the truth, never the update's answer (Security 12552.1): with the admin on TSP, read its list
  // again over DIDComm, read-only, before any add. Answered: the entries say whether the TSP update set the mediator.
  // Refused 403/73 at /inbound: the mediator's own reply to the admin was refused by the admin's list, which is
  // behaviour showing the mediator is not on it. Anything else is "can't tell" and the evaluator reads it as red.
  if (!ADMIN_DIDCOMM) {
    const sd = await didcommAdmin.signIn(post, ADMIN, MED)
    const rb = sd.ok ? await didcommAdmin.task(post, ADMIN, sd.token, MED, LIST_LIST, { did: admHash, entries: [medHash] }) : null
    const rbListed = (rb?.answer?.entries ?? []).map(String)
    results.setup.admin_list_readback_didcomm = { sign_in_ok: sd.ok, status: rb?.status ?? null, problem: rb?.problem ?? null, answered: !!rb?.answerType, answerType: rb?.answerType ?? null, accessListCount: rb?.answer?.accessListCount ?? null, mediator_listed: rbListed.includes(medHash) }
    log('admin list read back over DIDComm', results.setup.admin_list_readback_didcomm)
  }
}
const aclA = { accessListMode: 'explicitDeny', selfManageList: true, local: true, sendMessages: true, receiveMessages: true }
results.setup.account_A_acl = aclA
for (const [name, v, acl] of [['A', A, aclA], ['B', B], ['D', D]]) {
  const r = await adminTask(ACCOUNT_ADD, { did: await sha256hex(v.id), ...(acl ? { acl } : {}) })
  results.setup["account_add_" + name] = { status: r.status, answerType: r.answerType, problem: r.problem ?? null, confirmed: !!r.answerType }
  log(`admin account/add ${name}`, { status: r.status, answer: r.answerType ?? r.problem })
}
const sa = await signIn(A), sb = await signIn(B), sd = await signIn(D)
log('A, B, D sign in', { A: sa.ok || sa, B: sb.ok || sb, D: sd.ok || sd })
// Security 12672.1: whether each add landed, by a real sign-in (never the add's answer), for the expect-red's known-gap line.
results.setup.account_signs_in = { A: sa.ok, B: sb.ok, D: sd.ok }
if (!sa.ok || !sb.ok || !sd.ok) { results.error = 'a registered DID could not sign in'; writeFileSync(outFile, JSON.stringify(results, null, 2) + '\n'); process.exit(1) }

// ---- E1 (Security 12672.2): `enforce` is what the binary does, not only what the conf says ----
// Over DIDComm (the admin path that passes check_admin_signature with the guard on), the admin sends one WRITE with no
// proof: access-list/update adding U's hash to B's list. Under `enforce` it must be refused
// message.trust_task.proof_required (trust_task_verify.rs:79, :169-175); under `warn` it would be logged and let
// through (:176-187). The answer is never the proof: B's list is read back (signed) and U must not be on it. A READ with
// no proof (access-list/list, IS_PROOF_REQUIRED false) must still answer. Control: the same update signed lands and the
// read-back shows U, so the read-back can see a landed write; then B's list is cleared back to empty.
let e1rLate = null // the after-window half of E1r, run at the end
if (ADMIN_DIDCOMM) {
  const bHash = await sha256hex(B.id), uHash = await sha256hex(U.id)
  const listed = async () => { const l = await adminTask(LIST_LIST, { did: bHash, entries: [uHash] }); return { answered: !!l.answerType, listed: (l.answer?.entries ?? []).map(String).includes(uHash), status: l.status, problem: l.problem ?? null } }
  const w = await didcommAdmin.task(post, ADMIN, sAdm.token, MED, LIST_UPDATE, { did: bHash, add: [uHash] }, { unsigned: true })
  const afterUnsigned = await listed()
  const r = await didcommAdmin.task(post, ADMIN, sAdm.token, MED, LIST_LIST, { did: bHash, entries: [uHash] }, { unsigned: true })
  const ctl = await adminTask(LIST_UPDATE, { did: bHash, add: [uHash] })
  const afterSigned = await listed()
  await adminTask(LIST_UPDATE, { did: bHash, clear: true })
  const e1 = {
    unsigned_write: { status: w.status, answered: !!w.answerType, problem: typeof w.problem === 'number' ? w.problem : (w.problem ? 'other' : null), tt_code: w.tt_code ?? null },
    unsigned_write_landed: afterUnsigned.listed, readback_after_unsigned_answered: afterUnsigned.answered,
    unsigned_read: { status: r.status, answered: !!r.answerType, tt_code: r.tt_code ?? null },
    control_signed_write: { status: ctl.status, answered: !!ctl.answerType }, control_landed: afterSigned.listed,
  }
  e1.pass = !e1.unsigned_write.answered && e1.unsigned_write.tt_code === 'message.trust_task.proof_required' && afterUnsigned.answered && !afterUnsigned.listed && e1.unsigned_read.answered && afterSigned.listed
  results.checks.E1_enforce_unsigned_admin_write_refused = e1
  log('E1 unsigned admin write (enforce)', e1)

  // ---- E1r (Security 12856): a signed admin write played back is refused, inside the window and after it ----
  // Inside the window: claim() (trust_task_verify.rs claim, keyed on sender + document id, digest-bound) must refuse the
  // same document `message.trust_task.duplicate`. After it (issuedAt + DEFAULT_MAX_AGE 5 min + DEFAULT_SKEW 60 s,
  // trust-tasks-rs 0.37.0 freshness.rs:44/:54, FreshnessPolicy::consequential, no expiresAt): `message.trust_task.stale`.
  // An add is idempotent, so "one change, not two" is read this way: R (add a fresh hash to B's list) is sent once and
  // read back listed; a second, fresh signed update clears the list and reads back empty; then R is played back. If the
  // replay landed, the hash is on the list again. Played back two ways: the same signed document in a fresh envelope
  // (what claim() exists to catch), and the exact bytes again (a network replay). Both must be refused and not land.
  // The after-window replay runs at the end of this run (below), so the wait doesn't age anyone else's session.
  // A replay that lands under `enforce` stops the line: the expect-red goes red with a STOP and a finding for SECURITY.
  const rHash = await sha256hex(keyVid().id)
  const listedR = async () => { const l = await adminTask(LIST_LIST, { did: bHash, entries: [rHash] }); return { answered: !!l.answerType, listed: (l.answer?.entries ?? []).map(String).includes(rHash) } }
  const R = await didcommAdmin.packDoc(ADMIN, MED, didcommAdmin.trustTaskDoc(ADMIN, MED, LIST_UPDATE, { did: bHash, add: [rHash] }))
  const first = await didcommAdmin.sendPacked(post, ADMIN, sAdm.token, MED, R)
  const afterFirst = await listedR()
  const cleared = await adminTask(LIST_UPDATE, { did: bHash, clear: true })
  const afterClear = await listedR()
  const again = await didcommAdmin.sendPacked(post, ADMIN, sAdm.token, MED, await didcommAdmin.packDoc(ADMIN, MED, R.doc))
  const afterAgain = await listedR()
  const bytes = await didcommAdmin.sendPacked(post, ADMIN, sAdm.token, MED, R)
  const afterBytes = await listedR()
  const code = (x) => ({ status: x.status, answered: !!x.answerType, problem: typeof x.problem === 'number' ? x.problem : (x.problem ? 'other' : null), tt_code: x.tt_code ?? null })
  const e1r = {
    first: code(first), first_landed: afterFirst.listed, cleared: { answered: !!cleared.answerType }, cleared_readback_empty: afterClear.answered && !afterClear.listed,
    replay_same_doc: code(again), replay_same_doc_landed: afterAgain.listed, readback_after_replay_answered: afterAgain.answered,
    replay_same_bytes: code(bytes), replay_same_bytes_landed: afterBytes.listed, readback_after_bytes_answered: afterBytes.answered,
  }
  e1r.landed_under_enforce = afterAgain.listed || afterBytes.listed
  e1r.inside_window_pass = e1r.first.answered && e1r.first_landed && e1r.cleared_readback_empty
    && !e1r.replay_same_doc.answered && e1r.replay_same_doc.tt_code === 'message.trust_task.duplicate' && afterAgain.answered && !afterAgain.listed
    && !e1r.replay_same_bytes.answered && afterBytes.answered && !afterBytes.listed
  e1r.pass = false // set at the end, once the after-window replay has run
  results.checks.E1r_enforce_signed_replay_refused = e1r
  log('E1r replay inside the window', e1r)
  e1rLate = { R, bHash, rHash, issuedAt: Date.parse(R.doc.issuedAt) }
}

// ---- step 0 (Railroad 11606): account/add over TSP skips check_permissions; prove it is still admin-only ----
// Source (0.50.0 @ 34bbdea4): trust_tasks.rs consume_account_add refuses a non-admin session in explicit_allow mode
// (`mediator_acl_mode == ExplicitAllow && !is_admin`); is_admin is the session's account type, and the TSP sender is
// bound to the session DID by force_session_did_match (inbound.rs). In explicit_deny mode any signed-in account may add.
// Z1 a signed-in ordinary account (B) adds a fresh DID's hash: pass = refused AND the fresh DID then can't sign in.
// Z2 a DID with no account: can't sign in (no token), and a signed frame to /inbound with no token is refused.
{
  const F = keyVid()
  const z1 = await task(B, sb.token, ACCOUNT_ADD, { did: await sha256hex(F.id) })
  const z1f = await accountReal(F)
  results.checks.Z1_non_admin_account_add_refused = { pass: !(z1.answerType && !/problem|error|reject/i.test(z1.answerType)) && !z1f.real, add_status: z1.status, add_answer: z1.answerType, add_problem: z1.problem ?? null, fresh_did_check: z1f }
  log('Z1 non-admin account/add', { status: z1.status, answer: z1.answerType ?? z1.problem, fresh_signs_in: z1f.real })
  const N = keyVid(), G = keyVid()
  const sn = await signIn(N)
  const doc = attachProof({ id: 'urn:uuid:' + crypto.randomUUID(), type: ACCOUNT_ADD, issuer: N.id, recipient: medVid, issuedAt: new Date().toISOString(), payload: { did: await sha256hex(G.id) } }, N)
  const frame = await tsp.pack(utf8(JSON.stringify(doc)), N.id, medVid, { senderSigningKey: N.sk, receiverEncryptionKey: M.epk })
  const z2 = await post('/inbound', frame.bytes, null, 'application/tsp')
  const z2g = await accountReal(G)
  results.checks.Z2_no_account_did_cannot_add = { pass: !sn.ok && z2.status >= 400 && !z2g.real, sign_in: sn.ok ? 'ALLOWED' : { refused_at: sn.step, status: sn.status }, inbound_status: z2.status, inbound_problem: z2.status >= 300 ? problem(z2) : null, fresh_did_check: z2g }
  log('Z2 no-account DID account/add', { sign_in: sn.ok, inbound: z2.status, fresh_signs_in: z2g.real })
}
if (CLOSED) results.checks.S2_adds_confirmed_under_closed_default = { pass: ['A', 'B', 'D'].every((n) => results.setup['account_add_' + n].confirmed) }

// ---- R1: a plain-DID add is answered, but the setup check turns it red ----
const P = keyVid()
const r1 = await adminTask(ACCOUNT_ADD, { did: P.id })
const r1real = await accountReal(P)
results.checks.R1_plain_did_add_turns_check_red = { pass: !r1real.real, add_answer: r1.answerType, add_status: r1.status, check: r1real, note: 'pass = the setup check refused it (red), whatever the add answered' }
log('R1 plain-DID add', { answer: r1.answerType, check_real: r1real.real, refused_at: r1real.refused_at ?? null })
const realA = await accountReal(A)
results.checks.R1_hashed_add_passes_check = { pass: realA.real, check: realA }

// ---- line A (Railroad 11506): a DID with no X25519 keyAgreement must not sign in ----
// A did:peer:2 carrying only an Ed25519 key (V, authentication), no E key: registered by its hash, then a real sign-in.
// Pass = refused somewhere in the sign-in (the record says where), never a token.
const NK = keyVid()
NK.id = 'did:peer:2.Vz' + b58(new Uint8Array([0xed, 0x01, ...NK.spk]))
const nkAdd = await adminTask(ACCOUNT_ADD, { did: await sha256hex(NK.id) })
const nk = await signIn(NK)
results.checks.A_no_x25519_keyagreement_refused = { pass: !nk.ok, add_answer: nkAdd.answerType ?? nkAdd.problem ?? null, refused_at: nk.step ?? null, status: nk.status ?? null, problem: nk.problem ?? null, kind: nk.kind ?? null }
log('A no-X25519 DID signs in', nk.ok ? 'ALLOWED (fail)' : { refused_at: nk.step, status: nk.status, problem: nk.problem, kind: nk.kind })
// Control: the same shape with the X25519 key added (V + E) does sign in, so the refusal above is the missing key.
const NE = keyVid()
NE.id = 'did:peer:2.Vz' + b58(new Uint8Array([0xed, 0x01, ...NE.spk])) + '.Ez' + b58(new Uint8Array([0xec, 0x01, ...NE.epk]))
await adminTask(ACCOUNT_ADD, { did: await sha256hex(NE.id) })
const ne = await signIn(NE)
results.checks.A_control_with_x25519_signs_in = { pass: ne.ok, refused_at: ne.step ?? null, status: ne.status ?? null, problem: ne.problem ?? null, kind: ne.kind ?? null }
log('A control (V+E) signs in', ne.ok ? 'ok' : { refused_at: ne.step, status: ne.status, problem: ne.problem, kind: ne.kind })

// ---- A denies D on its own list ----
const upd = await task(A, sa.token, LIST_UPDATE, { did: await sha256hex(A.id), add: [await sha256hex(D.id)] })
results.setup.access_list_update = { status: upd.status, answerType: upd.answerType, accessListCount: upd.answer?.accessListCount ?? null, problem: upd.problem ?? null }
log('A access-list/update add D', results.setup.access_list_update)

const ping = () => utf8(JSON.stringify({ type: 'https://trusttasks.org/messaging/ping/0.2', id: 'urn:uuid:' + crypto.randomUUID() }))
async function sendTo(from, token, to, toEpk) {
  const body = ping()
  const inner = await tsp.pack(body, from.id, to, { senderSigningKey: from.sk, receiverEncryptionKey: toEpk })
  const outer = await tsp.packRouted(inner.bytes, [to], from.id, medVid, { senderSigningKey: from.sk, receiverEncryptionKey: M.epk })
  const r = await post('/inbound', outer.bytes, token, 'application/tsp')
  return { status: r.status, problem: r.status >= 300 ? problem(r) : null, body }
}

// ---- C2: a frame routed to a DID that isn't local is refused ----
// Caveat: X is a did:key, which publishes no endpoint, so this refusal (58, no TSP endpoint) does not yet show that
// forwarding-off is what refuses it. A DID with a TSP endpoint is the next step.
const X = keyVid()
const c2 = await sendTo(B, sb.token, X.id, X.epk)
results.checks.C2_route_to_non_local_refused = { pass: c2.status >= 400, status: c2.status, problem: c2.problem, caveat: 'did:key has no endpoint; not yet proof that forwarding-off refuses' }
log('C2 B → outside DID', { status: c2.status, problem: c2.problem })

// ---- C3: B (never met, not denied) → A lands ----
const c3 = await sendTo(B, sb.token, A.id, A.epk)
const gotA = await collect(A, sa.token, B.spk)
const opened = gotA.find((m) => m.sender === B.id && eq(m.payload, c3.body))
results.checks.C3_stranger_lands = { pass: c3.status < 300 && !!opened, status: c3.status, collected_and_opened: !!opened }
log('C3 B → A (stranger)', { status: c3.status, opened: !!opened })

// ---- C4: D (denied) → A refused ----
const c4 = await sendTo(D, sd.token, A.id, A.epk)
const leaked = (await collect(A, sa.token, D.spk)).some((m) => m.sender === D.id)
results.checks.C4_denied_refused = { pass: c4.status >= 400 && !leaked, status: c4.status, problem: c4.problem, reached_A: leaked }
log('C4 D → A (denied)', { status: c4.status, problem: c4.problem, reached_A: leaked })

// ---- Z3 (finding, not a pass/fail line): account/add on an EXISTING hash overwrites it ----
// Source: redis accounts.rs account_add HSETs ROLE_TYPE=Standard and ACLS with no existence check, and
// consume_account_add has none either. Here the admin re-adds A's hash with no acl; if A's selfManageList is gone,
// A's own access-list/update is refused afterwards. (In explicit_deny mode a non-admin could do the same to anyone.)
{
  const re = await adminTask(ACCOUNT_ADD, { did: await sha256hex(A.id) })
  const sa2 = await signIn(A)
  const after = sa2.ok ? await task(A, sa2.token, LIST_UPDATE, { did: await sha256hex(A.id), add: [await sha256hex(X.id)] }) : null
  results.findings = { Z3_readd_existing_account: { readd_answer: re.answerType ?? re.problem ?? null, a_signs_in_after: sa2.ok, a_list_update_after: after ? { status: after.status, answerType: after.answerType, problem: after.problem ?? null } : null, overwritten: !!after && !after.answerType } }
  log('Z3 re-add existing A', results.findings.Z3_readd_existing_account)
}
// ---- E1r, after the window (Security 12856): the same signed document once more → message.trust_task.stale ----
// Waits until issuedAt + 5 min + 60 s skew + a 20 s margin (about six minutes of this run). The admin signs in afresh
// first, so an expired session can't stand in for the refusal.
if (e1rLate) {
  const e1r = results.checks.E1r_enforce_signed_replay_refused
  const waitMs = e1rLate.issuedAt + (5 * 60 + 60 + 20) * 1000 - Date.now()
  if (waitMs > 0) { log('E1r waiting for the window to close', `${Math.ceil(waitMs / 1000)} s`); await new Promise((r) => setTimeout(r, waitMs)) }
  const s2 = await adminSignIn()
  const late = s2.ok ? await didcommAdmin.sendPacked(post, ADMIN, s2.token, MED, await didcommAdmin.packDoc(ADMIN, MED, e1rLate.R.doc)) : null
  const l = s2.ok ? await didcommAdmin.task(post, ADMIN, s2.token, MED, LIST_LIST, { did: e1rLate.bHash, entries: [e1rLate.rHash] }) : null
  const lateListed = (l?.answer?.entries ?? []).map(String).includes(e1rLate.rHash)
  e1r.after_window = { admin_signed_in: s2.ok, seconds_after_issued: Math.round((Date.now() - e1rLate.issuedAt) / 1000), ...(late ? { status: late.status, answered: !!late.answerType, tt_code: late.tt_code ?? null } : {}), readback_answered: !!l?.answerType, landed: lateListed }
  e1r.landed_under_enforce = e1r.landed_under_enforce || lateListed
  e1r.after_window_pass = !!late && !late.answerType && late.tt_code === 'message.trust_task.stale' && !!l?.answerType && !lateListed
  e1r.pass = e1r.inside_window_pass && e1r.after_window_pass && !e1r.landed_under_enforce
  log('E1r replay after the window', e1r.after_window)
}
results.pass = Object.values(results.checks).every((c) => c.pass)
results.log_lines_with_redis_password = medLog.split('\n').filter((l) => l.includes(PW)).length
writeFileSync(outFile, JSON.stringify(results, null, 2) + '\n')
log('all', results.pass ? 'PASS' : 'FAIL'); log('log lines with redis password', String(results.log_lines_with_redis_password))
stop(); process.exit(results.pass ? 0 : 1)
