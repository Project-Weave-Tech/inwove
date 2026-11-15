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
//   R1  (Railroad 11571, setup fact 1) a deliberate plain-DID account/add: the add's answer is not trusted; the
//       setup check (a real sign-in + an empty /fetch) must turn it red
// --closed-default (Railroad 11571, setup fact 2): the mediator's default for new accounts is explicit-allow (closed),
//   and the admin account is set to explicit-allow with exactly the mediator's own DID (hashed) on its list, then read
//   back with access-list/list, before any account/add. Without the flag the run is the 2026-11-15 shape (explicit-deny
//   default, the upstream test conf's), so the two can be compared.
// Usage: node mediator-acl.mjs <mediator binary> <conf dir> <redis-server> <out.json> [--closed-default]
// Test keys only; A, B, D, U are made here and die with the process. Prints statuses and problem codes, no keys.
import { spawn } from 'node:child_process'
import { mkdtempSync, cpSync, readFileSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import * as tsp from '@openvtc/vti-tsp-js'
import { ed25519 } from '@noble/curves/ed25519.js'
import { b58, utf8, eq, attachProof } from './lib.mjs'

const [binArg, confArg, redisBin, outFile] = process.argv.slice(2).filter((a) => !a.startsWith('--'))
const CLOSED = process.argv.includes('--closed-default')
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
writeFileSync(tomlPath, toml)
results.setup = { mediator_acl_mode: 'explicit_allow', global_acl_default: DEFAULT_ACL, external_forwarding: false, enable_inter_mediator_relay: false, trust_task_verification: 'enforce' }

procs.push(spawn(redisBin, ['--port', String(RPORT), '--bind', '127.0.0.1', '--requirepass', PW, '--save', '', '--appendonly', 'no'], { stdio: 'ignore' }))
await new Promise((r) => setTimeout(r, 500))
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
  if (a.status !== 200) return { ok: false, step: 'tsp/authenticate', status: a.status, problem: problem(a) }
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

// ---- C1: closed mode refuses an unknown DID ----
const su = await signIn(U)
results.checks.C1_unknown_did_cannot_sign_in = { pass: !su.ok, ...su, token: undefined }
log('C1 unknown DID signs in', su.ok ? 'ALLOWED (fail)' : { refused_at: su.step, status: su.status, problem: su.problem })

// ---- the admin registers A (open inbox with a deny list), B and D ----
const sAdm = await signIn(ADMIN); log('admin sign-in', sAdm.ok ? 'ok' : sAdm)
if (!sAdm.ok) { results.error = 'admin could not sign in'; writeFileSync(outFile, JSON.stringify(results, null, 2) + '\n'); process.exit(1) }
// ---- --closed-default: the admin account gets exactly the mediator's own DID on its explicit-allow list ----
if (CLOSED) {
  const medHash = await sha256hex(medVid), admHash = await sha256hex(ADMIN.id)
  // The answer to this update is the mediator's, into an inbox whose list is still empty, so none is expected.
  const u = await task(ADMIN, sAdm.token, LIST_UPDATE, { did: admHash, clear: true, add: [medHash] })
  const l = await task(ADMIN, sAdm.token, LIST_LIST, { did: admHash, entries: [medHash] })
  const listed = (l.answer?.entries ?? []).map(String)
  results.setup.admin_list = { update_status: u.status, update_answer: u.answerType, list_answer: l.answerType, accessListCount: l.answer?.accessListCount ?? null, mediator_listed: listed.includes(medHash), only_entry: l.answer?.accessListCount === 1 && listed.includes(medHash) }
  results.checks.S2_admin_allow_list_is_mediator_only = { pass: results.setup.admin_list.only_entry, ...results.setup.admin_list }
  log('admin list = mediator only', results.setup.admin_list)
}
const aclA = { accessListMode: 'explicitDeny', selfManageList: true, local: true, sendMessages: true, receiveMessages: true }
results.setup.account_A_acl = aclA
for (const [name, v, acl] of [['A', A, aclA], ['B', B], ['D', D]]) {
  const r = await task(ADMIN, sAdm.token, ACCOUNT_ADD, { did: await sha256hex(v.id), ...(acl ? { acl } : {}) })
  results.setup["account_add_" + name] = { status: r.status, answerType: r.answerType, problem: r.problem ?? null, confirmed: !!r.answerType }
  log(`admin account/add ${name}`, { status: r.status, answer: r.answerType ?? r.problem })
}
const sa = await signIn(A), sb = await signIn(B), sd = await signIn(D)
log('A, B, D sign in', { A: sa.ok || sa, B: sb.ok || sb, D: sd.ok || sd })
if (!sa.ok || !sb.ok || !sd.ok) { results.error = 'a registered DID could not sign in'; writeFileSync(outFile, JSON.stringify(results, null, 2) + '\n'); process.exit(1) }

if (CLOSED) results.checks.S2_adds_confirmed_under_closed_default = { pass: ['A', 'B', 'D'].every((n) => results.setup['account_add_' + n].confirmed) }

// ---- R1: a plain-DID add is answered, but the setup check turns it red ----
const P = keyVid()
const r1 = await task(ADMIN, sAdm.token, ACCOUNT_ADD, { did: P.id })
const r1real = await accountReal(P)
results.checks.R1_plain_did_add_turns_check_red = { pass: !r1real.real, add_answer: r1.answerType, add_status: r1.status, check: r1real, note: 'pass = the setup check refused it (red), whatever the add answered' }
log('R1 plain-DID add', { answer: r1.answerType, check_real: r1real.real, refused_at: r1real.refused_at ?? null })
const realA = await accountReal(A)
results.checks.R1_hashed_add_passes_check = { pass: realA.real, check: realA }

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

results.pass = Object.values(results.checks).every((c) => c.pass)
results.log_lines_with_redis_password = medLog.split('\n').filter((l) => l.includes(PW)).length
writeFileSync(outFile, JSON.stringify(results, null, 2) + '\n')
log('all', results.pass ? 'PASS' : 'FAIL'); log('log lines with redis password', String(results.log_lines_with_redis_password))
stop(); process.exit(results.pass ? 0 : 1)
