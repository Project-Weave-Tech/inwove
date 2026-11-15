// ref/09 shared helpers. Every key here is made by the test and dies with it: no secret, no real person's key.
import { spawn } from 'node:child_process'
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createInterface } from 'node:readline'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { sha256 } from '@noble/hashes/sha2.js'

export const HERE = dirname(fileURLToPath(import.meta.url))
export const ensureDir = (d) => mkdirSync(d, { recursive: true })
export const writeJson = (f, v) => { ensureDir(dirname(f)); writeFileSync(f, JSON.stringify(v, null, 2) + '\n') }
export const readJson = (f) => JSON.parse(readFileSync(f, 'utf8'))
export const hex = (b) => Buffer.from(b).toString('hex')
export const b64 = (b) => Buffer.from(b).toString('base64')
export const unb64 = (s) => new Uint8Array(Buffer.from(s, 'base64'))
export const utf8 = (s) => new TextEncoder().encode(s)
export const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i])

// base58btc, for did:key
const ALPHA = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
export function b58(bytes) {
  let n = BigInt('0x' + (hex(bytes) || '0')); let s = ''
  while (n > 0n) { s = ALPHA[Number(n % 58n)] + s; n /= 58n }
  for (const b of bytes) { if (b !== 0) break; s = '1' + s }
  return s
}

// A test VID: a did:key named by its Ed25519 key, plus an X25519 pair for HPKE.
export function makeVid() {
  const sk = ed25519.utils.randomSecretKey(); const spk = ed25519.getPublicKey(sk)
  const dk = x25519.utils.randomSecretKey(); const epk = x25519.getPublicKey(dk)
  const id = 'did:key:z' + b58(new Uint8Array([0xed, 0x01, ...spk]))
  return { id, sk, spk, dk, epk }
}

// JCS (RFC 8785) for the plain JSON the tests sign: strings, integers, booleans, null, arrays, objects.
export function jcs(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v)
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']'
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + jcs(v[k])).join(',') + '}'
}

// A messaging/ping/0.2 Trust Task signed with an eddsa-jcs-2022 Data Integrity proof (W3C vc-di-eddsa §3.3).
export function signedPing(issuer, { id = 'urn:uuid:' + crypto.randomUUID(), threadId } = {}) {
  const doc = { '@context': ['https://www.w3.org/ns/credentials/v2'], type: 'https://trusttasks.org/messaging/ping/0.2', id, issuer: issuer.id, issued: new Date().toISOString(), ...(threadId ? { threadId } : {}) }
  return attachProof(doc, issuer)
}
export function attachProof(doc, signer) {
  const config = { type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', created: doc.issued ?? new Date().toISOString(), verificationMethod: signer.id + '#' + signer.id.slice('did:key:'.length), proofPurpose: 'assertionMethod' }
  const data = new Uint8Array([...sha256(utf8(jcs(config))), ...sha256(utf8(jcs(doc)))])
  return { ...doc, proof: { ...config, proofValue: 'z' + b58(ed25519.sign(data, signer.sk)) } }
}
export function verifyProof(doc, spk) {
  try {
    const { proof, ...rest } = doc; if (!proof || proof.cryptosuite !== 'eddsa-jcs-2022') return false
    const { proofValue, ...config } = proof
    const data = new Uint8Array([...sha256(utf8(jcs(config))), ...sha256(utf8(jcs(rest)))])
    return ed25519.verify(unb58(proofValue.slice(1)), data, spk)
  } catch { return false }
}
function unb58(s) {
  let n = 0n; for (const c of s) { const i = ALPHA.indexOf(c); if (i < 0) throw new Error('bad b58'); n = n * 58n + BigInt(i) }
  let h = n.toString(16); if (h.length % 2) h = '0' + h
  const lead = s.match(/^1*/)[0].length
  return new Uint8Array([...new Array(lead).fill(0), ...Buffer.from(h === '0' ? '' : h, 'hex')])
}

// The binding envelope, built by byte concatenation so the document's own bytes travel untouched.
export const ENVELOPE_TYPE = 'https://trusttasks.org/binding/tsp/0.1/envelope'
const PREFIX = utf8('{"type":"' + ENVELOPE_TYPE + '","document":')
export function envelope(docBytes, type = ENVELOPE_TYPE) {
  const pre = type === ENVELOPE_TYPE ? PREFIX : utf8('{"type":' + JSON.stringify(type) + ',"document":')
  return new Uint8Array([...pre, ...docBytes, 0x7d])
}
// Returns { type, docBytes } or throws. The document's bytes are sliced out, never re-serialised.
export function openEnvelope(bytes) {
  const parsed = JSON.parse(new TextDecoder().decode(bytes))
  if (parsed?.type !== ENVELOPE_TYPE) return { type: parsed?.type ?? null, docBytes: null, parsed }
  if (!eq(bytes.slice(0, PREFIX.length), PREFIX) || bytes[bytes.length - 1] !== 0x7d) return { type: parsed.type, docBytes: null, parsed }
  return { type: parsed.type, docBytes: bytes.slice(PREFIX.length, bytes.length - 1), parsed }
}

// The Rust peer (affinidi-tsp 0.3.0): one long-lived process, JSON lines both ways.
export function rustPeer(bin = process.env.TSP_PEER_BIN || join(HERE, 'rs', 'target', 'release', 'tsp-peer')) {
  const p = spawn(bin, [], { stdio: ['pipe', 'pipe', 'inherit'] })
  const lines = createInterface({ input: p.stdout }); const waiting = []
  lines.on('line', (l) => waiting.shift()?.(JSON.parse(l)))
  const call = (cmd) => new Promise((res) => { waiting.push(res); p.stdin.write(JSON.stringify(cmd) + '\n') })
  return {
    call,
    async ok(cmd) { const r = await call(cmd); if (!r.ok) throw new Error(`rust ${cmd.op}: ${r.error}`); return r.r },
    private: (v) => call({ op: 'private', id: v.id, sk: hex(v.sk), dk: hex(v.dk) }),
    remote: (v) => call({ op: 'remote', id: v.id, spk: hex(v.spk), epk: hex(v.epk) }),
    close: () => { p.stdin.end(); return new Promise((r) => p.on('exit', r)) },
  }
}

// One result row per check; `answer` rows record a finding that is not pass/fail.
export function recorder(job) {
  const rows = []
  return {
    rows,
    check(what, ok, detail = '') { rows.push({ what, ok: !!ok, detail }); console.log(`${ok ? 'ok  ' : 'FAIL'}  ${what}${detail ? ': ' + detail : ''}`) },
    answer(what, detail) { rows.push({ what, answer: true, detail }); console.log(`ans   ${what}: ${detail}`) },
    finish(results, extra = {}) {
      const pass = rows.every((r) => r.answer || r.ok)
      writeJson(join(results, `${job}.json`), { job, pass, rows, ...extra, at: new Date().toISOString() })
      console.log(`${job}: ${pass ? 'PASS' : 'FAIL'} (${rows.filter((r) => !r.answer && r.ok).length}/${rows.filter((r) => !r.answer).length} checks, ${rows.filter((r) => r.answer).length} answers)`)
      return pass
    },
  }
}
