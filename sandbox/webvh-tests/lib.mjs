// Shared helpers for the TS side of the did:webvh library tests. TEST KEYS ONLY: every key is generated in the process
// that uses it and is dropped with it. Nothing here reads a secret, a real log or the network (except where a script
// says so, and then only the local static server of the job).
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { createDID, updateDID, resolveDIDFromLog, resolveDID, deriveNextKeyHash, prepareDataForSigning, signWitnessProofEntry } from 'didwebvh-ts'
import { newIdentity } from '../../src/shared/did.js'
import { ed25519, multibase } from '../../src/shared/crypto.js'
import { ed25519Multikey } from '../../src/shared/did.js'

export { resolveDIDFromLog, resolveDID, deriveNextKeyHash }

export const verifier = { verify: async (sig, msg, pub) => ed25519.verify(sig, msg, pub) }

/** A test key: { id (seed holder), mk (multikey), signer } */
export function testKey () {
  const id = newIdentity()
  const mk = ed25519Multikey(id.publicKey)
  const signer = {
    getVerificationMethodId: () => `did:key:${mk}#${mk}`,
    async sign ({ document, proof }) { return { proofValue: multibase(ed25519.sign(await prepareDataForSigning(document, proof), id.seed)) } },
  }
  return { id, mk, signer, did: `did:key:${mk}` }
}

export const readLog = (path) => readFileSync(path, 'utf8').split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l))
export const logText = (log) => log.map((e) => JSON.stringify(e)).join('\n') + '\n'
export const readJson = (path) => JSON.parse(readFileSync(path, 'utf8'))
export function writeJson (path, v) { writeFileSync(path, JSON.stringify(v, null, 2) + '\n') }
export function ensureDir (d) { mkdirSync(d, { recursive: true }) }

const iso = (ms) => new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(/\.\d+Z$/, 'Z')

/** The document every four-step log uses (same keys and services in TS and Rust, so they can be compared). */
export const baseDoc = (docKey, withService) => ({
  '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
  id: '{DID}',
  verificationMethod: [{ id: '{DID}#key-0', type: 'Multikey', controller: '{DID}', publicKeyMultibase: docKey }],
  authentication: ['{DID}#key-0'],
  assertionMethod: ['{DID}#key-0'],
  ...(withService ? { service: [{ id: '{DID}#site', type: 'LinkedDomains', serviceEndpoint: 'https://example.test/' }] } : {}),
})
const fillDid = (v, did) => JSON.parse(JSON.stringify(v).replaceAll('{DID}', did))

/**
 * The four-step log, made by didwebvh-ts:
 *   1 create with pre-rotation (nextKeyHashes -> k1), portable
 *   2 rotate once, consuming k1 (prerotation ends)
 *   3 add a witness rule 2-of-2
 *   4 change it to 1-of-1 (witnessed by BOTH current witnesses; the entry's own new rule does not govern it)
 * `oneProofOnly` (the section 3 test): entry 4 is signed by only ONE of the two witnesses.
 * Returns { did, log, witnessProofs, keys }.
 */
export async function tsFourStepLog (host, { oneProofOnly = false } = {}) {
  const now = Date.now()
  const at = (n) => iso(now - 600_000 + n * 60_000)
  const k0 = testKey(); const k1 = testKey(); const dk = testKey(); const w1 = testKey(); const w2 = testKey()
  const c = await createDID({
    address: host, signer: k0.signer, verifier, updateKeys: [k0.mk], portable: true, created: at(0),
    nextKeyHashes: [await deriveNextKeyHash(k1.mk)],
    didDocument: baseDoc(dk.mk, false),
  })
  const did = c.did
  let log = c.log
  const r2 = await updateDID({ log, signer: k1.signer, verifier, updateKeys: [k1.mk], nextKeyHashes: [], didDocument: fillDid(baseDoc(dk.mk, true), did), updated: at(1) })
  log = r2.log
  // The two libraries read the witness rule differently (the section 0 (d) split). didwebvh-ts requires the entry that
  // declares a rule to be witnessed under that new rule; didwebvh-rs requires the rule in force BEFORE the entry. A log both
  // accept is witnessed by both witnesses on entries 3 and 4, so that is what is made here.
  const addProofs = async (trustedLog, candidateLog, proofs, who) => {
    let out = proofs
    for (const w of who) {
      const e = await signWitnessProofEntry({ trustedLog, candidateLog, witnessSigner: w.signer, witnessProofs: out, verifier })
      const had = out.find((p) => p.versionId === e.versionId)?.proof ?? []
      out = [...out.filter((p) => p.versionId !== e.versionId), { versionId: e.versionId, proof: [...had, ...e.proof] }]
    }
    return out
  }
  const r3 = await updateDID({ log, signer: k1.signer, verifier, witness: { threshold: 2, witnesses: [{ id: w1.did }, { id: w2.did }] }, witnessProofs: [], updated: at(2) })
  let witnessProofs = await addProofs(log, r3.log, [], [w1, w2])
  log = r3.log
  const r4 = await updateDID({ log, signer: k1.signer, verifier, witness: { threshold: 1, witnesses: [{ id: w1.did }] }, witnessProofs, updated: at(3) })
  witnessProofs = await addProofs(log, r4.log, witnessProofs, oneProofOnly ? [w1] : [w1, w2])
  log = r4.log
  return { did, log, witnessProofs, keys: { k0, k1, dk, w1, w2 } }
}

/** Resolve a log with didwebvh-ts, never throw: { ok, error?, scid?, versionId?, versionNumber?, document? } */
export async function tsResolve (log, did, { witnessProofs = [], version } = {}) {
  try {
    const opts = { verifier, witnessProofs }
    if (version) opts.versionNumber = Number(version)
    const r = await resolveDIDFromLog(log, opts)
    if (!r.didDocument) return { ok: false, error: `${r.didResolutionMetadata?.error ?? 'no document'}: ${r.didResolutionMetadata?.problemDetails?.detail ?? ''}`.trim() }
    const m = r.didDocumentMetadata ?? {}
    const doc = r.didDocument
    if (did && doc.id !== did) return { ok: false, error: `document id ${doc.id} is not the asked DID ${did}` }
    return { ok: true, scid: m.scid, versionId: m.versionId, versionNumber: Number(String(m.versionId).split('-')[0]), portable: m.portable, witness: m.witness ?? null, document: doc, id: doc.id }
  } catch (e) {
    return { ok: false, error: `threw: ${e?.message ?? e}` }
  }
}

// ---------------------------------------------------------------------------------------------------------------------
// running the CLIs, local static server, comparison helpers
import { spawn, spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { dirname, join, resolve as pathResolve } from 'node:path'
import { fileURLToPath } from 'node:url'

export const HERE = dirname(fileURLToPath(import.meta.url))
export const RS_BIN = process.env.WPI_RS_BIN || join(HERE, 'rs', 'target', 'debug', 'wpi-webvh-rs')
export const TS_CLI = join(HERE, 'ts-cli.mjs')
export const PY_CLI = join(HERE, 'py_resolve.py')

/** Run a command, return { code, stdout, stderr, json (the last JSON line of stdout, or null), ms }. */
export function run (cmd, args, { env, input, timeout = 120_000 } = {}) {
  const t = Date.now()
  const r = spawnSync(cmd, args, { encoding: 'utf8', env: { ...process.env, ...env }, input, timeout, maxBuffer: 64 * 1024 * 1024 })
  let json = null
  const lines = (r.stdout ?? '').trim().split('\n').filter(Boolean)
  for (let i = lines.length - 1; i >= 0 && !json; i--) { try { json = JSON.parse(lines[i]) } catch { /* not json */ } }
  return { code: r.status ?? (r.signal ? 128 : 1), signal: r.signal, stdout: r.stdout ?? '', stderr: r.stderr ?? '', json, ms: Date.now() - t }
}
export const ts = (args, opts) => run('node', [TS_CLI, ...args], opts)
export const rs = (args, opts) => run(RS_BIN, args, opts)
export const py = (args, opts) => run(process.env.WPI_PYTHON || 'python3', ['-I', PY_CLI, ...args], opts)

/** What one resolver said about one log. A refusal is ANY failure to give a document: an error answer, a crash, a timeout. */
export function verdict (r) {
  if (r.json && r.json.ok === true) return { accepted: true, scid: r.json.scid, versionId: r.json.versionId, versionNumber: r.json.versionNumber, document: r.json.document, ms: r.ms }
  return { accepted: false, error: String(r.json?.error ?? (`exit ${r.code}${r.signal ? ' ' + r.signal : ''}: ` + (r.stderr || r.stdout).trim().split('\n').slice(-2).join(' | '))).slice(0, 300), ms: r.ms }
}

/** The resolvers, by library name, over local files: (did, logPath, witnessPath?, version?) -> verdict */
export const RESOLVERS = {
  ts: (did, log, wit, version) => verdict(ts(['resolve-file', did, log, ...(wit ? [wit] : []), ...(version ? ['--version', String(version)] : [])])),
  rs: (did, log, wit, version) => verdict(rs(['resolve-file', did, log, ...(wit ? [wit] : []), ...(version ? ['--version', String(version)] : [])])),
  py: (did, log, wit, version) => verdict(py(['resolve-file', did, log, ...(wit ? [wit] : []), ...(version ? ['--version', String(version)] : [])])),
}

/** Start the static server as its own process (the CLIs are run synchronously, so it cannot share their event loop). */
export function startStaticServer (root) {
  ensureDir(root)
  const logPath = join(root, '..', 'requests.jsonl')
  const child = spawn(process.execPath, [join(HERE, 'static-server.mjs'), root, logPath], { stdio: ['ignore', 'pipe', 'inherit'] })
  return new Promise((resolve, reject) => {
    child.stdout.once('data', (d) => resolve({
      port: Number(String(d).trim()), pid: child.pid,
      requests: () => (existsSync(logPath) ? readFileSync(logPath, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)) : []),
      close: () => { child.kill(); return Promise.resolve() },
    }))
    child.once('error', reject)
  })
}

/** Put a log (and its witness file) where the static server finds it for a hostname. */
export function publish (root, host, logPath, witnessPath) {
  const dir = join(root, host, '.well-known')
  ensureDir(dir)
  writeFileSync(join(dir, 'did.jsonl'), readFileSync(logPath))
  if (witnessPath) writeFileSync(join(dir, 'did-witness.json'), readFileSync(witnessPath))
}

const sortDeep = (v) => Array.isArray(v) ? v.map(sortDeep) : (v && typeof v === 'object') ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortDeep(v[k])])) : v

/**
 * Normalise a resolved DID document for comparison between libraries: only the SET OF KEYS AND SERVICES (and the
 * relationships that name them) is compared. Dropped on purpose, as the spec for this harness says: @context
 * placement, key order, format-only fields, the trailing slash of the #files endpoint. The DID string itself is
 * replaced by {DID} so two logs made for the same host compare equal only in shape, not by SCID.
 */
export function normaliseDoc (doc) {
  const did = doc.id
  const s = JSON.stringify(doc).replaceAll(did, '{DID}')
  const d = JSON.parse(s)
  delete d['@context']
  for (const sv of d.service ?? []) { if (typeof sv.serviceEndpoint === 'string' && sv.id.endsWith('#files')) sv.serviceEndpoint = sv.serviceEndpoint.replace(/\/+$/, ''); delete sv['@context'] }
  for (const k of ['service', 'verificationMethod']) if (d[k]) d[k] = d[k].map(sortDeep).sort((a, b) => a.id.localeCompare(b.id))
  for (const k of ['authentication', 'assertionMethod', 'keyAgreement', 'capabilityInvocation', 'capabilityDelegation', 'alsoKnownAs']) if (d[k]) d[k] = [...d[k]].sort()
  return sortDeep(d)
}
export const sameJson = (a, b) => JSON.stringify(sortDeep(a)) === JSON.stringify(sortDeep(b))

/** The DID a log names (its first entry's state.id), the asked DID for local resolution. */
export const didOfLog = (logPath) => readLog(logPath)[0].state.id

// ---------------------------------------------------------------------------------------------------------------------
// egress watching: strace -e trace=connect, optionally inside an empty network namespace (unshare -n)
// sudo's secure_path would hide node (setup-node puts it under /opt/hostedtoolcache), so the PATH is passed through `env`.
export const SUDO = process.getuid && process.getuid() === 0 ? [] : ['sudo', '-n', '-E', 'env', `PATH=${process.env.PATH}`]

/** Parse `strace -e trace=connect` output into [{family, addr, port, result}]. */
export function parseConnects (text) {
  const rows = []
  for (const line of text.split('\n')) {
    const m = /connect\(\d+, \{sa_family=(AF_\w+)(.*?)\}, \d+\)\s+=\s+(.*)$/.exec(line)
    if (!m) continue
    const [, family, rest, result] = m
    let addr = null; let port = null
    if (family === 'AF_INET') { port = Number(/htons\((\d+)\)/.exec(rest)?.[1]); addr = /inet_addr\("([^"]+)"\)/.exec(rest)?.[1] }
    else if (family === 'AF_INET6') { port = Number(/htons\((\d+)\)/.exec(rest)?.[1]); addr = /inet_pton\(AF_INET6, "([^"]+)"/.exec(rest)?.[1] }
    else if (family === 'AF_UNIX') addr = /sun_path="([^"]*)"/.exec(rest)?.[1] ?? '(abstract)'
    rows.push({ family, addr, port, result: result.trim() })
  }
  return rows
}

/** Run a command under strace (and, with empty:true, inside an empty network namespace). Returns { r, connects } */
export function traced (cmd, args, { empty = false, tag, dir }) {
  const f = join(dir, `strace-${tag}.txt`)
  const full = [...SUDO, ...(empty ? ['unshare', '-n', '--'] : []), 'strace', '-f', '-qq', '-e', 'trace=connect', '-o', pathResolve(f), '--', cmd, ...args]
  const r = run(full[0], full.slice(1), { env: process.env })
  return { r, connects: existsSync(f) ? parseConnects(readFileSync(f, 'utf8')) : [] }
}

/** The json lines a `probe` command printed (one per DID). */
export function probeLines (stdout) {
  return stdout.split('\n').map((l) => { try { return JSON.parse(l) } catch { return null } }).filter((o) => o && typeof o.did === 'string')
}

/** CVSS v3.x base score from a vector string, or null. */
export function cvss3 (vector) {
  if (typeof vector !== 'string' || !/^CVSS:3\.[01]\//.test(vector)) return null
  const m = Object.fromEntries(vector.split('/').slice(1).map((p) => p.split(':')))
  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[m.AV]; const AC = { L: 0.77, H: 0.44 }[m.AC]
  const scope = m.S === 'C'
  const PR = { N: 0.85, L: scope ? 0.68 : 0.62, H: scope ? 0.5 : 0.27 }[m.PR]; const UI = { N: 0.85, R: 0.62 }[m.UI]
  const cia = (x) => ({ H: 0.56, L: 0.22, N: 0 }[x])
  if ([AV, AC, PR, UI].some((x) => x === undefined) || ![m.C, m.I, m.A].every((x) => 'HLN'.includes(x))) return null
  const iss = 1 - (1 - cia(m.C)) * (1 - cia(m.I)) * (1 - cia(m.A))
  const impact = scope ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss
  const expl = 8.22 * AV * AC * PR * UI
  const roundUp = (x) => Math.ceil(x * 10 - 1e-9) / 10
  if (impact <= 0) return 0
  return roundUp(scope ? Math.min(1.08 * (impact + expl), 10) : Math.min(impact + expl, 10))
}
