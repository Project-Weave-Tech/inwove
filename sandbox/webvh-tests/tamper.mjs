#!/usr/bin/env node
// Job `tamper`. Usage: node tamper.mjs <logs-for-tamper dir (from roundtrip)> <workdir> <resultsdir> [<suite vectors dir>]
// Breaks each valid roundtrip log (the TS-made and the Rust-made one) seven ways, plus the suite's negative vectors, and runs TS,
// Rust and Python on every broken log. Pass: every resolver REFUSES every broken log (any error, any crash = refusal; a returned
// document = fail). Controls: every resolver is also run on the intact logs, so "refuses everything" cannot pass for the right reason
// without being said: TS and Rust must accept the intact logs (else the line fails); Python's control is reported.
import { copyFileSync, existsSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { RESOLVERS, ensureDir, writeJson, readJson, readLog, logText, testKey, verifier, traced, probeLines, HERE, TS_CLI, RS_BIN, PY_CLI } from './lib.mjs'
import { createDID, deriveNextKeyHash, prepareDataForSigning } from 'didwebvh-ts'
import { canonicalize, sha256, base58btc, multibase, concat, utf8, ed25519 } from '../../src/shared/crypto.js'
import { baseDoc } from './lib.mjs'

const [logsDir, work = 'work-tamper', results = 'results', vectorsDir = process.env.WPI_VECTORS_DIR] = process.argv.slice(2)
rmSync(work, { recursive: true, force: true }); ensureDir(work); ensureDir(results)
const t0 = Date.now()
const index = readJson(join(logsDir, 'index.json'))
const LIBS = ['ts', 'rs', 'py']
const rows = [] // { origin, variant, desc, did, perLib: { ts: {accepted, error}, ... } }

const flipAt = (text, from, offset) => { const i = from + offset; const c = text[i]; return text.slice(0, i) + (c === 'A' ? 'B' : 'A') + text.slice(i + 1) }

/** Forge a valid-looking entry 2 (correct entry hash, correct proof) that rotates to `signer`'s key. Under pre-rotation it is only legitimate when that key was committed in entry 1. */
export async function forgeRotation (entry1, signer) {
  const prev = entry1.versionId
  const entry = {
    versionId: prev,
    versionTime: new Date(Date.parse(entry1.versionTime) + 60_000).toISOString().replace(/\.\d+Z$/, 'Z'),
    parameters: { updateKeys: [signer.mk], nextKeyHashes: [] },
    state: entry1.state,
  }
  const digest = sha256(utf8(canonicalize(entry)))
  const hash = base58btc(concat(new Uint8Array([0x12, 0x20]), digest))
  const withId = { ...entry, versionId: `2-${hash}` }
  const template = { type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', verificationMethod: `did:key:${signer.mk}#${signer.mk}`, created: entry.versionTime, proofPurpose: 'assertionMethod' }
  const { proofValue } = await signer.signer.sign({ document: withId, proof: template })
  return { ...withId, proof: [{ ...template, proofValue }] }
}

function variantsOf (text) {
  const lines = text.replace(/\n$/, '').split('\n')
  const out = []
  const scidAt = text.indexOf('"scid":"') + 8
  out.push(['a-scid-byte', 'one byte of the SCID (entry 1 parameters.scid) changed', flipAt(text, scidAt, 10)])
  const line2At = lines[0].length + 1
  const uk = lines[1].indexOf('"updateKeys":["') + 15
  out.push(['b-updateKeys-byte', 'one byte inside entry 2 updateKeys changed', flipAt(text, line2At + uk, 10)])
  const lastAt = text.lastIndexOf('"proofValue":"') + 14
  out.push(['c-last-proof-byte', 'one byte of the last entry proof changed', flipAt(text, lastAt, 10)])
  out.push(['d-swap-entries', 'entries 2 and 3 swapped', [lines[0], lines[2], lines[1], ...lines.slice(3)].join('\n') + '\n'])
  out.push(['e-delete-middle', 'entry 3 deleted', lines.filter((_, i) => i !== 2).join('\n') + '\n'])
  out.push(['f-truncate-last', 'the last line cut in half (no newline)', lines.slice(0, -1).concat(lines.at(-1).slice(0, Math.floor(lines.at(-1).length / 2))).join('\n')])
  return out
}

function runAll (origin, variant, desc, did, logPath, witPath) {
  const dir = join(work, 'variants', origin, variant)
  ensureDir(dir)
  writeFileSync(join(dir, 'did.jsonl'), readFileSync(logPath))
  if (witPath && existsSync(witPath)) copyFileSync(witPath, join(dir, 'did-witness.json'))
  const wit = existsSync(join(dir, 'did-witness.json')) ? join(dir, 'did-witness.json') : undefined
  const perLib = {}
  for (const lib of LIBS) { const v = RESOLVERS[lib](did, join(dir, 'did.jsonl'), wit); perLib[lib] = { accepted: v.accepted, error: v.error, versionNumber: v.versionNumber, ms: v.ms } }
  rows.push({ origin, variant, desc, did, perLib })
  console.log(`${variant.padEnd(20)} ${origin}-made  ${LIBS.map((l) => `${l}:${perLib[l].accepted ? 'ACCEPTED' : 'refused'}`).join('  ')}`)
}

// controls: the intact logs
for (const origin of ['ts', 'rs']) runAll(origin, 'control-intact', 'the valid log, untouched (must be ACCEPTED by ts and rs)', index[origin].did, join(logsDir, `${origin}.did.jsonl`), join(logsDir, `${origin}.did-witness.json`))

for (const origin of ['ts', 'rs']) {
  const text = readFileSync(join(logsDir, `${origin}.did.jsonl`), 'utf8')
  const wit = join(logsDir, `${origin}.did-witness.json`)
  for (const [name, desc, broken] of variantsOf(text)) {
    const f = join(work, `${origin}-${name}.jsonl`)
    writeFileSync(f, broken)
    runAll(origin, name, desc, index[origin].did, f, wit)
  }
  // (g) a rotation to a key that was NOT in entry 1's nextKeyHashes, otherwise perfectly formed and signed by that key
  const entry1 = readLog(join(logsDir, `${origin}.did.jsonl`))[0]
  const rogue = testKey()
  const forged = await forgeRotation(entry1, rogue)
  const f = join(work, `${origin}-g-rogue-rotation.jsonl`)
  writeFileSync(f, logText([entry1, forged]))
  runAll(origin, 'g-rogue-rotation', `entry 2 rotates to a key not in entry 1's nextKeyHashes (committed: ${JSON.stringify(entry1.parameters.nextKeyHashes)})`, index[origin].did, f, null)
}

// control for (g): the SAME forging code, with the committed key, must be accepted - else (g) proves nothing about the forge
{
  const k0 = testKey(); const k1 = testKey(); const dk = testKey()
  const c = await createDID({ address: 'example.test', signer: k0.signer, verifier, updateKeys: [k0.mk], portable: true, nextKeyHashes: [await deriveNextKeyHash(k1.mk)], didDocument: baseDoc(dk.mk, false), created: new Date(Date.now() - 600_000).toISOString().replace(/\.\d+Z$/, 'Z') })
  const good = await forgeRotation(c.log[0], k1)
  const f = join(work, 'g-control.jsonl')
  writeFileSync(f, logText([c.log[0], good]))
  runAll('forge', 'g-control-committed-key', 'the forging code with the COMMITTED key: a legitimate rotation (must be ACCEPTED by ts and rs)', c.did, f, null)
  const bad = await forgeRotation(c.log[0], testKey())
  writeFileSync(join(work, 'g-control-bad.jsonl'), logText([c.log[0], bad]))
  runAll('forge', 'g-control-rogue-key', 'the same fresh log, rotation to an uncommitted key (must be refused)', c.did, join(work, 'g-control-bad.jsonl'), null)
}

// (h) the five parser-level negative vectors of the test suite ("resolve-did" vectors: a literal DID string that must be refused as invalidDid
// BEFORE any fetch). Each library's normal network resolver is run on each DID inside an empty network namespace under strace:
// pass = refused (the netwatch job is where trying to connect fails a library; here attempts are only reported, and the namespace has no network).
const NEG = readJson(join(HERE, 'pins.json')).negativeVectors
const negatives = { dir: vectorsDir ?? null, vectors: [] }
if (vectorsDir && existsSync(vectorsDir)) {
  for (const name of NEG) {
    const sy = join(vectorsDir, name, 'script.yaml')
    const text = existsSync(sy) ? readFileSync(sy, 'utf8') : ''
    const did = /^\s*(?:-\s*)?did:\s*["']?(did:webvh:[^"'\s]+)["']?\s*$/m.exec(text)?.[1] ?? null
    const isResolveDid = /op:\s*resolve-did/.test(text)
    const row = { name, did, isResolveDid, perLib: {} }
    if (did && isResolveDid) {
      for (const lib of LIBS) {
        const [cmd, base] = lib === 'ts' ? ['node', [TS_CLI]] : lib === 'rs' ? [RS_BIN, []] : [process.env.WPI_PYTHON || 'python3', ['-I', PY_CLI]]
        const { r, connects } = traced(cmd, [...base, 'probe', did], { empty: true, tag: `h-${name}-${lib}`, dir: work })
        const a = probeLines(r.stdout)[0]
        const net = connects.filter((c) => c.family === 'AF_INET' || c.family === 'AF_INET6')
        row.perLib[lib] = { refused: a ? a.ok === false : false, answered: !!a, error: a?.error ?? (a ? null : `no answer (exit ${r.code}): ${(r.stderr || r.stdout).trim().slice(-160)}`), networkConnects: net.map((c) => `${c.addr}:${c.port}`) }
      }
    }
    negatives.vectors.push(row)
    console.log(`${name.padEnd(42)} ${LIBS.map((l) => row.perLib[l] ? `${l}:${row.perLib[l].refused ? 'refused' : 'ACCEPTED'}${row.perLib[l].networkConnects.length ? '+CONNECTED(' + row.perLib[l].networkConnects.length + ')' : ''}` : `${l}:(vector unreadable)`).join('  ')}`)
  }
}
const nNeg = negatives.vectors.length

// verdicts
const attacks = rows.filter((r) => r.variant !== 'control-intact' && r.variant !== 'g-control-committed-key')
const controls = rows.filter((r) => r.variant === 'control-intact' || r.variant === 'g-control-committed-key')
const accepted = attacks.flatMap((r) => LIBS.filter((l) => r.perLib[l].accepted).map((l) => ({ lib: l, origin: r.origin, variant: r.variant })))
const controlsOk = Object.fromEntries(['ts', 'rs'].map((l) => [l, controls.every((r) => r.perLib[l].accepted)]))
const pyControl = controls.every((r) => r.perLib.py.accepted)
const byLib = Object.fromEntries(LIBS.map((l) => [l, { accepted: accepted.filter((a) => a.lib === l).map((a) => `${a.origin}-made: ${a.variant}`), attacks: attacks.length }]))
const checks = [
  { name: 'controls: ts and rs accept the intact logs and the legitimate rotation', ok: controlsOk.ts && controlsOk.rs, detail: JSON.stringify(controlsOk) },
  { name: 'every resolver refuses every broken log', ok: accepted.length === 0, detail: accepted.length ? accepted.map((a) => `${a.lib} accepted ${a.origin}-made ${a.variant}`).join('; ') : `${attacks.length} broken logs x ${LIBS.length} libraries, all refused` },
  { name: '(h) the five suite negative vectors were found and readable', ok: nNeg === 5 && negatives.vectors.every((v) => v.did && v.isResolveDid), detail: vectorsDir ? negatives.vectors.map((v) => `${v.name}${v.did && v.isResolveDid ? '' : ' (UNREADABLE)'}`).join(', ') : 'no suite vectors directory given' },
  { name: '(h) every library refuses each of the five', ok: nNeg === 5 && negatives.vectors.every((v) => LIBS.every((l) => v.perLib[l]?.refused)), detail: negatives.vectors.flatMap((v) => LIBS.filter((l) => !v.perLib[l]?.refused).map((l) => `${l} ACCEPTED or gave no answer on ${v.name}`)).join('; ') || `all refused (network connect() attempts while refusing, for information: ${negatives.vectors.flatMap((v) => LIBS.filter((l) => v.perLib[l]?.networkConnects.length).map((l) => `${l} on ${v.name} x${v.perLib[l].networkConnects.length}`)).join('; ') || 'none'})` },
]
// (g) must be refused FOR THE RIGHT REASON: the pre-rotation rule (a refusal for some other reason would hide a library that does not check it)
const gRows = rows.filter((r) => /^g-(rogue-rotation|control-rogue-key)$/.test(r.variant))
const wrongReason = gRows.flatMap((r) => LIBS.filter((l) => !r.perLib[l].accepted && !/nextKeyHash|pre-?rotation|committed|not specified in the pr|not found in/i.test(r.perLib[l].error ?? '')).map((l) => `${l} on ${r.origin}-made ${r.variant}: ${r.perLib[l].error}`))
checks.push({ name: '(g) each refusal names the pre-rotation rule (nextKeyHashes), not some other defect', ok: wrongReason.length === 0 || (wrongReason.every((w) => w.startsWith('py ')) && !pyControl), detail: wrongReason.length ? wrongReason.join(' || ').slice(0, 600) : 'all refusals cite nextKeyHashes / pre-rotation' })
const pass = checks.every((c) => c.ok)
writeJson(join(results, 'tamper.json'), { job: 'tamper', pass, checks, libs: LIBS, rows, byLib, controlsOk, pythonControlAcceptsIntactLog: pyControl, negatives, ms: Date.now() - t0 })
console.log(`tamper: ${pass ? 'PASS' : 'FAIL'}; accepted-by-library: ${JSON.stringify(Object.fromEntries(LIBS.map((l) => [l, byLib[l].accepted.length])))}; python control accepted intact log: ${pyControl}; ${Date.now() - t0} ms`)
