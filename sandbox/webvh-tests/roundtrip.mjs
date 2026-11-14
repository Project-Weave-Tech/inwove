#!/usr/bin/env node
// Job `roundtrip` (and the section 3 witness observation). Usage: node roundtrip.mjs <workdir> <resultsdir>
// Writes <resultsdir>/roundtrip.json and <resultsdir>/witness.json; the logs (no keys) go to <workdir>/logs-for-tamper.
import { copyFileSync, existsSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { ts, rs, run, verdict, RESOLVERS, startStaticServer, publish, normaliseDoc, sameJson, ensureDir, writeJson, readJson, readLog, didOfLog, RS_BIN } from './lib.mjs'

const [work = 'work', results = 'results'] = process.argv.slice(2)
rmSync(work, { recursive: true, force: true }); ensureDir(work); ensureDir(results)
const t0 = Date.now()
const server = await startStaticServer(join(work, 'www'))
const P = server.port
const HOST_FILES = 'example.test' // the logs that are only read from files (cross-resolve, tamper, offline): a plain test name, which every library accepts
const HOST_A = `a.localhost:${P}` // the move test is served over HTTP: *.localhost names are the only ones didwebvh-rs fetches over plain http; the DID spells the colon %3A
const HOST_B = `b.localhost:${P}`
const checks = []
const check = (name, ok, detail) => { checks.push({ name, ok: !!ok, detail }); console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  ' + detail : ''}`) }
const versions = {}
const info = { ports: { static: P }, tools: {} }

// versions printed, kept
info.tools.rs = run(RS_BIN, ['version']).json ?? undefined

// 1. TS creates the four-step log; 3. Rust creates the same four steps
const mk = {
  ts: ts(['create-log', join(work, 'ts'), HOST_FILES]),
  rs: rs(['create-log', join(work, 'rs'), HOST_FILES]),
}
for (const lib of ['ts', 'rs']) {
  const j = mk[lib].json
  check(`${lib} creates the four-step log`, j?.ok && j.entries === 4, j?.ok ? j.did : String(j?.error ?? mk[lib].stderr).slice(0, 300))
}
if (!mk.ts.json?.ok || !mk.rs.json?.ok) { writeJson(join(results, 'roundtrip.json'), { job: 'roundtrip', pass: false, checks, fatal: 'a log could not be created' }); process.exit(0) }

const logs = {}
for (const lib of ['ts', 'rs']) {
  const dir = join(work, lib)
  logs[lib] = { did: mk[lib].json.did, log: join(dir, 'did.jsonl'), wit: join(dir, 'did-witness.json') }
  check(`${lib} log names the DID it was created for`, didOfLog(logs[lib].log) === logs[lib].did)
}

// 2 + 3 + 5: each log resolved by BOTH libraries, latest and every version number
const cross = { }
for (const [maker, who] of [['ts', 'rs'], ['rs', 'ts']]) {
  const L = logs[maker]
  const latest = RESOLVERS[who](L.did, L.log, L.wit)
  cross[`${maker}->${who}`] = { latest: { accepted: latest.accepted, error: latest.error, scid: latest.scid, versionId: latest.versionId, versionNumber: latest.versionNumber, ms: latest.ms } }
  const scid = L.did.split(':')[2]
  check(`${who} resolves and verifies the ${maker}-made log (final version)`, latest.accepted && latest.versionNumber === 4, latest.accepted ? `versionId ${latest.versionId}` : latest.error)
  check(`${who} reports the same SCID for the ${maker}-made log`, latest.accepted && latest.scid === scid, latest.accepted ? latest.scid : '')
}
const docCompare = []
for (const maker of ['ts', 'rs']) {
  const L = logs[maker]
  for (let v = 1; v <= 4; v++) {
    const a = RESOLVERS.ts(L.did, L.log, L.wit, v); const b = RESOLVERS.rs(L.did, L.log, L.wit, v)
    const same = a.accepted && b.accepted && a.versionNumber === v && b.versionNumber === v && sameJson(normaliseDoc(a.document), normaliseDoc(b.document))
    docCompare.push({ log: `${maker}-made`, version: v, ts: a.accepted ? a.versionId : `refused: ${a.error}`, rs: b.accepted ? b.versionId : `refused: ${b.error}`, same })
    if (!same && a.accepted && b.accepted) docCompare.at(-1).diff = { ts: normaliseDoc(a.document), rs: normaliseDoc(b.document) }
  }
}
check('the document at each version number has the same keys and services in both libraries', docCompare.every((d) => d.same), `${docCompare.filter((d) => d.same).length}/${docCompare.length} (log, version) pairs equal`)
// the TS-made and Rust-made logs describe the same four steps: same normalised document at each version
const shape = [1, 2, 3, 4].map((v) => {
  const a = RESOLVERS.ts(logs.ts.did, logs.ts.log, logs.ts.wit, v); const b = RESOLVERS.rs(logs.rs.did, logs.rs.log, logs.rs.wit, v)
  return a.accepted && b.accepted && sameJson(normaliseDoc({ ...a.document }).service, normaliseDoc({ ...b.document }).service)
})
check('the TS-made and Rust-made logs give the same services at each of the four versions', shape.every(Boolean), shape.join(','))

// 4. Move: TS writes a portable move to a second hostname; Rust (and TS) resolve from the local static server
const hts = ts(['create-log', join(work, 'ts-http'), HOST_A.replace(':', '%3A')]) // a TS four-step log for the first test hostname
const mv = hts.json?.ok ? ts(['move', join(work, 'ts-http'), HOST_B.replace(':', '%3A')]) : hts
check('TS writes a portable move to a second hostname', mv.json?.ok && mv.json.entries === 5, mv.json?.did ?? mv.json?.error)
const move = { newDid: mv.json?.did, oldDid: hts.json?.did, scenarios: [] }
logs['ts-http'] = { did: hts.json?.did, log: join(work, 'ts-http', 'did.jsonl'), wit: join(work, 'ts-http', 'did-witness.json') }
if (mv.json?.ok) {
  const movedLog = join(work, 'ts-http-moved')
  const wwwHostA = 'a.localhost'; const wwwHostB = 'b.localhost'
  const pin = ['a.localhost=127.0.0.1', 'b.localhost=127.0.0.1']
  const http = (lib, did) => { const r = (lib === 'ts' ? ts : rs)(['resolve-http', did, ...pin]); return r.json ?? { ok: false, error: r.stderr.slice(0, 300) } }
  const classify = (r, asked) => !r.ok ? 'refuses' : (r.id === asked ? 'resolves (same DID string in the document)' : `resolves, but the document it returns is for ANOTHER DID string (${r.id === move.newDid ? 'the new one' : r.id})`)
  const scenario = (label, oldServes) => {
    rmSync(join(work, 'www'), { recursive: true, force: true })
    publish(join(work, 'www'), wwwHostB, join(movedLog, 'did.jsonl'), join(movedLog, 'did-witness.json'))
    if (oldServes === 'moved') publish(join(work, 'www'), wwwHostA, join(movedLog, 'did.jsonl'), join(movedLog, 'did-witness.json'))
    if (oldServes === 'original') publish(join(work, 'www'), wwwHostA, logs['ts-http'].log, logs['ts-http'].wit)
    const row = { label, newDid: {}, oldDid: {} }
    for (const lib of ['ts', 'rs']) {
      const n = http(lib, move.newDid); const o = http(lib, move.oldDid)
      row.newDid[lib] = { ok: n.ok, scid: n.scid, versionNumber: n.versionNumber, error: n.error }
      row.oldDid[lib] = { ok: o.ok, behaviour: classify(o, move.oldDid), scid: o.scid, versionNumber: o.versionNumber, returnedId: o.id, error: o.error }
    }
    return row
  }
  move.scenarios.push(scenario('old host serves nothing; new host serves the moved log', 'none'))
  move.scenarios.push(scenario('old host serves the moved log (copy left in place)', 'moved'))
  move.scenarios.push(scenario('old host still serves the pre-move log (4 entries)', 'original'))
  const s0 = move.scenarios[0]
  const scid = move.oldDid.split(':')[2]
  check('Rust resolves the moved log from the new host and reports the same SCID', s0.newDid.rs.ok && s0.newDid.rs.scid === scid, s0.newDid.rs.ok ? `scid ${s0.newDid.rs.scid}, v${s0.newDid.rs.versionNumber}` : s0.newDid.rs.error)
  check('TS resolves the moved log from the new host and reports the same SCID', s0.newDid.ts.ok && s0.newDid.ts.scid === scid, s0.newDid.ts.ok ? `scid ${s0.newDid.ts.scid}, v${s0.newDid.ts.versionNumber}` : s0.newDid.ts.error)
  // the Rust CLI also resolves the moved log from local files, for the record
  move.rsFileResolve = verdict(rs(['resolve-file', move.newDid, join(movedLog, 'did.jsonl'), join(movedLog, 'did-witness.json')])).accepted
  for (const s of move.scenarios) for (const lib of ['ts', 'rs']) console.log(`MOVE  [${s.label}] ${lib} old DID string -> ${s.oldDid[lib].behaviour}${s.oldDid[lib].error ? ' (' + String(s.oldDid[lib].error).slice(0, 120) + ')' : ''}`)
  move.served = server.requests()
}

// section 3: witness observations (observation only). N=4: the entry changes 2-of-2 to 1-of-1 and ONE witness signed it.
const wdir = join(work, 'witness-one')
const w1 = ts(['create-log', wdir, HOST_FILES, '--one-proof'])
const witness = { question: 'does a library accept an entry that changes the witness rule when too few of the then-active witnesses signed it?', cases: [] }
let caseNo = 0
const obs = (name, did, log, wit, version) => {
  // every library gets its own copy of the case with the witness file BESIDE the log (didwebvh-py reads it from there)
  const dir = join(work, 'witness-cases', String(++caseNo)); ensureDir(dir)
  copyFileSync(log, join(dir, 'did.jsonl')); copyFileSync(wit ?? join(work, 'empty-witness.json'), join(dir, 'did-witness.json'))
  const row = { case: name, libs: {} }
  for (const lib of ['ts', 'rs', 'py']) { const v = RESOLVERS[lib](did, join(dir, 'did.jsonl'), join(dir, 'did-witness.json'), version); row.libs[lib] = { accepted: v.accepted, versionId: v.versionId, error: v.error } }
  witness.cases.push(row)
  console.log(`WITNESS  ${name}: ` + ['ts', 'rs', 'py'].map((l) => `${l}=${row.libs[l].accepted ? 'accepts' : 'refuses'}`).join('  '))
  return row
}
writeFileSync(join(work, 'empty-witness.json'), '[]')
if (w1.json?.ok) {
  obs('N=4: 2-of-2 -> 1-of-1, signed by ONE witness (the one that stays)', w1.json.did, join(wdir, 'did.jsonl'), join(wdir, 'did-witness.json'))
  // N=3: the entry that first adds a witness rule, no proofs at all
  obs('N=3: the entry that adds the first witness rule (2-of-2), signed by NO witness', logs.ts.did, logs.ts.log, join(work, 'empty-witness.json'), 3)
  obs('N=3 control: the same entry signed by both witnesses', logs.ts.did, logs.ts.log, logs.ts.wit, 3)
  // N=4 with the proof file of the Rust-made log: the Rust log carries proofs for entry 4 only
}
// the test suite's own witness-update vector (the entry that lowers its own threshold from 2 to 1 with one proof), when a checkout is present.
// The suite keeps one committed log per implementation (vectors/witness-update/<impl>/did.jsonl); a flat did.jsonl is also read.
const vroot = process.env.WPI_VECTORS_DIR && join(process.env.WPI_VECTORS_DIR, 'witness-update')
const vcases = []
if (vroot && existsSync(vroot)) {
  if (existsSync(join(vroot, 'did.jsonl'))) vcases.push(['', vroot])
  for (const impl of readdirSync(vroot)) if (existsSync(join(vroot, impl, 'did.jsonl'))) vcases.push([impl, join(vroot, impl)])
}
for (const [impl, d] of vcases) {
  const wf = existsSync(join(d, 'did-witness.json')) ? join(d, 'did-witness.json') : null
  obs(`test-suite vector witness-update${impl ? ` (log committed by ${impl})` : ''}: the suite expects it to RESOLVE`, didOfLog(join(d, 'did.jsonl')), join(d, 'did.jsonl'), wf)
}
if (!vcases.length) witness.suiteVector = 'the test-suite witness-update vector was not present in this run (WPI_VECTORS_DIR unset or no witness-update vector)'
witness.answered = witness.cases.length > 0 && witness.cases.every((c) => ['ts', 'rs'].every((l) => typeof c.libs[l].accepted === 'boolean' && !/^exit |threw/.test(c.libs[l].error ?? '')))
witness.note = 'pass for line (d) = every library produced a recorded accept/refuse answer on each witness-entry case (none crashed before answering). It does NOT require the libraries to agree. didwebvh-py is shown as an extra column for information only (section 1 puts it in the tamper test only); it never decides this line.'

// keep the valid logs (no keys) for the tamper job
const keep = join(work, 'logs-for-tamper'); ensureDir(keep)
for (const lib of ['ts', 'rs']) {
  copyFileSync(logs[lib].log, join(keep, `${lib}.did.jsonl`)); copyFileSync(logs[lib].wit, join(keep, `${lib}.did-witness.json`))
}
writeJson(join(keep, 'index.json'), { ts: { did: logs.ts.did }, rs: { did: logs.rs.did } })

await server.close()
const pass = checks.every((c) => c.ok)
writeJson(join(results, 'roundtrip.json'), { job: 'roundtrip', pass, checks, cross, docCompare, move, ms: Date.now() - t0, tools: info.tools })
writeJson(join(results, 'witness.json'), { job: 'witness', pass: witness.answered, ...witness })
console.log(`roundtrip: ${checks.filter((c) => c.ok).length}/${checks.length} checks; witness observation answered: ${witness.answered}; ${Date.now() - t0} ms`)
process.exit(0)

