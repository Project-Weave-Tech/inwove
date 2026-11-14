#!/usr/bin/env node
// Turns the jobs' json results into the one markdown report of a run. Usage: node report.mjs <resultsdir> <out.md>
// A missing result file is a FAIL ("no result"), never a skip. Every number a job printed is kept.
import { existsSync, readdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { HERE, readJson } from './lib.mjs'

const [dir = 'results', outPath = 'report.md'] = process.argv.slice(2)
const load = (f) => { try { return existsSync(join(dir, f)) ? readJson(join(dir, f)) : null } catch (e) { return { corrupt: String(e) } } }
const R = { audit: load('audit.json'), suite: load('suite.json'), roundtrip: load('roundtrip.json'), witness: load('witness.json'), tamper: load('tamper.json'), netwatch: load('netwatch.json') }
const pins = readdirSync(dir).filter((f) => /^pins-.*\.json$/.test(f)).sort().map((f) => load(f))
const mark = (ok) => (ok ? 'PASS' : 'FAIL')
const verdictOf = (r) => (!r ? 'FAIL (no result: the job did not run to completion)' : r.corrupt ? 'FAIL (result unreadable)' : mark(r.pass))
const esc = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ')
const table = (head, rows) => [`| ${head.join(' | ')} |`, `| ${head.map(() => '---').join(' | ')} |`, ...rows.map((r) => `| ${r.map(esc).join(' | ')} |`)].join('\n')
const L = []
const w = (...x) => L.push(...x)

const gate = [
  ['(a) round trip between two implementations', R.roundtrip, R.roundtrip?.checks && `${R.roundtrip.checks.filter((c) => c.ok).length}/${R.roundtrip.checks.length} checks`],
  ['(b) tamper test', R.tamper, R.tamper?.checks && `${R.tamper.checks.filter((c) => c.ok).length}/${R.tamper.checks.length} checks`],
  ['(c) network watch', R.netwatch, R.netwatch?.checks && `${R.netwatch.checks.filter((c) => c.ok).length}/${R.netwatch.checks.length} checks`],
  ['(d) witness-rule meaning split (`witness-update`)', R.witness, R.witness?.cases && `${R.witness.cases.length} cases answered by every gated library`],
]
const allGate = gate.every(([, r]) => r && !r.corrupt && r.pass)
const others = [['audit', R.audit], ['suite', R.suite]]
const pinsOk = pins.length > 0 && pins.every((p) => p.pass)
const wholeRun = allGate && others.every(([, r]) => r && !r.corrupt && r.pass) && pinsOk
w('# did:webvh library tests: run report', '',
  `Run ${process.env.GITHUB_RUN_ID ?? '(local)'} attempt ${process.env.GITHUB_RUN_ATTEMPT ?? '-'}, commit ${process.env.GITHUB_SHA ?? '(local)'}, ${new Date().toISOString()}. Test values only: every key, log and host was generated inside the jobs and thrown away with them.`, '',
  `## Result: ${allGate ? 'PASS' : 'FAIL'} (the four gate lines)`, '',
  `Whole run, counting also the audit and suite jobs and the pins: **${wholeRun ? 'PASS' : 'FAIL'}**.`, '',
  'A run passes only if all four gate lines hold. A missing result is a failure, never a skip.', '',
  table(['gate line', 'result', 'detail'], gate.map(([n, r, d]) => [n, verdictOf(r), d ?? ''])), '',
  table(['other job', 'result'], [...others.map(([n, r]) => [n, verdictOf(r)]), ['pins and licences (first step of every job)', pins.length ? mark(pinsOk) : 'FAIL (no result)']]), '',
  `Line (d) definition: pass means every gated library (didwebvh-ts, didwebvh-rs) produced a recorded accept/refuse answer on each witness-entry case (none crashed before answering). It does not require the libraries to agree; the observation table below is the finding.`, '')

// pins
w('## Pins, versions, licences', '')
for (const p of pins) {
  w(`**${p.job}** (${p.at ?? ''}): ${mark(p.pass)}`, '', table(['check', 'result', 'detail'], p.rows.map((r) => [r.what, r.ok ? 'ok' : 'FAIL', r.detail])), '', `tools: \`${JSON.stringify(p.tools)}\``, '')
}

// pins moved on purpose (pins.json records each move, who asked for it and the commits it took in)
const pinFile = readJson(join(HERE, 'pins.json'))
const moves = Object.entries(pinFile).filter(([, p]) => p && p.movedOnPurpose)
if (moves.length) {
  w('### Pins moved on purpose', '')
  for (const [name, p] of moves) w(`**${name}**: \`${p.movedOnPurpose.from}\` → \`${p.movedOnPurpose.to}\` on ${p.movedOnPurpose.at}, by ${p.movedOnPurpose.by}. ${p.movedOnPurpose.why}`, '', 'Commits taken in (subject lines):', '', ...(p.movedOnPurpose.commits ?? []).map((c) => `- ${c}`), '')
}

// audit
w('## audit', '')
if (R.audit) {
  w(table(['check', 'result', 'detail'], R.audit.checks.map((c) => [c.name, mark(c.ok), c.detail])), '', `cargo-audit: ${R.audit.cargo?.tool ?? '-'}; npm counts: \`${JSON.stringify(R.audit.npm?.counts ?? {})}\`; cargo severity: \`${JSON.stringify(R.audit.cargo?.severity ?? {})}\`; ${R.audit.ms} ms`, '')
} else w('FAIL: no result.', '')

// suite
w('## suite (each library\'s own entry, against the pinned test-suite sha)', '')
if (R.suite) {
  w(`Test-suite sha: \`${R.suite.suiteSha}\` (pin \`${R.suite.suitePin}\`).`, '')
  w(table(['library', 'built from', 'pass', 'fail', 'skip', 'DIFF (reported)', 'gate', 'seconds'], Object.values(R.suite.libs).map((l) => [`${l.lib}  ${l.header ?? ''}`, l.builtFrom ? `${l.builtFrom.ref} @ ${l.builtFrom.commit}` : '-', l.counts?.pass, l.counts?.fail, l.counts?.skip, l.counts?.diff, l.impl === 'ts' ? '59/0/2 or better' : l.impl === 'rust' ? 'no worse than 57/3/2' : 'reported, not gated', l.seconds])), '')
  for (const l of Object.values(R.suite.libs)) if (l.failRows?.length) w(`**${l.lib} FAIL rows (named):**`, '', ...l.failRows.map((f) => `- ${f}`), '')
  for (const l of Object.values(R.suite.libs)) if (l.note) w(`*${l.lib}: ${l.note}*`, '')
  w(table(['check', 'result', 'detail'], R.suite.checks.map((c) => [c.name, mark(c.ok), String(c.detail ?? '').slice(0, 400)])), '')
} else w('FAIL: no result.', '')

// roundtrip
w('## roundtrip (a)', '')
if (R.roundtrip) {
  w(table(['check', 'result', 'detail'], R.roundtrip.checks.map((c) => [c.name, mark(c.ok), c.detail])), '', `${R.roundtrip.ms} ms; tools: \`${JSON.stringify(R.roundtrip.tools ?? {})}\``, '')
  w('Document at each version number, TS vs Rust (normalised: key order, `@context`, `versionNumber`, the `#files` trailing slash):', '',
    table(['log', 'version', 'ts', 'rs', 'same keys and services'], (R.roundtrip.docCompare ?? []).map((d) => [d.log, d.version, d.ts, d.rs, d.same ? 'yes' : 'NO'])), '')
  const m = R.roundtrip.move
  if (m?.scenarios) {
    w('### Move: what the verifier does with the OLD DID string', '', `old DID \`${m.oldDid}\`, new DID \`${m.newDid}\`. Files are served by a local static server; test hostnames only.`, '',
      table(['scenario', 'library', 'new DID', 'old DID string: behaviour', 'detail'], m.scenarios.flatMap((s) => ['ts', 'rs'].map((l) => [s.label, l, s.newDid[l].ok ? `resolves (scid ${s.newDid[l].scid}, v${s.newDid[l].versionNumber})` : `refuses: ${s.newDid[l].error}`, s.oldDid[l].behaviour, s.oldDid[l].ok ? `returned id ${s.oldDid[l].returnedId}, v${s.oldDid[l].versionNumber}` : s.oldDid[l].error]))), '',
      'Reading it: "refuses" = no document; "resolves, but the document it returns is for ANOTHER DID string" = no pointer is followed and nothing is refused, the verifier returns the latest document of the log, whose `id` is the new DID; "resolves (same DID string ...)" = the old location still served the pre-move log and the verifier answered from it.', '')
  }
} else w('FAIL: no result.', '')

// witness
w('## witness-entry observation (d)', '')
w('What the spec says (did:webvh v1.0, `spec-v1.0/specification.md` in github.com/decentralized-identity/didwebvh at `bf3d9b4c8fe6d604b7e965c87bb996839762b307`, read 2026-11-14; identity.foundation itself was refused from the cloud runner):', '',
  '> While all parameters in the first Log Entry take effect immediately, some kinds of parameters defined in later entries only take effect *after* that entry has been published. For example, updates to the `witnesses` array take effect only *after* the entry in which they are defined has been published. (lines 438-441)', '',
  '> If the `witness` property is updated from `{}`, the change is immediately active, and the corresponding log entry **MUST** be witnessed. (line 753)', '',
  '> If witnesses are active when the `witness` parameter is set to `{}`, that log entry **MUST** be witnessed. (lines 754-757)', '')
if (R.witness?.cases) {
  w(`Question: ${R.witness.question}`, '', table(['case', 'didwebvh-ts', 'didwebvh-rs', 'didwebvh-py (information only)'], R.witness.cases.map((c) => [c.case, ...['ts', 'rs', 'py'].map((l) => (c.libs[l] ? (c.libs[l].accepted ? `ACCEPTS (${c.libs[l].versionId})` : `refuses: ${c.libs[l].error}`) : '-'))])), '', R.witness.note, R.witness.suiteVector ? `\n${R.witness.suiteVector}` : '', '')
  w(`Line (d): ${verdictOf(R.witness)}`, '')
} else w('FAIL: no result.', '')

// tamper
w('## tamper (b)', '')
if (R.tamper) {
  w(table(['check', 'result', 'detail'], R.tamper.checks.map((c) => [c.name, mark(c.ok), String(c.detail).slice(0, 500)])), '')
  w('Accepted-by-library (a library that returned a document for a broken log):', '', table(['library', 'broken logs run', 'accepted', 'which'], R.tamper.libs.map((l) => [l, R.tamper.byLib[l].attacks, R.tamper.byLib[l].accepted.length, R.tamper.byLib[l].accepted.join('; ') || 'none'])), '',
    `Controls (intact logs, must be accepted): ts and rs ${JSON.stringify(R.tamper.controlsOk)}; didwebvh-py accepts the intact log: ${R.tamper.pythonControlAcceptsIntactLog} (if false, its refusals are not evidence).`, '')
  w(table(['variant', 'log', 'what', 'ts', 'rs', 'py'], R.tamper.rows.map((r) => [r.variant, `${r.origin}-made`, r.desc, ...R.tamper.libs.map((l) => (r.perLib[l].accepted ? 'ACCEPTED' : 'refused'))])), '')
  w('<details><summary>Refusal reasons</summary>', '', table(['variant', 'log', 'ts', 'rs', 'py'], R.tamper.rows.map((r) => [r.variant, `${r.origin}-made`, ...R.tamper.libs.map((l) => (r.perLib[l].accepted ? '(accepted)' : String(r.perLib[l].error).slice(0, 160)))])), '', '</details>', '')
  const neg = R.tamper.negatives?.vectors
  if (neg?.length) w('Suite negative vectors (literal DID strings; resolved with each library\'s normal network path inside an empty network namespace under strace):', '', table(['vector', 'DID', 'ts', 'rs', 'py'], neg.map((v) => [v.name, v.did, ...R.tamper.libs.map((l) => (v.perLib[l] ? `${v.perLib[l].refused ? 'refused' : 'ACCEPTED'}${v.perLib[l].networkConnects.length ? `; tried ${v.perLib[l].networkConnects.length} network connect()` : ''}` : '-'))])), '')
  w(`${R.tamper.ms} ms`, '')
} else w('FAIL: no result.', '')

// netwatch
w('## netwatch (c)', '')
if (R.netwatch) {
  w(table(['check', 'result', 'detail'], R.netwatch.checks.map((c) => [c.name, mark(c.ok), c.detail])), '',
    'Offline run (empty network namespace, local files), including didwebvh-py (reported, not gated):', '', table(['run', 'accepted', 'version', 'ms', 'error'], Object.entries(R.netwatch.offline).map(([k, v]) => [k, v.accepted, v.versionNumber ?? '', v.ms, v.error ?? ''])), '',
    `Logged run (strace -f -e trace=connect, local static server on 127.0.0.1:${R.netwatch.staticPort}):`, '', table(['run', 'accepted', 'connect() calls', 'connections elsewhere'], Object.entries(R.netwatch.logged).map(([k, v]) => [k, v.accepted, v.connects.join('; '), v.strangers.join(', ') || 'none'])), '',
    'Python probe (empty namespace, strace):', '', table(['probe', 'DID', 'refused', 'network connect() calls', 'answer'], R.netwatch.probes.map((p) => [p.name, p.did, p.refused, p.networkConnects.join('; ') || 'none', p.answer])), '',
    `Static server saw ${R.netwatch.staticServerRequests.length} request(s); ${R.netwatch.ms} ms.`, '')
} else w('FAIL: no result.', '')

writeFileSync(outPath, L.join('\n') + '\n')
console.log(`report written: ${outPath} (${L.join('\n').length} bytes); gate: ${allGate ? 'PASS' : 'FAIL'}; whole run: ${wholeRun ? 'PASS' : 'FAIL'}`)
process.exit(wholeRun ? 0 : 1)
