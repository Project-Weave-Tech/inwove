#!/usr/bin/env node
// ref/09 §3: one markdown report per run from every job's results JSON. A job with no results is a failure, never a skip.
// A line of §0 whose job is not built yet says so and counts as not passed. Usage: node report.mjs <resultsdir> <out.md>
import { readdirSync, writeFileSync, existsSync, readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { readJson } from './lib.mjs'

const [dir = 'results', out = 'report.md', stopsFile = join(dirname(fileURLToPath(import.meta.url)), 'expected-red.json')] = process.argv.slice(2)
// Security 11910.5 + Emrys 11900: the expected reds live in the repo as named STOP lines. A missing or malformed list
// fails loudly (it is never read as "nothing expected").
let STOPS
try { STOPS = JSON.parse(readFileSync(stopsFile, 'utf8')).stops; if (!Array.isArray(STOPS) || STOPS.some((x) => !x.stop || !x.key || !x.line)) throw new Error('each stop needs stop, key, line') }
catch (e) { console.error(`report: expected-red list unreadable (${e.message})`); process.exit(1) }
const all = {}
if (existsSync(dir)) for (const f of readdirSync(dir, { recursive: true })) if (String(f).endsWith('.json') && !String(f).endsWith('frames.json')) { const j = readJson(join(dir, String(f))); all[j.job] = j }
const line = (job) => !all[job] ? 'FAIL (no results)' : all[job].pass ? 'PASS' : 'FAIL'
const NOT_BUILT = 'NOT BUILT YET (counts as not passed)'
const L = []
L.push(`# ref/09 TSP 1.0 tests: run ${process.env.GITHUB_RUN_ID ?? 'local'} @ ${process.env.GITHUB_SHA ?? 'local'}`, '')
L.push('## The six lines (§0)', '', '| line | result |', '|---|---|')
L.push(`| (a) TS and Rust speak the same TSP 1.0, both ways | ${line('roundtrip')} |`)
L.push(`| (b) works through a real Affinidi mediator, REST pickup only | ${all.mediator ? line('mediator') : NOT_BUILT} |`)
L.push(`| (c) every broken frame refused | ${line('tamper')} (roundtrip frames; mediator frames join with the mediator job) |`)
L.push(`| (d) no unexpected network | ${line('netwatch')} (roundtrip offline; the mediator egress log joins with the mediator job) |`)
L.push(`| (e) binding envelope and the document's own proof behave | ${line('roundtrip')} |`)
L.push(`| (f) direct-URL endpoint answer recorded | ${all.mediator ? 'see mediator' : NOT_BUILT} |`)
L.push(`| vectors (spec Appendix A through both libraries) | ${all.vectors ? line('vectors') : NOT_BUILT} |`)
L.push(`| audit | ${line('audit')} |`, '')
for (const [job, j] of Object.entries(all)) {
  L.push(`## ${job}: ${j.pass ? 'PASS' : 'FAIL'}`, '', '| | check | detail |', '|---|---|---|')
  for (const r of j.rows) L.push(`| ${r.answer ? 'answer' : r.ok ? 'ok' : '**FAIL**'} | ${r.what.replace(/\|/g, '/')} | ${String(r.detail ?? '').replace(/\|/g, '/').replace(/\n/g, ' ')} |`)
  if (j.perLibrary) {
    L.push('', '| vector | version | TS | Rust | TS rebuild | optional suite |', '|---|---|---|---|---|---|')
    for (const v of j.perLibrary) L.push(`| ${[v.vector, v.version, v.ts, v.rust, v.rebuilt ?? '', v.optional ?? ''].map((x) => String(x ?? '').replace(/\|/g, '/')).join(' | ')} |`)
  }
  for (const k of ['shas', 'tools', 'npmCounts', 'relationship']) if (j[k]) L.push('', `${k}: \`${JSON.stringify(j[k])}\``)
  L.push('')
}
// Every red on this run, by key: a required job with no results is missing:<job>, a job that failed is fail:<job>.
const required = ['audit', 'roundtrip', 'tamper', 'netwatch', 'vectors', 'mediator']
const reds = new Set()
for (const j of required) if (!all[j]) reds.add(`missing:${j}`)
for (const [j, r] of Object.entries(all)) if (!r.pass) reds.add(`fail:${j}`)
const listed = new Set(STOPS.map((x) => x.key))
const unlisted = [...reds].filter((k) => !listed.has(k)).sort()
L.push('## Expected reds (STOP lines, `expected-red.json`)', '')
for (const x of STOPS) L.push(reds.has(x.key)
  ? `- STOP: ${x.stop} · red as expected (${x.key}) · ${x.line} · clears when: ${x.clears_when ?? '(not said)'}`
  : `- STOP: ${x.stop} · GREEN on this run (${x.key}) · ${x.line} · Security reads this run; only then is the STOP line removed, in a commit naming the run`)
L.push('', unlisted.length ? `**Unexpected red (fails the run):** ${unlisted.join(', ')}` : 'No unexpected red.', '')
writeFileSync(out, L.join('\n') + '\n')
console.log(L.join('\n'))
// The run fails on any red not on the list, and on a listed STOP line missing from the written report (read back, so a
// report that stopped writing them can't read as quiet). A listed line that went green does not fail the run.
const written = readFileSync(out, 'utf8')
const missingStops = STOPS.filter((x) => !written.includes(`- STOP: ${x.stop} · `)).map((x) => x.stop)
if (missingStops.length) console.error(`report: STOP line(s) missing from the report: ${missingStops.join(', ')}`)
if (unlisted.length) console.error(`report: unexpected red: ${unlisted.join(', ')}`)
process.exit(unlisted.length || missingStops.length ? 1 : 0)
