#!/usr/bin/env node
// ref/09 §3: one markdown report per run from every job's results JSON. A job with no results is a failure, never a skip.
// A line of §0 whose job is not built yet says so and counts as not passed. Usage: node report.mjs <resultsdir> <out.md>
import { readdirSync, writeFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { readJson } from './lib.mjs'

const [dir = 'results', out = 'report.md'] = process.argv.slice(2)
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
writeFileSync(out, L.join('\n') + '\n')
console.log(L.join('\n'))
// The run passes only when every line of §0 has a result and passed: a line not built yet keeps it red.
const required = ['audit', 'roundtrip', 'tamper', 'netwatch', 'vectors', 'mediator']
process.exit(required.every((j) => all[j]?.pass) && Object.values(all).every((j) => j.pass) ? 0 : 1)
