#!/usr/bin/env node
// ref/09 §2.1 `audit`: npm audit on the two @openvtc packages' production tree, cargo audit on affinidi-tsp's lock.
// Pass: 0 high/critical. Every count is kept, moderate and low included. Also records whether vti-tsp-js loads in
// plain Node 22 with no bundler (Enkara's server is Node). Usage: node audit.mjs <resultsdir>
import { spawnSync } from 'node:child_process'
import { join } from 'node:path'
import { HERE, recorder } from './lib.mjs'

const results = process.argv[2] ?? 'results'
const R = recorder('audit')
const npm = spawnSync('npm', ['audit', '--omit=dev', '--json'], { cwd: HERE, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })
let npmCounts = null; const npmFindings = []
try {
  const a = JSON.parse(npm.stdout); npmCounts = a.metadata.vulnerabilities
  for (const [n, v] of Object.entries(a.vulnerabilities ?? {})) npmFindings.push({ name: n, severity: v.severity, via: v.via.map((x) => x.title ?? x).join('; ').slice(0, 200) })
} catch (e) { R.check('npm audit ran', false, `${e.message} ${npm.stderr?.slice(0, 200)}`) }
if (npmCounts) R.check('npm audit: 0 high/critical in production dependencies', (npmCounts.high ?? 0) + (npmCounts.critical ?? 0) === 0, JSON.stringify(npmCounts))
const cargo = spawnSync('cargo', ['audit', '--json', '--file', join(HERE, 'rs', 'Cargo.lock')], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })
let cargoFindings = []
try {
  const a = JSON.parse(cargo.stdout)
  cargoFindings = (a.vulnerabilities?.list ?? []).map((v) => ({ crate: v.package.name, version: v.package.version, id: v.advisory.id, severity: v.advisory.cvss ? 'cvss ' + v.advisory.cvss : 'unrated', title: v.advisory.title }))
  const warnings = Object.fromEntries(Object.entries(a.warnings ?? {}).map(([k, v]) => [k, v.length]))
  // cargo audit's JSON carries the CVSS vector, not a score, so this is stricter than the spec: any advisory fails, listed in full.
  R.check('cargo audit (affinidi-tsp 0.3.0 lock): no vulnerability advisory', a.vulnerabilities?.count === 0, `vulnerabilities ${a.vulnerabilities?.count}${cargoFindings.length ? ' (' + cargoFindings.map((f) => f.crate + ' ' + f.id).join(', ') + ')' : ''}, warnings ${JSON.stringify(warnings)}`)
} catch (e) { R.check('cargo audit ran', false, `${e.message} ${cargo.stderr?.slice(0, 300)}`) }
const load = spawnSync('node', ['-e', "import('@openvtc/vti-tsp-js').then(m => console.log(Object.keys(m).length))"], { cwd: HERE, encoding: 'utf8' })
R.check('vti-tsp-js loads in plain Node 22, no bundler', load.status === 0, load.status === 0 ? `${load.stdout.trim()} exports, ${process.version}` : load.stderr.slice(0, 200))
R.answer('mediator cargo audit', 'not yet: comes with the mediator job')
process.exit(R.finish(results, { npmCounts, npmFindings, cargoFindings }) ? 0 : 1)
