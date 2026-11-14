#!/usr/bin/env node
// Job `audit`. Usage: node audit.mjs <workdir> <resultsdir>
// npm: audits exactly didwebvh-ts@<pin> (a throwaway package with that one dependency, lockfile only, --ignore-scripts): `npm audit --omit=dev`.
// cargo: `cargo audit` on the harness crate's committed Cargo.lock (which pins didwebvh-rs =<pin>).
// Pass: 0 high and 0 critical in production dependencies, for both. Everything counted is printed and kept.
import { writeFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { HERE, readJson, writeJson, ensureDir, cvss3 } from './lib.mjs'

const [work = 'work-audit', results = 'results'] = process.argv.slice(2)
rmSync(work, { recursive: true, force: true }); ensureDir(work); ensureDir(results)
const pins = readJson(join(HERE, 'pins.json'))
const t0 = Date.now()
const sh = (cmd, args, cwd) => spawnSync(cmd, args, { cwd, encoding: 'utf8', maxBuffer: 128 * 1024 * 1024 })
const out = { job: 'audit', npm: {}, cargo: {}, checks: [] }
const check = (name, ok, detail) => { out.checks.push({ name, ok: !!ok, detail }); console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}  ${detail ?? ''}`) }

// npm
writeFileSync(join(work, 'package.json'), JSON.stringify({ name: 'wpi-audit-probe', version: '0.0.0', private: true, dependencies: { 'didwebvh-ts': pins['didwebvh-ts'].npm } }))
const inst = sh('npm', ['install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund'], work)
if (inst.status !== 0) check('npm: lockfile for the pinned didwebvh-ts', false, inst.stderr.slice(0, 300))
else {
  const a = sh('npm', ['audit', '--omit=dev', '--json'], work)
  let rep = null
  try { rep = JSON.parse(a.stdout) } catch { /* printed below */ }
  if (!rep?.metadata) check('npm audit ran', false, (a.stderr || a.stdout).slice(0, 300))
  else {
    const v = rep.metadata.vulnerabilities
    out.npm = { counts: v, dependencies: rep.metadata.dependencies, advisories: Object.entries(rep.vulnerabilities ?? {}).map(([n, x]) => `${n} (${x.severity})`) }
    check(`npm audit --omit=dev on didwebvh-ts@${pins['didwebvh-ts'].npm}: 0 high / 0 critical`, v.high === 0 && v.critical === 0, `info ${v.info}, low ${v.low}, moderate ${v.moderate}, high ${v.high}, critical ${v.critical}; ${rep.metadata.dependencies.prod} production dependencies`)
  }
}

// cargo
const ver = sh('cargo', ['audit', '--version'])
if (ver.status !== 0) check('cargo audit is installed', false, ver.stderr.slice(0, 200))
else {
  out.cargo.tool = ver.stdout.trim()
  const c = sh('cargo', ['audit', '--json', '--file', join(HERE, 'rs', 'Cargo.lock')])
  let rep = null
  try { rep = JSON.parse(c.stdout) } catch { /* printed below */ }
  if (!rep?.vulnerabilities) check('cargo audit ran', false, (c.stderr || c.stdout).slice(0, 300))
  else {
    // RustSec advisories carry a CVSS v3 vector, not a score: compute the base score. An advisory with no vector is "unrated" and counts against the pass.
    const sev = { critical: 0, high: 0, medium: 0, low: 0, unrated: 0 }
    const list = []
    for (const v of rep.vulnerabilities.list ?? []) {
      const score = cvss3(v.advisory?.cvss)
      const s = score === null ? 'unrated' : score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : 'low'
      sev[s]++
      list.push(`${v.advisory?.id} ${v.package?.name}@${v.package?.version} (${s}${score === null ? '' : ' ' + score})`)
    }
    out.cargo = { ...out.cargo, found: rep.vulnerabilities.count, severity: sev, advisories: list, warnings: Object.fromEntries(Object.entries(rep.warnings ?? {}).map(([k, a]) => [k, a.length])), lockfilePackages: rep.lockfile?.['dependency-count'] }
    // unrated vulnerabilities cannot be shown to be below high: they fail the line until someone reads them
    check('cargo audit on the harness Cargo.lock (didwebvh-rs =' + pins['didwebvh-rs'].crate + '): 0 high / 0 critical (unrated counts against)', sev.high === 0 && sev.critical === 0 && sev.unrated === 0, `${rep.vulnerabilities.count} vulnerabilities (critical ${sev.critical}, high ${sev.high}, medium ${sev.medium}, low ${sev.low}, unrated ${sev.unrated}); ${rep.lockfile?.['dependency-count'] ?? '?'} crates in the lockfile${list.length ? '; ' + list.join(', ') : ''}`)
  }
}
out.pass = out.checks.length > 0 && out.checks.every((c) => c.ok)
out.ms = Date.now() - t0
writeJson(join(results, 'audit.json'), out)
console.log(`audit: ${out.pass ? 'PASS' : 'FAIL'} (${out.ms} ms)`)
