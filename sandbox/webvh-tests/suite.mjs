#!/usr/bin/env node
// Job `suite`: run each library's own entry in the pinned didwebvh-test-suite checkout (`scripts/run <impl>`: builds the library in Docker,
// regenerates its vectors, cross-resolves every implementation's logs, writes implementations/<impl>/status.md), then count the rows.
// Usage: node suite.mjs <suite checkout> <resultsdir> [--parse-only]
//   --parse-only: do not run Docker; count the status.md files as committed (used to test the counting).
// Gates (section 2): TS pass >= 59, fail <= 0, skip <= 2; Rust pass >= 57, fail <= 3, skip <= 2 (the failing rows are named). Python: reported, not gated.
// "pass" = rows marked PASS, "fail" = FAIL, "skip" = SKIP; DIFF rows (cross-resolution differences) are counted and reported separately.
import { readFileSync, existsSync, copyFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import { HERE, readJson, writeJson, ensureDir } from './lib.mjs'

const args = process.argv.slice(2)
const parseOnly = args.includes('--parse-only')
const [suiteDir, results = 'results'] = args.filter((a) => !a.startsWith('--'))
ensureDir(results)
const pins = readJson(join(HERE, 'pins.json'))
const IMPLS = [
  { impl: 'ts', lib: 'didwebvh-ts', pin: pins['didwebvh-ts'].head, gate: { pass: 59, fail: 0, skip: 2 } },
  { impl: 'rust', lib: 'didwebvh-rs', pin: pins['didwebvh-rs'].head, gate: { pass: 57, fail: 3, skip: 2 } },
  { impl: 'python', lib: 'didwebvh-py', pin: pins['didwebvh-py'].head, gate: null },
]
const git = (...a) => spawnSync('git', ['-C', suiteDir, ...a], { encoding: 'utf8' }).stdout.trim()
const out = { job: 'suite', suiteSha: git('rev-parse', 'HEAD'), suitePin: pins['didwebvh-test-suite'].head, libs: {}, checks: [] }
const check = (name, ok, detail) => { out.checks.push({ name, ok: !!ok, detail }); console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}  ${detail ?? ''}`) }
check('the checkout is the pinned test-suite sha', out.suiteSha.startsWith(out.suitePin), `${out.suiteSha} (pin ${out.suitePin})`)
const lic = existsSync(join(suiteDir, 'LICENSE')) && /Apache License/.test(readFileSync(join(suiteDir, 'LICENSE'), 'utf8'))
check('the test-suite licence is Apache-2.0', lic, '')

/** Count the result marks of a status.md, and name every FAIL / SKIP row with its section. */
export function tally (text) {
  const c = { pass: 0, fail: 0, skip: 0, diff: 0 }
  const named = { fail: [], skip: [] }
  let section = ''
  for (const line of text.split('\n')) {
    const h = /^##\s+(.*)$/.exec(line)
    if (h) { section = h[1].trim(); continue }
    if (!line.startsWith('|')) continue
    const cells = line.split('|').slice(1, -1).map((x) => x.trim())
    const mark = cells.find((x) => /^(✅ PASS|❌ FAIL|⚠️ SKIP|🔶 DIFF)/.test(x))
    if (!mark) continue
    const k = mark.includes('PASS') ? 'pass' : mark.includes('FAIL') ? 'fail' : mark.includes('SKIP') ? 'skip' : 'diff'
    c[k]++
    if (k === 'fail' || k === 'skip') named[k].push(`${section}: ${cells.filter((x) => x && x !== mark).join(' / ')}`)
  }
  return { counts: c, named }
}

for (const { impl, lib, pin, gate } of IMPLS) {
  const t = Date.now()
  let ran = null
  if (!parseOnly) {
    const r = spawnSync(join(suiteDir, 'scripts', 'run'), [impl], { cwd: suiteDir, stdio: 'inherit', timeout: 50 * 60_000 })
    ran = { exit: r.status, signal: r.signal }
  }
  const sp = join(suiteDir, 'implementations', impl, 'status.md')
  if (!existsSync(sp)) { out.libs[impl] = { lib, error: 'no status.md was written', ran }; check(`${lib}: the suite entry produced a result file`, false, `exit ${ran?.exit}`); continue }
  copyFileSync(sp, join(results, `suite-status-${impl}.md`))
  const text = readFileSync(sp, 'utf8')
  const { counts, named } = tally(text)
  const built = /Built from: (\S+) @ (\S+) \(([0-9a-f]+)\)/.exec(text)
  const header = /^Implementation: (.*)$/m.exec(text)?.[1] ?? ''
  const row = { lib, impl, counts, header, builtFrom: built ? { repo: built[1], ref: built[2], commit: built[3] } : null, failRows: named.fail, skipRows: named.skip, ran, seconds: Math.round((Date.now() - t) / 1000) }
  out.libs[impl] = row
  console.log(`${impl}: ${counts.pass} pass / ${counts.fail} fail / ${counts.skip} skip (+${counts.diff} DIFF)  ${header}`)
  for (const f of named.fail) console.log(`  FAIL row: ${f}`)
  if (gate) {
    check(`${lib}: pass/fail/skip ${counts.pass}/${counts.fail}/${counts.skip} no worse than ${gate.pass}/${gate.fail}/${gate.skip}`, counts.pass >= gate.pass && counts.fail <= gate.fail && counts.skip <= gate.skip, named.fail.length ? 'failing rows: ' + named.fail.join(' | ') : '')
    // the library must have been built from the pinned source head (scripts/run builds the branch tip; a moved head would test something else)
    if (!parseOnly) check(`${lib}: the suite built the pinned source head`, !!built && built[3] && pin.startsWith(built[3].slice(0, 7)), built ? `built ${built[3]}, pin ${pin}` : 'no "Built from" footer')
  } else {
    row.note = 'reported, not gated; scripts/run builds the branch tip of the library, which is not necessarily the pinned sha' + (built && !pin.startsWith(built[3].slice(0, 7)) ? ` (built ${built[3]}, pin ${pin})` : '')
  }
}
out.pass = out.checks.every((c) => c.ok)
writeJson(join(results, 'suite.json'), out)
console.log(`suite: ${out.pass ? 'PASS' : 'FAIL'}`)
