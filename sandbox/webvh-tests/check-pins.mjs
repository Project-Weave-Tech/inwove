#!/usr/bin/env node
// First step of every job: re-confirm the pinned shas and the licences, and fail if an upstream repo moved (head no longer starts with the
// pin) or a licence field changed. Prints the full shas (the job records them). Usage:
//   node check-pins.mjs <resultsdir> [--python <python with did-webvh installed>] [--no-network-shas]
// Output: <resultsdir>/pins-<job>.json when WPI_JOB is set; always prints a table.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { HERE, readJson, writeJson, ensureDir } from './lib.mjs'

const args = process.argv.slice(2)
const python = args.includes('--python') ? args[args.indexOf('--python') + 1] : null
const results = args.find((a) => !a.startsWith('--') && a !== python) ?? 'results'
const pins = readJson(join(HERE, 'pins.json'))
const rows = []
const bad = []
const row = (r) => { rows.push(r); console.log(`${r.ok ? 'ok  ' : 'FAIL'}  ${r.what}: ${r.detail}`); if (!r.ok) bad.push(r) }

// 1. upstream heads
for (const [name, p] of Object.entries(pins)) {
  if (name.startsWith('_') || !p.repo) continue
  const r = spawnSync('git', ['ls-remote', p.repo, 'HEAD'], { encoding: 'utf8', timeout: 60_000, env: { ...process.env, GIT_TERMINAL_PROMPT: '0' } })
  const head = (r.stdout ?? '').split(/\s+/)[0]
  if (r.status !== 0 || !/^[0-9a-f]{40}$/.test(head)) { row({ what: `${name} head`, ok: false, pinned: p.head, detail: `could not read ${p.repo} (git ls-remote exit ${r.status}): ${(r.stderr ?? '').trim().slice(0, 200)}` }); continue }
  row({ what: `${name} head`, ok: head.startsWith(p.head), pinned: p.head, head, detail: head.startsWith(p.head) ? `${head} (pin ${p.head})` : `MOVED: upstream HEAD is ${head}, pin is ${p.head}; update the pin on purpose or fix the pin` })
}

// 2. versions and licences of what is actually installed
const tsPkg = JSON.parse(readFileSync(join(HERE, '..', '..', 'node_modules', 'didwebvh-ts', 'package.json'), 'utf8'))
row({ what: 'didwebvh-ts (npm)', ok: tsPkg.version === pins['didwebvh-ts'].npm && tsPkg.license === pins['didwebvh-ts'].licence, detail: `version ${tsPkg.version}, licence ${tsPkg.license}` })
const meta = spawnSync('cargo', ['metadata', '--locked', '--format-version', '1', '--manifest-path', join(HERE, 'rs', 'Cargo.toml')], { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 })
if (meta.status !== 0) row({ what: 'didwebvh-rs (crate)', ok: false, detail: `cargo metadata failed: ${meta.stderr.slice(0, 200)}` })
else {
  const pkg = JSON.parse(meta.stdout).packages.find((x) => x.name === 'didwebvh-rs')
  row({ what: 'didwebvh-rs (crate)', ok: pkg?.version === pins['didwebvh-rs'].crate && pkg?.license === pins['didwebvh-rs'].licence, detail: `version ${pkg?.version}, licence ${pkg?.license}` })
}
if (python) {
  const r = spawnSync(python, ['-I', '-c', `import importlib.metadata as m; d=m.metadata(${JSON.stringify(pins['didwebvh-py'].pipPackage)}); print(d.get("License-Expression") or d.get("License") or "")`], { encoding: 'utf8' })
  const lic = r.stdout.trim()
  row({ what: 'didwebvh-py (installed)', ok: r.status === 0 && lic === pins['didwebvh-py'].licence, detail: `licence field "${lic}" ${r.status === 0 ? '' : r.stderr.trim().slice(0, 200)}` })
}
const tool = (c, a) => { const r = spawnSync(c, a, { encoding: 'utf8' }); return r.status === 0 ? (r.stdout || r.stderr).trim().split('\n')[0] : null }
const tools = { node: tool('node', ['-v']), npm: tool('npm', ['-v']), cargo: tool('cargo', ['-V']), rustc: tool('rustc', ['-V']), python: tool(python || 'python3', ['-V']), docker: tool('docker', ['--version']), strace: tool('strace', ['-V']), os: tool('uname', ['-sr']) }
console.log('tools: ' + JSON.stringify(tools))
ensureDir(results)
writeJson(join(results, `pins-${process.env.WPI_JOB || 'job'}.json`), { job: process.env.WPI_JOB || 'job', pass: bad.length === 0, rows, tools, at: new Date().toISOString() })
process.exit(bad.length ? 1 : 0)
