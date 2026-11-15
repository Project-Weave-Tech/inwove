#!/usr/bin/env node
// ref/09 §1: re-confirm the pins and licences of what is actually installed; fail if one moved or a licence changed.
// An @openvtc package that is not Apache-2.0 or MIT fails (Railroad then takes it to Legal). Pinned source commits
// are resolved to their full sha (recorded), and fail if they can't be. Usage: node check-pins.mjs <resultsdir>
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { HERE, readJson, recorder } from './lib.mjs'

const results = process.argv[2] ?? 'results'
const R = recorder(`pins-${process.env.WPI_JOB || 'job'}`)
const pins = readJson(join(HERE, 'pins.json'))
const shas = {}
for (const [name, p] of Object.entries(pins)) {
  if (name.startsWith('_')) continue
  if (p.npm) {
    const pkg = JSON.parse(readFileSync(join(HERE, 'node_modules', ...p.npm.split('/'), 'package.json'), 'utf8'))
    R.check(`${name} installed`, pkg.version === p.version && pkg.license === p.licence, `version ${pkg.version}, licence ${pkg.license}`)
    if (p.npm.startsWith('@openvtc/')) R.check(`${name} licence is Apache-2.0 or MIT`, ['Apache-2.0', 'MIT'].includes(pkg.license), pkg.license)
  }
  if (p.crate) {
    const meta = spawnSync('cargo', ['metadata', '--locked', '--format-version', '1', '--manifest-path', join(HERE, 'rs', 'Cargo.toml')], { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 })
    const pkg = meta.status === 0 ? JSON.parse(meta.stdout).packages.find((x) => x.name === p.crate) : null
    R.check(`${name} (crate, Cargo.lock)`, pkg?.version === p.version && pkg?.license === p.licence, pkg ? `version ${pkg.version}, licence ${pkg.license}` : `cargo metadata failed: ${meta.stderr?.slice(0, 200)}`)
  }
  if (p.repo && p.source && !process.argv.includes('--no-network-shas')) {
    // Resolve the short pin to a full sha by fetching exactly that commit (GitHub serves a commit by its prefix only via the API, so ask the API).
    const api = p.repo.replace('https://github.com/', 'https://api.github.com/repos/') + '/commits/' + p.source
    const r = spawnSync('curl', ['-fsS', '-H', 'Accept: application/vnd.github.sha', api], { encoding: 'utf8', timeout: 60_000 })
    const full = (r.stdout ?? '').trim()
    shas[name] = full
    R.check(`${name} source ${p.source}`, /^[0-9a-f]{40}$/.test(full) && full.startsWith(p.source), /^[0-9a-f]{40}$/.test(full) ? full : `could not resolve (curl exit ${r.status}): ${(r.stderr ?? '').trim().slice(0, 160)}`)
  }
}
const tool = (c, a) => { const r = spawnSync(c, a, { encoding: 'utf8' }); return r.status === 0 ? (r.stdout || r.stderr).trim().split('\n')[0] : null }
const tools = { node: tool('node', ['-v']), npm: tool('npm', ['-v']), cargo: tool('cargo', ['-V']), rustc: tool('rustc', ['-V']), os: tool('uname', ['-sr']) }
console.log('tools: ' + JSON.stringify(tools))
process.exit(R.finish(results, { shas, tools }) ? 0 : 1)
