#!/usr/bin/env node
// ref/09 §1: re-confirm the pins and licences of what is actually installed; fail if one moved or a licence changed.
// An @openvtc package that is not Apache-2.0 or MIT fails (Railroad then takes it to Legal). Pinned source commits
// are fetched by their full sha (no token) and must be ancestors of their ref (fetch-pinned.sh, Security 12036). Usage: node check-pins.mjs <resultsdir>
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
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
    // Security 12036: compare, never resolve. git-fetch exactly the full sha written in pins.json, with no token, and
    // prove upstream has it (an ancestor of the pin's ref, so a fork's "imposter commit" can't satisfy it). No
    // api.github.com call and no fallback to one; a fetch error fails the check.
    const dir = mkdtempSync(join(tmpdir(), `pin-${name}-`))
    const r = spawnSync('bash', [join(HERE, 'fetch-pinned.sh'), p.repo, p.sha ?? '', p.ref ?? '', dir], { encoding: 'utf8', timeout: 300_000 })
    let got = null
    try { got = JSON.parse((r.stdout ?? '').trim().split('\n').at(-1)) } catch {}
    // run 43869868962: a git process still writing under .git/objects made the remove race (ENOTEMPTY) and crashed the
    // step, which then read as "a pin moved". Retry the remove; a remove that still fails is not a pin result.
    try { rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }) } catch (e) { console.error(`pins: temp clone not removed (${e.code})`) }
    shas[name] = got ?? { error: (r.stderr ?? '').trim().slice(0, 200) }
    const ok = r.status === 0 && got?.sha === p.sha && got?.ancestor === true && /^[0-9a-f]{40}$/.test(p.sha ?? '') && p.sha.startsWith(p.source)
    R.check(`${name} source ${p.source} (full sha, upstream's on ${p.ref})`, ok, got ? `${got.sha} on ${got.ref} @ ${got.ref_tip}, ancestor ${got.ancestor}` : `fetch failed (exit ${r.status}): ${(r.stderr ?? '').trim().slice(0, 160)}`)
  }
}
const tool = (c, a) => { const r = spawnSync(c, a, { encoding: 'utf8' }); return r.status === 0 ? (r.stdout || r.stderr).trim().split('\n')[0] : null }
const tools = { node: tool('node', ['-v']), npm: tool('npm', ['-v']), cargo: tool('cargo', ['-V']), rustc: tool('rustc', ['-V']), os: tool('uname', ['-sr']) }
console.log('tools: ' + JSON.stringify(tools))
process.exit(R.finish(results, { shas, tools }) ? 0 : 1)
