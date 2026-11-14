#!/usr/bin/env node
// Fails if the licence field of any package in the two production dependency closures differs from the committed snapshot
// (or a package appears/disappears): didwebvh-ts's npm closure (from the repo's package-lock.json) and the Rust harness's cargo closure
// (from `cargo metadata --locked`). Usage: node check-licences.mjs [--write]   (--write refreshes the snapshot: a reviewed change)
import { readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { HERE, readJson, writeJson } from './lib.mjs'

const root = join(HERE, '..', '..')
const lock = readJson(join(root, 'package-lock.json')).packages
const resolveDep = (from, name) => { // node resolution inside the lockfile: nearest node_modules/<name> walking up
  let base = from
  for (;;) {
    const key = (base ? base + '/' : '') + 'node_modules/' + name
    if (lock[key]) return key
    if (!base) return null
    const i = base.lastIndexOf('/node_modules/')
    base = i >= 0 ? base.slice(0, i) : ''
  }
}
const npm = {}
const seen = new Set()
const walk = (key) => {
  if (seen.has(key)) return
  seen.add(key)
  const p = lock[key]
  npm[`${key.replace(/^.*node_modules\//, '')}@${p.version}`] = p.license ?? JSON.parse(readFileSync(join(root, key, 'package.json'), 'utf8')).license ?? 'UNKNOWN'
  for (const d of Object.keys(p.dependencies ?? {})) { const k = resolveDep(key, d); if (k) walk(k) }
}
walk('node_modules/didwebvh-ts')

const meta = spawnSync('cargo', ['metadata', '--locked', '--format-version', '1', '--manifest-path', join(HERE, 'rs', 'Cargo.toml')], { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 })
if (meta.status !== 0) { console.error('cargo metadata failed', meta.stderr); process.exit(1) }
const m = JSON.parse(meta.stdout)
const cargo = {}
for (const p of m.packages) if (p.name !== 'wpi-webvh-rs') cargo[`${p.name}@${p.version}`] = p.license ?? (p.license_file ? `license-file:${p.license_file.split('/').pop()}` : 'UNKNOWN')

const now = { npm: Object.fromEntries(Object.entries(npm).sort()), cargo: Object.fromEntries(Object.entries(cargo).sort()) }
const snap = join(HERE, 'licences.snapshot.json')
if (process.argv.includes('--write') || !existsSync(snap)) { writeJson(snap, now); console.log(`snapshot written: ${Object.keys(now.npm).length} npm, ${Object.keys(now.cargo).length} cargo packages`); process.exit(0) }
const was = readJson(snap)
const diffs = []
for (const eco of ['npm', 'cargo']) {
  for (const k of new Set([...Object.keys(was[eco]), ...Object.keys(now[eco])])) if (was[eco][k] !== now[eco][k]) diffs.push(`${eco} ${k}: ${was[eco][k] ?? '(absent)'} -> ${now[eco][k] ?? '(absent)'}`)
}
console.log(`licences: ${Object.keys(now.npm).length} npm + ${Object.keys(now.cargo).length} cargo packages compared; ${diffs.length} difference(s)`)
for (const d of diffs) console.log('FAIL  ' + d)
process.exit(diffs.length ? 1 : 0)
