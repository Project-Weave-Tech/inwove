#!/usr/bin/env node
// Security 12491 (a): the features check lets `keyring-core` and `dbus-secret-service-keyring-store` through by name
// (SECRET_NAMED_OK in mediator-features.mjs), because at 34bbdea4 they arrive only as affinidi-tdk-common's default
// client keyring. This binds that exception to its path: in `cargo tree -i <crate> -e normal`, EVERY path from the
// crate up to a root must pass through `affinidi-tdk-common`, and `affinidi-messaging-mediator-common` (the mediator's
// own secret-store backends) must appear nowhere. A crate absent from the build passes (nothing to land), and says so.
// Usage: node mediator-keyring-paths.mjs <out.json> <label>=<inverted tree file> ...
// Names and versions only; no paths from the checkout are kept.
import { readFileSync, writeFileSync } from 'node:fs'

export const THROUGH = 'affinidi-tdk-common'
export const FORBIDDEN = 'affinidi-messaging-mediator-common'

const TREE_LINE = /^([\s│├└─]*)([A-Za-z0-9_][\w-]*) v[0-9][^\s]*/
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

// Parse one `cargo tree -i <crate>` output into nodes (name) and edges child -> parent (dependency -> dependent).
// `crate` is the name the tree was asked for (Security 12615.1): "absent" is accepted only on cargo's own words for
// THAT crate, never for another name (a renamed or missing root would otherwise read as absent), and only when the
// output holds no tree line at all (12615.2: a real tree with the sentence added to it is not absent).
export function parseInverted(text, crate) {
  const lines = String(text).split('\n').filter((l) => l.trim())
  if (!crate || !/^[\w-]+$/.test(crate)) return { error: 'no crate named' }
  // Every "did not match" sentence in the output, by the crate it names (12734.2: `cargo tree -i <one crate>` prints
  // at most one, so a sentence for any other crate means the output isn't what was asked, even beside the right one).
  const named = [...String(text).matchAll(/package ID specification `([^`]*)` did not match any packages/g)].map((m) => m[1])
  if (named.some((n) => n !== crate)) return { error: 'absent words for another crate' }
  const absentWords = new RegExp('package ID specification `' + escapeRe(crate) + '` did not match any packages')
  if (absentWords.test(text)) {
    if (lines.some((l) => TREE_LINE.test(l))) return { error: 'absent words beside a tree' }
    return { absent: true }
  }
  if (!lines.length) return { error: 'empty tree' }
  const edges = new Map(), stack = []
  let target = null
  for (const l of lines) {
    const m = l.match(TREE_LINE)
    if (!m) return { error: 'unparsed line' }
    const depth = Math.round([...m[1]].length / 4), name = m[2]
    if (depth === 0) { if (target && target !== name) return { error: 'two targets' }; if (name !== crate) return { error: 'tree for another crate' }; target = name }
    stack.length = depth; stack[depth] = name
    if (depth > 0) { const child = stack[depth - 1]; if (!child) return { error: 'bad indent' }; if (!edges.has(child)) edges.set(child, new Set()); edges.get(child).add(name) }
  }
  return { target, edges }
}

// Pass = every path from the target to a root goes through THROUGH, and FORBIDDEN is nowhere in the tree.
export function pathVerdict(text, crate) {
  const p = parseInverted(text, crate)
  if (p.absent) return { pass: true, absent: true }
  if (p.error) return { pass: false, error: p.error }
  const nodes = new Set([p.target, ...p.edges.keys(), ...[...p.edges.values()].flatMap((s) => [...s])])
  const forbidden = nodes.has(FORBIDDEN)
  // Roots: nodes that nothing depends on (no outgoing child->parent edge). Walk up without stepping on THROUGH.
  const isRoot = (n) => !p.edges.get(n)?.size
  const bypass = [], seen = new Set()
  const walk = (n, path) => {
    if (n === THROUGH) return
    if (isRoot(n)) { bypass.push([...path, n].join(' <- ')); return }
    if (seen.has(n)) return; seen.add(n)
    for (const up of p.edges.get(n)) walk(up, [...path, n])
  }
  walk(p.target, [])
  const roots = [...nodes].filter(isRoot).sort()
  return { pass: !forbidden && bypass.length === 0 && nodes.has(THROUGH), target: p.target, roots, through: nodes.has(THROUGH), forbidden_in_tree: forbidden, paths_bypassing: bypass }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [out, ...pairs] = process.argv.slice(2)
  if (!out || !pairs.length) { console.error('usage: mediator-keyring-paths.mjs <out.json> <label>=<file> ...'); process.exit(2) }
  const results = {}
  for (const pair of pairs) {
    const i = pair.indexOf('='); const label = pair.slice(0, i), file = pair.slice(i + 1)
    // The crate is the label's part after the mode (`lean:keyring-core` -> `keyring-core`), Security 12615.1.
    const crate = label.slice(label.indexOf(':') + 1)
    results[label] = pathVerdict(readFileSync(file, 'utf8'), crate)
    console.log(label.padEnd(44), results[label].pass ? 'PASS' : 'FAIL', JSON.stringify({ ...results[label], pass: undefined }))
  }
  const pass = Object.values(results).every((r) => r.pass)
  writeFileSync(out, JSON.stringify({ check: 'keyring exception bound to its path (Security 12491 a)', through: THROUGH, forbidden: FORBIDDEN, pass, results }, null, 2) + '\n')
  console.log('keyring paths:', pass ? 'PASS' : 'FAIL')
  process.exit(pass ? 0 : 1)
}
