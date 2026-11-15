// Every workflow in .github/workflows must be YAML GitHub can read. From 2026-11-09 to 2026-11-15 the export round
// trip never ran: its job name held an unquoted ": " ("a room started here: export"), GitHub could not read the file,
// and every branch push showed a failed run with no jobs, while the tests that read the file as text still passed.
// This is not a YAML parser (the room takes no dependency for it); it refuses the faults that stop GitHub from reading
// a workflow: a tab in the indentation, and a plain (unquoted) value holding ": " or ending in ":".
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { test } from 'node:test'

export function workflowFaults(text) {
  const faults = []
  let blockIndent = -1 // inside a block scalar (`run: |`), lines indented deeper than its key are its text
  text.split('\n').forEach((line, i) => {
    const indent = line.length - line.trimStart().length
    if (blockIndent >= 0) {
      if (!line.trim() || indent > blockIndent) return
      blockIndent = -1
    }
    if (line.slice(0, indent).includes('\t')) faults.push(`line ${i + 1}: a tab in the indentation`)
    if (!line.trim() || line.trim().startsWith('#')) return
    const m = /^(\s*)(- +)?([A-Za-z0-9_.${}-]+):(?: +(.*))?$/.exec(line)
    if (!m || m[4] === undefined) return
    const value = m[4].replace(/\s+#.*$/, '').trim()
    if (/^[|>][-+0-9]*$/.test(value)) { blockIndent = m[1].length + (m[2] ? m[2].length : 0); return }
    if (/^["'[{&*!]/.test(value)) return
    if (/: /.test(value) || value.endsWith(':')) faults.push(`line ${i + 1}: an unquoted value holding ": " (put the value in quotes)`)
  })
  return faults
}

test('every workflow is YAML GitHub can read', () => {
  const dir = '.github/workflows'
  const files = readdirSync(dir).filter((f) => /\.ya?ml$/.test(f))
  assert.ok(files.length >= 1, 'the workflows are found')
  for (const f of files) assert.deepEqual(workflowFaults(readFileSync(join(dir, f), 'utf8')), [], `${f} would not run`)
})

test('the check refuses the fault that stopped the export round trip, and passes what GitHub reads', () => {
  assert.deepEqual(workflowFaults('jobs:\n  a:\n    name: export round trip (a room started here: export, re-import, compare)\n'),
    ['line 3: an unquoted value holding ": " (put the value in quotes)'])
  assert.deepEqual(workflowFaults('jobs:\n  a:\n    name: "a room started here: export"\n'), [])
  assert.deepEqual(workflowFaults('on:\n  push:\n    branches: [main]\n'), [])
  assert.deepEqual(workflowFaults('    - uses: actions/checkout@11d5960a # v4: pinned\n'), [], 'a comment may hold ": "')
  assert.deepEqual(workflowFaults('      - run: |\n          echo "a: b"\n          x: y\n      - run: ok\n'), [], 'a block scalar is text')
  assert.deepEqual(workflowFaults('      - run: echo a: b\n'), ['line 1: an unquoted value holding ": " (put the value in quotes)'])
  assert.deepEqual(workflowFaults('jobs:\n\ta: x\n'), ['line 2: a tab in the indentation'])
})
