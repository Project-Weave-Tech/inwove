// scripts/token-verdict.sh is the verdict verify-setup-token-dead.yml runs on Railway's answer (Security, bus 17720).
// Railway refuses a token with HTTP 200 + "Not Authorized", not 401, so the verdict is tested here on made-up bodies.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, describe, test } from 'node:test'

const script = new URL('../scripts/token-verdict.sh', import.meta.url).pathname
const dir = mkdtempSync(join(tmpdir(), 'verdict-'))
after(() => rmSync(dir, { recursive: true, force: true }))
let n = 0
const verdict = (code, body) => {
  const file = join(dir, `b${n++}`)
  writeFileSync(file, body)
  const r = spawnSync('bash', [script, code, file], { encoding: 'utf8' })
  return { status: r.status, out: r.stdout.trim() }
}

describe('token-verdict.sh', () => {
  test('dead: 200 with data null and Not Authorized', () => {
    const r = verdict('200', '{"data":null,"errors":[{"message":"Not Authorized"}]}')
    assert.equal(r.status, 0)
    assert.equal(r.out, 'OK: Railway refused the setup token (HTTP 200, Not Authorized)')
  })
  test('dead: 401', () => {
    const r = verdict('401', 'not json')
    assert.equal(r.status, 0)
    assert.match(r.out, /^OK: Railway refused the setup token \(HTTP 401/)
  })
  test('alive: projects come back, only the count is printed', () => {
    const r = verdict('200', '{"data":{"projects":{"edges":[{"node":{"id":"x"}}]}}}')
    assert.equal(r.status, 1)
    assert.equal(r.out, 'KEY STILL ALIVE: Railway answered with 1 project(s)')
    assert.doesNotMatch(r.out, /"x"|\bx\b/)
  })
  test('unclear: another message', () => {
    const r = verdict('200', '{"errors":[{"message":"Problem processing request"}]}')
    assert.equal(r.status, 1)
    assert.equal(r.out, 'UNCLEAR: HTTP 200, data_is_null=true, message: Problem processing request')
  })
  test('unclear: a message outside the safe shape is withheld', () => {
    const r = verdict('200', '{"data":null,"errors":[{"message":"token abc123: bad"}]}')
    assert.equal(r.status, 1)
    assert.equal(r.out, 'UNCLEAR: HTTP 200, data_is_null=true, message: (message withheld)')
  })
  test('unclear: body not JSON, other code', () => {
    const r = verdict('500', '<html>secret</html>')
    assert.equal(r.status, 1)
    assert.equal(r.out, 'UNCLEAR: HTTP 500, data_is_null=false, message: (message withheld)')
    assert.doesNotMatch(r.out, /secret/)
  })
})
