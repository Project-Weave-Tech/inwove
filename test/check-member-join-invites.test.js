// The content-blind check Security asked for before the member-join fix's card (bus 18708): how many member joins
// carried a one-person invite, and how many of those codes would still let someone in. Only the two counts come out.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, before, describe, test } from 'node:test'
import { newIdentity } from '../src/shared/did.js'
import { makeExport } from '../src/server/export.js'
import { checkMemberJoinInvites } from '../agent/check-member-join-invites.js'
import { startRoom } from './helpers/room.js'

describe('the member-join invite check', () => {
  let room, a, b
  before(async () => { room = await startRoom(); a = await room.firstMember('Person A'); b = await room.newMember(a.id) })
  after(() => room.stop())
  // a member's join carrying an invite, as the room accepted before the fix (the fixed room refuses it, so it is made by hand)
  const oldJoin = (entries, did, invite) => [...entries, { seq: entries.at(-1).seq + 1, hash: 'stand-in-' + entries.length, type: 'member/join', author: did, onBehalfOf: did, timestamp: new Date().toISOString(), document: { payload: { name: 'Person B', invite } } }]

  test('a newcomer\'s own join is not counted; nothing found in a clean record', () => {
    assert.deepEqual(checkMemberJoinInvites(room.ctx.log.entries), { memberJoinsWithInvite: 0, stillValid: 0, lines: [] })
  })

  test('the fixed room refuses a member\'s join with an invite, so no new one can appear', async () => {
    const code = await room.invite(a.id)
    assert.equal((await room.say(b.id, 'join', { name: 'Person B', invite: code })).status, 403)
    assert.equal(checkMemberJoinInvites(room.ctx.log.entries).memberJoinsWithInvite, 0)
  })

  test('an old member join with a live code counts as still valid until the code is used or turned off', async () => {
    const live = await room.invite(a.id), used = await room.invite(a.id)
    const lineOf = (code) => room.ctx.log.state.findInvite(code).hash
    let entries = oldJoin(oldJoin(room.ctx.log.entries, b.id.did, live), b.id.did, used)
    assert.equal((await room.say(newIdentity(), 'join', { name: 'Person C', invite: used })).status, 201, 'the second code is spent by its newcomer')
    entries = [...entries, room.ctx.log.entries.at(-1)]
    const r = checkMemberJoinInvites(entries)
    assert.equal(r.memberJoinsWithInvite, 2); assert.equal(r.stillValid, 1); assert.deepEqual(r.lines, [lineOf(live)], 'the line that made the live one, never its code')
    assert.ok(!JSON.stringify({ memberJoinsWithInvite: r.memberJoinsWithInvite, stillValid: r.stillValid }).includes(live))
    assert.equal((await room.say(a.id, 'inviteStop', { invite: lineOf(live) })).status, 201)
    assert.equal(checkMemberJoinInvites([...entries, room.ctx.log.entries.at(-1)]).stillValid, 0, 'turned off by its maker, it no longer counts')
  })

  test('the command prints only the two counts, and writes line hashes owner-only when asked', async () => {
    const live = await room.invite(a.id)
    const dir = mkdtempSync(join(tmpdir(), 'wpi-check-')), file = join(dir, 'export.json'), lines = join(dir, 'lines.txt')
    try {
      writeFileSync(file, JSON.stringify(makeExport(oldJoin(room.ctx.log.entries, b.id.did, live))))
      const out = execFileSync(process.execPath, ['agent/check-member-join-invites.js', file, '--lines-out', lines], { encoding: 'utf8' })
      assert.deepEqual(JSON.parse(out), { memberJoinsWithInvite: 1, stillValid: 1 })
      assert.ok(!out.includes(live) && !out.includes('did:'), 'no code, no DID')
      assert.equal(statSync(lines).mode & 0o777, 0o600)
      assert.equal(readFileSync(lines, 'utf8'), room.ctx.log.state.findInvite(live).hash + '\n')
    } finally { rmSync(dir, { recursive: true, force: true }) }
  })
})
