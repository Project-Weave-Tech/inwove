// Security 18457, follow-ups 2 and 3: a wrong code is counted and slowed the same at both doors (a one-person invite inside
// the join, a group link's code beside it), and the counts are kept as one row per day and kind, never an address or a code.
import assert from 'node:assert/strict'
import { after, before, describe, test } from 'node:test'
import { newIdentity } from '../src/shared/did.js'
import { TYPES, signedDocument } from '../src/shared/types.js'
import { hashOf, newCode } from '../src/server/invites.js'
import { startRoom } from './helpers/room.js'

describe('wrong invite codes: one counter for both doors, kept per day', () => {
  let room, host
  before(async () => {
    room = await startRoom({ extra: { inviteMissesPerMinute: 3 } })
    host = await room.firstMember('Host')
    room.config.hosts = [host.id.did]
  })
  after(() => room.stop())
  const say = (id, payload) => room.say(id, 'join', payload) // the one-person path: the code is in the signed line
  const today = () => new Date().toISOString().slice(0, 10)

  test('a one-person join with a wrong code is counted as a join miss; a spent or ended code is too', async () => {
    const before = { ...room.ctx.inviteMissCount }
    const r = await say(newIdentity(), { name: 'Stranger', invite: newCode() })
    assert.equal(r.status, 403)
    const used = await room.invite(host.id)
    assert.equal((await say(newIdentity(), { name: 'Newcomer', invite: used })).status, 201)
    assert.equal((await say(newIdentity(), { name: 'Late', invite: used })).status, 403)
    assert.equal(room.ctx.inviteMissCount.join, before.join + 2)
  })

  test('refusals that are not about the code are not misses: a current member\'s join with an invite, a join with none', async () => {
    const before = { ...room.ctx.inviteMissCount }
    const code = await room.invite(host.id)
    const m = await say(host.id, { name: 'Host', invite: code }); assert.equal(m.status, 403); assert.match(m.body.payload.message, /already a member/)
    assert.equal((await say(newIdentity(), { name: 'No code' })).status, 403)
    assert.deepEqual(room.ctx.inviteMissCount, before)
  })

  test('after enough misses from one address, the one-person door slows it too, and that is counted', async () => {
    const before = { ...room.ctx.inviteMissCount }
    room.ctx.inviteMisses.hits.clear()
    for (let i = 0; i < 3; i++) assert.equal((await say(newIdentity(), { name: 'Guess', invite: newCode() })).status, 403)
    const slowed = await say(newIdentity(), { name: 'Guess', invite: newCode() })
    assert.equal(slowed.status, 429)
    assert.equal(room.ctx.inviteMissCount.join, before.join + 3); assert.equal(room.ctx.inviteMissCount.slowed, before.slowed + 1)
    const lookup = await room.call('/api/invite', { method: 'POST', body: { code: newCode() } })
    assert.equal(lookup.status, 429, 'the lookup shares the same counter')
    room.ctx.inviteMisses.hits.clear()
  })

  test('a group join whose code does not match is a miss; a group link that is full is too', async () => {
    const before = { ...room.ctx.inviteMissCount }
    const code = newCode(), h = hashOf(code)
    await room.say(host.id, 'invite', { codeHash: h, expiresAt: new Date(Date.now() + 86400000).toISOString(), group: { name: 'Retreat', max: 2 } })
    const groupJoin = (c) => room.call('/api/entries', { method: 'POST', headers: { 'x-inwove-invite': c }, body: signedDocument(newIdentity(), { type: TYPES.join, payload: { name: 'Guest', groupInvite: h } }) })
    assert.equal((await groupJoin(newCode())).status, 403, 'a code that is not this link\'s')
    assert.equal((await groupJoin(code)).status, 201); assert.equal((await groupJoin(code)).status, 201)
    const full = await groupJoin(code); assert.equal(full.status, 403)
    assert.equal(room.ctx.inviteMissCount.join, before.join + 2)
  })

  test('the counts are written as one row per day and kind, with no address or code, and the host sees the last week', async () => {
    await room.ctx.flushInviteMisses()
    const { rows } = await room.ctx.db.query('select * from invite_misses order by what')
    assert.deepEqual(Object.keys(rows[0]).sort(), ['day', 'n', 'what'], 'nothing else is kept')
    const n = (what) => Number(rows.find((r) => r.what === what && r.day === today())?.n ?? 0)
    assert.equal(n('join'), room.ctx.inviteMissCount.join); assert.equal(n('lookup'), room.ctx.inviteMissCount.lookup); assert.equal(n('slowed'), room.ctx.inviteMissCount.slowed)
    await say(newIdentity(), { name: 'One more', invite: newCode() }) // not written yet: still shown
    const r = await room.call('/api/group-links', { cookie: host.cookie })
    assert.equal(r.status, 200)
    const shown = r.body.wrongCodesByDay.find((x) => x.day === today() && x.what === 'join')
    assert.equal(shown.n, room.ctx.inviteMissCount.join, 'written and not-yet-written counts together')
    assert.ok(!JSON.stringify(r.body.wrongCodesByDay).includes('127.0.0.1'))
  })
})
