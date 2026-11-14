#!/usr/bin/env node
// One content-blind check over a room's record (Security, bus 18708, before the member-join fix's card):
// before that fix a current member's join could carry a fresh one-person invite, which the room did not
// spend, so the live code sat in the signed record every reader and downloader can see.
// This counts, replaying the record in order:
//   memberJoinsWithInvite  `join` lines whose author was already a current member at that point, with `invite` in the payload
//   stillValid             of those, how many codes the room would still let a newcomer in with right now
// It prints only the two counts: never a code, a DID, a name or a line.
//   node agent/check-member-join-invites.js <room url | export.json | --data-dir <copy of DATA_DIR>>
// A members-only room's address needs a member: set WPI_MEMBER_KEY_FILE (a file holding your key).
// --data-dir opens the folder as a database: give it a scratch copy, never the live room's own folder.
// --lines-out <file> (optional): when stillValid > 0, also writes, owner-only, the hash of each line that made a
// still-valid invite (a line hash, never the code), so its maker or the host can turn that link off.
import { readFileSync, rmSync, writeFileSync } from 'node:fs'
import { State } from '../src/server/state.js'

async function readEntries (src, dataDir) {
  if (dataDir) {
    const { openDb, loadEntries } = await import('../src/server/db.js')
    const db = await openDb({ databaseUrl: '', dataDir })
    try { return await loadEntries(db) } finally { await db.close() }
  }
  if (/^https?:\/\//.test(src)) {
    const { oneLine, readWholeLog, roomFetch } = await import('./member-session.js')
    return readWholeLog(src, roomFetch(src)).catch(oneLine)
  }
  const doc = JSON.parse(readFileSync(src, 'utf8'))
  return Array.isArray(doc) ? doc : doc.entries ?? doc.log ?? []
}

/** The two counts (and the still-valid invites' line hashes) for a record, replayed in order. */
export function checkMemberJoinInvites (entries, now = Date.now()) {
  const st = new State(), codes = []
  for (const e of entries) {
    const p = e.document?.payload
    if (e.type === 'member/join' && p && p.invite !== undefined && st.isCurrentMember(e.author)) codes.push(p.invite)
    st.apply(e)
  }
  const valid = codes.map((c) => st.inviteFor(c, now)).filter((r) => r.ok)
  return { memberJoinsWithInvite: codes.length, stillValid: valid.length, lines: [...new Set(valid.map((r) => r.invite.hash))] }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2)
  const opt = (k) => { const i = args.indexOf('--' + k); return i >= 0 ? args.splice(i, 2)[1] : null }
  const dataDir = opt('data-dir'), linesOut = opt('lines-out'), src = args[0]
  if (!dataDir && !src) { console.error('usage: node agent/check-member-join-invites.js <room url | export.json | --data-dir <copy>> [--lines-out file]'); process.exit(2) }
  const r = checkMemberJoinInvites(await readEntries(src, dataDir))
  console.log(JSON.stringify({ memberJoinsWithInvite: r.memberJoinsWithInvite, stillValid: r.stillValid }))
  if (linesOut && r.lines.length) { rmSync(linesOut, { force: true }); writeFileSync(linesOut, r.lines.join('\n') + '\n', { mode: 0o600, flag: 'wx' }) } // removed first: the mode is only set on a new file (Security 15279); 'wx' refuses a link placed between the remove and the write (Security 15957)
}
