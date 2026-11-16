#!/usr/bin/env node
// "Admin over TSP is refused with the guard on (expected)": the expect-red evaluator (Security 12552, conditions 1-6;
// Railroad 12567.1 + Security 12582.1: it is part of every re-pin's evidence).
// It reads the two closed-default results files from the same job, never the steps' outcomes (both steps are
// continue-on-error):
//   acl-closed.json          the admin over TSP   (mediator-acl.mjs --closed-default)
//   acl-closed-didcomm.json  the admin over DIDComm (mediator-acl.mjs --closed-default --admin-didcomm)
// PASS only when:
//   - the TSP run's list update was refused with the known shape (HTTP 403 at /inbound, no answer), the TSP list read
//     got no answer, the read-back over DIDComm does not show the mediator's hash on the admin's list (answered without
//     it, or the mediator's reply to the admin refused 403/73 by that same list), and none of the three adds is
//     confirmed by an answer; every non-admin check in that run still passes;
//   - the DIDComm run says pass with S2 admin-list, S2 adds and E1 (Security 12672.2: an unsigned admin write is refused
//     proof_required and does not land, an unsigned read answers) passing;
//   - the known-gap line tsp_account_add_lands_despite_refusal (Security 12672.1) reads 3/3, AMBER; any other count is
//     a STOP (red, a re-pin note), never silently accepted;
//   - both record block_remote_admin_msgs: true and their admin_transport (tsp / didcomm).
// "Can't tell" is never a pass: a missing or unparseable file, an `error` (crash, the admin couldn't sign in), a
// run that didn't reach its end, a 5xx or any other code is red. If the TSP update (or an add) is ever accepted, it is
// red AND a finding for SECURITY, not a test to update: the guard is off or upstream changed check_admin_signature.
// Usage: node mediator-expect-red.mjs <acl-closed.json> <acl-closed-didcomm.json> <out.json>
// Prints the verdict, reasons and statuses only.
import { readFileSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

export const KNOWN_REFUSAL_STATUS = 403 // the update's refusal at /inbound, as runs 43800972273 / 43803025356 saw it
export const LIST_DENIED_PROBLEM = 73 // the mediator's reply refused by the recipient's access list (C4's code)
const ADDS = ['A', 'B', 'D']

export function readResults(path) {
  let text
  try { text = readFileSync(path, 'utf8') } catch { return { missing: true } }
  try { return { json: JSON.parse(text) } } catch { return { unparseable: true } }
}

// Security 12672.1, the known-gap line beside the expect-red (report 2, the silent account/add): how many of the TSP
// run's three adds answered a refusal and then landed, proved by a real sign-in (setup fact 1), never by the answer.
// At the pin that is 3 of 3, shown AMBER, never green. Any other count, or a count that can't be read, is a STOP: the
// setup job's own add path would behave differently, so it comes back as a re-pin note.
export const EXPECTED_LANDED = 3
export function addsLandDespiteRefusal(tsp) {
  const s = tsp?.json?.setup ?? null, signs = s?.account_signs_in ?? null
  const note = 'report 2 (upstream): a refused account/add over TSP still lands; custody covers it, the expect-red does not gate on it'
  if (!s || !signs) return { count: 'unknown', expected: `${EXPECTED_LANDED}/${ADDS.length}`, state: 'STOP', note }
  let n = 0
  for (const k of ADDS) { const a = s['account_add_' + k]; if (a && !a.confirmed && !a.answerType && a.status >= 400 && signs[k] === true) n++ }
  return { count: `${n}/${ADDS.length}`, expected: `${EXPECTED_LANDED}/${ADDS.length}`, state: n === EXPECTED_LANDED ? 'amber' : 'STOP', note }
}

// tsp, didcomm: parsed JSON objects, or { missing } / { unparseable } markers from readResults.
export function evaluate(tsp, didcomm) {
  const reasons = [], findings = []
  const red = (r) => reasons.push(r)

  // ---- the DIDComm run: must be green on S2, with the guard recorded ----
  if (!didcomm || didcomm.missing) red('didcomm: results file missing')
  else if (didcomm.unparseable) red('didcomm: results file not JSON')
  else {
    const d = didcomm.json
    if (d.error) red('didcomm: run error: ' + String(d.error).slice(0, 80))
    if (d.setup?.block_remote_admin_msgs !== true) red('didcomm: block_remote_admin_msgs not recorded true')
    if (d.setup?.admin_transport !== 'didcomm') red('didcomm: admin_transport is not didcomm')
    if (d.pass !== true) red('didcomm: run did not pass')
    if (d.checks?.S2_admin_allow_list_is_mediator_only?.pass !== true) red('didcomm: S2 admin list not mediator-only')
    if (d.checks?.S2_adds_confirmed_under_closed_default?.pass !== true) red('didcomm: S2 adds not confirmed')
    if (d.checks?.E1_enforce_unsigned_admin_write_refused?.pass !== true) red('didcomm: E1 an unsigned admin write was not refused proof_required (enforce), or it landed')
  }

  // ---- the TSP run: refused exactly as known, and nothing landed by that call ----
  if (!tsp || tsp.missing) red('tsp: results file missing')
  else if (tsp.unparseable) red('tsp: results file not JSON')
  else {
    const t = tsp.json, s = t.setup ?? {}
    if (t.error) red('tsp: run error: ' + String(t.error).slice(0, 80))
    if (typeof t.pass !== 'boolean') red('tsp: run did not reach its end')
    if (s.block_remote_admin_msgs !== true) red('tsp: block_remote_admin_msgs not recorded true')
    if (s.admin_transport !== 'tsp') red('tsp: admin_transport is not tsp')
    if (s.admin_sign_in?.ok !== true) red('tsp: admin could not sign in')
    const al = s.admin_list
    if (!al) red('tsp: no admin list update recorded')
    else {
      if (al.update_status === 200 || al.update_answer) { red('tsp: the admin list update was accepted'); findings.push('admin access-list/update over TSP accepted with the guard on') }
      else if (al.update_status !== KNOWN_REFUSAL_STATUS) red(`tsp: list update answered ${al.update_status}, not the known ${KNOWN_REFUSAL_STATUS}`)
      if (al.list_answer) red('tsp: the TSP list read was answered')
      if (al.mediator_listed) { red('tsp: the TSP list read shows the mediator'); findings.push('the TSP read shows the mediator on the admin list') }
    }
    const rb = s.admin_list_readback_didcomm
    if (!rb) red('tsp: no read-back over DIDComm')
    else if (rb.sign_in_ok !== true) red('tsp: read-back: admin could not sign in over DIDComm')
    else if (rb.answered) {
      if (rb.mediator_listed) { red('tsp: read-back shows the mediator on the admin list'); findings.push('admin access-list/update over TSP took effect (read back over DIDComm)') }
    } else if (!(rb.status === 403 && rb.problem === LIST_DENIED_PROBLEM)) red(`tsp: read-back can't tell (status ${rb.status}, problem ${typeof rb.problem === 'number' ? rb.problem : 'other'})`)
    for (const n of ADDS) {
      const a = s['account_add_' + n]
      if (!a) red(`tsp: account/add ${n} not recorded`)
      else if (a.confirmed || a.answerType) { red(`tsp: account/add ${n} confirmed by an answer`); findings.push(`admin account/add ${n} over TSP answered with the guard on`) }
      else if (a.status >= 500 || !(a.status >= 400)) red(`tsp: account/add ${n} answered ${a.status}`)
    }
    // The rest of the closed run still has to hold: an expect-red must not hide a red Z1, C4, ...
    for (const [k, c] of Object.entries(t.checks ?? {})) if (!k.startsWith('S2_') && c?.pass !== true) red(`tsp: ${k} failed`)
    if (t.log_lines_with_redis_password !== 0) red('tsp: redis password count is not 0')
  }

  const known_gaps = { tsp_account_add_lands_despite_refusal: addsLandDespiteRefusal(tsp) }
  if (known_gaps.tsp_account_add_lands_despite_refusal.state !== 'amber') red(`STOP: tsp_account_add_lands_despite_refusal is ${known_gaps.tsp_account_add_lands_despite_refusal.count}, not the known ${EXPECTED_LANDED}/${ADDS.length} (a re-pin note to SECURITY + RAILROAD: the setup job's add path now behaves differently)`)
  return { line: 'admin over TSP is refused with the guard on (expected)', pass: reasons.length === 0, reasons, findings, finding_for_security: findings.length > 0, known_gaps }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const [tspPath, dcPath, outPath] = process.argv.slice(2)
  if (!tspPath || !dcPath || !outPath) { console.error('usage: mediator-expect-red.mjs <acl-closed.json> <acl-closed-didcomm.json> <out.json>'); process.exit(2) }
  const v = evaluate(readResults(tspPath), readResults(dcPath))
  const t = readResults(tspPath).json
  v.tsp_statuses = t ? { update: t.setup?.admin_list?.update_status ?? null, update_problem: typeof t.setup?.admin_list?.update_problem === 'number' ? t.setup.admin_list.update_problem : null, readback: t.setup?.admin_list_readback_didcomm ? { answered: t.setup.admin_list_readback_didcomm.answered, status: t.setup.admin_list_readback_didcomm.status, problem: typeof t.setup.admin_list_readback_didcomm.problem === 'number' ? t.setup.admin_list_readback_didcomm.problem : null } : null, adds: ADDS.map((n) => t.setup?.['account_add_' + n]?.status ?? null) } : null
  writeFileSync(outPath, JSON.stringify(v, null, 2) + '\n')
  console.log(`${v.line}: ${v.pass ? 'PASS' : 'FAIL'}`)
  for (const [k, g] of Object.entries(v.known_gaps)) console.log(`  known gap ${k}: ${g.count} (${g.state === 'amber' ? 'AMBER, expected' : 'STOP'})`)
  for (const r of v.reasons) console.log('  - ' + r)
  if (v.finding_for_security) console.log('FINDING for SECURITY: ' + v.findings.join('; '))
  process.exit(v.pass ? 0 : 1)
}
