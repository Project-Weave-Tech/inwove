// The expect-red evaluator for "admin over TSP is refused with the guard on (expected)" (Security 12552 condition 6).
// Made-up results files only, shaped like mediator-acl.mjs writes them at the pin.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { evaluate, readResults } from '../sandbox/tsp-tests/mediator-expect-red.mjs';

const ok = (v) => ({ json: v });
const otherChecks = () => ({
  C1_unknown_did_cannot_sign_in: { pass: true },
  Z1_non_admin_account_add_refused: { pass: true },
  Z2_no_account_did_cannot_add: { pass: true },
  C4_denied_refused: { pass: true },
});
const refusedAdd = () => ({ status: 403, answerType: null, problem: 73, confirmed: false });
// The TSP run as runs 43800972273 / 43803025356 saw it, plus the read-back this change adds.
const tspRun = () => ({
  setup: {
    block_remote_admin_msgs: true, admin_transport: 'tsp', admin_sign_in: { ok: true, via: 'tsp' },
    admin_list: { update_status: 403, update_answer: null, update_problem: 73, list_status: 403, list_answer: null, list_problem: 73, accessListCount: null, mediator_listed: false, only_entry: false },
    admin_list_readback_didcomm: { sign_in_ok: true, status: 403, problem: 73, answered: false, answerType: null, accessListCount: null, mediator_listed: false },
    account_add_A: refusedAdd(), account_add_B: refusedAdd(), account_add_D: refusedAdd(),
    account_signs_in: { A: true, B: true, D: true },
  },
  checks: { ...otherChecks(), S2_admin_allow_list_is_mediator_only: { pass: false }, S2_adds_confirmed_under_closed_default: { pass: false } },
  pass: false, log_lines_with_redis_password: 0,
});
const dcRun = () => ({
  setup: { block_remote_admin_msgs: true, admin_transport: 'didcomm', admin_sign_in: { ok: true, via: 'didcomm' } },
  checks: { ...otherChecks(), S2_admin_allow_list_is_mediator_only: { pass: true }, S2_adds_confirmed_under_closed_default: { pass: true }, E1_enforce_unsigned_admin_write_refused: { pass: true } },
  pass: true, log_lines_with_redis_password: 0,
});

test('expect-red: refused as expected over TSP + DIDComm green → pass', () => {
  const v = evaluate(ok(tspRun()), ok(dcRun()));
  assert.deepEqual(v.reasons, []);
  assert.equal(v.pass, true);
  assert.equal(v.finding_for_security, false);
});

test('expect-red: read-back over DIDComm answered without the mediator → pass', () => {
  const t = tspRun();
  t.setup.admin_list_readback_didcomm = { sign_in_ok: true, status: 200, problem: null, answered: true, answerType: 'x#response', accessListCount: 0, mediator_listed: false };
  assert.equal(evaluate(ok(t), ok(dcRun())).pass, true);
});

test('expect-red: the TSP update accepted → red and a finding for Security', () => {
  const t = tspRun();
  t.setup.admin_list.update_status = 200; t.setup.admin_list.update_answer = 'https://trusttasks.org/spec/messaging/access-list/update/0.1#response';
  const v = evaluate(ok(t), ok(dcRun()));
  assert.equal(v.pass, false);
  assert.equal(v.finding_for_security, true);
});

test('expect-red: refused answer but the read-back shows the mediator listed (the write landed) → red and a finding', () => {
  const t = tspRun();
  t.setup.admin_list_readback_didcomm = { sign_in_ok: true, status: 200, problem: null, answered: true, answerType: 'x#response', accessListCount: 1, mediator_listed: true };
  const v = evaluate(ok(t), ok(dcRun()));
  assert.equal(v.pass, false);
  assert.equal(v.finding_for_security, true);
});

test('expect-red: an add confirmed by answer over TSP → red and a finding', () => {
  const t = tspRun();
  t.setup.account_add_B = { status: 200, answerType: 'x#response', problem: null, confirmed: true };
  const v = evaluate(ok(t), ok(dcRun()));
  assert.equal(v.pass, false);
  assert.equal(v.finding_for_security, true);
});

test('expect-red: TSP run crashed, missing or not JSON → red', () => {
  const crashed = { setup: { block_remote_admin_msgs: true, admin_transport: 'tsp', admin_sign_in: { ok: false } }, checks: {}, error: 'admin could not sign in' };
  for (const t of [ok(crashed), { missing: true }, { unparseable: true }, ok({ setup: tspRun().setup, checks: tspRun().checks })]) {
    const v = evaluate(t, ok(dcRun()));
    assert.equal(v.pass, false);
    assert.equal(v.finding_for_security, false);
  }
});

test('expect-red: a different code (5xx, 401, timeout-shaped null) at the update → red, not a finding', () => {
  for (const code of [500, 502, 401, 400, null]) {
    const t = tspRun(); t.setup.admin_list.update_status = code;
    const v = evaluate(ok(t), ok(dcRun()));
    assert.equal(v.pass, false, String(code));
    assert.equal(v.finding_for_security, false, String(code));
  }
});

test('expect-red: read-back can\'t tell (refused with another code, or no DIDComm sign-in) → red', () => {
  const a = tspRun(); a.setup.admin_list_readback_didcomm.problem = 37;
  const b = tspRun(); b.setup.admin_list_readback_didcomm.status = 500;
  const c = tspRun(); c.setup.admin_list_readback_didcomm = { sign_in_ok: false };
  const d = tspRun(); delete d.setup.admin_list_readback_didcomm;
  for (const t of [a, b, c, d]) assert.equal(evaluate(ok(t), ok(dcRun())).pass, false);
});

test('expect-red: DIDComm run red, missing, or an S2 line failing → red', () => {
  const a = dcRun(); a.pass = false;
  const b = dcRun(); b.checks.S2_adds_confirmed_under_closed_default.pass = false;
  const c = dcRun(); c.checks.S2_admin_allow_list_is_mediator_only.pass = false;
  for (const d of [ok(a), ok(b), ok(c), { missing: true }, { unparseable: true }]) assert.equal(evaluate(ok(tspRun()), d).pass, false);
});

test('expect-red: the guard flag or the transport missing in either file → red', () => {
  const a = tspRun(); delete a.setup.block_remote_admin_msgs;
  const b = dcRun(); b.setup.block_remote_admin_msgs = false;
  const c = tspRun(); c.setup.admin_transport = 'didcomm';
  const d = dcRun(); delete d.setup.admin_transport;
  assert.equal(evaluate(ok(a), ok(dcRun())).pass, false);
  assert.equal(evaluate(ok(tspRun()), ok(b)).pass, false);
  assert.equal(evaluate(ok(c), ok(dcRun())).pass, false);
  assert.equal(evaluate(ok(tspRun()), ok(d)).pass, false);
});

test('expect-red: a red non-admin check in the TSP run is not hidden by the expect-red', () => {
  const t = tspRun(); t.checks.Z1_non_admin_account_add_refused.pass = false;
  assert.equal(evaluate(ok(t), ok(dcRun())).pass, false);
  const u = tspRun(); u.log_lines_with_redis_password = 1;
  assert.equal(evaluate(ok(u), ok(dcRun())).pass, false);
});

test('expect-red: readResults marks a missing file and a non-JSON file', () => {
  const dir = mkdtempSync(join(tmpdir(), 'expred-'));
  try {
    writeFileSync(join(dir, 'bad.json'), '{not json');
    assert.deepEqual(readResults(join(dir, 'none.json')), { missing: true });
    assert.deepEqual(readResults(join(dir, 'bad.json')), { unparseable: true });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// Security 12672.1: the known-gap line, amber at 3/3, a STOP on any change.
test('expect-red 12672.1: 3 of 3 refused adds that still land is AMBER and does not change the verdict', () => {
  const v = evaluate(ok(tspRun()), ok(dcRun()));
  assert.equal(v.pass, true);
  assert.deepEqual(v.known_gaps.tsp_account_add_lands_despite_refusal, { count: '3/3', expected: '3/3', state: 'amber', note: v.known_gaps.tsp_account_add_lands_despite_refusal.note });
});
test('expect-red 12672.1: a changed count (upstream fixed, or only some land) is a STOP, red', () => {
  for (const signs of [{ A: false, B: false, D: false }, { A: true, B: false, D: true }]) {
    const t = tspRun(); t.setup.account_signs_in = signs;
    const v = evaluate(ok(t), ok(dcRun()));
    assert.equal(v.pass, false);
    assert.equal(v.known_gaps.tsp_account_add_lands_despite_refusal.state, 'STOP');
    assert.ok(v.reasons.some((r) => r.startsWith('STOP: tsp_account_add_lands_despite_refusal')));
  }
});
test('expect-red 12672.1: no sign-in record is a STOP, never amber', () => {
  const t = tspRun(); delete t.setup.account_signs_in;
  const v = evaluate(ok(t), ok(dcRun()));
  assert.equal(v.known_gaps.tsp_account_add_lands_despite_refusal.state, 'STOP');
  assert.equal(v.pass, false);
});
test('expect-red 12672.2: the DIDComm run must carry a passing E1 (unsigned admin write refused under enforce)', () => {
  for (const e1 of [undefined, { pass: false }]) {
    const d = dcRun(); if (e1) d.checks.E1_enforce_unsigned_admin_write_refused = e1; else delete d.checks.E1_enforce_unsigned_admin_write_refused;
    const v = evaluate(ok(tspRun()), ok(d));
    assert.equal(v.pass, false);
    assert.ok(v.reasons.some((r) => r.startsWith('didcomm: E1')));
  }
});
