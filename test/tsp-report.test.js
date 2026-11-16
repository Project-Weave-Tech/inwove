// Security 11910.5 + Emrys 11900: the report passes with only listed STOP lines red, fails on any unlisted red, on a
// listed STOP line missing from the written report, and on a missing or malformed list.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const REPORT = new URL('../sandbox/tsp-tests/report.mjs', import.meta.url).pathname;
const STOPS = new URL('../sandbox/tsp-tests/expected-red.json', import.meta.url).pathname;
const job = (name, pass) => ({ job: name, pass, rows: [{ what: `${name} line`, ok: pass }] });
function run(jobs, stops = STOPS) {
  const d = mkdtempSync(join(tmpdir(), 'rep-'));
  try {
    mkdirSync(join(d, 'results'));
    for (const j of jobs) writeFileSync(join(d, 'results', `${j.job}.json`), JSON.stringify(j));
    const r = spawnSync(process.execPath, [REPORT, join(d, 'results'), join(d, 'report.md'), stops], { encoding: 'utf8' });
    let md = ''; try { md = readFileSync(join(d, 'report.md'), 'utf8'); } catch {}
    return { code: r.status, md, err: r.stderr };
  } finally { rmSync(d, { recursive: true, force: true }); }
}
const built = ['audit', 'roundtrip', 'tamper', 'netwatch', 'vectors'];

test('report: today\'s shape (every built job green, the mediator line not built) passes, with its STOP line written', () => {
  const r = run(built.map((n) => job(n, true)));
  assert.equal(r.code, 0, r.err);
  assert.match(r.md, /- STOP: mediator-full-line · red as expected \(missing:mediator\)/);
  assert.match(r.md, /No unexpected red\./);
});

test('report: a red not on the list fails the run (a failed built job, or a required job with no results)', () => {
  const a = run(built.map((n) => job(n, n !== 'vectors')));
  assert.equal(a.code, 1);
  assert.match(a.md, /Unexpected red \(fails the run\):\*\* fail:vectors/);
  const b = run(built.filter((n) => n !== 'tamper').map((n) => job(n, true)));
  assert.equal(b.code, 1);
  assert.match(b.err, /unexpected red: missing:tamper/);
});

test('report: a listed line that goes green passes and says Security reads the run before the STOP line goes', () => {
  const r = run([...built, 'mediator'].map((n) => job(n, true)));
  assert.equal(r.code, 0, r.err);
  assert.match(r.md, /- STOP: mediator-full-line · GREEN on this run/);
});

test('report: a mediator job that ran and failed is not the listed red (missing), so it fails', () => {
  const r = run([...built.map((n) => job(n, true)), job('mediator', false)]);
  assert.equal(r.code, 1);
  assert.match(r.err, /unexpected red: fail:mediator/);
});

test('report: a missing, empty or malformed expected-red list fails loudly', () => {
  const d = mkdtempSync(join(tmpdir(), 'stops-'));
  try {
    assert.equal(run(built.map((n) => job(n, true)), join(d, 'absent.json')).code, 1);
    writeFileSync(join(d, 'bad.json'), JSON.stringify({ stops: [{ stop: 'x' }] }));
    assert.equal(run(built.map((n) => job(n, true)), join(d, 'bad.json')).code, 1);
    writeFileSync(join(d, 'none.json'), JSON.stringify({ stops: 'nope' }));
    assert.equal(run(built.map((n) => job(n, true)), join(d, 'none.json')).code, 1);
  } finally { rmSync(d, { recursive: true, force: true }); }
});
