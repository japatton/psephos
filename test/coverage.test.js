import { test, before } from 'node:test';
import assert from 'node:assert';
import { mkdtempSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { openDb, initSchema } from '../store/db.js';
import { importPlan, listPlan } from '../store/plan.js';
import { readPlan, writePlan, addTaskFromBank, addTask } from '../store/plan-file.js';
import { getBankEntry, listBank } from '../store/bank.js';
import { planCoverage } from '../store/coverage.js';

/*
  Coverage of intent, not of findings.

  The Navigator export already shows which techniques the case file has evidence
  for — what was discovered. This shows which ones the plan set out to look for,
  and the gap between the two is the useful thing. Conflating them would make a
  plan look thorough because a hunt went well.
*/

let db, live;

/** Draw through the file and re-derive the database, as the server does. */
const draw = (id, phaseKey = 'P1') => {
  const plan = readPlan(live);
  addTaskFromBank(plan, getBankEntry(id), { phaseKey, actor: 'test' });
  writePlan(plan, live);
  importPlan(db, live);
};

before(() => {
  const dir = mkdtempSync(join(tmpdir(), 'coverage-'));
  live = join(dir, 'data', 'plan.json');
  mkdirSync(dirname(live), { recursive: true });
  writePlan({
    plan: { name: 'Coverage Test', version: 'v1', period: 'week 1' },
    phases: [{ key: 'P1', name: 'Hunt', intent: '', source: 'team', tasks: [] }],
  }, live);
  db = openDb(':memory:');
  initSchema(db);
  importPlan(db, live);
});

const stateOf = (cov, id) => {
  for (const t of cov.tactics) {
    const hit = t.techniques.find(x => x.id === id);
    if (hit) return hit.state;
  }
  return null;
};

/*
  A fresh db+plan per test, rather than the shared one above, because these
  tests care about the exact order two tasks naming the same technique land
  in — and the shared db already has T1053.005 authored by the time these
  run. planCoverage walks listPlan(db) in `ord`, i.e. file order, so which
  task is written first is which task the guard has to protect.
*/
const freshCoverage = () => {
  const dir = mkdtempSync(join(tmpdir(), 'coverage-order-'));
  const path = join(dir, 'data', 'plan.json');
  mkdirSync(dirname(path), { recursive: true });
  writePlan({
    plan: { name: 'Order Test', version: 'v1', period: 'week 1' },
    phases: [{ key: 'P1', name: 'Hunt', intent: '', source: 'team', tasks: [] }],
  }, path);
  const d = openDb(':memory:');
  initSchema(d);
  importPlan(d, path);
  return { db: d, path };
};

const drawBank = (db, path, id, phaseKey = 'P1') => {
  const plan = readPlan(path);
  addTaskFromBank(plan, getBankEntry(id), { phaseKey, actor: 'test' });
  writePlan(plan, path);
  importPlan(db, path);
};

/** A plain task naming a technique, with no steps — a stub the bank did not draw. */
const drawNamedStub = (db, path, id, phaseKey = 'P1') => {
  const plan = readPlan(path);
  addTask(plan, { phaseKey, title: `${id} named without depth`, mitre: [id] });
  writePlan(plan, path);
  importPlan(db, path);
};

test('a technique no task names is uncovered', () => {
  const cov = planCoverage(db, 'enterprise');
  assert.equal(stateOf(cov, 'T1053.005'), 'none');
});

test('a stub drawn into the plan is named but not authored', () => {
  draw('T1595');   // no overlay, so the drawn task has no steps
  const cov = planCoverage(db, 'enterprise');
  assert.equal(stateOf(cov, 'T1595'), 'named');
});

test('a task carrying steps counts as authored', () => {
  draw('T1053.005');
  const cov = planCoverage(db, 'enterprise');
  assert.equal(stateOf(cov, 'T1053.005'), 'authored');
});

/*
  T1053.005 is the only technique plans/bank/enterprise.mjs authors depth for,
  so it is the only id that can produce both an authored task and a named-only
  stub without inventing a second overlay just to make this test possible.
*/
test('a stub named after an authored task does not downgrade it', () => {
  const { db: d, path } = freshCoverage();
  drawBank(d, path, 'T1053.005');       // authored, written first
  drawNamedStub(d, path, 'T1053.005');  // named, written second, same id

  const cov = planCoverage(d, 'enterprise');
  assert.equal(stateOf(cov, 'T1053.005'), 'authored',
    'a stub naming an already-authored technique must not erase the authored task');
});

test('an authored task drawn after a stub still ends authored', () => {
  const { db: d, path } = freshCoverage();
  drawNamedStub(d, path, 'T1053.005');  // named, written first
  drawBank(d, path, 'T1053.005');       // authored, written second, same id

  const cov = planCoverage(d, 'enterprise');
  assert.equal(stateOf(cov, 'T1053.005'), 'authored');
});

/*
  The plan view badges a task from its stepsSource; the coverage grid decides
  the same thing for itself. Both now ask stepsSourceOf(), and this is what
  says so: a task the plan calls authored must colour its techniques authored,
  and one the plan calls standard-loop must leave them merely named. Divergence
  here is not a crash — it is a briefing that says a technique is written up
  next to a plan page that says it is not.
*/
test('coverage grades a task the same way the plan view labels it', () => {
  const { db: d, path } = freshCoverage();
  drawBank(d, path, 'T1053.005');    // the one enterprise overlay with steps
  drawNamedStub(d, path, 'T1595');   // named, no procedure under it

  const cov = planCoverage(d, 'enterprise');
  const tasks = listPlan(d).filter(t => (t.mitre ?? []).length);
  assert.equal(tasks.length, 2, 'both fixtures should have landed');
  for (const t of tasks) {
    const expected = t.stepsSource === 'authored' ? 'authored' : 'named';
    for (const id of t.mitre) {
      assert.equal(stateOf(cov, id), expected,
        `${t.taskKey} is labelled ${t.stepsSource} but ${id} grades ${stateOf(cov, id)}`);
    }
  }
});

test('the matrix version travels with the coverage', () => {
  const cov = planCoverage(db, 'enterprise');
  assert.ok(cov.version, 'a plan built against one ATT&CK release should say which');
  assert.equal(cov.domain, 'enterprise');
});

test('counts add up to the whole matrix, and every technique lands once per tactic it declares', () => {
  const cov = planCoverage(db, 'enterprise');
  const total = cov.counts.none + cov.counts.named + cov.counts.authored;
  const inGrid = cov.tactics.reduce((n, t) => n + t.techniques.length, 0);
  const entries = listBank({ domain: 'enterprise' });
  // One row per technique in the matrix — a broken domain filter changes this.
  assert.equal(total, entries.length);
  /*
    A technique in two tactics appears twice in the grid and once in the
    counts, so inGrid is not merely bounded below by total — it is fixed by
    the fan-out: once per tactic declared, or once under "(no tactic)" for a
    technique that declares none. `assert.ok(inGrid >= total)` passed under
    any fan-out at all, including one that dropped every second tactic.
  */
  const expectedInGrid = entries.reduce((n, e) => n + Math.max(e.tactics.length, 1), 0);
  assert.equal(inGrid, expectedInGrid);
});

/*
  "come back in a stable order" used to mean "two calls in one process return
  the same thing" — true of literally any deterministic function, including
  one with no sort at all. What actually has to hold is the specific order
  coverage.js promises: tactics alphabetically, and techniques within a tactic
  by id. Deleting either .sort() left all 8 tests in this file passing before
  this rewrite.
*/
test('tactics come back sorted alphabetically', () => {
  const tactics = planCoverage(db, 'enterprise').tactics.map(t => t.tactic);
  assert.deepEqual(tactics, [...tactics].sort((a, b) => a.localeCompare(b)));
});

test('techniques within a tactic come back sorted by id', () => {
  const { tactics } = planCoverage(db, 'enterprise');
  for (const t of tactics) {
    const ids = t.techniques.map(x => x.id);
    assert.deepEqual(ids, [...ids].sort((a, b) => a.localeCompare(b)),
      `${t.tactic} techniques are not sorted by id`);
  }
});

/*
  A plan id that matches no live technique.

  Found by authoring the ICS overlays: this repository's own plan files named
  T0855, T0812, T0857, T1070.001 and T1562.002, all revoked into the T16xx
  series. They are migrated now, so T0855 survives here as a fixture — a
  genuinely dead id, which is what this test needs.
  A task naming one of them contributes nothing to any state and appears in no
  cell, so the plan claims ground the matrix cannot show and nothing says so —
  the same silent loss orphanOverlays() exists to prevent, one file over.

  Reported rather than dropped, and reported per plan rather than per domain: an
  Enterprise id is not an orphan because you are looking at the ICS matrix.
*/

const namePlain = (ids) => {
  const plan = readPlan(live);
  addTask(plan, { phaseKey: 'P1', title: `names ${ids.join(', ')}`, mitre: ids });
  writePlan(plan, live);
  importPlan(db, live);
};

test('a plan id that matches no live technique is reported, not swallowed', () => {
  namePlain(['T0855', 'T1053.005']);   // T0855 revoked upstream; T1053.005 live
  const cov = planCoverage(db, 'enterprise');
  assert.deepEqual(cov.orphans, ['T0855'],
    'a revoked id named by the plan went unreported');
});

test('the orphan list does not confuse the other matrix for a dead id', () => {
  namePlain(['T0842']);   // a live ICS id, seen while looking at Enterprise
  assert.ok(!planCoverage(db, 'enterprise').orphans.includes('T0842'),
    'an ICS id was called dead because Enterprise was on screen');
  assert.ok(!planCoverage(db, 'ics').orphans.includes('T1053.005'),
    'an Enterprise id was called dead because ICS was on screen');
});

test('a plan naming only live techniques reports no orphans', () => {
  const clean = openDb(':memory:');
  initSchema(clean);
  assert.deepEqual(planCoverage(clean, 'enterprise').orphans, []);
});
