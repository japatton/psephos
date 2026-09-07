import { test, before } from 'node:test';
import assert from 'node:assert';
import { mkdtempSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { openDb, initSchema } from '../store/db.js';
import { importPlan, listPlan } from '../store/plan.js';
import { readPlan, writePlan, addTaskFromBank, findTask } from '../store/plan-file.js';
import { getBankEntry } from '../store/bank.js';

/*
  Drawing from the bank copies; it never references. The copy is an ordinary
  plan task from the moment it lands — editable, assignable, and unable to
  change the bank by being edited. There is no sync and nothing to resolve,
  which is the whole reason the copy is a snapshot.

  It goes through the plan file rather than into plan_tasks, for the reason
  store/plan-file.js opens with: the file is the authority and the database is
  re-derived from it at every startup, so a row written straight into the
  database is a task that disappears on the next restart. The round trip below
  is the test for exactly that — mutate, write, re-import, read back.
*/

const PLAN = () => ({
  plan: { name: 'Bank Test', version: 'v1', period: 'week 1' },
  phases: [
    { key: 'P0', name: 'Prepare', intent: '', source: 'team', tasks: [] },
    { key: 'P1', name: 'Hunt', intent: '', source: 'team', tasks: [] },
  ],
});

let db, live;

const roundTrip = (mutate) => {
  const plan = readPlan(live);
  const out = mutate(plan);
  writePlan(plan, live);
  importPlan(db, live);
  return out;
};

before(() => {
  const dir = mkdtempSync(join(tmpdir(), 'bank-plan-'));
  live = join(dir, 'data', 'plan.json');
  mkdirSync(dirname(live), { recursive: true });
  writePlan(PLAN(), live);
  db = openDb(':memory:');
  initSchema(db);
  importPlan(db, live);
});

test('an authored entry lands as a plan task carrying its depth', () => {
  const entry = getBankEntry('T1053.005');
  const task = roundTrip(p => addTaskFromBank(p, entry, { phaseKey: 'P1', actor: 'Lindqvist' }));

  assert.ok(task.title.includes('Scheduled Task'), `unexpected title: ${task.title}`);
  assert.ok(task.steps.length > 0, 'authored steps did not survive the copy');
  assert.deepEqual(task.mitre, ['T1053.005']);
});

/*
  The assertion that makes the file path load-bearing: read it back out of the
  database after a re-import, which is what a restart does.
*/
test('the drawn task survives the re-import, and says where it came from', () => {
  const t = listPlan(db).find(x => x.mitre.includes('T1053.005'));
  assert.ok(t, 'the task did not survive importPlan — it was written to the database, not the file');
  assert.equal(t.source, 'bank');
  assert.equal(t.bankId, 'T1053.005');
  assert.equal(t.phaseKey, 'P1');
  assert.ok(t.steps.length > 0);
});

/*
  The distinction that matters at briefing time: a task naming a technique with
  nothing written under it is not the same as one somebody has thought about.
*/
test('a stub lands too, and is visibly empty of steps', () => {
  const stub = getBankEntry('T1595');
  assert.equal(stub.depth, null, 'pick a technique with no overlay for this test');
  const task = roundTrip(p => addTaskFromBank(p, stub, { phaseKey: 'P1', actor: 'Lindqvist' }));
  assert.deepEqual(task.steps, []);
  assert.equal(task.bankId, 'T1595');
  assert.equal(listPlan(db).find(x => x.bankId === 'T1595').stepsSource, 'standard-loop');
  // A stub has no authored data sources, but MITRE's own detection strategy
  // names the logs its analytics read — replacing detectionLogs() with () =>
  // [] would leave every other assertion here passing while a drawn stub
  // landed with nothing telling the analyst where to even look.
  assert.deepEqual(listPlan(db).find(x => x.bankId === 'T1595').dataSources, ['Network Traffic'],
    "a drawn stub should carry MITRE's own detection log sources, not an empty list");
});

/*
  Finding: a drawn stub used to fall back to entry.desc as its intent, so
  MITRE's own prose rendered in the slot everywhere else on this board holds an
  argument a human wrote about this engagement. intent must stay empty for a
  stub, and MITRE's description must travel separately, under its own name.
*/
test('a stub carries no invented intent, and keeps MITRE\'s wording separately labelled', () => {
  const stub = getBankEntry('T1595');
  const task = roundTrip(p => addTaskFromBank(p, stub, { phaseKey: 'P1', actor: 'Lindqvist' }));
  assert.equal(task.intent, '', "a stub has nothing authored to say — MITRE's prose must not fill this in");
  assert.equal(task.bankDesc, stub.desc, "MITRE's own description should still travel, just not as intent");
  const landed = listPlan(db).find(x => x.taskKey === task.key);
  assert.equal(landed.intent, '');
  assert.equal(landed.bankDesc, stub.desc, 'bankDesc did not survive the re-import');
});

/*
  A different authored entry than T1053.005: that id is used below to test
  drawing the same technique twice, and this test must not add a third draw of
  it to the shared plan and throw off that count.
*/
test('an authored entry keeps its own intent and carries no separate bank description', () => {
  const entry = getBankEntry('PRAC-deconfliction');
  assert.ok(entry.depth?.intent, 'pick an authored entry for this test');
  const task = roundTrip(p => addTaskFromBank(p, entry, { phaseKey: 'P1', actor: 'Lindqvist' }));
  assert.equal(task.intent, entry.depth.intent);
  assert.equal(task.bankDesc, null);
  assert.equal(listPlan(db).find(x => x.taskKey === task.key).bankDesc, null);
});

test('editing the copy cannot change the bank', () => {
  const before = JSON.stringify(getBankEntry('T1053.005'));
  const key = listPlan(db).find(x => x.bankId === 'T1053.005').taskKey;
  roundTrip((p) => { findTask(p, key).intent = 'rewritten by hand'; });
  assert.equal(JSON.stringify(getBankEntry('T1053.005')), before,
    'editing a drawn task reached back into the bank');
  assert.equal(listPlan(db).find(x => x.taskKey === key).intent, 'rewritten by hand');
});

test('a practice entry lands with no MITRE id', () => {
  const e = getBankEntry('PRAC-telemetry-coverage');
  const task = roundTrip(p => addTaskFromBank(p, e, { phaseKey: 'P0', actor: 'Reyes' }));
  assert.deepEqual(task.mitre, []);
  assert.equal(task.bankId, 'PRAC-telemetry-coverage');
  assert.ok(task.steps.length > 0);
});

/*
  addTask throws on a duplicate key, and the same technique can legitimately be
  hunted twice — different terrain, different phase.
*/
test('the same entry drawn twice does not collide', () => {
  const e = getBankEntry('T1053.005');
  const second = roundTrip(p => addTaskFromBank(p, e, { phaseKey: 'P0', actor: 'Okafor' }));
  const drawn = listPlan(db).filter(t => t.bankId === 'T1053.005');
  assert.equal(drawn.length, 2);
  assert.equal(new Set(drawn.map(t => t.taskKey)).size, 2, 'the second copy reused the first key');
  // addTaskFromBank's return value has no phaseKey of its own — key is the
  // only field naming the task — so the phase it actually landed in can only
  // be checked by reading it back through listPlan, where phaseKey exists.
  const landed = listPlan(db).find(t => t.taskKey === second.key);
  assert.ok(landed, 'the second copy did not survive the round trip');
  assert.equal(landed.phaseKey, 'P0', 'the second copy did not land in the phase it was drawn into');
});

test('drawing into a phase that does not exist is refused, not silently placed', () => {
  assert.throws(
    () => roundTrip(p => addTaskFromBank(p, getBankEntry('T1595'), { phaseKey: 'NOPE' })),
    /no such phase/);
});

/*
  Provenance travels with the copy.

  A drafted entry drawn into the plan becomes a task carrying steps, and at
  briefing time that is indistinguishable from one somebody wrote and stood
  behind — which is the whole failure the bank's two tiers exist to prevent,
  relocated one table over. The plan file carries it so the badge can say so
  weeks later, when nothing else can.
*/
test('a drawn task records whether its depth was authored or drafted', () => {
  const authoredTask = roundTrip(p =>
    addTaskFromBank(p, getBankEntry('T1053.005'), { phaseKey: 'P1', actor: 'Reyes' }));
  assert.equal(authoredTask.bankProvenance, 'authored');
  assert.equal(listPlan(db).find(t => t.taskKey === authoredTask.key).bankProvenance, 'authored',
    'provenance did not survive the re-import');
});

test('a stub carries no provenance, because there is no depth to stand behind', () => {
  const t = roundTrip(p =>
    addTaskFromBank(p, getBankEntry('T1595'), { phaseKey: 'P1', actor: 'Reyes' }));
  assert.equal(t.bankProvenance, null);
});
