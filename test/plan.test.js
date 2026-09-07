import { test } from 'node:test';
import assert from 'node:assert';
import { openDb, initSchema } from '../store/db.js';
import {
  importPlan, listPlan, getTask, setTaskStatus, setAssignees,
  listTaskEvents, listRecentEvents, planSummary,
} from '../store/plan.js';

const fresh = () => { const db = openDb(':memory:'); initSchema(db); importPlan(db); return db; };

test('the profile plan imports with its phases and tasks', () => {
  const rows = listPlan(fresh());
  assert.ok(rows.length > 0, 'a plan that imports nothing is a broken profile');
  assert.ok(rows.every(r => r.taskKey && r.title), 'every task has a key and a title');
  assert.ok(new Set(rows.map(r => r.phaseKey)).size > 0, 'and lands in a phase');
});

test('a task keeps whatever the source said, verbatim', () => {
  // Expansion must never paraphrase what a team wrote. Where a task carries an
  // original row, it survives the import untouched.
  const withOriginal = listPlan(fresh()).filter(r => r.original);
  for (const t of withOriginal) assert.equal(typeof t.original, 'object');
});

test('every task carries steps', () => {
  assert.ok(listPlan(fresh()).every(t => t.steps.length > 0));
});

test('a task can be completed and reset by anyone', () => {
  const db = fresh();
  const key = listPlan(db)[0].taskKey;
  assert.equal(getTask(db, key).status, 'pending');

  setTaskStatus(db, key, 'complete', 'Lindqvist');
  assert.equal(getTask(db, key).status, 'complete');
  assert.equal(getTask(db, key).changedBy, 'Lindqvist');

  // No guard: a different member resets it.
  setTaskStatus(db, key, 'pending', 'Okafor');
  assert.equal(getTask(db, key).status, 'pending');
});

test('a reset is recorded as a reset, not just a status change', () => {
  const db = fresh();
  const key = listPlan(db)[0].taskKey;
  setTaskStatus(db, key, 'complete', 'Lindqvist');
  setTaskStatus(db, key, 'pending', 'Okafor');
  const actions = listTaskEvents(db, key).map(e => e.action);
  assert.ok(actions.includes('reset'), `expected a reset event, got ${actions}`);
  assert.ok(actions.includes('status:complete'));
});

test('history persists and is ordered newest first', () => {
  const db = fresh();
  const key = listPlan(db)[0].taskKey;
  setTaskStatus(db, key, 'in-progress', 'Lindqvist');
  setTaskStatus(db, key, 'complete', 'Lindqvist');
  setTaskStatus(db, key, 'pending', 'Okafor');
  const ev = listTaskEvents(db, key);
  assert.equal(ev.length, 3);
  assert.equal(ev[0].actor, 'Okafor', 'newest first');
  assert.ok(ev.every(e => e.ts), 'every event is timestamped');
});

test('assignment is recorded with what it changed from', () => {
  const db = fresh();
  // Any task will do; the point is what the event records, not which phase.
  const key = listPlan(db)[0].taskKey;
  setAssignees(db, key, ['Baptiste', 'Lindqvist'], 'Reyes');
  assert.deepEqual(getTask(db, key).assignees, ['Baptiste', 'Lindqvist']);

  setAssignees(db, key, ['Baptiste'], 'Reyes');
  assert.deepEqual(getTask(db, key).assignees, ['Baptiste']);
  const ev = listTaskEvents(db, key).find(e => e.action === 'assign');
  const d = JSON.parse(ev.detail);
  assert.deepEqual(d.to, ['Baptiste']);
});

test('re-importing a revised plan keeps progress and history', () => {
  // The whole point of separating plan content from task state.
  const db = fresh();
  const key = listPlan(db)[0].taskKey;
  setTaskStatus(db, key, 'complete', 'Lindqvist');
  setAssignees(db, key, ['Baptiste'], 'Okafor');

  importPlan(db);

  const t = getTask(db, key);
  assert.equal(t.status, 'complete', 'completion survives a re-import');
  assert.deepEqual(t.assignees, ['Baptiste'], 'assignment survives');
  assert.ok(listTaskEvents(db, key).length >= 2, 'history survives');
});

test('an unknown status or task is refused', () => {
  const db = fresh();
  const key = listPlan(db)[0].taskKey;
  assert.throws(() => setTaskStatus(db, key, 'donezo', 'Lindqvist'));
  assert.throws(() => setTaskStatus(db, 'no-such-task', 'complete', 'Lindqvist'));
});

test('the summary reports what leaders need', () => {
  const db = fresh();
  const rows = listPlan(db);
  setTaskStatus(db, rows[0].taskKey, 'complete', 'Lindqvist');
  const s = planSummary(db);
  assert.equal(s.total, rows.length);
  assert.equal(s.byStatus.complete, 1);
  assert.ok(s.unassigned > 0);
  assert.ok(listRecentEvents(db).length >= 1);
});

/*
  Assignment is a delete followed by inserts, which is the shape importPlan
  wraps in a transaction and explains at length: a value the driver cannot bind
  throws partway down the loop, and by then the delete has committed. The task
  is left assigned to whoever happened to come before the bad value, with
  nothing to say the others were ever on it.
*/
test('a bad name in an assignment leaves the previous one intact', () => {
  const db = fresh();
  const key = listPlan(db)[0].taskKey;
  setAssignees(db, key, ['Reyes', 'Okafor'], 'Lindqvist');
  const before = listPlan(db).find(t => t.taskKey === key).assignees;
  assert.deepEqual(before, ['Okafor', 'Reyes']);

  assert.throws(() => setAssignees(db, key, ['Baptiste', { bad: 1 }, 'Reyes'], 'Lindqvist'));

  assert.deepEqual(listPlan(db).find(t => t.taskKey === key).assignees, before,
    'a failed assignment must leave the task as it was, not half-rewritten');
});
