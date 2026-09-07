import { test } from 'node:test';
import assert from 'node:assert';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, readdirSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';

import { openDb, initSchema } from '../store/db.js';
import { importPlan, listPlan, getTask, setTaskStatus, setAssignees, listTaskEvents } from '../store/plan.js';
import {
  ensureLivePlan, readPlan, writePlan, addTask, editTask, addPhase, editPhase,
  findTask, findPhase, slugKey, phaseKeyOf,
} from '../store/plan-file.js';

const scratch = () => mkdtempSync(join(tmpdir(), 'hunt-plan-'));

const PLAN = () => ({
  plan: { name: 'Test Plan', version: 'v1', period: 'week 1' },
  phases: [
    {
      key: 'P1', name: 'Baselining', intent: 'know normal', source: 'team',
      tasks: [{
        key: 'P1-accounts', title: 'Validate accounts', source: 'team',
        intent: 'baseline admins', priority: 'normal', team: 'Bravo',
        mitre: ['T1078'], tools: ['PowerShell'], dataSources: [], commands: [],
        terrain: [], references: [], steps: [{ text: 'enumerate', tooling: 'LDAP', expect: 'short list' }],
        evidenceExpected: 'a list', analysis: '', doNext: '', original: null, assignees: [],
      }],
    },
    { key: 'M2', name: 'Hunt', intent: '', source: 'expanded', tasks: [] },
  ],
});

const withPlan = () => {
  const dir = scratch();
  const path = join(dir, 'plan.json');
  writeFileSync(path, JSON.stringify(PLAN(), null, 2));
  return path;
};

// --- pure mutators ----------------------------------------------------------

test('a new task is keyed from its title and marked local', () => {
  const plan = PLAN();
  const t = addTask(plan, { phaseKey: 'M2', title: 'Kerberoast sweep on Enclave A', actor: 'Okafor' });
  assert.equal(t.key, 'LOCAL-kerberoast-sweep-on-enclave-a');
  assert.equal(t.source, 'local');
  assert.equal(t.createdBy, 'Okafor');
  assert.equal(findPhase(plan, 'M2').tasks.length, 1);
});

test('a duplicate title gets a distinct key rather than colliding', () => {
  const plan = PLAN();
  addTask(plan, { phaseKey: 'M2', title: 'Sweep' });
  const b = addTask(plan, { phaseKey: 'M2', title: 'Sweep' });
  assert.equal(b.key, 'LOCAL-sweep-2', 'task_key is UNIQUE; a second Sweep must not reuse the key');
});

test('an explicit key that is already taken is refused', () => {
  const plan = PLAN();
  assert.throws(() => addTask(plan, { phaseKey: 'M2', title: 'x', key: 'P1-accounts' }), /already in use/);
});

test('a task needs a title and a real phase', () => {
  const plan = PLAN();
  assert.throws(() => addTask(plan, { phaseKey: 'M2', title: '   ' }), /needs a title/);
  assert.throws(() => addTask(plan, { phaseKey: 'NOPE', title: 'x' }), /no such phase/);
});

test('a title with no usable characters cannot be keyed', () => {
  const plan = PLAN();
  assert.throws(() => addTask(plan, { phaseKey: 'M2', title: '!!!' }), /could not derive a key/);
});

test('editing changes fields and stamps who did it', () => {
  const plan = PLAN();
  const t = editTask(plan, 'P1-accounts', { title: 'Validate admin accounts', priority: 'high', actor: 'Lindqvist' });
  assert.equal(t.title, 'Validate admin accounts');
  assert.equal(t.priority, 'high');
  assert.equal(t.editedBy, 'Lindqvist');
  assert.match(t.editedAt, /^\d{4}-\d{2}-\d{2}T/);
});

test('a task key cannot be changed', () => {
  const plan = PLAN();
  assert.throws(() => editTask(plan, 'P1-accounts', { key: 'something-else' }), /cannot be changed/);
  // Passing the same key is a no-op, not an error.
  assert.doesNotThrow(() => editTask(plan, 'P1-accounts', { key: 'P1-accounts', title: 'ok' }));
});

test('an edit cannot blank the title', () => {
  const plan = PLAN();
  assert.throws(() => editTask(plan, 'P1-accounts', { title: '  ' }), /needs a title/);
});

test('changing the phase moves the task rather than copying it', () => {
  const plan = PLAN();
  editTask(plan, 'P1-accounts', { phaseKey: 'M2' });
  assert.equal(phaseKeyOf(plan, 'P1-accounts'), 'M2');
  assert.equal(findPhase(plan, 'P1').tasks.length, 0);
  assert.equal(findPhase(plan, 'M2').tasks.length, 1);
});

test('steps are normalised and blank ones dropped', () => {
  const plan = PLAN();
  const t = editTask(plan, 'P1-accounts', {
    steps: [{ text: 'one', tooling: 'Kibana' }, { text: '  ' }, { text: 'two', expect: 'clean' }],
  });
  assert.equal(t.steps.length, 2);
  assert.deepEqual(t.steps.map(s => s.text), ['one', 'two']);
  assert.equal(t.steps[0].expect, '', 'missing fields become empty strings, not undefined');
  assert.equal(t.stepsSource, 'authored');
});

test('a task with no steps is marked as following the standard loop', () => {
  const plan = PLAN();
  const t = editTask(plan, 'P1-accounts', { steps: [] });
  assert.equal(t.stepsSource, 'standard-loop');
});

test('an unknown priority falls back rather than being stored', () => {
  const plan = PLAN();
  assert.equal(editTask(plan, 'P1-accounts', { priority: 'catastrophic' }).priority, 'normal');
});

test('phases can be added and edited, and keys are validated', () => {
  const plan = PLAN();
  const p = addPhase(plan, { key: 'M5', name: 'Thread E', intent: 'OT pivot', actor: 'Reyes' });
  assert.equal(p.source, 'local');
  assert.deepEqual(p.tasks, []);
  assert.throws(() => addPhase(plan, { key: 'M5', name: 'dup' }), /already in use/);
  assert.throws(() => addPhase(plan, { key: 'bad key!', name: 'x' }), /may only contain/);
  assert.throws(() => addPhase(plan, { key: 'M6', name: ' ' }), /needs a name/);

  editPhase(plan, 'M5', { name: 'Thread E · OT pivot', intent: 'MOE1 …', actor: 'Reyes' });
  assert.equal(findPhase(plan, 'M5').name, 'Thread E · OT pivot');
});

test('slugKey refuses to collide with an existing key', () => {
  const plan = PLAN();
  addTask(plan, { phaseKey: 'M2', title: 'Sweep' });
  assert.equal(slugKey('Sweep', plan), 'LOCAL-sweep-2');
});

// --- file layer -------------------------------------------------------------

test('the live plan is seeded once and never overwritten afterwards', () => {
  const dir = scratch();
  const seed = join(dir, 'seed.json');
  const live = join(dir, 'data', 'plan.json');
  writeFileSync(seed, JSON.stringify(PLAN(), null, 2));

  assert.equal(ensureLivePlan(live, seed).seeded, true);
  assert.ok(existsSync(live));

  // Simulate a week of team edits, then restart.
  const edited = readPlan(live);
  addTask(edited, { phaseKey: 'M2', title: 'Team authored this' });
  writePlan(edited, live);

  assert.equal(ensureLivePlan(live, seed).seeded, false, 'a second start must not re-seed');
  assert.ok(findTask(readPlan(live), 'LOCAL-team-authored-this'), 'the team edit survived');
});

test('seeding fails loudly when there is no seed to copy', () => {
  const dir = scratch();
  assert.throws(() => ensureLivePlan(join(dir, 'plan.json'), join(dir, 'missing.json')), /no plan to seed from/);
});

test('a write is atomic and leaves no temp file behind', () => {
  const path = withPlan();
  const plan = readPlan(path);
  addTask(plan, { phaseKey: 'M2', title: 'atomic' });
  writePlan(plan, path);
  assert.ok(!existsSync(`${path}.tmp`), 'the temp file must be renamed away, not left');
  assert.ok(findTask(readPlan(path), 'LOCAL-atomic'));
});

test('an unserialisable plan throws before the existing file is touched', () => {
  const path = withPlan();
  const before = readFileSync(path, 'utf8');
  const plan = readPlan(path);
  plan.self = plan;                       // circular; JSON.stringify throws
  assert.throws(() => writePlan(plan, path));
  assert.equal(readFileSync(path, 'utf8'), before, 'the good plan must survive a failed write');
});

test('each write backs the previous plan up, and backups are pruned to 20', () => {
  const path = withPlan();
  for (let i = 0; i < 25; i++) {
    const plan = readPlan(path);
    addTask(plan, { phaseKey: 'M2', title: `task ${i}` });
    writePlan(plan, path);
  }
  const backups = readdirSync(join(dirname(path), 'plan-backups'));
  assert.ok(backups.length <= 20, `expected at most 20 backups, found ${backups.length}`);
  assert.ok(backups.length >= 19, 'backups should actually be written');
});

// --- round trip through the database ----------------------------------------

test('an edit survives the write and re-import that follows it', () => {
  const path = withPlan();
  const db = openDb(':memory:'); initSchema(db);
  importPlan(db, path);

  const plan = readPlan(path);
  editTask(plan, 'P1-accounts', {
    title: 'Validate admin accounts', priority: 'high',
    mitre: ['T1078', 'T1110.003'], commands: ['Get-ADUser -Filter *'],
    steps: [{ text: 'enumerate', tooling: 'LDAP', expect: 'short list' },
      { text: 'diff against baseline', tooling: 'PowerShell', expect: 'no drift' }],
    actor: 'Lindqvist',
  });
  writePlan(plan, path);
  importPlan(db, path);

  const t = getTask(db, 'P1-accounts');
  assert.equal(t.title, 'Validate admin accounts');
  assert.equal(t.priority, 'high');
  assert.deepEqual(t.mitre, ['T1078', 'T1110.003']);
  assert.deepEqual(t.commands, ['Get-ADUser -Filter *']);
  assert.equal(t.steps.length, 2);
  assert.equal(t.editedBy, 'Lindqvist');
});

test('a locally authored task reaches the database as source local', () => {
  const path = withPlan();
  const db = openDb(':memory:'); initSchema(db);
  const plan = readPlan(path);
  addTask(plan, { phaseKey: 'M2', title: 'Kerberoast sweep', actor: 'Okafor', priority: 'high', team: 'Bravo' });
  writePlan(plan, path);
  importPlan(db, path);

  const t = getTask(db, 'LOCAL-kerberoast-sweep');
  assert.equal(t.source, 'local');
  assert.equal(t.createdBy, 'Okafor');
  assert.equal(t.priority, 'high');
  assert.equal(t.phaseKey, 'M2');
});

/*
  The invariant the whole design rests on. Editing the plan re-imports it, and
  re-importing deletes and rebuilds plan_tasks -- so if progress were stored
  there, every edit would silently reset the team's week.
*/
test('completions, assignments and history survive editing the plan', () => {
  const path = withPlan();
  const db = openDb(':memory:'); initSchema(db);
  importPlan(db, path);

  setTaskStatus(db, 'P1-accounts', 'complete', 'Baptiste', 'admins baselined');
  setAssignees(db, 'P1-accounts', ['Lindqvist', 'Baptiste'], 'Okafor');
  const eventsBefore = listTaskEvents(db, 'P1-accounts').length;

  const plan = readPlan(path);
  editTask(plan, 'P1-accounts', { title: 'Renamed after the fact', actor: 'Reyes' });
  addTask(plan, { phaseKey: 'M2', title: 'And a new one', actor: 'Reyes' });
  writePlan(plan, path);
  importPlan(db, path);

  const t = getTask(db, 'P1-accounts');
  assert.equal(t.status, 'complete', 'completion must survive');
  assert.equal(t.changedBy, 'Baptiste');
  assert.deepEqual(t.assignees, ['Baptiste', 'Lindqvist'], 'assignments must survive');
  assert.equal(listTaskEvents(db, 'P1-accounts').length, eventsBefore, 'history must survive');
  assert.equal(t.title, 'Renamed after the fact');
  assert.equal(listPlan(db).length, 2);
});

test('a new phase created alongside a task shows up in the board', () => {
  const path = withPlan();
  const db = openDb(':memory:'); initSchema(db);
  const plan = readPlan(path);
  addPhase(plan, { key: 'M5', name: 'Thread E', intent: 'OT pivot', actor: 'Reyes' });
  addTask(plan, { phaseKey: 'M5', title: 'Pivot check', actor: 'Reyes' });
  writePlan(plan, path);
  importPlan(db, path);

  const t = getTask(db, 'LOCAL-pivot-check');
  assert.equal(t.phaseKey, 'M5');
  assert.equal(t.phaseName, 'Thread E');
  assert.equal(t.phaseIntent, 'OT pivot');
});
