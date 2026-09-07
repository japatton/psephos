import { readFileSync, existsSync } from 'node:fs';
import { nowIso } from '../lib/ids.js';
import { seedPlanPath } from './plan-file.js';
import { notify } from './notifications.js';

const j = (v) => (v == null ? null : JSON.stringify(v));
const unj = (v, fallback) => { try { return v ? JSON.parse(v) : fallback; } catch { return fallback; } };

/**
 * Load a plan file into the store.
 *
 * plan_tasks is replaced wholesale, because the uploaded file is the authority
 * on what the tasks are. task_state, task_assignees and task_events are never
 * touched: a revised plan must not erase what the team has already completed,
 * and the history has to outlive any number of plan versions.
 *
 * A task removed from the plan keeps its state and history rows. They are
 * inert while the task is absent and reattach if it comes back, which is the
 * behaviour you want when someone re-uploads a plan with a typo fixed.
 */
/*
  Defaults to the profile's plan, not the live copy. A default of "whatever
  this machine happens to have edited" made the test suite pass here and fail
  on a fresh clone. The server passes LIVE_PLAN explicitly.
*/
export function importPlan(db, path = seedPlanPath()) {
  if (!existsSync(path)) return { imported: 0, version: null };
  const doc = JSON.parse(readFileSync(path, 'utf8').replace(/^﻿/, ''));
  const version = doc.plan?.version ?? 'unversioned';

  const ins = db.prepare(`insert into plan_tasks
    (id, plan_version, phase_key, phase_name, phase_intent, phase_source,
     task_key, title, intent, source, steps_source, priority, team,
     mitre, tools, data_sources, commands, terrain, refs,
     evidence_expected, analysis, do_next, steps, original, ord,
     created_by, created_at, edited_by, edited_at, bank_id, bank_desc, bank_provenance)
    values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);

  /*
    The delete and the inserts are one unit of work. task_key is NOT NULL
    UNIQUE and title is NOT NULL, so a plan that repeats a key across phases —
    easy when each phase numbers its own tasks T1, T2 — used to commit the
    delete and then throw partway through the reload, leaving a half-written
    plan and no way back to the old one.
  */
  let ord = 0;
  db.exec('begin');
  try {
    db.exec('delete from plan_tasks');
    for (const ph of doc.phases ?? []) {
      for (const t of ph.tasks ?? []) {
        ins.run(
          `${version}:${t.key}`, version, ph.key, ph.name, ph.intent ?? '', ph.source ?? 'team',
          t.key, t.title, t.intent ?? '', t.source ?? 'team', t.stepsSource ?? '',
          t.priority ?? 'normal', t.team ?? '',
          j(t.mitre ?? []), j(t.tools ?? []), j(t.dataSources ?? []), j(t.commands ?? []),
          j(t.terrain ?? []), j(t.references ?? []),
          t.evidenceExpected ?? '', t.analysis ?? '', t.doNext ?? '',
          j(t.steps ?? []), j(t.original ?? null), ord++,
          t.createdBy ?? null, t.createdAt ?? null, t.editedBy ?? null, t.editedAt ?? null,
          t.bankId ?? null, t.bankDesc ?? null, t.bankProvenance ?? null,
        );

        // Assignments declared in the file seed the first import; anything the
        // team has since changed in the UI wins, so this never overwrites.
        for (const who of t.assignees ?? []) {
          db.prepare('insert or ignore into task_assignees (task_key, member) values (?,?)')
            .run(t.key, who);
        }
      }
    }
    db.exec('commit');
  } catch (err) {
    db.exec('rollback');
    throw err;
  }
  return { imported: ord, version, name: doc.plan?.name ?? 'Hunt Plan', period: doc.plan?.period ?? '' };
}

const rowToTask = (r, assignees) => ({
  taskKey: r.task_key,
  phaseKey: r.phase_key,
  phaseName: r.phase_name,
  phaseIntent: r.phase_intent,
  phaseSource: r.phase_source,
  title: r.title,
  intent: r.intent,
  source: r.source,
  bankId: r.bank_id ?? null,
  bankProvenance: r.bank_provenance ?? null,
  bankDesc: r.bank_desc ?? null,
  stepsSource: r.steps_source,
  priority: r.priority,
  team: r.team,
  mitre: unj(r.mitre, []),
  tools: unj(r.tools, []),
  dataSources: unj(r.data_sources, []),
  commands: unj(r.commands, []),
  terrain: unj(r.terrain, []),
  references: unj(r.refs, []),
  evidenceExpected: r.evidence_expected,
  analysis: r.analysis,
  doNext: r.do_next,
  steps: unj(r.steps, []),
  original: unj(r.original, null),
  status: r.status ?? 'pending',
  changedBy: r.changed_by,
  changedAt: r.changed_at,
  note: r.note,
  assignees,
  ord: r.ord,
  createdBy: r.created_by,
  createdAt: r.created_at,
  editedBy: r.edited_by,
  editedAt: r.edited_at,
});

export function listPlan(db) {
  const rows = db.prepare(`select t.*, s.status, s.changed_by, s.changed_at, s.note
    from plan_tasks t left join task_state s on s.task_key = t.task_key
    order by t.ord`).all();
  const byTask = new Map();
  for (const a of db.prepare('select * from task_assignees').all()) {
    if (!byTask.has(a.task_key)) byTask.set(a.task_key, []);
    byTask.get(a.task_key).push(a.member);
  }
  return rows.map(r => rowToTask(r, (byTask.get(r.task_key) ?? []).sort()));
}

export function getTask(db, taskKey) {
  const r = db.prepare(`select t.*, s.status, s.changed_by, s.changed_at, s.note
    from plan_tasks t left join task_state s on s.task_key = t.task_key
    where t.task_key = ?`).get(taskKey);
  if (!r) return null;
  const assignees = db.prepare('select member from task_assignees where task_key = ? order by member')
    .all(taskKey).map(x => x.member);
  return rowToTask(r, assignees);
}

/** Plan authoring shares the task event log with completions and resets. */
export const logPlanEvent = (db, taskKey, actor, action, detail = null) =>
  logEvent(db, taskKey, actor, action, detail);

function logEvent(db, taskKey, actor, action, detail = null) {
  db.prepare('insert into task_events (ts, task_key, actor, action, detail) values (?,?,?,?,?)')
    .run(nowIso(), taskKey, actor ?? null, action, detail);
}

const VALID = new Set(['pending', 'in-progress', 'complete', 'blocked']);

/**
 * Anyone may set any status, including resetting a completed task back to
 * pending. That is deliberate: the team asked for no guards, because a lead
 * needs to reattack a task on a new day without hunting for permissions.
 * The absence of a guard is why the event log matters.
 */
export function setTaskStatus(db, taskKey, status, actor, note = null) {
  if (!VALID.has(status)) throw new Error(`unknown status: ${status}`);
  if (!db.prepare('select 1 from plan_tasks where task_key = ?').get(taskKey)) {
    throw new Error(`no such task: ${taskKey}`);
  }
  const before = db.prepare('select status from task_state where task_key = ?').get(taskKey);
  const from = before?.status ?? 'pending';

  db.prepare(`insert into task_state (task_key, status, changed_by, changed_at, note)
              values (?,?,?,?,?)
              on conflict(task_key) do update set
                status = excluded.status, changed_by = excluded.changed_by,
                changed_at = excluded.changed_at, note = excluded.note`)
    .run(taskKey, status, actor ?? null, nowIso(), note);

  // A reset is its own verb in the history. "complete -> pending" read back as
  // a status change loses the fact that somebody deliberately reopened it.
  const action = (from === 'complete' && status !== 'complete') ? 'reset' : `status:${status}`;
  logEvent(db, taskKey, actor, action, JSON.stringify({ from, to: status, note }));
  return getTask(db, taskKey);
}

export function setAssignees(db, taskKey, members, actor) {
  if (!db.prepare('select 1 from plan_tasks where task_key = ?').get(taskKey)) {
    throw new Error(`no such task: ${taskKey}`);
  }
  const before = db.prepare('select member from task_assignees where task_key = ? order by member')
    .all(taskKey).map(x => x.member);
  /*
    The delete and the inserts are one unit of work, for the same reason
    importPlan gives seven functions up: a value the driver cannot bind — a
    number, an object, anything a caller passed through without checking —
    throws partway down the loop, and the delete has already committed. What is
    left is a task assigned to whoever happened to sort before the bad value,
    with no record that the rest were ever there.

    Reproduced with ['Carol', {bad: 1}, 'Dave']: the task came back assigned to
    Carol alone.
  */
  db.exec('begin');
  try {
    db.prepare('delete from task_assignees where task_key = ?').run(taskKey);
    for (const m of members) {
      db.prepare('insert or ignore into task_assignees (task_key, member) values (?,?)').run(taskKey, m);
    }
    db.exec('commit');
  } catch (err) {
    db.exec('rollback');
    throw err;
  }
  logEvent(db, taskKey, actor, 'assign', JSON.stringify({ from: before, to: [...members].sort() }));

  /*
    Only the people who were not already on it. Re-saving a task with the same
    four names on it is a common way to change something else about it, and
    telling all four again each time is how a notification becomes furniture.
  */
  const task = getTask(db, taskKey);
  const had = new Set(before.map(m => m.toLowerCase()));
  for (const m of members) {
    if (had.has(String(m).toLowerCase())) continue;
    notify(db, {
      member: m, kind: 'assigned', actor,
      title: `You were assigned ${taskKey}`,
      body: task?.title ?? null,
      link: '#/plan',
    });
  }
  return task;
}

export const listTaskEvents = (db, taskKey) =>
  db.prepare('select * from task_events where task_key = ? order by id desc').all(taskKey);

/** Recent activity across the whole plan, for the leader view. */
export const listRecentEvents = (db, limit = 100) =>
  db.prepare('select * from task_events order by id desc limit ?').all(limit);

export function planSummary(db) {
  const rows = listPlan(db);
  const by = (k) => rows.reduce((a, r) => ((a[r[k]] = (a[r[k]] ?? 0) + 1), a), {});
  return {
    total: rows.length,
    byStatus: by('status'),
    unassigned: rows.filter(r => r.assignees.length === 0).length,
    version: rows[0] ? db.prepare('select plan_version from plan_tasks limit 1').get().plan_version : null,
  };
}
