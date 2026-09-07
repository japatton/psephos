/**
 * The plan file: where it lives, how it is read, and how it is changed.
 *
 * The plan is edited through the UI, and the server re-imports it at every
 * startup. Writing plan_tasks directly would therefore lose every edit on the
 * next restart, so the file is the thing that gets written and the database is
 * re-derived from it. The file stays the single authority it already was, and
 * the two cannot drift.
 *
 * The live plan is data/plan.json, not the profile's plan.json, for one
 * practical reason: a week of team edits sitting in the seed file makes the
 * seed and the working copy the same object, so re-seeding a second server
 * from the profile would carry a week of one team's state with it. The
 * profile's file is the seed; the live file is the working copy.
 * tools/promote-plan.mjs moves edits back.
 *
 * Mutators here are pure functions over the plan object so they can be tested
 * without touching a disk.
 */
import {
  readFileSync, writeFileSync, existsSync, copyFileSync,
  mkdirSync, readdirSync, unlinkSync, renameSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { missionPaths } from './mission.js';

/** The mission profile's plan. Read-only at runtime; the live copy is written. */
export const seedPlanPath = () => missionPaths().plan;
/** Live and writable. Gitignored, because the team edits it all week. */
export const LIVE_PLAN = resolve(process.env.HUNT_PLAN || 'data/plan.json');

const KEEP_BACKUPS = 20;
const backupDir = (livePath) => join(dirname(livePath), 'plan-backups');

/**
 * Millisecond precision plus a counter, because seconds are not enough.
 * Correcting three fields on one task is three writes inside the same second,
 * and a second-resolution name would have each overwrite the last — leaving
 * "the last 20 backups" meaning "the last write in each of 20 seconds".
 * The counter covers two writes landing in the same millisecond.
 */
let lastStamp = '';
let seq = 0;
const stamp = () => {
  const t = new Date().toISOString().replace(/[:.]/g, '-').replace(/Z$/, '');
  if (t === lastStamp) seq++; else { lastStamp = t; seq = 0; }
  // Reset per millisecond so the counter stays zero-padded to three digits and
  // the names keep sorting chronologically, which is what prune relies on.
  return `${t}-${String(seq).padStart(3, '0')}`;
};

// --- io ---------------------------------------------------------------------

/**
 * Copy the seed into place the first time only. An existing live plan is never
 * overwritten — that would silently discard the team's work on a restart,
 * which is the exact failure this whole design exists to prevent.
 */
export function ensureLivePlan(live = LIVE_PLAN, seed = seedPlanPath()) {
  if (existsSync(live)) return { seeded: false, path: live };
  if (!existsSync(seed)) throw new Error(`no plan to seed from: ${seed}`);
  mkdirSync(dirname(live), { recursive: true });
  copyFileSync(seed, live);
  return { seeded: true, path: live };
}

export function readPlan(path = LIVE_PLAN) {
  return JSON.parse(readFileSync(path, 'utf8').replace(/^﻿/, ''));
}

/**
 * Write the plan, atomically, keeping a rolling backup.
 *
 * Serialise before touching anything on disk: if the plan object is somehow
 * not serialisable, the throw happens with the existing file still intact.
 * Then write a temp file and rename over the target, so a reader never sees a
 * half-written plan and a crash mid-write cannot truncate the real one.
 */
export function writePlan(plan, path = LIVE_PLAN) {
  const body = JSON.stringify(plan, null, 2) + '\n';

  if (existsSync(path)) {
    const dir = backupDir(path);
    mkdirSync(dir, { recursive: true });
    copyFileSync(path, join(dir, `plan-${stamp()}.json`));
    pruneBackups(dir);
  }

  const tmp = `${path}.tmp`;
  writeFileSync(tmp, body, 'utf8');
  renameSync(tmp, path);
  return path;
}

function pruneBackups(dir) {
  const files = readdirSync(dir).filter(f => f.startsWith('plan-') && f.endsWith('.json')).sort();
  for (const f of files.slice(0, Math.max(0, files.length - KEEP_BACKUPS))) {
    try { unlinkSync(join(dir, f)); } catch { /* already gone */ }
  }
}

// --- mutators ---------------------------------------------------------------

const TASK_FIELDS = [
  'title', 'intent', 'priority', 'team', 'mitre', 'tools', 'dataSources',
  'commands', 'terrain', 'references', 'evidenceExpected', 'analysis',
  'doNext', 'steps',
];
const LIST_FIELDS = new Set(['mitre', 'tools', 'dataSources', 'commands', 'terrain', 'references', 'steps']);
const PRIORITIES = new Set(['low', 'normal', 'high']);

export const allTasks = (plan) => plan.phases.flatMap(p => p.tasks ?? []);
export const findTask = (plan, key) => allTasks(plan).find(t => t.key === key) ?? null;
export const findPhase = (plan, key) => plan.phases.find(p => p.key === key) ?? null;

/** "Kerberoast sweep on the DCs" -> "LOCAL-kerberoast-sweep-on-the-dcs" */
export function slugKey(title, plan, prefix = 'LOCAL-') {
  const base = prefix + String(title ?? '').toLowerCase()
    .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 48);
  if (base === prefix) return null;
  if (!findTask(plan, base)) return base;
  for (let n = 2; n < 200; n++) if (!findTask(plan, `${base}-${n}`)) return `${base}-${n}`;
  return null;
}

const clean = (v) => (v == null ? '' : String(v));
const cleanList = (v) => (Array.isArray(v) ? v : []).filter(x => x != null && x !== '');

/** Steps are objects, not strings; keep the shape the plan view expects. */
const cleanSteps = (v) => (Array.isArray(v) ? v : [])
  .filter(s => s && String(s.text ?? '').trim())
  .map(s => ({
    text: clean(s.text), tooling: clean(s.tooling), expect: clean(s.expect),
    source: s.source ?? 'local',
  }));

/*
  Whether a task carries its own procedure, and the label that says so.

  Two places asked this question and each answered it for itself: the editor
  stamped stepsSource here, and the coverage view re-derived "authored" from
  steps.length of its own accord. They agreed by coincidence. Change the rule
  in one — count a procedure pulled from the bank as something other than
  authored, say — and the plan view and the coverage view would disagree about
  the same task, with nothing failing to say so.
*/
export const stepsSourceOf = (task) =>
  ((task?.steps ?? []).length ? 'authored' : 'standard-loop');

function applyFields(task, patch) {
  for (const f of TASK_FIELDS) {
    if (!(f in patch)) continue;
    if (f === 'steps') task.steps = cleanSteps(patch.steps);
    else if (LIST_FIELDS.has(f)) task[f] = cleanList(patch[f]);
    else if (f === 'priority') task.priority = PRIORITIES.has(patch.priority) ? patch.priority : 'normal';
    else task[f] = clean(patch[f]);
  }
  task.stepsSource = stepsSourceOf(task);
  task.ttpText = (task.mitre ?? []).join(', ');
}

/**
 * Add a task to an existing phase.
 * @returns the created task
 */
export function addTask(plan, { phaseKey, key, actor, ...fields }) {
  const phase = findPhase(plan, phaseKey);
  if (!phase) throw new Error(`no such phase: ${phaseKey}`);
  if (!String(fields.title ?? '').trim()) throw new Error('a task needs a title');

  const taskKey = String(key ?? '').trim() || slugKey(fields.title, plan);
  if (!taskKey) throw new Error('could not derive a key from that title');
  /*
    The same charset a phase key is held to, and for a harder reason: the key
    goes into the per-task route patterns, which are [\w.:-]+. A task created
    with a space in its key rendered on the board with status, assign and
    history controls, and every one of those routes answered "no such route" —
    including the PATCH that would edit it, and there is no delete. It could
    only be removed by hand-editing data/plan.json.
  */
  if (!/^[\w.:-]+$/.test(taskKey)) {
    throw new Error('a task key may only contain letters, digits, . : _ and -');
  }
  if (findTask(plan, taskKey)) throw new Error(`task key already in use: ${taskKey}`);

  const task = {
    key: taskKey, source: 'local', priority: 'normal', team: '',
    mitre: [], tools: [], dataSources: [], commands: [], terrain: [], references: [],
    intent: '', evidenceExpected: '', analysis: '', doNext: '', steps: [],
    original: null, assignees: [],
    createdBy: actor ?? null, createdAt: new Date().toISOString(),
  };
  applyFields(task, fields);
  phase.tasks = phase.tasks ?? [];
  phase.tasks.push(task);
  return task;
}

/**
 * Edit a task in place. The key is immutable — completion state, assignments
 * and the event log are all keyed on it, and renaming would silently detach
 * every one of them.
 */
export function editTask(plan, key, { actor, ...patch }) {
  const task = findTask(plan, key);
  if (!task) throw new Error(`no such task: ${key}`);
  if (patch.key !== undefined && patch.key !== key) {
    throw new Error('a task key cannot be changed; history is keyed on it');
  }
  if ('title' in patch && !String(patch.title ?? '').trim()) {
    throw new Error('a task needs a title');
  }

  // Moving between phases is a move, not a field edit.
  if (patch.phaseKey && patch.phaseKey !== phaseKeyOf(plan, key)) {
    const to = findPhase(plan, patch.phaseKey);
    if (!to) throw new Error(`no such phase: ${patch.phaseKey}`);
    const from = plan.phases.find(p => (p.tasks ?? []).some(t => t.key === key));
    from.tasks = from.tasks.filter(t => t.key !== key);
    to.tasks = to.tasks ?? [];
    to.tasks.push(task);
  }

  applyFields(task, patch);
  task.editedBy = actor ?? null;
  task.editedAt = new Date().toISOString();
  return task;
}

/**
 * Copy a bank entry into the plan.
 *
 * A copy, never a reference. Editing the result is editing an ordinary task,
 * the bank does not change, and there is no sync to get wrong. The cost is that
 * a later improvement to a bank entry does not reach plans already built from
 * it — the right trade: a plan records what the team decided to do, not a live
 * view of a catalogue.
 *
 * Pure over the plan object like everything else here, so the caller writes the
 * file and re-imports. @returns the created task
 */
export function addTaskFromBank(plan, entry, { phaseKey, actor = null } = {}) {
  if (!entry) throw new Error('no such bank entry');
  const d = entry.depth ?? {};
  const title = entry.kind === 'technique' ? `${entry.id} — ${entry.name}` : entry.name;

  const task = addTask(plan, {
    phaseKey, actor,
    // slugKey resolves collisions with a numeric suffix, so the same technique
    // can be drawn twice — different terrain, different phase.
    key: slugKey(`${entry.id} ${entry.name}`, plan, 'BANK-'),
    title,
    // Never entry.desc here. intent is an argument a human wrote about this
    // engagement, read everywhere else in the UI as somebody's judgement — a
    // stub has none, and MITRE's paragraph is not a substitute for one.
    intent: d.intent ?? '',
    priority: d.priority ?? 'normal',
    team: d.team ?? '',
    mitre: entry.kind === 'technique' ? [entry.id] : [],
    tools: d.tools ?? [],
    dataSources: d.dataSources ?? detectionLogs(entry),
    commands: d.commands ?? [],
    terrain: d.terrain ?? [],
    references: d.references ?? [],
    evidenceExpected: d.evidenceExpected ?? '',
    analysis: d.analysis ?? '',
    doNext: d.doNext ?? '',
    steps: d.steps ?? [],
  });

  // Neither is a TASK_FIELDS entry — source is not user-editable, and bankId
  // and bankDesc are provenance rather than content. bankDesc is set only when
  // there is no authored intent to show instead: MITRE's own description is
  // worth keeping, but under its own label, never as this task's intent.
  task.source = 'bank';
  task.bankId = entry.id;
  /*
    Null for a stub rather than a value meaning "none": there is no depth here
    to have a provenance, and a stub reporting one would claim somebody had
    looked at it.
  */
  task.bankProvenance = entry.depth?.provenance ?? null;
  task.bankDesc = d.intent ? null : (entry.desc || null);
  return task;
}

/*
  A stub has no authored data sources, but MITRE's detection strategies name the
  logs their analytics read. Carrying those across is the difference between a
  drawn stub being a starting point and being only a title.
*/
const detectionLogs = (entry) =>
  [...new Set((entry.detection ?? []).flatMap(d => d.logSources ?? []))];

export const phaseKeyOf = (plan, taskKey) =>
  plan.phases.find(p => (p.tasks ?? []).some(t => t.key === taskKey))?.key ?? null;

export function addPhase(plan, { key, name, intent, actor }) {
  const phaseKey = String(key ?? '').trim();
  if (!phaseKey) throw new Error('a phase needs a key');
  if (!/^[\w.:-]+$/.test(phaseKey)) throw new Error('a phase key may only contain letters, digits, . : _ and -');
  if (!String(name ?? '').trim()) throw new Error('a phase needs a name');
  if (findPhase(plan, phaseKey)) throw new Error(`phase key already in use: ${phaseKey}`);

  const phase = {
    key: phaseKey, name: String(name).trim(), intent: clean(intent),
    source: 'local', createdBy: actor ?? null, tasks: [],
  };
  plan.phases.push(phase);
  return phase;
}

export function editPhase(plan, key, { name, intent, actor }) {
  const phase = findPhase(plan, key);
  if (!phase) throw new Error(`no such phase: ${key}`);
  if (name !== undefined) {
    if (!String(name).trim()) throw new Error('a phase needs a name');
    phase.name = String(name).trim();
  }
  if (intent !== undefined) phase.intent = clean(intent);
  phase.editedBy = actor ?? null;
  phase.editedAt = new Date().toISOString();
  return phase;
}
