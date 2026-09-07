/**
 * Copy the live plan over the committed seed, so the team's edits enter git.
 *
 *   node tools/promote-plan.mjs --dry-run    show what changed, write nothing
 *   node tools/promote-plan.mjs              copy live over the seed
 *
 * The live plan (data/plan.json) is gitignored and is what the UI writes all
 * week. The seed is the active mission profile's plan.json.
 * Promoting is deliberate, because committing the plan is a decision about
 * what the team's plan of record is — not something a hunt should do as a
 * side effect of somebody fixing a typo at 0200.
 *
 * Nothing is destroyed either way: the seed is in git, and the live file is
 * left exactly as it is.
 */
import { existsSync, readFileSync, copyFileSync } from 'node:fs';
import { seedPlanPath, LIVE_PLAN } from '../store/plan-file.js';

const SEED_PLAN = seedPlanPath();

const dryRun = process.argv.includes('--dry-run');

if (!existsSync(LIVE_PLAN)) {
  console.error(`no live plan at ${LIVE_PLAN} — has the server run yet?`);
  process.exit(1);
}

const read = (p) => JSON.parse(readFileSync(p, 'utf8').replace(/^﻿/, ''));
const live = read(LIVE_PLAN);
const seed = existsSync(SEED_PLAN) ? read(SEED_PLAN) : { phases: [] };

const index = (plan) => new Map(plan.phases.flatMap(p => (p.tasks ?? []).map(t => [t.key, t])));
const liveTasks = index(live);
const seedTasks = index(seed);

const added = [...liveTasks.keys()].filter(k => !seedTasks.has(k));
const removed = [...seedTasks.keys()].filter(k => !liveTasks.has(k));
const changed = [...liveTasks.entries()]
  .filter(([k, t]) => seedTasks.has(k) && JSON.stringify(t) !== JSON.stringify(seedTasks.get(k)))
  .map(([k]) => k);
const newPhases = live.phases.filter(p => !seed.phases.some(q => q.key === p.key)).map(p => p.key);

console.log(`\n  live  ${LIVE_PLAN}  (${liveTasks.size} tasks)`);
console.log(`  seed  ${SEED_PLAN}  (${seedTasks.size} tasks)\n`);

const show = (label, keys) => {
  if (!keys.length) return;
  console.log(`  ${label} (${keys.length})`);
  for (const k of keys.slice(0, 40)) {
    const t = liveTasks.get(k) ?? seedTasks.get(k);
    const by = t?.editedBy || t?.createdBy;
    console.log(`    ${k}${by ? `   — ${by}` : ''}`);
  }
  if (keys.length > 40) console.log(`    …and ${keys.length - 40} more`);
  console.log('');
};

show('ADDED', added);
show('CHANGED', changed);
show('REMOVED FROM SEED', removed);
if (newPhases.length) console.log(`  NEW PHASES  ${newPhases.join(', ')}\n`);

if (!added.length && !changed.length && !removed.length) {
  console.log('  Nothing to promote — the live plan matches the seed.\n');
  process.exit(0);
}

if (dryRun) {
  console.log('  --dry-run: nothing was written.\n');
  process.exit(0);
}

copyFileSync(LIVE_PLAN, SEED_PLAN);
console.log(`  promoted ${LIVE_PLAN}\n        -> ${SEED_PLAN}\n`);
console.log('  Review and commit:');
console.log(`    git diff --stat ${'plans/'}`);
console.log('    git add plans/ && git commit\n');
