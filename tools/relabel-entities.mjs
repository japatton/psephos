/**
 * Recompute every stored row label from the row itself.
 *
 *   node tools/relabel-entities.mjs [--apply]
 *
 * labelOf runs once, at insert. So a row written before the field resolution
 * improved keeps whatever label it got at the time, and two fixes have landed
 * since: host.name no longer claims the bare "name" ahead of task.name or
 * file.name, and declared columns now resolve through the repository's
 * aliases. 131 scheduled tasks are still labelled with the machine they were
 * found on rather than the task.
 *
 * Display only. The ident is the key everything diffs on and is not touched
 * here, so no comparison moves — this changes what the table says, not what it
 * means.
 */
import { openDb, initSchema } from '../store/db.js';
import { REPOS, labelOf, isRepo } from '../store/characterization.js';

const apply = process.argv.includes('--apply');
const db = openDb(process.env.HUNT_DB || 'data/hunt.db');
initSchema(db);

const rows = db.prepare('select id, repo, host, label, attrs from char_entities').all();
const upd = db.prepare('update char_entities set label = ? where id = ?');

const changes = [];
for (const r of rows) {
  if (!isRepo(r.repo)) continue;
  let attrs;
  try { attrs = JSON.parse(r.attrs ?? '{}'); } catch { continue; }
  const next = labelOf(r.repo, attrs);
  if (next && next !== r.label) changes.push({ ...r, next });
}

const byRepo = new Map();
for (const c of changes) {
  const b = byRepo.get(c.repo) ?? { n: 0, wasHost: 0, sample: null };
  b.n++;
  if (c.host && String(c.label).split('.')[0].toLowerCase() === String(c.host).split('.')[0].toLowerCase()) {
    b.wasHost++;
  }
  b.sample ??= c;
  byRepo.set(c.repo, b);
}

console.log(`\n${rows.length} rows examined, ${changes.length} label(s) wrong\n`);
console.log('repository         wrong   of which named after their host');
for (const [repo, b] of byRepo) {
  console.log(`  ${repo.padEnd(17)} ${String(b.n).padStart(5)}   ${String(b.wasHost).padStart(6)}`);
  console.log(`     e.g. ${JSON.stringify(b.sample.label).slice(0, 44)} -> ${JSON.stringify(b.sample.next).slice(0, 44)}`);
}

if (!changes.length) { console.log('\nnothing to do.'); process.exit(0); }
if (!apply) { console.log('\ndry run — nothing written. Pass --apply to fix.'); process.exit(0); }

db.exec('begin');
try {
  for (const c of changes) upd.run(c.next, c.id);
  db.exec('commit');
} catch (e) { db.exec('rollback'); throw e; }
console.log(`\nrelabelled ${changes.length} row(s). Idents untouched, so no comparison moved.`);
