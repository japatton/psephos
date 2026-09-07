/**
 * Recompute stored identities from the repository's current ident function.
 *
 *   node tools/reident-entities.mjs [--repo <key>] [--apply]
 *
 * An ident is written once, at insert, and is what every comparison keys on.
 * So improving an ident function only affects future uploads: the next
 * collection produces keys that match nothing already stored, and every
 * affected row reads as GONE with a NEW one beside it. That is a lie about the
 * estate, produced by a change meant to make it more truthful.
 *
 * Backfilling is what makes such a change safe, and it has to be checked
 * before it is made rather than after. Two rows in one upload landing on the
 * same identity means one of them stops being visible — the read-time union
 * keeps the last — so that is refused outright rather than reported.
 */
import { openDb, initSchema } from '../store/db.js';
import { REPOS, isRepo } from '../store/characterization.js';

const args = process.argv.slice(2);
const apply = args.includes('--apply');
const only = args.includes('--repo') ? args[args.indexOf('--repo') + 1] : null;
if (only && !isRepo(only)) { console.error(`unknown repository: ${only}`); process.exit(1); }

const db = openDb(process.env.HUNT_DB || 'data/hunt.db');
initSchema(db);

const rows = db.prepare(
  `select id, repo, host, upload_id, ident, attrs from char_entities
   ${only ? 'where repo = ?' : ''}`).all(...(only ? [only] : []));

const changes = [];
let unreadable = 0;
let unnameable = 0;
for (const r of rows) {
  if (!isRepo(r.repo)) continue;
  let attrs;
  try { attrs = JSON.parse(r.attrs ?? '{}'); } catch { unreadable++; continue; }
  const next = REPOS[r.repo].ident(attrs);
  /*
    The same guard stageSnapshot applies at write time. A row the repository
    cannot name is stored under a content hash rather than under an empty
    string, and recomputing without this would overwrite a perfectly good hash
    with "|" — turning one unnameable row into a key that every other
    unnameable row would also land on.
  */
  if (!next || next === '|' || /^\|+$/.test(next)) { unnameable++; continue; }
  if (next !== r.ident) changes.push({ ...r, next });
}

/*
  What the backfill would do to the table, not what it would do to one row.
  Two rows sharing an identity inside one upload is the failure this guards.
*/
const after = new Map();
for (const r of rows) {
  const c = changes.find(x => x.id === r.id);
  const key = `${r.upload_id}\u0000${c ? c.next : r.ident}`;
  after.set(key, (after.get(key) ?? 0) + 1);
}
const before = new Map();
for (const r of rows) {
  const key = `${r.upload_id}\u0000${r.ident}`;
  before.set(key, (before.get(key) ?? 0) + 1);
}
const collideNow = [...before.values()].filter(n => n > 1).length;
const collideAfter = [...after.values()].filter(n => n > 1).length;

const byRepo = new Map();
for (const c of changes) {
  const b = byRepo.get(c.repo) ?? { n: 0, sample: null };
  b.n++; b.sample ??= c;
  byRepo.set(c.repo, b);
}

console.log(`\n${rows.length} row(s) examined, ${changes.length} identity change(s)`);
if (unreadable) console.log(`  ${unreadable} row(s) had unreadable attributes and were left alone`);
if (unnameable) {
  console.log(`  ${unnameable} row(s) the repository cannot name kept their content hash`);
}
for (const [repo, b] of byRepo) {
  console.log(`\n  ${repo}: ${b.n}`);
  console.log(`     ${JSON.stringify(b.sample.ident).slice(0, 48)}`);
  console.log(`  -> ${JSON.stringify(b.sample.next).slice(0, 48)}`);
}
console.log(`\nrows sharing an identity within one upload: ${collideNow} now, ${collideAfter} after`);

if (!changes.length) { console.log('\nnothing to do.'); process.exit(0); }
if (collideAfter > collideNow) {
  console.error('\nREFUSED: the backfill would hide rows that are visible today.');
  process.exit(1);
}
if (!apply) { console.log('\ndry run — nothing written. Pass --apply to backfill.'); process.exit(0); }

db.exec('begin');
try {
  const upd = db.prepare('update char_entities set ident = ? where id = ?');
  for (const c of changes) upd.run(c.next, c.id);
  db.exec('commit');
} catch (e) { db.exec('rollback'); throw e; }
console.log(`\nbackfilled ${changes.length} identity/identities.`);
