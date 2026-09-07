/**
 * Rebuild characterization snapshots whose rows were lost to the field-naming
 * bug, from the original uploads still in the session transcript.
 *
 *   node tools/recover-characterization.mjs [--dry-run]
 *
 * Between characterization shipping and the identity functions being made
 * field-name agnostic, any row whose source spelled things differently from our
 * field names was dropped on insert. Nineteen snapshots were recorded holding
 * nothing, while reporting they had extracted dozens of rows each.
 *
 * Nothing was lost from the estate: the analyst's original paste is in the
 * messages table. Both formats the team used carry the host inside the data —
 * ECS scheduled-task CSV in "host.name", Velociraptor account exports in
 * "host" as an address — so the split across hosts is recoverable exactly,
 * rather than guessed from timing. That is the only reason this is worth doing
 * automatically; a guess at which host an account list belonged to would be a
 * false baseline, which is worse than an empty one.
 *
 * Replays uploads in their original order so the snapshot history, and
 * therefore the diff, comes out the way it would have.
 */
import { openDb, initSchema } from '../store/db.js';
import { stageSnapshot } from '../store/characterization.js';
import { parseCsv } from './import-nessus.mjs';
import { terrainNamer } from '../lib/terrain-names.js';

const dryRun = process.argv.includes('--dry-run');
const db = openDb(process.env.HUNT_DB || 'data/hunt.db');
initSchema(db);

/** Address or short name to the terrain's name for it, so hosts line up. */
const resolveHostName = terrainNamer(db.prepare('select ip, name from hosts').all());

/** ECS scheduled-task CSV: dotted headers, many hosts in one file. */
function ecsTasks(text) {
  const rows = parseCsv(text);
  if (rows.length < 2) return null;
  const header = rows[0].map(h => h.trim());
  if (!header.some(h => /^task\./i.test(h))) return null;
  const hostCol = header.findIndex(h => /^host\.name$/i.test(h));
  if (hostCol < 0) return null;
  const out = new Map();
  for (const r of rows.slice(1)) {
    const host = resolveHostName(r[hostCol]);
    if (!host) continue;
    const rec = Object.fromEntries(
      header.map((h, i) => [h, String(r[i] ?? '').trim()]).filter(([, v]) => v !== ''));
    if (!out.has(host)) out.set(host, []);
    out.get(host).push(rec);
  }
  return out.size ? { repo: 'scheduled-tasks', byHost: out } : null;
}

/**
 * Velociraptor account export. Not JSON — an object dump with unquoted keys —
 * so it is walked rather than parsed. Each record carries `host` as an address.
 */
function velociraptorAccounts(text) {
  if (!/UserName\s*:/.test(text)) return null;
  const out = new Map();
  for (const chunk of text.split(/(?=_id\s*:)/)) {
    if (!/UserName\s*:/.test(chunk)) continue;
    const rec = {};
    for (const m of chunk.matchAll(/(\w+)\s*:\s*(\[[^\]]*\]|"[^"]*"|[^,\n}\]]+)/g)) {
      const v = m[2].trim();
      rec[m[1]] = v.startsWith('[')
        ? [...v.matchAll(/"([^"]*)"/g)].map(x => x[1])
        : v.replace(/^"|"$/g, '').trim();
    }
    if (!rec.UserName) continue;
    const host = resolveHostName(rec.host);
    if (!host) continue;
    if (!out.has(host)) out.set(host, []);
    out.get(host).push(rec);
  }
  return out.size ? { repo: 'accounts', byHost: out } : null;
}

// --- replay -----------------------------------------------------------------

const empty = db.prepare(`
  select s.id, s.repo, s.host from char_snapshots s
  where (select count(*) from char_entities e where e.snapshot_id = s.id) = 0`).all();

const uploads = db.prepare(
  "select ts, content, session_id from messages where role = 'user' and mode = 'characterization' order by ts, rowid")
  .all();

console.log(`\n  ${empty.length} snapshot(s) hold no rows`);
console.log(`  ${uploads.length} original upload(s) available in the transcript\n`);

/*
  Merged per host, not replayed upload by upload.

  These uploads are pages of a single collection run, not observations spread
  over time — the analyst worked through the estate across twenty minutes, and
  several hosts appear in two uploads with partial lists (RL-4 as 12 rows then
  35, RL-6 as 18 then 29). Staging those in sequence would show twenty-three
  accounts "appearing" on RL-4, which never happened and which somebody would
  then go and investigate. One collection is one baseline per host.
*/
const merged = new Map();   // "repo|host" -> Map(identity -> row)
const identOf = (row) => JSON.stringify(
  ['UserName', 'username', 'task.name', 'taskPath', 'name'].map(k => String(row[k] ?? '').toLowerCase()));

for (const up of uploads) {
  const parsed = ecsTasks(up.content) ?? velociraptorAccounts(up.content);
  if (!parsed) { console.log(`    ${up.ts.slice(11, 19)}  unrecognised format, left alone`); continue; }
  for (const [host, rows] of parsed.byHost) {
    const key = `${parsed.repo}|${host}`;
    if (!merged.has(key)) merged.set(key, new Map());
    const into = merged.get(key);
    // Later pages win only where they carry more; never lose a field.
    for (const r of rows) {
      const id = identOf(r);
      const prev = into.get(id);
      into.set(id, prev && Object.keys(prev).length > Object.keys(r).length ? prev : r);
    }
  }
}

const plan = [...merged].map(([key, rows]) => {
  const [repo, host] = key.split('|');
  return { repo, host, rows: [...rows.values()] };
}).sort((a, b) => a.repo.localeCompare(b.repo) || a.host.localeCompare(b.host));

for (const p of plan) {
  console.log(`    ${p.repo.padEnd(16)} ${p.host.padEnd(30)} ${String(p.rows.length).padStart(3)} rows`);
}

if (!plan.length) { console.log('\n  nothing recoverable\n'); process.exit(0); }
if (dryRun) { console.log(`\n  --dry-run: would restage ${plan.length} snapshot(s), nothing written\n`); process.exit(0); }

// Retire the empty snapshots first, or a recovered one would diff against a
// husk and report every single row as brand new.
for (const s of empty) db.prepare('delete from char_snapshots where id = ?').run(s.id);

let flagged = 0;
for (const p of plan) {
  const snap = stageSnapshot(db, {
    repo: p.repo, host: p.host, sourceFormat: 'recovered from the original upload',
    claimedRows: p.rows.length, entities: p.rows, analyst: 'recovery',
  });
  if (snap.status !== 'ok') { flagged++; console.log(`      flagged  ${p.host}: ${snap.note}`); }
}

console.log(`\n  restaged ${plan.length} snapshot(s), removed ${empty.length} empty one(s)` +
  `${flagged ? `, ${flagged} flagged` : ''}\n`);
