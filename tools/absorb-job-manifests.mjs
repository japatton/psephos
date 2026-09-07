/**
 * Take collection-job manifests out of the baseline and keep what is real.
 *
 *   node tools/absorb-job-manifests.mjs [--dry-run]
 *
 * A Velociraptor job manifest describes the collection, not the estate. Filed
 * as baseline rows it is noise in a repository whose whole value is that
 * everything in it is a real thing on a real host.
 *
 * But it is not worthless. Each manifest carries three things worth keeping:
 *
 *   OS, kernel and architecture   genuine host facts. They belong on the host
 *                                 record, where the map and drawer already
 *                                 show them, not in a baseline repository.
 *   count_*                       what the collector says it gathered. An
 *                                 authoritative yardstick from the collector
 *                                 beats the model's own report, and it shows
 *                                 what the job holds that nobody uploaded.
 *   PickupStatus, *_errors        whether the collection actually finished.
 *
 * So: fold the host facts into hosts, write the coverage into the snapshot's
 * note where it explains what that run did and did not capture, and drop the
 * manifest rows.
 */
import { openDb, initSchema } from '../store/db.js';

const dryRun = process.argv.includes('--dry-run');
const db = openDb(process.env.HUNT_DB || 'data/hunt.db');
initSchema(db);

const manifests = db.prepare(`select e.id, e.host, e.attrs, u.id upload_id, u.snapshot_id
  from char_entities e join char_uploads u on u.id = e.upload_id
  where e.repo = 'unclassified'`).all()
  .map(r => ({ ...r, a: JSON.parse(r.attrs) }))
  .filter(r => /manifest|job/i.test(r.a.label ?? '') || r.a.PickupStatus != null);

if (!manifests.length) { console.log('\n  no job manifests in the baseline\n'); process.exit(0); }
console.log(`\n  ${manifests.length} manifest row(s) to absorb\n`);

// --- host facts -------------------------------------------------------------
const osUpdates = [];
for (const m of manifests) {
  const os = [m.a.OSDistribution, m.a.OSVersion && `(kernel ${m.a.OSVersion})`]
    .filter(Boolean).join(' ');
  if (!os) continue;
  const host = m.a.ip
    ? db.prepare('select id, name, os from hosts where ip = ?').get(m.a.ip)
    : db.prepare('select id, name, os from hosts where lower(name) = lower(?)').get(m.host);
  if (!host || host.os === os) continue;
  osUpdates.push({ id: host.id, name: host.name, from: host.os, to: os });
}
console.log('  HOST FACTS');
for (const u of osUpdates) console.log(`    ${u.name.padEnd(30)} ${u.from ?? '-'}  ->  ${u.to}`);
if (!osUpdates.length) console.log('    nothing to enrich');

// --- coverage ---------------------------------------------------------------
const totals = {};
for (const m of manifests) {
  for (const [k, v] of Object.entries(m.a)) {
    if (!k.startsWith('count_') || typeof v !== 'number') continue;
    totals[k.slice(6)] = (totals[k.slice(6)] ?? 0) + v;
  }
}
const staged = (repoGuess) => db.prepare(
  'select count(*) n from char_entities where repo = ?').get(repoGuess).n;
const REPO_FOR = { accounts: 'accounts', apps: 'software' };

console.log('\n  WHAT THE JOB GATHERED, AGAINST WHAT IS BASELINED');
const gaps = [];
for (const [what, n] of Object.entries(totals).sort((a, b) => b[1] - a[1])) {
  const repo = REPO_FOR[what];
  const have = repo ? staged(repo) : 0;
  const note = repo
    ? `${have} in ${repo}`
    : 'no repository holds this yet';
  if (n > 0 && have === 0) gaps.push(`${n} ${what}`);
  console.log(`    ${String(n).padStart(6)}  ${what.padEnd(14)} ${note}`);
}

const summaryNote =
  `Velociraptor job ${manifests[0].a.name ?? ''} across ${manifests.length} host(s). ` +
  `Collector reported: ${Object.entries(totals).map(([k, v]) => `${v} ${k}`).join(', ')}. ` +
  (gaps.length ? `Collected but not yet uploaded: ${gaps.join(', ')}.` : 'All of it is baselined.');

const snapIds = [...new Set(manifests.map(m => m.snapshot_id).filter(Boolean))];
console.log('\n  SNAPSHOT NOTE');
console.log('    ' + summaryNote);

if (dryRun) { console.log('\n  --dry-run: nothing written\n'); process.exit(0); }

db.exec('begin');
try {
  for (const u of osUpdates) db.prepare('update hosts set os = ? where id = ?').run(u.to, u.id);
  for (const id of snapIds) {
    const prev = db.prepare('select note from char_snapshots where id = ?').get(id)?.note;
    db.prepare('update char_snapshots set note = ? where id = ?')
      .run([prev, summaryNote].filter(Boolean).join(' — '), id);
  }
  for (const m of manifests) {
    db.prepare('delete from char_entities where id = ?').run(m.id);
    // Drop the upload too if the manifest was all it held.
    const left = db.prepare('select count(*) n from char_entities where upload_id = ?').get(m.upload_id).n;
    if (left === 0) db.prepare('delete from char_uploads where id = ?').run(m.upload_id);
  }
  db.exec('commit');
} catch (err) {
  db.exec('rollback');
  throw err;
}

console.log(`\n  enriched ${osUpdates.length} host(s), annotated ${snapIds.length} snapshot(s), ` +
  `removed ${manifests.length} manifest row(s) from the baseline\n`);
