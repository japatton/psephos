/**
 * Rebuild the rows the catch-all repository destroyed, from the original
 * uploads still in the session transcripts.
 *
 *   node tools/recover-lost-rows.mjs [--apply]
 *
 * The catch-all keyed rows on their label, and a label is a constant per
 * format, so every row on a host shared one identity and each overwrote the
 * last. 879 of 912 rows went that way. Nothing left the estate: the analyst's
 * paste is in the messages table, and every format carries host.name inside
 * the data, so the split across hosts is recovered exactly rather than guessed
 * from timing. A guess at which host a command history belonged to would be a
 * false baseline, which is worse than an empty one.
 *
 * Parsed deterministically rather than re-read by the model. These are ECS CSV
 * exports with known headers; a re-parse would cost tokens and introduce
 * exactly the extraction variance this is meant to undo.
 *
 * One paste holds three sections with different headers — outbound SMB
 * sessions, then a share inventory — so sections are split on each header line
 * rather than assuming one schema per upload.
 */
import { openDb, initSchema } from '../store/db.js';
import { stageSnapshot } from '../store/characterization.js';
import { parseCsv } from './import-nessus.mjs';
import { terrainNamer } from '../lib/terrain-names.js';

const apply = process.argv.includes('--apply');
const db = openDb(process.env.HUNT_DB || 'data/hunt.db');
initSchema(db);

/** Address or short name to the terrain's name for it, so hosts line up. */
const resolveHostName = terrainNamer(db.prepare('select ip, name from hosts').all());


/** Split a paste into CSV sections, one per header line. */
function sections(text) {
  const lines = String(text).split('\n');
  const out = [];
  let current = null;
  for (const line of lines) {
    if (/^"?host\.name"?\s*,/i.test(line)) {
      current = { header: line, body: [] };
      out.push(current);
    } else if (current && line.trim()) {
      current.body.push(line);
    }
  }
  return out.filter(s => s.body.length);
}

/*
  How each export becomes rows the repository can key on.

  The shapes matter as much as the destination. A console history keyed on
  user and command diffs usefully; the same data as {label,name,value} does
  not. SMB versions become one row per protocol rather than one row carrying
  both, so "SMBv1 turned on" is a change to a row rather than a new row.
*/
const SHAPES = [
  {
    match: (h) => h.includes('user.command'),
    repo: 'command-history',
    rows: (r) => [{
      user: r['user.name'], command: r['user.command'],
      when: r.timestamp, shell: 'PowerShell',
    }],
  },
  {
    match: (h) => h.includes('smb.path'),
    repo: 'shares',
    rows: (r) => [{
      name: r['smb.share'], path: r['smb.path'], description: r['smb.description'],
      when: r.timestamp,
    }],
  },
  {
    match: (h) => h.includes('smb.protocol.v1_enabled'),
    repo: 'host-config',
    rows: (r) => [
      { setting: 'SMBv1', value: r['smb.protocol.v1_enabled'], source: 'SMBEnabledVersions' },
      { setting: 'SMBv2', value: r['smb.protocol.v2_enabled'], source: 'SMBEnabledVersions' },
    ],
  },
  /*
    Outbound SMB sessions share a paste with the share inventory, but they are
    deliberately not recovered. That repository was never collapsed — it lost
    two rows of twenty-three to a truncated upload, not to the identity bug —
    and these same sessions were already staged into it successfully. Adding
    them again would duplicate a working baseline to fix a problem it does not
    have.
  */
  {
    match: (h) => h.includes('smb.server') && h.includes('smb.connections'),
    repo: null,
    rows: () => [],
  },
];

/** Which snapshot a recovered upload belongs to: the one it was filed under. */
const snapshotFor = (repo) => db.prepare(
  `select u.snapshot_id id from char_uploads u
   where u.repo = ? and u.snapshot_id is not null
   order by u.ts limit 1`).get(repo)?.id ?? null;

const messages = db.prepare(
  `select id, ts, content from messages
   where role = 'user'
     and (content like '%PSConsoleHistory%' or content like '%SMBShares%'
          or content like '%SMBEnabledVersions%' or content like '%SMBOutbound%')
   order by ts`).all();

/*
  A continuation chunk starts mid-data with no header of its own. The columns
  are the previous chunk's, so it is carried forward — otherwise 273 lines of
  console history are silently dropped a second time.
*/
let lastHeader = null;
const staged = [];

for (const m of messages) {
  const found = sections(m.content);
  const parts = found.length
    ? found
    : (lastHeader ? [{ header: lastHeader, body: m.content.split('\n').filter(l => l.trim()) }] : []);

  for (const part of parts) {
    lastHeader = part.header;
    const table = parseCsv([part.header, ...part.body].join('\n'));
    if (table.length < 2) continue;
    const head = table[0].map(h => h.trim());
    const shape = SHAPES.find(s => s.match(head));
    if (shape && shape.repo === null) continue;   // recognised, deliberately skipped
    if (!shape) {
      console.log(`  ? unrecognised section in ${m.id.slice(0, 8)}: ${head.join(',').slice(0, 80)}`);
      continue;
    }

    const byHost = new Map();
    for (const line of table.slice(1)) {
      const r = Object.fromEntries(head.map((h, i) => [h, String(line[i] ?? '').trim()]));
      const host = resolveHostName(r['host.name']);
      if (!host) continue;
      for (const row of shape.rows(r)) {
        const clean = Object.fromEntries(Object.entries(row).filter(([, v]) => v !== '' && v != null));
        if (!Object.keys(clean).length) continue;
        if (!byHost.has(host)) byHost.set(host, []);
        byHost.get(host).push(clean);
      }
    }
    for (const [host, rows] of byHost) {
      staged.push({ repo: shape.repo, host, rows, from: m.id, ts: m.ts });
    }
  }
}

// --- report -------------------------------------------------------------------

const summary = {};
for (const s of staged) {
  const b = (summary[s.repo] ??= { hosts: new Set(), rows: 0 });
  b.hosts.add(s.host);
  b.rows += s.rows.length;
}

console.log('\nrepository        hosts   rows parsed   currently stored');
for (const [repo, b] of Object.entries(summary)) {
  const now = db.prepare(
    `select count(e.id) n from char_uploads u join char_entities e on e.upload_id = u.id
     where u.repo = ?`).get(repo).n;
  console.log(`  ${repo.padEnd(17)} ${String(b.hosts.size).padStart(4)}   ${String(b.rows).padStart(11)}`
    + `   ${String(now).padStart(16)}`);
}

if (!apply) {
  console.log('\ndry run — nothing written. Pass --apply to commit.');
  process.exit(0);
}

/*
  The placeholders are each the single survivor of a destroyed set, and they
  carry the catch-all's {label,name,value} shape rather than the shape their
  repository keys on. Superseded wholesale rather than merged, so the
  repository does not end up half in one shape and half in the other.
*/
const replaced = new Set(Object.keys(summary).filter(r => r !== 'connections'));
let dropped = 0;
db.exec('begin');
try {
  for (const repo of replaced) {
    const olds = db.prepare(
      "select id from char_uploads where repo = ? and source_format like '%PSConsoleHistory%'"
      + " or repo = ? and source_format like '%SMBShares%'"
      + " or repo = ? and source_format like '%SMBEnabledVersions%'").all(repo, repo, repo);
    for (const o of olds) {
      dropped += db.prepare('delete from char_entities where upload_id = ?').run(o.id).changes;
      db.prepare('delete from char_uploads where id = ?').run(o.id);
    }
  }
  db.exec('commit');
} catch (e) { db.exec('rollback'); throw e; }

let inserted = 0;
for (const s of staged) {
  const out = stageSnapshot(db, {
    repo: s.repo,
    host: s.host,
    snapshotId: snapshotFor(s.repo),
    entities: s.rows,
    sourceFormat: `recovered from the original upload ${s.from.slice(0, 8)}`,
    claimedRows: s.rows.length,
  });
  inserted += out?.stored ?? s.rows.length;
}

console.log(`\nreplaced ${dropped} placeholder row(s); staged ${inserted} recovered row(s).`);
