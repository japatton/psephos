/**
 * Import an existing 18-column investigation CSV into the store.
 *
 *   node tools/import-csv.mjs <file.csv> [--state filed] [--thread A]
 *
 * Exists so a hunt already in progress does not have to start from an empty
 * map. Records land as `filed` by default, because they were already worked.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { openDb, initSchema } from '../store/db.js';
import { seedThreads, listThreads } from '../store/threads.js';
import { seedHosts } from '../store/hosts.js';
import { createRecord, COLUMNS, HEADERS } from '../store/records.js';

/** RFC 4180 parser — the analyst notes contain commas, quotes and newlines. */
function parseCsv(text) {
  const rows = [];
  let row = [], field = '', quoted = false;
  const s = text.replace(/^﻿/, '');

  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (quoted) {
      if (c === '"') {
        if (s[i + 1] === '"') { field += '"'; i++; }
        else quoted = false;
      } else field += c;
    } else if (c === '"') quoted = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\r') { /* handled with \n */ }
    else if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; }
    else field += c;
  }
  if (field !== '' || row.length) { row.push(field); rows.push(row); }
  return rows.filter(r => r.some(c => c.trim() !== ''));
}

const norm = (h) => h.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();

/** Map the workbook's header text onto our column names. */
function headerMap(header) {
  const map = new Map();
  const canonical = new Map(HEADERS.map((h, i) => [norm(h), COLUMNS[i]]));
  const aliases = new Map([
    ['event id', 'event_id'], ['event time', 'event_time'], ['hostname', 'hostname'],
    ['source ip', 'source_ip'], ['destination ip', 'destination_ip'], ['user', 'user'],
    ['indicator process name executable', 'indicator'], ['indicator', 'indicator'],
    ['command', 'command'], ['pid', 'pid'], ['sha256 hash', 'sha256'], ['sha256', 'sha256'],
    ['description justification', 'description'], ['description', 'description'],
    ['misp when applicable or file contents', 'misp'], ['misp', 'misp'],
    ['evidence source', 'evidence_source'], ['confidence', 'confidence'],
    ['triage status', 'triage_status'], ['analyst notes', 'analyst_notes'],
    ['mitre att ck', 'mitre'], ['mitre attack', 'mitre'], ['mitre', 'mitre'],
    ['reference', 'reference'],
  ]);
  header.forEach((h, i) => {
    const key = norm(h);
    const col = canonical.get(key) ?? aliases.get(key);
    if (col) map.set(i, col);
  });
  return map;
}

const file = process.argv[2];
if (!file) {
  console.error('usage: node tools/import-csv.mjs <file.csv> [--state filed|pending] [--thread A]');
  process.exit(1);
}
const stateArg = process.argv.includes('--state')
  ? process.argv[process.argv.indexOf('--state') + 1] : 'filed';
const threadKey = process.argv.includes('--thread')
  ? process.argv[process.argv.indexOf('--thread') + 1] : null;

const db = openDb(resolve(process.env.HUNT_DB || 'data/hunt.db'));
initSchema(db);
seedThreads(db);
seedHosts(db);

const threadId = threadKey
  ? (listThreads(db).find(t => t.key === threadKey)?.id ?? null) : null;
if (threadKey && !threadId) console.warn(`warning: no thread with key ${threadKey}; importing unassigned`);

const rows = parseCsv(readFileSync(file, 'utf8'));
const map = headerMap(rows[0]);
if (map.size === 0) { console.error('no recognisable 18-column headers in row 1'); process.exit(1); }

let imported = 0;
const tiers = { exact: 0, approximate: 0, unplaceable: 0 };

for (const row of rows.slice(1)) {
  const fields = {};
  for (const [i, col] of map) fields[col] = row[i] ?? '';
  if (!(fields.description ?? '').trim()) continue;
  const rec = createRecord(db, fields, { analyst: 'import', state: stateArg, threadId });
  tiers[rec.time_tier]++;
  imported++;
}

console.log(`imported ${imported} records as ${stateArg}` + (threadKey ? ` into thread ${threadKey}` : ''));
console.log(`  time tiers: ${tiers.exact} exact, ${tiers.approximate} approximate, ${tiers.unplaceable} unplaceable`);
console.log(`  columns mapped: ${map.size} of 18`);
