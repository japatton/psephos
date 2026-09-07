/**
 * Import a Nessus / ACAS CSV export into the vulnerabilities baseline.
 *
 *   node tools/import-nessus.mjs <export.csv> [--dry-run] [--analyst NAME]
 *
 * Parsed in code rather than pushed through the model. Characterization
 * uploads generally go to Claude because appliance and OT output will not match
 * any parser worth writing — but a Nessus CSV is a fixed, well-specified shape
 * the team will export every scan cycle, and a thousand-row file costs real
 * quota to extract and can silently lose rows doing it. Deterministic here is
 * free, exact, and repeatable.
 *
 * One snapshot is written per host, because that is the unit the diff works on:
 * "what changed on this host since the last scan" is the question M1V-tt6 asks
 * daily, and "what did this scan find that the last one did not" is M1V-tt7.
 */
import { readFileSync, existsSync } from 'node:fs';
import { openDb, initSchema } from '../store/db.js';
import { stageSnapshot, repoView } from '../store/characterization.js';

/**
 * RFC 4180 enough for Tenable: quoted fields, doubled quotes to escape, and
 * embedded newlines — which Nessus uses heavily in Solution and Plugin Output,
 * so a line-based split would shred the file.
 */
export function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;

  const src = text.replace(/^﻿/, '').replace(/\r\n/g, '\n');
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (quoted) {
      if (c === '"') {
        if (src[i + 1] === '"') { field += '"'; i++; } else quoted = false;
      } else field += c;
      continue;
    }
    if (c === '"') { quoted = true; continue; }
    if (c === ',') { row.push(field); field = ''; continue; }
    if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; continue; }
    field += c;
  }
  if (field !== '' || row.length) { row.push(field); rows.push(row); }
  return rows.filter(r => r.some(f => f.trim() !== ''));
}

const pick = (header, ...names) => {
  for (const n of names) {
    const i = header.findIndex(h => h.trim().toLowerCase() === n.toLowerCase());
    if (i >= 0) return i;
  }
  return -1;
};

/** Nessus rows to entities, grouped by the host they were found on. */
export function nessusToHosts(text) {
  const rows = parseCsv(text);
  if (!rows.length) return { byHost: new Map(), total: 0, skipped: 0 };
  const header = rows[0];

  const col = {
    plugin: pick(header, 'Plugin ID', 'Plugin'),
    cve: pick(header, 'CVE'),
    risk: pick(header, 'Risk', 'Severity', 'Risk Factor'),
    host: pick(header, 'Host', 'IP Address', 'DNS Name'),
    name: pick(header, 'Name', 'Plugin Name'),
    synopsis: pick(header, 'Synopsis'),
    solution: pick(header, 'Solution'),
    output: pick(header, 'Plugin Output'),
    cvss: pick(header, 'CVSS v3.0 Base Score', 'CVSS v3 Base Score', 'CVSS Base Score', 'CVSS'),
    port: pick(header, 'Port'),
    protocol: pick(header, 'Protocol'),
  };
  if (col.host < 0 || col.plugin < 0) {
    throw new Error('this does not look like a Nessus export: no Host or Plugin ID column');
  }

  const at = (r, i) => (i >= 0 ? String(r[i] ?? '').trim() : '');
  const byHost = new Map();
  let skipped = 0;

  for (const r of rows.slice(1)) {
    const host = at(r, col.host);
    if (!host) { skipped++; continue; }
    if (!byHost.has(host)) byHost.set(host, []);
    byHost.get(host).push({
      name: at(r, col.name),
      risk: at(r, col.risk) || 'None',
      cvss: at(r, col.cvss),
      cve: at(r, col.cve),
      pluginId: at(r, col.plugin),
      port: at(r, col.port),
      protocol: at(r, col.protocol),
      synopsis: at(r, col.synopsis),
      solution: at(r, col.solution).replace(/\s+/g, ' ').slice(0, 400),
      // Host-specific detail — the clock skew, the cipher list, the community
      // string. Kept because it is what makes one host's finding differ from
      // another's, which is exactly what the diff compares.
      output: at(r, col.output).replace(/\s+/g, ' ').trim().slice(0, 600),
    });
  }
  return { byHost, total: rows.length - 1, skipped };
}

// --- cli --------------------------------------------------------------------

if (import.meta.url === `file://${process.argv[1].replace(/\\/g, '/')}` ||
    process.argv[1]?.endsWith('import-nessus.mjs')) {
  const args = process.argv.slice(2);
  const src = args.find(a => !a.startsWith('--'));
  const dryRun = args.includes('--dry-run');
  const ai = args.indexOf('--analyst');
  const analyst = ai >= 0 ? args[ai + 1] : 'nessus-import';

  if (!src || !existsSync(src)) {
    console.error('usage: node tools/import-nessus.mjs <export.csv> [--dry-run] [--analyst NAME]');
    process.exit(1);
  }

  const { byHost, total, skipped } = nessusToHosts(readFileSync(src, 'utf8'));
  console.log(`\n  ${src}`);
  console.log(`  ${total} finding row(s) across ${byHost.size} host(s)` +
    `${skipped ? `, ${skipped} skipped with no host` : ''}\n`);

  const bySeverity = {};
  for (const rows of byHost.values()) for (const e of rows) bySeverity[e.risk] = (bySeverity[e.risk] ?? 0) + 1;
  for (const [k, v] of Object.entries(bySeverity).sort((a, b) => b[1] - a[1])) {
    console.log(`    ${String(v).padStart(5)}  ${k}`);
  }

  if (dryRun) { console.log('\n  --dry-run: nothing was written.\n'); process.exit(0); }

  const db = openDb(process.env.HUNT_DB || 'data/hunt.db');
  initSchema(db);
  let incomplete = 0;
  for (const [host, entities] of byHost) {
    const snap = stageSnapshot(db, {
      repo: 'vulnerabilities', host, sourceFormat: 'Nessus CSV export',
      claimedRows: entities.length, countedRows: entities.length,
      entities, analyst,
    });
    if (snap.status === 'incomplete') incomplete++;
  }

  const v = repoView(db, 'vulnerabilities');
  console.log(`\n  staged ${byHost.size} snapshot(s)` +
    `${incomplete ? `, ${incomplete} flagged incomplete` : ''}`);
  console.log(`  ${v.counts.total} row(s) in the baseline: ` +
    `${v.counts.new} new, ${v.counts.changed} changed, ${v.counts.gone} gone\n`);
}
