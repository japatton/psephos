/**
 * HuntPlan.xlsx -> canonical hunt plan JSON.
 *
 *   node tools/import-huntplan.mjs <HuntPlan.xlsx> [--out plans/huntplan.json] [--no-expand] [--no-mission-phases]
 *
 * The team's spreadsheet is the source of truth for WHAT to hunt. Every row
 * becomes a task with source:"team" and its original cells preserved verbatim
 * under `original`, so nothing the team wrote is paraphrased away.
 *
 * Expansion is layered on top and always marked source:"expanded", so an
 * analyst can tell at a glance which procedure came from the team and which
 * came from a standards reference. Run with --no-expand to see the plan
 * exactly as uploaded.
 *
 * xlsx is a zip of XML, so this reads it with node:zlib rather than adding a
 * dependency — the same approach export/xlsx.js uses to write one.
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { inflateRawSync } from 'node:zlib';
import { dirname, resolve } from 'node:path';
import { expandPlan } from '../plans/expansion.mjs';
import { addMissionPhases } from '../plans/mission-phases.mjs';

// --- minimal xlsx reader ---------------------------------------------------

function unzip(buf) {
  const out = new Map();
  let eocd = buf.length - 22;
  while (eocd >= 0 && buf.readUInt32LE(eocd) !== 0x06054b50) eocd--;
  if (eocd < 0) throw new Error('not a zip file');
  const count = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);
  for (let i = 0; i < count; i++) {
    const method = buf.readUInt16LE(p + 10);
    const csize = buf.readUInt32LE(p + 20);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const cmtLen = buf.readUInt16LE(p + 32);
    const local = buf.readUInt32LE(p + 42);
    const name = buf.toString('utf8', p + 46, p + 46 + nameLen);
    const start = local + 30 + buf.readUInt16LE(local + 26) + buf.readUInt16LE(local + 28);
    const body = buf.subarray(start, start + csize);
    out.set(name, method === 8 ? inflateRawSync(body) : body);
    p += 46 + nameLen + extraLen + cmtLen;
  }
  return out;
}

const unesc = (s) => s
  .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"')
  .replace(/&#x27;|&apos;/g, "'").replace(/&amp;/g, '&');

function sharedStrings(parts) {
  const xml = parts.get('xl/sharedStrings.xml');
  if (!xml) return [];
  // One <si> may hold several <t> runs; concatenating them keeps the cell whole.
  return [...xml.toString('utf8').matchAll(/<si>([\s\S]*?)<\/si>/g)].map(m =>
    unesc([...m[1].matchAll(/<t[^>]*>([\s\S]*?)<\/t>/g)].map(t => t[1]).join('')));
}

function readSheet(parts, strings) {
  const xml = (parts.get('xl/worksheets/sheet1.xml') ?? Buffer.from('')).toString('utf8');
  const rows = [];
  for (const rm of xml.matchAll(/<row[^>]*r="(\d+)"[^>]*>([\s\S]*?)<\/row>/g)) {
    const cells = {};
    for (const cm of rm[2].matchAll(/<c r="([A-Z]+)\d+"([^>]*)>([\s\S]*?)<\/c>/g)) {
      const [, col, attrs, body] = cm;
      let v = '';
      if (/t="s"/.test(attrs)) {
        const i = /<v>(\d+)<\/v>/.exec(body);
        if (i) v = strings[+i[1]] ?? '';
      } else if (/t="inlineStr"/.test(attrs)) {
        v = unesc([...body.matchAll(/<t[^>]*>([\s\S]*?)<\/t>/g)].map(t => t[1]).join(''));
      } else {
        const i = /<v>([\s\S]*?)<\/v>/.exec(body);
        if (i) v = unesc(i[1]);
      }
      cells[col] = v;
    }
    rows.push({ n: +rm[1], cells });
  }
  return rows;
}

// --- shape -----------------------------------------------------------------

const COLS = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I'];
const FIELDS = ['objective', 'task', 'ttp', 'evidence', 'tool', 'data', 'command', 'analysis', 'doNext'];

/** "T1078.002, T1133" out of free text, however the analyst wrote it. */
const mitreIds = (s) => [...new Set(
  [...String(s ?? '').matchAll(/\b(T[AS]?\d{3,4}(?:\.\d{3})?)\b/g)].map(m => m[1]))];

const splitList = (s) => String(s ?? '')
  .split(/[\n;]+/).map(x => x.trim()).filter(Boolean);

const slug = (s) => String(s ?? '').toLowerCase()
  .replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 48);

export function parseWorkbook(buf) {
  const parts = unzip(buf);
  const rows = readSheet(parts, sharedStrings(parts));
  if (rows.length < 2) throw new Error('sheet has no data rows');

  const phases = new Map();
  const seen = new Map();
  let skipped = 0;

  for (const r of rows.slice(1)) {
    const get = (i) => (r.cells[COLS[i]] ?? '').trim();
    const rec = Object.fromEntries(FIELDS.map((f, i) => [f, get(i)]));
    if (!rec.objective && !rec.task) { skipped++; continue; }

    // "2. Initial Access" -> key P2, name "Initial Access"
    const m = /^\s*(\d+)\.\s*(.+)$/.exec(rec.objective);
    const pkey = m ? `P${m[1]}` : slug(rec.objective).toUpperCase() || 'P0';
    const pname = m ? m[2].trim() : rec.objective;

    if (!phases.has(pkey)) {
      phases.set(pkey, { key: pkey, name: pname, intent: '', source: 'team', tasks: [] });
    }
    const phase = phases.get(pkey);

    // Two rows can carry the same task name (the plan has three such pairs);
    // they are distinct approaches, so suffix rather than collapse.
    const base = `${pkey}-${slug(rec.task) || 'task'}`;
    const n = (seen.get(base) ?? 0) + 1;
    seen.set(base, n);

    phase.tasks.push({
      key: n > 1 ? `${base}-${n}` : base,
      title: rec.task || '(untitled)',
      source: 'team',
      intent: '',
      mitre: mitreIds(`${rec.ttp} ${rec.evidence}`),
      ttpText: rec.ttp,
      tools: splitList(rec.tool),
      dataSources: splitList(rec.data),
      commands: splitList(rec.command),
      evidenceExpected: rec.evidence,
      analysis: rec.analysis,
      doNext: rec.doNext,
      assignees: [],
      steps: [],
      // Verbatim, so nothing the team wrote is lost to normalisation.
      original: rec,
    });
  }

  return { phases: [...phases.values()], skipped, rowCount: rows.length - 1 };
}

// --- run -------------------------------------------------------------------

const args = process.argv.slice(2);
const src = args.find(a => !a.startsWith('--'));
const outIdx = args.indexOf('--out');
const out = outIdx >= 0 ? args[outIdx + 1] : 'plans/huntplan.json';
const doExpand = !args.includes('--no-expand');

if (!src) {
  console.error('usage: node tools/import-huntplan.mjs <HuntPlan.xlsx> [--out file] [--no-expand]');
  process.exit(1);
}

const parsed = parseWorkbook(readFileSync(src));
let plan = {
  plan: {
    name: 'Hunt Plan',
    version: 'week2',
    period: 'Week 2 — Linux and OT/ICS',
    objective: 'Hunt the defended terrain, with the week weighted toward the Linux and OT/ICS estate.',
    sourceFile: src.split(/[\\/]/).pop(),
    importedAt: new Date().toISOString(),
  },
  phases: parsed.phases,
};

const teamTasks = plan.phases.reduce((n, p) => n + p.tasks.length, 0);
if (doExpand) plan = expandPlan(plan);
// The mission-phase frame (M0-M4) layers on last, so P1-P8 keep their keys.
if (doExpand && !args.includes('--no-mission-phases')) plan = addMissionPhases(plan);

mkdirSync(dirname(resolve(out)), { recursive: true });
writeFileSync(out, JSON.stringify(plan, null, 2) + '\n', 'utf8');

const all = plan.phases.flatMap(p => p.tasks);
console.log(`read ${parsed.rowCount} rows from ${src}${parsed.skipped ? ` (${parsed.skipped} blank)` : ''}`);
console.log(`  team tasks     ${teamTasks}`);
if (doExpand) {
  console.log(`  added tasks    ${all.filter(t => t.source === 'expanded').length}`);
  console.log(`  steps written  ${all.reduce((n, t) => n + t.steps.length, 0)}`);
}
console.log(`  phases         ${plan.phases.length}`);
console.log(`  wrote          ${out}`);
