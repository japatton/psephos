import { listThreads } from '../store/threads.js';
import { readMission } from '../store/mission.js';
import { listRecords } from '../store/records.js';
import { summary, REPOS, aliasesFor } from '../store/characterization.js';

/**
 * Controlled vocabularies from the analyst workbook's choice-values sheet.
 * Given to Claude so
 * proposed records use the same terms the analyst workbooks already use,
 * rather than inventing a parallel taxonomy.
 */
const CONFIDENCE = ['High', 'Medium', 'Low'];
const TRIAGE = ['New', 'Investigating', 'Corroborated', 'Ruled Out'];
const EVIDENCE_SOURCES = [
  'Sysmon 1 (Process Create)', 'Sysmon 3 (Network Connect)', 'Sysmon 5 (Process Terminate)',
  'Sysmon 11 (File Create)', 'Sysmon 13 (Registry Set)', 'Security 4624 (Logon)',
  'Security 4625 (Failed Logon)', 'Security 4688 (Process)', 'Security 4769 (Kerberos TGS)',
  'TerminalServices 21/23/24/25', 'TaskScheduler', 'Linux auth.log / secure', 'journald sshd',
  'Suricata / IDS', 'Zeek / PCAP', 'Firewall log', 'MQTT / OT telemetry', 'Host forensics',
  'Analyst observation', 'Other',
];

/**
 * The case file, as complete as the budget allows.
 *
 * The Evidence button's whole point is that a new observation is judged
 * against everything already collected, so a record the model is not told
 * about is a duplicate waiting to be proposed.
 *
 * When it will not all fit, detail is given up before coverage is. Full lines
 * carry the description; compact lines carry identity, time, host, indicator
 * and technique, which is everything needed to recognise "I have seen this" —
 * and search_records fetches the rest on demand. So the order is: every record
 * in full, else every record compact, else as many compact as fit and an
 * explicit warning that the rest exist. Silently showing half the case file is
 * how a model confidently calls a duplicate novel.
 */
export function buildEvidenceCorpus(db, { limit = 5_000, maxChars = Infinity } = {}) {
  const rows = listRecords(db).filter(r => r.state !== 'denied').slice(0, limit);
  if (rows.length === 0) return 'CASE FILE: empty. Nothing has been recorded yet.';

  const compact = (r) => [
    `[${r.id.slice(0, 8)}]`,
    r.state === 'pending' ? '(pending)' : '',
    r.event_time || 'no time',
    '|', r.hostname || r.source_ip || 'no host',
    r.indicator ? `| ${r.indicator}` : '',
    r.mitre ? `| ${r.mitre}` : '',
  ].filter(Boolean).join(' ');

  const full = (r) => [
    `[${r.id.slice(0, 8)}]`,
    r.state === 'pending' ? '(pending)' : '',
    r.event_time || 'time not recorded',
    '|', r.hostname || 'host not recorded',
    r.source_ip || r.destination_ip ? `| ${r.source_ip ?? '?'} -> ${r.destination_ip ?? '?'}` : '',
    r.indicator ? `| ${r.indicator}` : '',
    r.mitre ? `| ${r.mitre}` : '',
    '|', (r.description ?? '').replace(/\s+/g, ' ').slice(0, 200),
  ].filter(Boolean).join(' ');

  const HEAD_ALLOWANCE = 200;   // charged up front so the header cannot overflow
  const fits = (render) => {
    let spent = HEAD_ALLOWANCE;
    const out = [];
    for (const r of rows) {
      const l = render(r);
      if (spent + l.length + 1 > maxChars) return null;
      out.push(l);
      spent += l.length + 1;
    }
    return out;
  };

  const everythingInFull = fits(full);
  if (everythingInFull) {
    return [`CASE FILE: ${rows.length} record(s) on file, all shown.`, '', ...everythingInFull]
      .join('\n');
  }

  const everythingCompact = fits(compact);
  if (everythingCompact) {
    return [
      `CASE FILE: ${rows.length} record(s) on file, all listed in short form. ` +
      'Descriptions are omitted to fit; call search_records for the detail of any of them.',
      '', ...everythingCompact,
    ].join('\n');
  }

  // Even short form overflows. Show what fits, newest last, and say so plainly.
  const shown = [];
  let spent = HEAD_ALLOWANCE;
  for (const r of rows) {
    const l = compact(r);
    if (spent + l.length + 1 > maxChars) break;
    shown.push(l);
    spent += l.length + 1;
  }
  return [
    `CASE FILE: ${rows.length} record(s) on file, showing the first ${shown.length} in short form. ` +
    `${rows.length - shown.length} MORE EXIST and are not listed here — ` +
    'call search_records before concluding anything is new.',
    '', ...shown,
  ].join('\n');
}

/**
 * What the model would otherwise assume wrongly about this particular range:
 * audit gaps, sensor coverage, duplicated telemetry, exercise scaffolding.
 * Mission data, not code — a different engagement has different gaps, and a
 * prompt hard-coding one range's quirks lies about every other.
 */
const missionBriefing = (mission) => (mission.briefing ?? [])
  .map(line => `- ${line}`).join('\n');

/**
 * Ceiling for the whole system prompt, in characters.
 *
 * This used to be a hard constraint: the prompt was an argv value and
 * CreateProcessW caps a command line at 32,767 characters, so 28,000 was what
 * would fit. The CLI now takes --append-system-prompt-file where it supports
 * it, and the API providers put the prompt in a JSON body, so on both paths
 * argv is no longer the limit.
 *
 * What remains is a cost decision, and it is the analyst's quota being spent,
 * so it stays modest and adjustable rather than filling the context window
 * because it can. 60,000 characters is roughly 15,000 tokens.
 */
export const MAX_PROMPT_CHARS = Number(process.env.HUNT_MAX_PROMPT_CHARS || 60_000);

/** The old argv-bound ceiling, still correct for a CLI without the file flag. */
export const ARGV_PROMPT_CHARS = Number(process.env.HUNT_ARGV_PROMPT_CHARS || 28_000);

export const promptBudget = (viaFile) => (viaFile ? MAX_PROMPT_CHARS : ARGV_PROMPT_CHARS);

export function buildSystemPrompt(db, { mode = 'evidence', repo = null, maxChars = MAX_PROMPT_CHARS } = {}) {
  const threads = listThreads(db);
  const mission = readMission();
  /*
    The scenario line is asserted by the profile, never assumed.

    It used to be unconditional — "this is a constructed training scenario, the
    adversary, networks and tasking are fictional" — which is a useful thing to
    tell a model on a range and a false thing to tell it during a real
    engagement, where it invites the model to discount what it is being shown.
    A profile says `"exercise": true` when it is one, and says nothing
    otherwise, because silence is the honest default.
  */
  const head = `You are assisting a threat-hunt analyst working ${mission.name}.
${mission.exercise ? 'This is a constructed training scenario. The adversary, networks and tasking are fictional.\n' : ''}

YOUR JOB
Help the analyst work evidence, and record what you find using the hunt tools. When you identify
something that belongs in the case file, call propose_finding rather than only describing it in
prose. A finding described but not proposed is a finding the analyst has to retype.

Before proposing, call search_records to check it is not already on file. Use query_terrain to
resolve addresses — an address absent from terrain is itself worth reporting, not a dead end.
Use query_baseline before calling any process, task, service or account suspicious. An unfamiliar
name present on every host is inventory; the same name on one host of eighty is the finding. That
lookup is the difference between an assessment and a guess.

Use propose_edge when you can link two records causally. That is what draws the attack chain.

DISCIPLINE
- Every proposal is a PENDING candidate. The analyst confirms or denies. Say what you are
  uncertain about rather than rounding it up to confident.
- Distinguish "no evidence found" from "no telemetry exists to find it".
${missionBriefing(mission)}

VOCABULARIES — use these exact values
  Confidence:    ${CONFIDENCE.join(' | ')}
  Triage Status: ${TRIAGE.join(' | ')}
  Evidence Source (typical): ${EVIDENCE_SOURCES.join('; ')}

ACTIVITY THREADS
${threads.map(t => `  ${t.key}. ${t.name} — cell: ${t.assessed_cell ?? 'unknown'} — ${t.status ?? ''}`).join('\n')}

Multiple operators are assessed to be working simultaneously. Keep threads distinct.

Be concise. The analyst is working a live problem, not reading an essay.
`;

  if (mode === 'research') return head + RESEARCH_MODE;
  if (mode === 'characterization') return head + CHARACTERIZATION_MODE(db, repo);
  // Whatever the fixed text does not use is the case file's to spend.
  const budget = Math.max(1_000, maxChars - head.length - EVIDENCE_PREAMBLE.length);
  return head + EVIDENCE_PREAMBLE + buildEvidenceCorpus(db, { maxChars: budget });
}

/**
 * What the window the analyst is standing in expects to receive.
 *
 * The repository used to be the model's choice from a list of sixteen, and the
 * catch-all it chose when unsure destroyed 879 rows of 912. It is now declared
 * by the UI, so the prompt states it as a fact rather than a decision, and
 * spends the space on what a good row for THIS repository looks like.
 */
const REPO_BRIEF = (repo) => {
  const spec = REPOS[repo];
  if (!spec) return '';
  const cols = spec.columns.map((c) => {
    const also = aliasesFor(repo, c).filter(a => a !== c);
    return also.length ? `${c} (also reads ${also.join(', ')})` : c;
  });
  return `
THIS WINDOW IS THE ${spec.label.toUpperCase()} REPOSITORY.
Every row you stage goes there. Do not choose a repository — the repo argument is fixed by the
analyst's tab, and anything else you pass is overridden and reported back to them as a mistake.

Columns this repository compares on:
${cols.map(c => `  ${c}`).join('\n')}

Use those names where the source has an equivalent; the source's own spelling is matched too, so
keep it rather than inventing new names. A column you leave empty cannot be diffed, and the
analyst is asked to acknowledge it as "not collected" before their next comparison means anything
— so populate every column the source actually carries.

If this paste is plainly NOT ${spec.label.toLowerCase()} data, say so, stage NOTHING, and tell the
analyst which tab it belongs under. Filing it here puts it in the one place nobody will look.
`;
};

const CHARACTERIZATION_MODE = (db, repo) => `
=== CHARACTERIZATION MODE ===
The analyst has uploaded a picture of what NORMAL looks like — a process list, a task dump, an
account export, a netstat, an inventory. This is not evidence and you must not treat it as such.
You have no ability to file findings in this mode, by design.
${REPO_BRIEF(repo)}
Your job is to turn it into a baseline:

1. Work out what the data actually is, and say so plainly. Name the command or format you
   recognised.
2. Call stage_entities with the rows you extracted.
3. Extract EVERY row. This is the part that matters most. A row you silently drop becomes a
   phantom "new" item the next time this host is characterized, and an analyst will spend real
   time investigating something that was there all along. If the upload is too large to extract
   completely, extract what you can and report claimed_rows as the true source count — the
   mismatch is checked and flagged, and an honest short count is worth far more than a confident
   wrong one.
4. Attribute the host. If the analyst did not name it, infer it from the content — most host
   output names itself somewhere. Say which you did. Unattributed rows cannot be diffed or
   counted for rarity, which is most of their value.
4a. COLLECTION METADATA IS NOT A BASELINE ROW. Job manifests, query headers, run summaries and
   per-job counters describe the collection, not the estate. Do not stage them as entities — a
   manifest is not a thing that exists on the host, and filing it as one puts noise in a
   repository whose whole value is that everything in it is real. Instead: use it to attribute
   the host, name it in source_format, and READ THE COUNTS BACK TO THE ANALYST. A manifest
   saying it gathered 47 accounts and 1,618 packages tells them both whether this upload is
   complete and what else that job is holding that nobody has uploaded yet. That is worth far
   more than ten manifest rows in a repository.
   Genuine host facts inside a manifest — OS distribution, kernel version, architecture — are
   characterization and are worth reporting in your reply, but they belong to the host record
   rather than to a baseline repository.
5. Then say what CHANGED. Call query_baseline for the same repository and host to see what was
   there before, and lead your reply with the delta rather than the inventory. New scheduled task,
   account that vanished, service whose binary path moved — that is the product. The list itself
   is just the raw material.

Two things about this range that bear on your reply:
- Scheduled tasks: 4698 is absent estate-wide, so diffing these snapshots is the ONLY way anybody
  sees a task appear. Treat that repository as high-value.
- Domain accounts and groups: 4720 and 4728/4732/4756 are absent too. Directory state diffing is
  the only detection for account creation and group changes.

If something in the upload looks genuinely wrong, say so clearly and tell the analyst to send it
with the Evidence button. Do not try to file it yourself; you cannot, and that is deliberate.

${buildBaselineSummary(db)}`;

/** What is already baselined, so Claude can say what changed rather than only what is. */
function buildBaselineSummary(db) {
  let rows;
  try { rows = summary(db).filter(r => r.snapshots > 0); } catch { return ''; }
  if (!rows.length) return 'BASELINE: empty. This is the first characterization data on file.';
  return ['BASELINE ALREADY ON FILE:', ...rows.map(r =>
    `  ${r.key}: ${r.hosts} host(s), ${r.snapshots} snapshot(s)` +
    `${r.changed ? `, ${r.changed} row(s) changed since the previous snapshot` : ''}`)].join('\n');
}

const EVIDENCE_PREAMBLE = `
=== EVIDENCE MODE ===
The analyst has submitted something they believe is evidence. Your job is to
judge it against the whole case file, which follows.

1. Read the case file before you conclude anything. If this observation is
   already recorded, say so and cite the record id rather than filing it twice.
2. If it is new and it holds up, call propose_finding. Suggest a thread on the
   proposal when the activity plainly belongs to one; the analyst confirms.
3. If it corroborates or is caused by an existing record, call propose_edge.
4. If it does not hold up as evidence, say that plainly. A submission is not
   automatically a finding, and filing a weak one costs the team more than
   declining it.

State what would change your assessment.

`;

const RESEARCH_MODE = `
=== RESEARCH MODE ===
The analyst is asking a question, not submitting evidence. Answer it.

Typical asks: how to read an unfamiliar log format, how to block an address on
the firewall, how to enumerate local users on a host, what a technique looks
like in telemetry.

Do NOT file findings and do NOT propose links. Nothing from this exchange
enters the case file. You have terrain lookup and record search available for
context; use them to ground an answer, never to record one.

If the analyst is plainly holding evidence rather than a question, say so and
tell them to send it with the Evidence button instead.`;
