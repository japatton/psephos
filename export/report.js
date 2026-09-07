/**
 * The engagement deliverable, assembled from what the case file already holds.
 *
 * The tool produced spreadsheets and the deliverable is a report, so the last
 * step of every engagement was somebody retyping the store into a document.
 * Every input a hunt report conventionally needs — findings, analysis, gaps,
 * indicators, what was looked for, who decided what — was already recorded.
 *
 * Deterministic and complete on its own. Nothing here is drafted by a model:
 * the findings table is a statement about evidence, and a paraphrase of it is
 * a different claim. If a narrative summary is wanted on top, it belongs above
 * this material and in front of a human, not woven through it.
 *
 * Markdown because it is the format that survives being pasted anywhere.
 */

const h = (level, text) => `${'#'.repeat(level)} ${text}\n\n`;

/** An em-rule of a section that has nothing in it, rather than an absent one.
 *  A missing section reads as an oversight; an empty one is a finding. */
const orNone = (lines, none) => (lines.length ? lines.join('\n') : `_${none}_`) + '\n\n';

const escapePipes = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\n+/g, ' ').trim();

export function buildReport({
  mission = {},
  generatedAt = new Date().toISOString(),
  threads = [],
  records = [],
  hosts = [],
  plan = {},
  gaps = [],
  emptyRepos = [],
  iocs = [],
} = {}) {
  const filed = records.filter(r => r.state === 'filed');
  const pending = records.filter(r => r.state === 'pending');
  const byThread = new Map(threads.map(t => [t.id, []]));
  const unassigned = [];
  for (const r of filed) {
    (byThread.get(r.thread_id) ?? unassigned).push(r);
  }

  let md = '';
  md += h(1, `${mission.name ?? 'Hunt'} — hunt report`);
  md += `${[mission.week, `Generated ${generatedAt.slice(0, 10)}`]
    .filter(Boolean).join(' · ')}\n\n`;

  /*
    Said before anything else, because a reader who takes the findings as the
    whole picture has been misled by omission. The counts are the honest frame:
    what was confirmed, what is still somebody's open question.
  */
  md += h(2, 'Summary');
  md += `- **${filed.length}** confirmed finding${filed.length === 1 ? '' : 's'}\n`;
  md += `- **${pending.length}** proposal${pending.length === 1 ? '' : 's'} awaiting adjudication`
    + `${pending.length ? ' — not included as findings below' : ''}\n`;
  /*
    'confirmed' is the word the store actually holds — the hosts CHECK allows
    unknown, suspected, confirmed and cleared, and nothing else can ever be
    written. This filtered on 'compromised', which the drawer uses as a LABEL
    ("Confirmed compromised") and the schema rejects, so the deliverable
    reported zero compromised hosts however many the team had adjudicated.
  */
  const compromised = hosts.filter(x => x.verdict === 'confirmed');
  md += `- **${compromised.length}** host${compromised.length === 1 ? '' : 's'} assessed compromised`
    + ` of ${hosts.length} in the estate\n`;
  if (plan.summary) {
    md += `- **${plan.summary.complete ?? 0}** of ${plan.summary.total ?? 0} planned tasks complete\n`;
  }
  md += '\n';

  // --- findings -------------------------------------------------------------------
  md += h(2, 'Findings');
  if (!filed.length) {
    md += '_No confirmed findings. Nothing in this case file has been adjudicated as a '
      + 'finding, which is a result and not an omission._\n\n';
  } else {
    for (const t of threads) {
      const rs = byThread.get(t.id) ?? [];
      if (!rs.length) continue;
      md += h(3, `${t.key ? `${t.key} — ` : ''}${t.name}`);
      md += table(rs);
    }
    if (unassigned.length) {
      md += h(3, 'Not assigned to a thread');
      md += table(unassigned);
    }
  }

  // --- estate ---------------------------------------------------------------------
  md += h(2, 'Hosts assessed');
  md += orNone(compromised.map(x => `- **${x.name}**${x.ip ? ` (${x.ip})` : ''} — compromised`),
    'No host has been assessed compromised.');

  // --- coverage and gaps ----------------------------------------------------------
  /*
    The section most teams write from memory on the last afternoon. Everything
    in it was recorded as it happened, which is the difference between "we think
    we covered that" and knowing.
  */
  md += h(2, 'Coverage and gaps');
  const gapLines = [
    ...gaps.map(g => `- \`${g.repo ?? '?'}\`: **${g.field}** was not collected`
      + `${g.note ? ` — ${escapePipes(g.note)}` : ''}`),
    ...emptyRepos.map(r => `- \`${r}\`: nothing collected`),
    // 'unanswered' is the survey's word for it; 'no response' is the map's
    // label for that word, and filtering on the label matched nothing.
    ...hosts.filter(x => x.presence === 'unanswered')
      .map(x => `- **${x.name}** did not answer collection`),
  ];
  md += orNone(gapLines, 'No coverage gaps were recorded.');

  // --- what was looked for --------------------------------------------------------
  md += h(2, 'What was looked for');
  const taskLines = [];
  for (const ph of plan.phases ?? []) {
    taskLines.push(`- **${ph.name}**`);
    for (const t of ph.tasks ?? []) {
      taskLines.push(`  - ${t.status === 'complete' ? '[x]' : '[ ]'} ${t.title}`);
    }
  }
  md += orNone(taskLines, 'No hunt plan was loaded.');

  // --- indicators -----------------------------------------------------------------
  if (iocs.length) {
    md += h(2, 'Indicators');
    md += '| Type | Value | Records |\n|---|---|---|\n';
    for (const i of iocs) {
      md += `| ${i.type} | \`${escapePipes(i.value)}\` | ${escapePipes(i.from)} |\n`;
    }
    md += '\n';
  }

  md += '---\n\n';
  md += '_Assembled from the case file. Confirmed findings only; proposals awaiting '
    + 'adjudication are counted in the summary and reported nowhere else._\n';
  return md;
}

function table(rs) {
  let out = '| Event | Time | Host | ATT&CK | Description |\n|---|---|---|---|---|\n';
  for (const r of rs) {
    out += `| ${escapePipes(r.event_id || r.id)} | ${escapePipes(r.event_time) || '—'} `
      + `| ${escapePipes(r.hostname) || '—'} | ${escapePipes(r.mitre) || '—'} `
      + `| ${escapePipes(r.description)} |\n`;
  }
  return `${out}\n`;
}
