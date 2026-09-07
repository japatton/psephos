import { state, api, toast, esc, shortTime, preservingFocus, thisMount, stillMounted } from '../core.js';
import { formHtml, readForm, readNewPhase, bindSteps, bindNewPhase } from './plan-edit.js';

let root = null;
let tasks = [];
let summary = {};
let filterTeam = '';
let filterStatus = '';
let filterMine = false;
let openTask = null;
let editing = null;   // task key being edited, or '+<phaseKey>' when adding

/*
  Plan or coverage. The map already uses this shape for Map | List, and a mode
  inside the view it belongs to is better than an eighth top-level tab for
  something you look at while building a plan.
*/
let mode = 'plan';
/*
  Which bank domain Coverage is looking at. Enterprise and ICS are both real
  matrices — ICS is not a special case, it is a second one, per the design
  spec's "not a fourth category, a second matrix" — and share every line of
  matrixHtml() below. Practice has no tactics to grid against, so it renders
  through practiceHtml() instead; domain still gates which loader runs.
*/
let domain = 'enterprise';
let coverage = null;   // matrix shape, enterprise/ics only
let practice = null;   // flat entry list, practice only
let covEntry = null;   // the bank entry behind the clicked cell or list row

const me = () => decodeURIComponent(
  (document.cookie.match(/(?:^|;\s*)hunt_analyst=([^;]*)/) ?? [])[1] ?? '');

const STATUSES = ['pending', 'in-progress', 'complete', 'blocked'];

/** Phases in board order, for the form's phase picker. */
const phaseList = () => {
  const seen = new Map();
  for (const t of tasks) if (!seen.has(t.phaseKey)) seen.set(t.phaseKey, { key: t.phaseKey, name: t.phaseName });
  return [...seen.values()];
};

/*
  Which phase a drawn task lands in. Not a hardcoded 'P1': addTask throws on a
  phase that does not exist, and a plan built from the example or from an upload
  need not have one. The first phase is the honest default, and the task can be
  moved afterwards like any other.
*/
const phaseForNewTasks = () => phaseList()[0]?.key ?? 'P1';

async function load() {
  const d = await api('/api/plan');
  tasks = d.tasks; summary = d.summary;
}

async function loadCoverage() {
  try { coverage = await api(`/api/plan/coverage?domain=${domain}`); } catch { coverage = null; }
}

async function loadPractice() {
  try { practice = await api('/api/bank?domain=practice'); } catch { practice = null; }
}

/*
  Whatever the current domain needs, and nothing else. planCoverage rejects
  'practice' with a 400 by design — practice entries carry no tactics, so there
  is no matrix to grid them against — and calling it anyway on every visit to
  Practice would just be console noise nobody would ever act on.
*/
async function loadDomainData() {
  if (domain === 'practice') { coverage = null; await loadPractice(); }
  else { practice = null; await loadCoverage(); }
}

async function openBankEntry(id) {
  covEntry = null;
  paint();
  try {
    // domain-scoped: an ICS or practice id is not enterprise's to find, and the
    // three domains are disjoint id spaces, so searching the wrong one is a
    // silent miss rather than a slow success.
    const found = await api(`/api/bank?domain=${domain}&q=${encodeURIComponent(id)}`);
    covEntry = found.find(e => e.id === id) ?? null;
  } catch { covEntry = null; }
  paint();
}

const COV_LABEL = {
  none: 'nothing in the plan names it',
  named: 'named by a task with nothing written under it',
  authored: 'named by a task carrying steps',
};

/*
  The entry panel opened by a click, shared by the matrix and the practice
  list: both hand it a bank entry (technique or practice) and the shape it
  reads — id, name, desc, depth, detection — is the same either way. A
  practice entry's detection is always [] (it has no MITRE analytics to
  carry), so that block simply does not render; nothing here needs to know
  which kind of entry it was given.
*/
/*
  What each tier claims, in the panel where somebody decides whether to draw the
  entry. Only the last one asserts anything about this estate; the first two say
  so plainly rather than leaving the reader to assume the flattering reading.
*/
const PROVENANCE_LINE = {
  drafted: 'Drafted from general practice and checked by nobody — read it before you rely on it',
  reviewed: 'Independently reviewed for correctness, but not against this estate — check it fits before you rely on it',
  authored: 'Written here and reviewed against this estate',
};

function covPanelHtml() {
  if (!covEntry) return '';
  return `
    <div class="cov-panel">
      <div class="cov-panel-head">
        <b>${esc(covEntry.id)} — ${esc(covEntry.name)}</b>
        <button data-close-entry>close</button>
      </div>
      ${covEntry.depth
    /*
      The authored argument, not the step count.

      What decides whether this entry is worth drawing is why somebody thought
      it mattered, and a bare "carries 4 steps" hides exactly that behind the
      act of drawing it. MITRE's description is kept underneath and labelled,
      because the two are different claims by different authors and the whole
      design turns on not letting them read alike.

      addTaskFromBank tolerates depth with no steps (an overlay author who has
      written intent and commands but not steps yet); this render must too.
      Every practice entry carries depth by construction, so this branch is the
      one a practice entry always takes.
    */
    /*
      Three claims by three authors, and they must not run together: the
      argument, who stands behind it, and what MITRE says. The provenance line
      gets its own colour when it is the one carrying a caveat; MITRE's text
      stays muted underneath either way, because it is the same claim whoever
      wrote the overlay.
    */
    ? `<p>${esc(covEntry.depth.intent ?? covEntry.desc)}</p>
       <p class="${covEntry.depth.provenance === 'authored' ? 'muted' : 'cov-drafted'}">${
      PROVENANCE_LINE[covEntry.depth.provenance] ?? 'Provenance unknown — treat as unreviewed'}${(covEntry.depth.steps ?? []).length
      ? `, ${(covEntry.depth.steps ?? []).length} steps` : ''}.</p>
       ${covEntry.desc ? `<p class="muted">MITRE says: ${esc(covEntry.desc)}</p>` : ''}`
    : `<p>${esc(covEntry.desc)}</p>
       <p class="muted">No authored task for this one. What follows is MITRE's own detection
         strategy, which is a starting point rather than tradecraft somebody here wrote.</p>`}
      ${covEntry.detection.length ? `
        <ul class="cov-detect">
          ${covEntry.detection.map(d => `<li>${esc(d.strategy)}
            <span class="mono muted">${esc(d.logSources.join(' · '))}</span></li>`).join('')}
        </ul>` : ''}
      <button class="primary" data-add="${esc(covEntry.id)}">Add to the plan</button>
    </div>`;
}

// planCoverage echoes the raw query-string domain back ('enterprise', 'ics'),
// which is fine as a cache key but reads as a typo next to the toggle's own
// "ICS" label — this is display only, never sent anywhere.
const DOMAIN_LABEL = { enterprise: 'Enterprise', ics: 'ICS' };

/*
  Ids the plan names that are no longer in either matrix — revoked or renumbered
  upstream. They colour no cell, so without saying so here the plan would look
  like it covers ground the matrix cannot show it covering. Rendered beside the
  counts rather than as a toast: it is a standing fact about the plan, not an
  event, and it stays true until somebody edits the task.
*/
function orphanHtml() {
  const dead = coverage?.orphans ?? [];
  if (!dead.length) return '';
  return `<p class="cov-orphans">
    The plan names ${dead.length} technique${dead.length === 1 ? '' : 's'} that ATT&amp;CK has
    since revoked or renumbered, so ${dead.length === 1 ? 'it colours' : 'they colour'} no cell
    here and ${dead.length === 1 ? 'is' : 'are'} not counted above:
    <span class="mono">${dead.map(esc).join(' · ')}</span>.
    Look the current number up and edit the task; the old id is not wrong about the
    behaviour, only about where to find it.
  </p>`;
}

function matrixHtml() {
  if (!coverage) return '<div class="loading">Reading the matrix…</div>';
  const { counts } = coverage;
  return `
    <div class="cov-head">
      <b>${counts.authored}</b> techniques carry a written task ·
      <b>${counts.named}</b> named but not written up ·
      <b>${counts.none}</b> not in the plan
      <span class="muted">ATT&CK ${esc(DOMAIN_LABEL[coverage.domain] ?? coverage.domain)} ${esc(coverage.version)}</span>
      <p class="muted">
        Full coverage is not the goal and never has been. What can be hunted is bounded by the
        telemetry that exists and by the threats worth planning for, so most of this matrix
        being uncoloured is the normal state of an honest plan. The useful question is whether
        anything uncoloured should not be.
      </p>
      ${orphanHtml()}
    </div>
    ${covPanelHtml()}
    ${coverage.tactics.map(t => `
      <div class="cov-tactic">
        <h3>${esc(t.tactic.replace(/-/g, ' '))} <span class="muted">${t.techniques.length}</span></h3>
        <div class="cov-grid">
          ${t.techniques.map(x => `
            <button class="cov-cell cov-${x.state}" data-bank="${esc(x.id)}"
              title="${esc(x.id)} ${esc(x.name)} — ${COV_LABEL[x.state]}">
              <span class="cov-id">${esc(x.id)}</span>
              <span class="cov-name">${esc(x.name)}</span>
            </button>`).join('')}
        </div>
      </div>`).join('')}`;
}

const PRACTICE_LABEL = {
  telemetry: 'Telemetry and blind spots',
  hypothesis: 'Hypothesis and negative results',
  deconfliction: 'Deconfliction',
};

/*
  Practice entries have no tactics, so a tactic-grouped grid would be one empty
  group — grouped by category instead, and as a list rather than a grid: three
  categories of a handful of entries each is not dense enough to earn the
  matrix's compressed cells, and these read better with room for a sentence.
*/
function practiceHtml() {
  if (!practice) return '<div class="loading">Reading the bank…</div>';
  // Every practice entry is authored, so there is no stub/named/authored
  // ladder to colour — only "is this one already in the plan", answered from
  // the tasks already loaded rather than a second fetch.
  const drawn = new Set(tasks.map(t => t.bankId).filter(Boolean));
  const byCategory = new Map();
  for (const e of practice) {
    if (!byCategory.has(e.category)) byCategory.set(e.category, []);
    byCategory.get(e.category).push(e);
  }
  return `
    <div class="cov-head">
      <p class="muted">
        No ATT&CK id and no matrix: these are the work around the hunt rather than a
        behaviour in it — telemetry gaps, unstated hypotheses, activity nobody has
        deconflicted — which is where hunts go wrong in ways the matrix cannot show.
      </p>
    </div>
    ${covPanelHtml()}
    ${[...byCategory.entries()].map(([cat, entries]) => `
      <div class="cov-tactic">
        <h3>${esc(PRACTICE_LABEL[cat] ?? cat)} <span class="muted">${entries.length}</span></h3>
        <div class="prac-list">
          ${entries.map(e => `
            <button class="prac-item ${drawn.has(e.id) ? 'prac-drawn' : ''}" data-bank="${esc(e.id)}">
              <span class="prac-name">${esc(e.name)}
                ${drawn.has(e.id) ? '<span class="prac-badge">in the plan</span>' : ''}</span>
              <span class="prac-desc">${esc(e.desc)}</span>
            </button>`).join('')}
        </div>
      </div>`).join('')}`;
}

function coverageHtml() {
  return domain === 'practice' ? practiceHtml() : matrixHtml();
}

function visible() {
  return tasks.filter(t =>
    (!filterTeam || t.team === filterTeam || t.phaseSource === 'expanded' && !t.team) &&
    (!filterStatus || t.status === filterStatus) &&
    (!filterMine || t.assignees.includes(me())));
}

function stepsHtml(t) {
  if (!t.steps.length) return '';
  return `<ol class="steps">${t.steps.map(s => `
    <li>
      <div>${esc(s.text)}</div>
      <div class="step-meta">
        ${s.tooling ? `<span class="tool">${esc(s.tooling)}</span>` : ''}
        ${s.expect ? `<span class="expect">Expect: ${esc(s.expect)}</span>` : ''}
      </div>
    </li>`).join('')}</ol>`;
}

function detailHtml(t) {
  const orig = t.original;
  return `
    <div class="task-detail">
      ${t.intent ? `<p class="intent">${esc(t.intent)}</p>` : ''}
      ${t.bankDesc ? `
        <p class="bank-desc-label muted small">Drawn from the bank with no authored intent —
          what follows is MITRE's own description, a starting point rather than an argument
          anyone here has made:</p>
        <p class="bank-desc">${esc(t.bankDesc)}</p>` : ''}
      <div class="chips">
        ${t.mitre.map(x => `<span class="chip mitre">${esc(x)}</span>`).join('')}
        ${t.tools.map(x => `<span class="chip">${esc(x)}</span>`).join('')}
        ${t.terrain.map(x => `<span class="chip mono">${esc(x)}</span>`).join('')}
      </div>

      <label>Procedure ${t.stepsSource === 'authored'
    ? '<span class="src-exp">expanded</span>' : '<span class="src-std">standard loop</span>'}</label>
      ${stepsHtml(t)}

      ${t.evidenceExpected ? `<label>Evidence expected</label>
        <p class="small">${esc(t.evidenceExpected)}</p>` : ''}
      ${t.references.length ? `<label>References</label>
        <p class="small">${t.references.map(esc).join(' · ')}</p>` : ''}

      ${orig ? `<details class="orig"><summary>As written by the team</summary>
        <dl>
          ${['ttp', 'evidence', 'tool', 'data', 'command', 'analysis', 'doNext']
    .filter(k => orig[k]).map(k => `<dt>${esc(k)}</dt><dd>${esc(orig[k])}</dd>`).join('')}
        </dl></details>` : ''}

      <label>Assign</label>
      <div class="assign">
        ${state.members.map(mem => `
          <label class="who"><input type="checkbox" data-assign="${esc(t.taskKey)}"
            value="${esc(mem.name)}" ${t.assignees.includes(mem.name) ? 'checked' : ''}>
            ${esc(mem.name)}<span class="muted"> ${esc(mem.team)}</span></label>`).join('')}
      </div>

      <label>History</label>
      <div class="history" id="hist-${esc(t.taskKey)}"><span class="muted">loading…</span></div>
    </div>`;
}

/*
  Which of the three bank tiers this task came from.

  A stub carries nothing. A drafted entry carries steps written from general
  practice that nobody has checked against this estate. An authored one carries
  an argument somebody made and stood behind. All three read identically in a
  plan a week later unless the badge says otherwise, and the middle one is the
  dangerous one precisely because it looks finished.
*/
function bankBadge(t) {
  if (t.stepsSource !== 'authored') {
    return '<span class="src-bank-stub" title="Drawn from the bank; nobody has written a task under it yet">bank stub</span>';
  }
  if (t.bankProvenance === 'drafted') {
    return '<span class="src-bank-draft" title="Drawn from the bank; drafted from general practice and checked by nobody">bank draft</span>';
  }
  if (t.bankProvenance === 'reviewed') {
    return '<span class="src-bank-reviewed" title="Drawn from the bank; independently reviewed, but not against this estate">bank reviewed</span>';
  }
  return '<span class="src-bank" title="Drawn from the bank; carries a task somebody here wrote">bank</span>';
}

function taskRow(t) {
  const mine = t.assignees.includes(me());
  return `
    <div class="task ${t.status}" data-key="${esc(t.taskKey)}">
      <div class="task-head">
        <button class="tick ${t.status === 'complete' ? 'done' : ''}"
          data-toggle="${esc(t.taskKey)}" title="${t.status === 'complete' ? 'Reset to pending' : 'Mark complete'}">
          ${t.status === 'complete' ? '✓' : ''}
        </button>
        <div class="task-title">
          <div>${esc(t.title)}
            ${t.source === 'expanded' ? '<span class="src-exp">added</span>' : ''}
            ${t.source === 'local' ? '<span class="src-local">local</span>' : ''}
            ${t.source === 'bank' ? bankBadge(t) : ''}
            ${t.editedBy ? `<span class="src-edited" title="edited by ${esc(t.editedBy)} ${
  esc(shortTime(t.editedAt).slice(0, 16))}">edited</span>` : ''}
            ${t.priority === 'high' ? '<span class="pri">high</span>' : ''}
          </div>
          <div class="task-sub">
            <span class="mono">${esc(t.taskKey)}</span>
            ${t.assignees.length
    ? `· ${t.assignees.map(a => `<span class="${a === me() ? 'you' : ''}">${esc(a)}</span>`).join(', ')}`
    : '· <span class="unassigned">unassigned</span>'}
            ${t.changedBy ? `· ${esc(t.status)} by ${esc(t.changedBy)} ${esc(shortTime(t.changedAt).slice(0, 16))}` : ''}
          </div>
        </div>
        <select class="status" data-status="${esc(t.taskKey)}">
          ${STATUSES.map(s => `<option ${s === t.status ? 'selected' : ''}>${s}</option>`).join('')}
        </select>
        <button class="edit" data-edit="${esc(t.taskKey)}" title="Edit this task">✎</button>
        <button class="expand" data-expand="${esc(t.taskKey)}">${openTask === t.taskKey ? '▴' : '▾'}</button>
      </div>
      ${editing === t.taskKey ? formHtml({ task: t, phases: phaseList() })
    : openTask === t.taskKey ? detailHtml(t) : ''}
      ${mine && t.status !== 'complete' ? '<div class="mine-flag"></div>' : ''}
    </div>`;
}

function paint() {
  const rows = visible();
  const phases = [...new Set(rows.map(t => t.phaseKey))];
  const teams = [...new Set(tasks.map(t => t.team).filter(Boolean))];
  const done = summary.byStatus?.complete ?? 0;

  root.innerHTML = `
    <div class="bar">
      <strong>${esc(summary.version ?? '')}</strong>
      <span class="muted">${done} of ${summary.total} complete · ${summary.unassigned} unassigned</span>
      <select id="ft"><option value="">all teams</option>
        ${teams.map(t => `<option ${t === filterTeam ? 'selected' : ''}>${esc(t)}</option>`).join('')}</select>
      <select id="fs"><option value="">any status</option>
        ${STATUSES.map(s => `<option ${s === filterStatus ? 'selected' : ''}>${s}</option>`).join('')}</select>
      <label style="display:flex;align-items:center;gap:6px;margin:0;text-transform:none;font-size:12.5px">
        <input type="checkbox" id="fm" style="width:auto" ${filterMine ? 'checked' : ''}> only mine
      </label>
      <span class="muted">${rows.length} shown</span>
      <span class="viewtoggle">
        <button class="${mode === 'plan' ? 'on' : ''}" data-mode="plan">Plan</button><button
          class="${mode === 'coverage' ? 'on' : ''}" data-mode="coverage">Coverage</button>
      </span>
      ${mode === 'coverage' ? `
      <span class="viewtoggle">
        <button class="${domain === 'enterprise' ? 'on' : ''}" data-domain="enterprise">Enterprise</button><button
          class="${domain === 'ics' ? 'on' : ''}" data-domain="ics">ICS</button><button
          class="${domain === 'practice' ? 'on' : ''}" data-domain="practice">Practice</button>
      </span>` : ''}
    </div>

    ${mode === 'coverage' ? coverageHtml() : phases.map(pk => {
    const inPhase = rows.filter(t => t.phaseKey === pk);
    const p = inPhase[0];
    const pdone = inPhase.filter(t => t.status === 'complete').length;
    return `
      <section class="phase">
        <h2 class="section">${esc(p.phaseKey)} · ${esc(p.phaseName)}
          ${p.phaseSource === 'expanded' ? '<span class="src-exp">added</span>' : ''}
          <span class="muted" style="font-weight:400"> ${pdone}/${inPhase.length}</span>
          <button class="addtask" data-add="${esc(p.phaseKey)}">+ add task</button></h2>
        ${p.phaseIntent ? `<p class="phase-intent">${esc(p.phaseIntent)}</p>` : ''}
        ${editing === '+' + p.phaseKey
    ? `<div class="task adding">${formHtml({ task: null, phaseKey: p.phaseKey, phases: phaseList() })}</div>`
    : ''}
        ${inPhase.map(taskRow).join('')}
      </section>`;
  }).join('')}`;

  root.querySelectorAll('[data-mode]').forEach(b => b.addEventListener('click', async () => {
    mode = b.dataset.mode;
    if (mode === 'coverage' && !coverage && !practice) { paint(); await loadDomainData(); }
    paint();
  }));

  root.querySelectorAll('[data-domain]').forEach(b => b.addEventListener('click', async () => {
    if (b.dataset.domain === domain) return;
    domain = b.dataset.domain;
    covEntry = null;
    // Cleared before the fetch, not after: painting with the old domain's
    // matrix or list still on screen while the new one loads would show
    // Enterprise cells under an ICS-selected toggle, which is worse than a
    // loading state.
    coverage = null; practice = null;
    paint();
    await loadDomainData();
    paint();
  }));

  // [data-bank] rather than .cov-cell alone: a practice list row (.prac-item)
  // answers the same click the same way, through the same entry panel.
  root.querySelectorAll('[data-bank]').forEach(b =>
    b.addEventListener('click', () => openBankEntry(b.dataset.bank)));
  root.querySelector('[data-close-entry]')?.addEventListener('click', () => {
    covEntry = null; paint();
  });
  // Scoped to .cov-panel: unscoped, this would also match the first phase's
  // "+ add task" button in Plan mode (same data-add attribute, a phase key
  // rather than a bank id) and wire a doomed from-bank POST onto it too.
  root.querySelector('.cov-panel [data-add]')?.addEventListener('click', async (e) => {
    const id = e.currentTarget.dataset.add;
    try {
      await api('/api/plan/task/from-bank', {
        method: 'POST',
        body: { bankId: id, phaseKey: phaseForNewTasks() },
      });
      toast('Added to the plan');
      covEntry = null;
      // Not loadCoverage() directly: that 400s against domain 'practice'.
      await Promise.all([load(), loadDomainData()]);
      paint();
    } catch (err) { toast(err.message, true); }
  });

  root.querySelector('#ft').addEventListener('change', e => { filterTeam = e.target.value; paint(); });
  root.querySelector('#fs').addEventListener('change', e => { filterStatus = e.target.value; paint(); });
  root.querySelector('#fm').addEventListener('change', e => { filterMine = e.target.checked; paint(); });

  root.querySelectorAll('[data-expand]').forEach(b => b.addEventListener('click', () => {
    openTask = openTask === b.dataset.expand ? null : b.dataset.expand;
    editing = null;
    paint();
    if (openTask) loadHistory(openTask);
  }));

  root.querySelectorAll('[data-edit]').forEach(b => b.addEventListener('click', () => {
    editing = editing === b.dataset.edit ? null : b.dataset.edit;
    if (editing) openTask = null;
    paint();
  }));

  // Scoped to .addtask: the coverage panel's "Add to the plan" button also
  // carries data-add (the bank id, not a phase key), and this generic handler
  // matching it too would set editing to a bogus slot that never clears,
  // silently dropping every live update afterwards (onDelta bails on editing).
  root.querySelectorAll('.addtask[data-add]').forEach(b => b.addEventListener('click', () => {
    const slot = '+' + b.dataset.add;
    editing = editing === slot ? null : slot;
    openTask = null;
    paint();
  }));

  bindForm();

  // One click completes; clicking a completed task resets it. No guard on who.
  root.querySelectorAll('[data-toggle]').forEach(b => b.addEventListener('click', async () => {
    const t = tasks.find(x => x.taskKey === b.dataset.toggle);
    await setStatus(t.taskKey, t.status === 'complete' ? 'pending' : 'complete');
  }));

  root.querySelectorAll('[data-status]').forEach(sel =>
    sel.addEventListener('change', () => setStatus(sel.dataset.status, sel.value)));

  root.querySelectorAll('[data-assign]').forEach(cb => cb.addEventListener('change', async () => {
    const key = cb.dataset.assign;
    const picked = [...root.querySelectorAll(`[data-assign="${CSS.escape(key)}"]`)]
      .filter(x => x.checked).map(x => x.value);
    try {
      const t = await api(`/api/plan/task/${encodeURIComponent(key)}/assign`,
        { method: 'PATCH', body: { assignees: picked } });
      Object.assign(tasks.find(x => x.taskKey === key), t);
      toast(picked.length ? `Assigned to ${picked.join(', ')}` : 'Unassigned');
      loadHistory(key);
    } catch (err) { toast(err.message, true); }
  }));
}

/**
 * Save the open form.
 *
 * A new phase, if one was filled in, is created first — the task cannot be
 * added to a phase that does not exist yet. If the task then fails to save the
 * phase is left behind empty, which is recoverable and visible, unlike the
 * alternative of losing the analyst's typing.
 */
function bindForm() {
  const form = root.querySelector('#tf');
  if (!form) return;
  bindSteps(root);
  bindNewPhase(root);

  const err = (msg) => { root.querySelector('#tf-err').textContent = msg; };
  // Reload on cancel: deltas were suppressed while the form was open, so the
  // board may have moved on underneath it.
  root.querySelector('#cancel').addEventListener('click', () => {
    editing = null;
    load().then(paint).catch(paint);
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    err('');
    const adding = editing.startsWith('+');
    const body = readForm(root);
    if (!body.title) return err('a task needs a title');

    try {
      const np = adding ? readNewPhase(root) : null;
      if (np) {
        await api('/api/plan/phase', { method: 'POST', body: np });
        body.phaseKey = np.key;
      }
      if (adding) await api('/api/plan/task', { method: 'POST', body });
      else await api(`/api/plan/task/${encodeURIComponent(editing)}`, { method: 'PATCH', body });

      const saved = adding ? null : editing;
      editing = null;
      await load();
      paint();
      if (saved) loadHistory(saved);
      toast(adding ? 'Task added' : 'Saved');
    } catch (e2) { err(e2.message); }
  });

  form.querySelector('[data-f="title"]').focus();
}

async function setStatus(key, status) {
  try {
    const t = await api(`/api/plan/task/${encodeURIComponent(key)}/status`,
      { method: 'PATCH', body: { status } });
    Object.assign(tasks.find(x => x.taskKey === key), t);
    await load();
    paint();
    if (openTask === key) loadHistory(key);
    toast(status === 'complete' ? 'Marked complete' : `Set to ${status}`);
  } catch (err) { toast(err.message, true); }
}

async function loadHistory(key) {
  const el = root.querySelector(`#hist-${CSS.escape(key)}`);
  if (!el) return;
  try {
    const t = await api(`/api/plan/task/${encodeURIComponent(key)}`);
    el.innerHTML = t.events.length
      ? t.events.map(e => {
        let d = {};
        try { d = JSON.parse(e.detail ?? '{}'); } catch { /* free text */ }
        const what = e.action === 'reset' ? `<b class="reset">reset</b> from complete`
          : e.action === 'assign' ? `assigned to ${esc((d.to ?? []).join(', ') || 'nobody')}`
            : esc(e.action.replace('status:', 'set '));
        return `<div class="hist-row"><span class="mono">${esc(shortTime(e.ts).slice(0, 16))}</span>
          <span>${esc(e.actor ?? '—')}</span><span>${what}</span></div>`;
      }).join('')
      : '<span class="muted">No activity yet.</span>';
  } catch { el.innerHTML = '<span class="muted">Could not load history.</span>'; }
}

export async function mount(el) {
  root = el;
  // covEntry answers a click on a specific cell from a specific coverage
  // fetch; carrying it across a remount would show it beside whatever the
  // matrix looks like now, keyed to a cell that render might not even repeat.
  covEntry = null;
  /*
    mode survives unmount as a convenience — reopen the same view in the same
    mode you left it in. coverage's cache does not get that same benefit: a
    change can land while this view is not mounted at all (onDelta never runs
    for a route that is not on screen), so a stale object carried across a
    remount is indistinguishable from a correct one until somebody notices the
    matrix disagrees with the plan. Dropping it here means mounting back into
    Coverage always asks again rather than trusting whatever it last held.
  */
  if (mode === 'coverage') { coverage = null; practice = null; }
  const gen = thisMount();
  root.innerHTML = '<div class="loading">Loading hunt plan…</div>';
  try { await load(); } catch (e) {
    if (!stillMounted(gen)) return;
    root.innerHTML = `<div class="loading">No plan loaded: ${esc(e.message)}</div>`;
    return;
  }
  if (mode === 'coverage') await loadDomainData();
  if (!stillMounted(gen)) return;
  paint();
}

export function onDelta(type) {
  if (!root) return;
  if (type !== 'plan.task' && type !== 'plan.changed') return;
  /*
    Never repaint over an open form. paint() replaces the subtree, so a
    colleague ticking a task on the other side of the room would otherwise
    delete the procedure this analyst is halfway through writing. A briefly
    stale board is the cheaper failure; save and cancel both reload.
  */
  if (editing) return;
  /*
    Coverage is not part of what load() refreshes, and any plan change can
    move a cell — not only a draw from the bank, which already reloads it
    itself. While Coverage is on screen, refresh it in place so the grid keeps
    agreeing with the board underneath it; otherwise drop it, so the next
    toggle into Coverage asks again instead of replaying whatever this delta
    might have made stale.
  */
  // Practice has nothing server-side to re-fetch on a plan delta — its "drawn"
  // state comes entirely from `tasks`, which load() below already refreshes —
  // so only enterprise/ics re-hit /api/plan/coverage here.
  let refreshed;
  if (mode === 'coverage' && domain !== 'practice') refreshed = loadCoverage();
  else if (mode !== 'coverage') { coverage = null; practice = null; refreshed = Promise.resolve(); }
  else refreshed = Promise.resolve();
  /*
    Wrapped here rather than relying on the caller. app.js runs every onDelta
    through preservingFocus, but that only helps a repaint that happens while
    it is on the stack — this one is inside a promise, so by the time paint()
    runs the wrapper has already restored and returned.
  */
  Promise.all([load(), refreshed]).then(() => {
    preservingFocus(root, paint);
    // The history panel renders "loading…" on every paint and is only filled
    // by an explicit fetch, so an open task needs its history re-requested.
    if (openTask) loadHistory(openTask);
  }).catch(() => {});
}
