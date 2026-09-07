/**
 * The Characterization tab: what normal looks like, what stopped being it, and
 * what never reported at all.
 *
 * The list is deliberately not the headline. Coverage comes first — a host that
 * answered on Monday and is silent on Wednesday is a finding, and it used to
 * vanish from the comparison entirely. Then the delta. The four hundred
 * unremarkable rows are underneath, which is the order a hunter reads them in.
 */
import { api, toast, esc, shortTime, on, preservingFocus, thisMount, stillMounted } from '../core.js';
import { uploadFile } from './comms.js';

let root = null;
let repos = [];
let snapshots = [];
let active = null;
let view = null;
let hostFilter = '';
let q = '';
let showSame = false;
let showNever = false;
let pinFrom = '';        // explicit comparison, both sides literal
let pinTo = '';
let openRow = null;      // ident of the expanded CHANGED row
let fixRow = null;       // id of the row whose correction form is open
let unsubs = [];
let showImport = false;
let staged = [];         // extracted but not yet in any baseline
let importing = false;
let importSnapshot = '';
let importHost = '';
let importText = '';
let importFiles = [];
let colFilters = {};   // per-column, applied server-side before truncation

const CHANGE = {
  new: ['NEW', 'chg-new'],
  gone: ['GONE', 'chg-gone'],
  changed: ['CHANGED', 'chg-changed'],
  // Differs only by a column somebody said they did not collect. Visible,
  // deliberately not counted as a changed asset.
  partial: ['PARTIAL', 'chg-partial'],
  baseline: ['baseline', 'chg-base'],
  same: ['', ''],
};

/** Why a host is silent. The store cannot tell these apart; a person can. */
const REASONS = [
  ['', '— reason not set —'],
  ['not-collected', 'Not collected — missed this run'],
  ['host-down', 'Host down — known outage'],
  ['out-of-scope', 'Out of scope'],
  ['unreachable', 'Unreachable — investigate'],
];

async function load() {
  [repos, staged] = await Promise.all([
    api('/api/characterization'),
    api('/api/characterization/staged').catch(() => []),
  ]);
  if (!active || !repos.some(r => r.key === active)) {
    active = (repos.find(r => r.changed > 0) ?? repos.find(r => r.snapshots > 0) ?? repos[0])?.key ?? null;
  }
  /*
    Scoped to the repository being looked at, and fetched after it is known
    rather than alongside it. Listing every run in every tab is what taught
    operators to type the repository into the run's name by hand.
  */
  snapshots = active
    ? await api(`/api/characterization/snapshots?repo=${encodeURIComponent(active)}`).catch(() => [])
    : [];
  if (!importSnapshot || !snapshots.some(s => s.id === importSnapshot)) {
    importSnapshot = snapshots[0]?.id ?? '';
  }
}

async function loadRepo() {
  if (!active) { view = null; return; }
  const p = new URLSearchParams();
  if (hostFilter) p.set('host', hostFilter);
  if (q) p.set('q', q);
  if (pinFrom) p.set('snapshot', pinFrom);
  if (pinTo) p.set('against', pinTo);
  for (const [k, val] of Object.entries(colFilters)) if (val) p.set(`col.${k}`, val);
  view = await api(`/api/characterization/${active}${p.toString() ? '?' + p : ''}`);
}

// --- rendering --------------------------------------------------------------

function railHtml() {
  const withData = repos.filter(r => r.snapshots > 0);
  const empty = repos.filter(r => r.snapshots === 0);
  const row = (r) => `
    <div class="session-item ${r.key === active ? 'active' : ''}" data-repo="${esc(r.key)}"
         ${r.snapshots ? '' : 'style="opacity:.45"'}>
      <div>${esc(r.label)}
        ${r.changed ? `<span class="unread">${r.changed}</span>` : ''}</div>
      <div class="meta">${r.snapshots
    ? `${r.hosts} host${r.hosts === 1 ? '' : 's'}`
    : 'nothing yet'}${r.feeds ? ` · ${esc(r.feeds)}` : ''}</div>
    </div>`;
  return `
    ${withData.length ? `<div class="roster-team">Populated</div>${withData.map(row).join('')}` : ''}
    ${empty.length ? `<div class="roster-team">Empty</div>${empty.map(row).join('')}` : ''}`;
}

/**
 * Coverage, before any rows.
 *
 * While a snapshot is still being filled, a host that has not arrived is not a
 * finding — it is next in the queue. Saying "unreachable, investigate" about it
 * would teach the team to ignore this band within a day.
 */
function coverageHtml(v) {
  const c = v.coverage ?? {};
  const missing = c.missing ?? [];
  const never = c.neverCharacterized ?? [];
  if (!missing.length && !never.length) return '';

  const collecting = c.collecting;
  /*
    Split by whether anyone has said why. Recording a reason used to change
    nothing on screen: the host stayed in the red band under a warning triangle
    exactly as before, so answering the question looked like it had failed. An
    absence somebody has accounted for is not an open question, and the count
    in the headline is the number still unanswered.
  */
  const open = missing.filter(m => !m.reason);
  const explained = missing.filter(m => m.reason);
  const seen = (v.hosts ?? []).length;
  const plural = (n) => (n === 1 ? '' : 's');

  const hostRow = (m) => `
    <div class="coverage-row ${m.reason ? 'coverage-explained' : ''}">
      <span class="mono">${esc(m.host)}</span>
      <span class="muted">last seen ${esc(m.lastSeen)}</span>
      ${collecting ? '' : `
        <select data-reason="${esc(m.host)}">
          ${REASONS.map(([val, label]) =>
    `<option value="${val}" ${val === (m.reason ?? '') ? 'selected' : ''}>${esc(label)}</option>`).join('')}
        </select>
        ${m.reason === 'unreachable'
    ? `<button class="bad" data-missing-evid="${esc(m.host)}"
         title="A host that stopped answering the collector is a finding">file as evidence</button>` : ''}`}
    </div>`;

  const missingBand = !missing.length ? '' : `
    <div class="coverage ${collecting || !open.length ? 'coverage-soft' : 'coverage-hard'}">
      <div class="coverage-head">
        ${collecting
    ? `<b>${missing.length} host${plural(missing.length)} not yet in this snapshot</b>
           <span class="muted">still collecting — mark the snapshot complete to judge coverage</span>`
    : open.length
      ? `<b>⚠ NOT COLLECTED — ${open.length} of ${seen + missing.length} host${plural(seen + missing.length)}</b>
           <span class="muted">reported previously, absent from this collection${explained.length
    ? ` · ${explained.length} more accounted for below` : ''}</span>`
      : `<b>${explained.length} host${plural(explained.length)} absent, all accounted for</b>
           <span class="muted">every gap in this collection has a reason on record</span>`}
      </div>
      ${collecting
    ? missing.map(hostRow).join('')
    : open.map(hostRow).join('') + (explained.length
      ? `<div class="coverage-sub">accounted for</div>${explained.map(hostRow).join('')}`
      : '')}
    </div>`;

  const total = never.reduce((n, e) => n + e.count, 0);
  const neverBand = !never.length ? '' : `
    <div class="coverage coverage-info">
      <div class="coverage-head" id="never-toggle" style="cursor:pointer">
        <b>${showNever ? '▾' : '▸'} NEVER CHARACTERIZED — ${total} host${total === 1 ? '' : 's'}</b>
        <span class="muted">in enclaves this repository has started on</span>
      </div>
      ${showNever ? never.map(e => `
        <div class="never-group">
          <div class="never-head">
            <span class="mono">${esc(e.enclave)}</span>
            <span class="muted">${e.count} host${e.count === 1 ? '' : 's'}</span>
            <button data-copy-never="${esc(e.enclave)}">copy</button>
          </div>
          <textarea class="never-list" readonly spellcheck="false"
            rows="${Math.min(10, e.hosts.length)}"
            data-never="${esc(e.enclave)}">${esc(e.hosts.join('\n'))}</textarea>
        </div>`).join('') : ''}
    </div>`;

  return missingBand + neverBand;
}

function columnsFor(v) {
  const present = new Set();
  for (const r of v.rows) for (const k of Object.keys(r.display ?? {})) present.add(k);
  const cols = (v.columns ?? []).filter(c => present.has(c));
  for (const k of present) if (!cols.includes(k) && cols.length < 7) cols.push(k);
  return cols.slice(0, 7);
}

/** A changed row, opened: which fields moved, and what they were. */
function expansionHtml(r, span) {
  const now = r.display ?? {};
  const was = r.previous ?? {};
  const keys = [...new Set([...Object.keys(was), ...Object.keys(now)])];
  const moved = keys.filter(k => String(was[k] ?? '') !== String(now[k] ?? ''));
  const same = keys.filter(k => !moved.includes(k));
  return `
    <tr class="row-detail"><td colspan="${span}">
      <table class="fielddiff">
        <thead><tr><th>field</th><th>was</th><th>now</th></tr></thead>
        <tbody>
          ${moved.map(k => `<tr>
            <td class="mono">${esc(k)}</td>
            <td class="was">${esc(was[k] ?? '—')}</td>
            <td class="now">${esc(now[k] ?? '—')}</td>
          </tr>`).join('')}
        </tbody>
      </table>
      ${same.length ? `<p class="muted" style="margin:6px 0 0;font-size:11.5px">
        unchanged: ${esc(same.join(', '))}</p>` : ''}
    </td></tr>`;
}

/**
 * Corrections, deliberately not inline.
 *
 * A baseline is what was observed. Making it casually editable turns it into
 * what somebody thinks was there, so every change needs a reason, keeps the
 * collected value, and lands in the audit log.
 */
function fixHtml(r, span) {
  // Identity fields are omitted rather than offered and refused: changing one
  // would make this row read GONE and a new one NEW in every future diff.
  const norm = (k) => String(k).toLowerCase().replace(/[^a-z0-9]/g, '');
  const locked = new Set((view?.identFields ?? []).map(norm));
  const editable = Object.keys(r.display ?? {}).filter(k => !locked.has(norm(k)));
  return `
    <tr class="row-detail"><td colspan="${span}">
      <div class="fixform" data-fixfor="${esc(r.id)}">
        <div class="task-form-grid">
          <label>Correct a value</label>
          <div class="row">
            ${editable.length ? `
              <select id="fix-field">${editable.map(k => `<option>${esc(k)}</option>`).join('')}</select>
              <input id="fix-value" placeholder="new value" class="grow">`
    : '<span class="muted">Every field on this row is part of its identity, so none can be corrected in place.</span>'}
          </div>

          <label>Reattribute host</label>
          <input id="fix-host" placeholder="${esc(r.host ?? 'host')}">

          <label>Move to snapshot</label>
          <select id="fix-snap">
            <option value="">— leave where it is —</option>
            ${snapshots.filter(s => s.id !== r.snapshotId)
    .map(s => `<option value="${esc(s.id)}">${esc(s.label)}</option>`).join('')}
          </select>

          <label>Reason<span class="hint">required</span></label>
          <input id="fix-reason" placeholder="why this row is wrong">
        </div>
        <div class="task-form-actions">
          <button class="primary" id="fix-save">Apply</button>
          <button id="fix-cancel">Cancel</button>
          <span class="err" id="fix-err"></span>
        </div>
        <p class="muted" style="margin:6px 0 0;font-size:11.5px">
          Identity fields are not editable — changing one would make this row read GONE and a new
          one NEW in every future diff. Discard and re-import instead.
        </p>
      </div>
    </td></tr>`;
}

function tableHtml(v) {
  const rows = showSame ? v.rows : v.rows.filter(r => r.change !== 'same');
  if (!rows.length) {
    return `<p class="muted" style="padding:20px">${v.rows.length
      ? 'Nothing has changed since the comparison snapshot. Tick "show unchanged" for the full baseline.'
      : 'No data in this repository yet.'}</p>`;
  }
  const cols = columnsFor(v);
  const span = cols.length + 4;
  return `
    <div class="table-wrap sticky">
      <table>
        <thead>
          <tr>
            <th></th><th>Change</th><th>Host</th><th>Seen on</th>
            ${cols.map(c => `<th>${esc(c)}</th>`).join('')}<th></th>
          </tr>
          <tr class="filterrow">
            <th></th>
            <th><input data-col="change" value="${esc(colFilters.change ?? '')}" placeholder="new…"></th>
            <th><input data-col="host" value="${esc(colFilters.host ?? '')}" placeholder="host…"></th>
            <th></th>
            ${cols.map(c => `<th><input data-col="${esc(c)}" value="${esc(colFilters[c] ?? '')}"
              placeholder="filter…"></th>`).join('')}
            <th>${Object.values(colFilters).some(Boolean)
    ? '<button id="clearfilters" title="Clear column filters">✕</button>' : ''}</th>
          </tr>
        </thead>
        <tbody>
          ${rows.slice(0, 500).map(r => {
    const [label, cls] = CHANGE[r.change] ?? ['', ''];
    const rare = r.totalHosts > 1 && r.hosts <= Math.max(1, Math.floor(r.totalHosts * 0.1));
    const key = `${r.host}|${r.ident}`;
    const open = openRow === key;
    const canOpen = r.change === 'changed' && r.previous;
    return `<tr class="${r.confident ? '' : 'unconfident'} ${r.stale ? 'stale' : ''}">
              <td>${canOpen ? `<button class="rowexp" data-open="${esc(key)}">${open ? '▾' : '▸'}</button>` : ''}</td>
              <td>${label ? `<span class="${cls}">${label}</span>` : ''}</td>
              <td>${esc(r.host ?? '—')}</td>
              <td class="${rare ? 'rare' : 'muted'}">${r.hosts}/${r.totalHosts}${rare ? ' rare' : ''}</td>
              ${cols.map(c => `<td class="clip">${esc(r.display?.[c] ?? '')}</td>`).join('')}
              <td style="white-space:nowrap">
                <button data-evid="${esc(r.id)}" title="File this row as a pending record">file</button>
                <button data-fix="${esc(r.id)}" title="Correct, reattribute or move this row">⋯</button>
              </td></tr>
            ${fixRow === r.id ? fixHtml(r, span) : ''}
            ${open ? expansionHtml(r, span) : ''}`;
  }).join('')}
        </tbody>
      </table>
      ${rows.length > 500 ? `<p class="muted" style="padding:10px">
        Showing the first 500 of ${rows.length} matching row${rows.length === 1 ? '' : 's'}.
        Narrow with the column filters — they run over the whole repository, not just what is shown.</p>` : ''}
    </div>`;
}

/**
 * Apply an acknowledgement made against the whole repository.
 *
 * It is stored per run, because that is where the fact lives — this collection
 * did not gather this field. So a repository-wide choice is fanned back out to
 * exactly the runs that lack each field, and merged with what those runs
 * already say, since the endpoint replaces a run's whole set.
 */
async function applyGaps(add = [], remove = []) {
  const per = new Map();
  const slot = (sid) => {
    if (!per.has(sid)) per.set(sid, { add: new Set(), remove: new Set() });
    return per.get(sid);
  };
  for (const e of view.fieldGaps?.candidates ?? []) {
    if (add.includes(e.field)) for (const sid of e.snapshots) slot(sid).add.add(e.field);
  }
  for (const e of view.fieldGaps?.acknowledged ?? []) {
    if (remove.includes(e.field)) for (const sid of e.snapshots) slot(sid).remove.add(e.field);
  }
  const note = root.querySelector('#gap-note')?.value.trim() || null;
  try {
    for (const [sid, want] of per) {
      const url = `/api/characterization/snapshots/${sid}/gaps`;
      const have = new Set((await api(url)).map(g => g.field));
      for (const f of want.add) have.add(f);
      for (const f of want.remove) have.delete(f);
      await api(url, { method: 'PUT', body: { fields: [...have], note } });
    }
    await reload();
  } catch (e) { toast(e.message, true); }
}

/**
 * Columns that are driving differences because somebody did not collect them.
 *
 * The operator answers once for the whole run. Ninety accounts read as changed
 * because one Get-ADUser was run without -Properties, and the honest answer
 * was never "ninety things changed" — it was "we did not ask about two
 * fields". Acknowledging says so, and those rows stop counting as changed.
 */
function gapBarHtml(v) {
  const { candidates = [], acknowledged = [], osMix = [] } = v.fieldGaps ?? {};
  if (!candidates.length && !acknowledged.length) return '';
  const rows = candidates.reduce((n, c) => Math.max(n, c.rows), 0);
  /*
    Acknowledging covers the whole run. On a run spanning OS families that means
    one click answers for hosts where the field is a real gap and for hosts
    where it is a category error — "shell not collected" being both at once. The
    warning does not block it; it makes the operator choose rather than assume.
  */
  const mix = osMix.length > 1 ? `
        <div class="gapmix">This run spans ${osMix
    .map(o => `${esc(o.family)} (${o.hosts})`).join(' and ')}. A column that is
          meaningless on one of those is a real gap on another, and acknowledging
          answers for all of them at once.</div>` : '';
  return `
    <div class="gapbar${candidates.length ? ' gapbar-open' : ''}">
      ${mix}
      ${candidates.length ? `
        <div class="gaphead">
          <b>${candidates.length} column${candidates.length === 1 ? '' : 's'} may not have been collected</b>
          <span class="muted">Up to ${rows} row${rows === 1 ? '' : 's'} differ only because a column is
            absent on one side. If the command simply did not return it, say so and they stop
            counting as changed.</span>
        </div>
        <div class="gapfields">
          ${candidates.map(c => `
            <label class="gapchip">
              <input type="checkbox" data-gapfield="${esc(c.field)}" checked>
              ${esc(c.field)} <span class="muted">${c.rows}</span>
            </label>`).join('')}
        </div>
        <div class="gapactions">
          <input id="gap-note" placeholder="Why? e.g. Get-ADUser run without -Properties">
          <button class="primary" id="gap-ack">Acknowledge as not collected</button>
        </div>` : ''}
      ${acknowledged.length ? `
        <div class="gapacked">
          <span class="muted">already acknowledged:</span>
          ${acknowledged.map(a => `
            <span class="gapchip acked">${esc(a.field)} <span class="muted">${a.rows}</span>
              <button data-gapundo="${esc(a.field)}" title="Treat as a real difference again">×</button>
            </span>`).join('')}
        </div>` : ''}
    </div>`;
}

function snapshotBarHtml(v) {
  const opt = (sel) => snapshots.map(s =>
    `<option value="${esc(s.id)}" ${s.id === sel ? 'selected' : ''}>${esc(s.label)}</option>`).join('');
  const cur = snapshots.find(s => s.id === (pinFrom || v.snapshot?.id));
  // Inline, not a bar of its own. These are three controls, and they were
  // costing four rows before any data appeared.
  return `
      <span class="sep">|</span>
      <span class="muted">comparing</span>
      <select id="pinfrom" title="Which collection to read"><option value="">latest per host</option>${opt(pinFrom)}</select>
      <span class="muted">against</span>
      <select id="pinto" title="Which collection to compare it with"><option value="">the one before</option>${opt(pinTo)}</select>
      ${cur && !cur.completed_at ? `
        <span class="collecting">still collecting</span>
        <button id="markdone" title="Coverage is only judged once a collection has finished">mark complete</button>`
    : cur ? `<span class="muted" title="Collection marked complete ${esc(shortTime(cur.completed_at))}"
          >✓ ${esc(shortTime(cur.completed_at).slice(0, 10))}</span>
        <button id="markopen">reopen</button>` : ''}`;
}

/**
 * The import panel, in the tab the result appears in.
 *
 * Pasting in one place and checking the outcome in another is what made this
 * cumbersome, and it is why three silent failures survived for hours: nothing
 * in the old flow ever showed what actually landed.
 */
function importHtml() {
  if (!showImport) return '';
  const snap = snapshots.find(s => s.id === importSnapshot);
  return `
    <div class="importer">
      <div class="bar">
        <strong>Import</strong>
        <select id="imp-snap">
          ${snapshots.map(s => `<option value="${esc(s.id)}" ${s.id === importSnapshot ? 'selected' : ''}>
            ${esc(s.label)}</option>`).join('')}
          ${snapshots.length ? '' : '<option value="">no snapshot yet</option>'}
        </select>
        <button id="imp-newsnap">+ new snapshot</button>
        <input id="imp-host" class="charhost" placeholder="Host (optional — inferred if blank)"
          value="${esc(importHost)}">
        <span class="muted">${snap
    ? `${snap.hosts} host${snap.hosts === 1 ? '' : 's'} · ${snap.rows} rows already`
    : ''}</span>
      </div>

      <div class="dropzone" id="imp-drop">
        ${importFiles.length
    ? importFiles.map(f => `<span class="pending-file">${esc(f.name)}</span>`).join('')
    : '<span class="muted">Drop files here, or paste below</span>'}
        <label class="attach">Choose files<input type="file" id="imp-file" hidden multiple></label>
      </div>
      <textarea id="imp-text" rows="5"
        placeholder="Paste a process list, task dump, netstat, account export or scan output.">${esc(importText)}</textarea>
      <div class="task-form-actions">
        <button class="primary" id="imp-go" ${importing ? 'disabled' : ''}>
          ${importing ? 'analysing…' : 'Analyse'}</button>
        <span class="muted">Extracted rows are held for review. Nothing reaches a baseline until you commit.</span>
      </div>

      ${stagedHtml()}
    </div>`;
}

/** What is about to land: per repository, per host, with samples. */
function stagedHtml() {
  if (!staged.length) return '';
  const warn = staged.some(u => u.status !== 'ok' || u.unattributed || u.newHost);
  return `
    <div class="staged ${warn ? 'staged-warn' : ''}">
      <div class="coverage-head">
        <b>HELD FOR REVIEW — ${staged.length} upload${staged.length === 1 ? '' : 's'}</b>
        <span class="muted">${staged.reduce((n, u) => n + u.rows, 0)} rows, not yet in any baseline</span>
      </div>
      ${staged.map(u => `
        <div class="staged-row">
          <div class="staged-head">
            <span class="chip">${esc(u.repo)}</span>
            <input class="mono staged-host" data-stagedhost="${esc(u.id)}"
              value="${esc(u.host ?? '')}" placeholder="host not attributed">
            <span class="muted">${u.rows} row${u.rows === 1 ? '' : 's'}${
    u.claimed && u.claimed !== u.rows ? ` of ${u.claimed} claimed` : ''} → ${esc(u.snapshot ?? '')}</span>
            <button data-discard="${esc(u.id)}" class="bad">discard</button>
          </div>
          <div class="staged-meta">
            ${u.sourceFormat ? `<span class="muted">${esc(u.sourceFormat)}</span>` : ''}
            ${u.unattributed ? '<span class="warnchip">no host — rows cannot diff or count for rarity</span>' : ''}
            ${u.newHost ? '<span class="warnchip">host not seen in this repository before</span>' : ''}
            ${u.status !== 'ok' ? `<span class="warnchip">${esc(u.note ?? 'incomplete')}</span>` : ''}
          </div>
          ${u.samples.length ? `<table class="fielddiff"><tbody>
            ${u.samples.map(sm => `<tr><td class="mono">${esc(sm.label)}</td>
              <td class="clip muted">${esc(Object.entries(sm.attrs).slice(0, 4)
    .map(([k, val]) => `${k}=${val}`).join('  '))}</td></tr>`).join('')}
          </tbody></table>` : ''}
        </div>`).join('')}
      <div class="task-form-actions">
        <button class="primary" id="imp-commit">Commit ${staged.length} upload${staged.length === 1 ? '' : 's'}</button>
        <button id="imp-discard-all">Discard all</button>
      </div>
    </div>`;
}

function paint() {
  const v = view;
  root.innerHTML = `
    <div class="comms-layout">
      <div class="session-list">
        <h2 class="section">Repositories</h2>
        ${railHtml()}
      </div>

      <div class="chat">
        <div class="bar">
          <button class="primary" id="toggle-import">${showImport ? '▾' : '▸'} Import</button>
          ${staged.length ? `<span class="unread">${staged.length} held for review</span>` : ''}
          ${v ? snapshotBarHtml(v) : ''}
        </div>
        ${importHtml()}
        ${!v ? '<div class="loading">Nothing characterized yet.</div>' : `
          <div class="bar">
            <strong>${esc(v.label)}</strong>
            <input class="grow" id="q" placeholder="Search this repository…" value="${esc(q)}">
            <select id="host">
              <option value="">all hosts</option>
              ${(v.hosts ?? []).filter(Boolean).map(h =>
    `<option ${h === hostFilter ? 'selected' : ''}>${esc(h)}</option>`).join('')}
            </select>
            <label style="display:flex;align-items:center;gap:6px;margin:0;text-transform:none;font-size:12.5px">
              <input type="checkbox" id="same" style="width:auto" ${showSame ? 'checked' : ''}> show unchanged
            </label>
            <span class="muted">${v.counts.new} new · ${v.counts.changed} changed · ${v.counts.gone} gone
              · ${v.counts.total} total</span>
          </div>

          ${coverageHtml(v)}
          ${gapBarHtml(v)}
          ${v.note ? `<p class="phase-intent" style="margin:0 14px">${esc(v.note)}</p>` : ''}
          ${v.incompleteSnapshots ? `<p class="incomplete-warn">
            ${v.incompleteSnapshots} upload${v.incompleteSnapshots === 1 ? '' : 's'} in this repository
            came back short of what the model reported for the source. Those rows are dimmed and their
            deltas may be extraction artifacts rather than real change.
          </p>` : ''}

          ${tableHtml(v)}`}
      </div>
    </div>`;

  bind();
}

function bind() {
  const reload = async () => { try { await loadRepo(); paint(); } catch (e) { toast(e.message, true); } };
  const refresh = async () => { try { await load(); await loadRepo(); paint(); } catch (e) { toast(e.message, true); } };

  // --- import panel ---------------------------------------------------------
  root.querySelector('#toggle-import')?.addEventListener('click', () => { showImport = !showImport; paint(); });
  root.querySelector('#imp-snap')?.addEventListener('change', (e) => { importSnapshot = e.target.value; paint(); });
  root.querySelector('#imp-host')?.addEventListener('input', (e) => { importHost = e.target.value; });
  root.querySelector('#imp-text')?.addEventListener('input', (e) => { importText = e.target.value; });

  root.querySelector('#imp-newsnap')?.addEventListener('click', async () => {
    // The name is generated from repository, operator and time. What a person
    // knows and the server does not is why this collection exists.
    const note = prompt('Anything worth noting about this collection? (optional)\n'
      + 'It names itself: Repository_Baseline_You_Timestamp.');
    if (note === null) return;
    try {
      const sn = await api('/api/characterization/snapshots', {
        method: 'POST', body: { repo: active, note: note.trim() || null } });
      await load();
      importSnapshot = sn.id;
      paint();
    } catch (e) { toast(e.message, true); }
  });

  root.querySelector('#gap-ack')?.addEventListener('click', async () => {
    const chosen = [...root.querySelectorAll('[data-gapfield]')]
      .filter(i => i.checked).map(i => i.dataset.gapfield);
    if (!chosen.length) { toast('nothing selected', true); return; }
    await applyGaps(chosen, []);
  });

  root.querySelectorAll('[data-gapundo]').forEach(b => b.addEventListener('click',
    () => applyGaps([], [b.dataset.gapundo])));

  const takeFiles = (list) => { importFiles = [...list].slice(0, 5); paint(); };
  root.querySelector('#imp-file')?.addEventListener('change', (e) => takeFiles(e.target.files));
  const drop = root.querySelector('#imp-drop');
  if (drop) {
    drop.addEventListener('dragover', (e) => { e.preventDefault(); drop.classList.add('over'); });
    drop.addEventListener('dragleave', () => drop.classList.remove('over'));
    drop.addEventListener('drop', (e) => {
      e.preventDefault(); drop.classList.remove('over');
      takeFiles(e.dataTransfer.files);
    });
  }

  root.querySelector('#imp-go')?.addEventListener('click', async () => {
    if (!importText.trim() && !importFiles.length) return toast('Nothing to import', true);
    importing = true; paint();
    try {
      const fileIds = [];
      for (const f of importFiles) fileIds.push((await uploadFile(f)).id);
      await api('/api/characterization/import', { method: 'POST', body: {
        text: importText, fileIds, host: importHost || undefined,
        repo: active,
        snapshotId: importSnapshot || undefined,
      } });
      toast('Analysing — the result will appear below for review');
      importText = ''; importFiles = [];
    } catch (e) { toast(e.message, true); }
    importing = false; paint();
  });

  root.querySelectorAll('[data-stagedhost]').forEach(inp => inp.addEventListener('change', async () => {
    try {
      await api(`/api/characterization/staged/${inp.dataset.stagedhost}/host`,
        { method: 'PATCH', body: { host: inp.value } });
      await refresh();
    } catch (e) { toast(e.message, true); }
  }));

  root.querySelectorAll('[data-discard]').forEach(b => b.addEventListener('click', async () => {
    try {
      await api('/api/characterization/staged/discard', { method: 'POST', body: { ids: [b.dataset.discard] } });
      await refresh();
    } catch (e) { toast(e.message, true); }
  }));

  root.querySelector('#imp-commit')?.addEventListener('click', async () => {
    try {
      const r = await api('/api/characterization/staged/commit',
        { method: 'POST', body: { ids: staged.map(u => u.id) } });
      await refresh();
      toast(`Committed ${r.committed} upload(s) into the baseline`);
    } catch (e) { toast(e.message, true); }
  });

  root.querySelector('#imp-discard-all')?.addEventListener('click', async () => {
    try {
      await api('/api/characterization/staged/discard', { method: 'POST', body: { ids: staged.map(u => u.id) } });
      await refresh();
      toast('Discarded');
    } catch (e) { toast(e.message, true); }
  });

  root.querySelectorAll('[data-repo]').forEach(d => d.addEventListener('click', async () => {
    active = d.dataset.repo; q = ''; hostFilter = ''; openRow = null;
    // The pinned runs belong to the repository being left, and the picker has
    // to be refilled from the new one — reload() alone would leave the old
    // repository's baselines listed under the new tab.
    pinFrom = ''; pinTo = ''; importSnapshot = '';
    await refresh();
  }));

  // Column filters: debounced, and sent to the server so they apply before the
  // display cap rather than over a truncated page.
  let ft;
  root.querySelectorAll('[data-col]').forEach(inp => inp.addEventListener('input', () => {
    colFilters[inp.dataset.col] = inp.value;
    clearTimeout(ft);
    ft = setTimeout(async () => {
      const col = inp.dataset.col;
      const at = inp.selectionStart;
      await reload();
      const again = root.querySelector(`[data-col="${col}"]`);
      if (again) { again.focus(); again.setSelectionRange(at, at); }
    }, 300);
  }));
  root.querySelector('#clearfilters')?.addEventListener('click', async () => { colFilters = {}; await reload(); });

  root.querySelectorAll('[data-fix]').forEach(b => b.addEventListener('click', () => {
    fixRow = fixRow === b.dataset.fix ? null : b.dataset.fix;
    openRow = null;
    paint();
  }));
  root.querySelector('#fix-cancel')?.addEventListener('click', () => { fixRow = null; paint(); });

  root.querySelector('#fix-save')?.addEventListener('click', async () => {
    const id = fixRow;
    const reason = root.querySelector('#fix-reason').value.trim();
    const err = (msg) => { root.querySelector('#fix-err').textContent = msg; };
    if (!reason) return err('a reason is required');

    const value = root.querySelector('#fix-value')?.value ?? '';
    const fieldName = root.querySelector('#fix-field')?.value;
    const newHost = root.querySelector('#fix-host').value.trim();
    const toSnap = root.querySelector('#fix-snap').value;

    try {
      if (value !== '') {
        await api(`/api/characterization/entity/${id}/correct`,
          { method: 'POST', body: { attrs: { [fieldName]: value }, reason } });
      }
      if (newHost) {
        await api(`/api/characterization/entity/${id}/reattribute`,
          { method: 'POST', body: { host: newHost, reason } });
      }
      if (toSnap) {
        await api(`/api/characterization/entity/${id}/move`,
          { method: 'POST', body: { snapshotId: toSnap, reason } });
      }
      fixRow = null;
      await reload();
      toast('Corrected — the collected value is kept and the change is in the audit log');
    } catch (e) { err(e.message); }
  });

  root.querySelectorAll('[data-open]').forEach(b => b.addEventListener('click', () => {
    openRow = openRow === b.dataset.open ? null : b.dataset.open;
    paint();
  }));

  const qi = root.querySelector('#q');
  if (qi) {
    let t;
    qi.addEventListener('input', (e) => {
      q = e.target.value;
      clearTimeout(t);
      t = setTimeout(async () => {
        const at = qi.selectionStart;
        await reload();
        const again = root.querySelector('#q');
        if (again) { again.focus(); again.setSelectionRange(at, at); }
      }, 300);
    });
  }

  root.querySelector('#host')?.addEventListener('change', async (e) => { hostFilter = e.target.value; await reload(); });
  root.querySelector('#same')?.addEventListener('change', (e) => { showSame = e.target.checked; paint(); });
  root.querySelector('#never-toggle')?.addEventListener('click', () => { showNever = !showNever; paint(); });

  /*
    Copy the whole list, not the eight that fitted.

    The clipboard API needs a secure context, and this server is reached over
    plain http from the LAN by most of the team — so selecting the text is the
    fallback that actually works for them, and the box is a real textarea for
    exactly that reason.
  */
  root.querySelectorAll('[data-copy-never]').forEach(b => b.addEventListener('click', async () => {
    const box = root.querySelector(`textarea[data-never="${CSS.escape(b.dataset.copyNever)}"]`);
    if (!box) return;
    box.focus();
    box.select();
    try {
      await navigator.clipboard.writeText(box.value);
      toast(`${box.value.split('\n').filter(Boolean).length} host(s) copied`);
    } catch {
      toast('Selected — press Ctrl+C to copy', true);
    }
  }));
  root.querySelector('#pinfrom')?.addEventListener('change', async (e) => { pinFrom = e.target.value; await reload(); });
  root.querySelector('#pinto')?.addEventListener('change', async (e) => { pinTo = e.target.value; await reload(); });

  const setComplete = async (complete) => {
    const id = pinFrom || view?.snapshot?.id;
    if (!id) return;
    try {
      await api(`/api/characterization/snapshots/${id}/complete`, { method: 'PATCH', body: { complete } });
      await load(); await reload();
      toast(complete ? 'Collection marked complete — coverage is now judged' : 'Snapshot reopened');
    } catch (e) { toast(e.message, true); }
  };
  root.querySelector('#markdone')?.addEventListener('click', () => setComplete(true));
  root.querySelector('#markopen')?.addEventListener('click', () => setComplete(false));

  root.querySelectorAll('[data-reason]').forEach(sel => sel.addEventListener('change', async () => {
    try {
      await api(`/api/characterization/${active}/coverage`, {
        method: 'PUT', body: { host: sel.dataset.reason, reason: sel.value || null },
      });
      await reload();
    } catch (e) { toast(e.message, true); }
  }));

  root.querySelectorAll('[data-missing-evid]').forEach(b => b.addEventListener('click', async () => {
    const host = b.dataset.missingEvid;
    try {
      await api('/api/records', { method: 'POST', body: {
        hostname: host,
        evidence_source: `Characterization — ${active} coverage`,
        description: `${host} reported ${view.label.toLowerCase()} in a previous collection and did not ` +
          'respond to this one. Marked unreachable rather than missed or powered off, so the collection ' +
          'path itself is in question.',
        analyst_notes: 'Raised from the characterization coverage band. Confirm whether the host is up, '
          + 'whether the agent is running, and whether anything changed on the collection path.',
        confidence: 'Low', triage_status: 'New',
      } });
      toast('Filed as a pending record');
    } catch (e) { toast(e.message, true); }
  }));

  root.querySelectorAll('[data-evid]').forEach(b => b.addEventListener('click', async () => {
    try {
      await api(`/api/characterization/entity/${b.dataset.evid}/evidence`, { method: 'POST', body: {} });
      toast('Filed as a pending record');
    } catch (e) { toast(e.message, true); }
  }));
}

export async function mount(el) {
  root = el;
  const gen = thisMount();
  root.innerHTML = '<div class="loading">Loading baselines…</div>';
  try { await load(); await loadRepo(); } catch (e) {
    if (!stillMounted(gen)) return;
    root.innerHTML = `<div class="loading">Could not load characterization: ${esc(e.message)}</div>`;
    return;
  }
  if (!stillMounted(gen)) return;
  paint();

  const refreshOnDelta = async () => {
    /*
      This used to skip the repaint entirely whenever focus was in the search
      or the paste box, which kept the caret but left the view stale with
      nothing to bring it back — and only covered three ids, so a column
      filter or the gap note lost the caret anyway. Repainting through
      preservingFocus keeps both: the rows update and the caret stays put.
    */
    try {
      await load();
      await loadRepo();
      preservingFocus(root, paint);
    } catch { /* transient */ }
  };
  /*
    Coalesced, because one refresh is three round trips — the repository list,
    this repository's baselines, and the rows — and it measured 408ms. Several
    deltas arriving together used to buy several of those in a row.
  */
  let pending = null;
  const scheduleRefresh = () => {
    clearTimeout(pending);
    pending = setTimeout(refreshOnDelta, 250);
  };
  unsubs = [
    on('characterization.changed', scheduleRefresh),
    /*
      A FINISHED turn is what puts rows in the review queue, which is what the
      comment here always said and the code did not: it fired on every state
      change of every analyst's session, so twelve people running turns
      refreshed this view on each transition, twice per turn, for nothing.
    */
    on('session.state', (session) => {
      if (session?.state === 'running') return;
      scheduleRefresh();
    }),
    () => clearTimeout(pending),
  ];
}

export function unmount() { unsubs.forEach(u => u()); unsubs = []; root = null; }
