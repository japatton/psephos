import {
  state, api, toast, esc, shortTime, hostById, recordById, threadById,
} from '../core.js';

const el = () => document.getElementById('drawer');
let current = null; // { kind: 'host'|'record', id }
let editingHost = false;
let hostDetail = null;   // overrides and evidence counts, fetched on demand
let hostChar = null;     // latest collection per repository for the open host
/*
  The whole record, fetched when one is opened.

  state.records carries a projection now — enough for the map, the timeline and
  the rails, and without the notes, command and hash that are most of a record's
  weight and that nothing renders until this drawer opens. So the drawer asks for
  the row it is about to show. Held here rather than merged back into
  state.records, which would make the projection ragged: some rows whole, some
  not, depending on what somebody happened to click.
*/
let recordDetail = null;
/* The findings on the open host, fetched by the same rule the map counts by.
   Filtering a local copy of every record was the other reason that copy had to
   exist, and keeping the rule server-side is what stops the badge on a node and
   this list disagreeing. */
let hostRecords = [];

const OVERRIDABLE = ['name', 'ip', 'enclave', 'segment', 'cidr', 'os', 'role'];

export function closeDrawer() {
  current = null;
  recordDetail = null;
  hostRecords = [];
  const d = el();
  d.hidden = true;
  d.innerHTML = '';
}

export const openHostDrawer = (id) => {
  current = { kind: 'host', id };
  editingHost = false;
  hostDetail = null;
  hostChar = null;
  hostRecords = [];
  paint();
  loadHostChar(id);
  loadHostRecords(id);
};

async function loadHostRecords(id) {
  let rows = [];
  try { rows = await api(`/api/hosts/${id}/records`); } catch { return; }
  if (current?.kind !== 'host' || current.id !== id) return;   // moved on
  hostRecords = rows;
  paint();
}

/**
 * What has actually been collected from this machine.
 *
 * Fetched rather than held in the shared state: the estate has a hundred and
 * ninety hosts and hundreds of thousands of baseline rows between them, and
 * this is one host's worth, wanted only while its drawer is open.
 */
async function loadHostChar(id) {
  const host = hostById(id);
  if (!host?.name) { hostChar = []; return; }
  const rows = await api(`/api/characterization/host?name=${encodeURIComponent(host.name)}`)
    .catch(() => []);
  // The analyst may have clicked another node while this was in flight.
  if (current?.kind === 'host' && current.id === id) { hostChar = rows; paint(); }
}

/**
 * The newest collection per repository, with a few rows of each.
 *
 * The drawer could show a host's findings and its verdict but not one fact
 * anybody had collected from it — so an analyst asking "what is actually
 * running on this box" had to leave the map, change tab, pick the repository
 * and filter by host, four times over.
 */
function collectionsHtml() {
  if (hostChar === null) return '<p class="muted">Reading collections…</p>';
  if (!hostChar.length) return '<p class="muted">Nothing has been collected from this host.</p>';

  return hostChar.map(c => `
    <details class="coll"${hostChar.length <= 2 ? ' open' : ''}>
      <summary>
        <b>${esc(c.label)}</b>
        <span class="muted">${c.rows} row${c.rows === 1 ? '' : 's'}</span>
        <span class="muted">${esc(shortTime(c.at).slice(0, 16))}</span>
      </summary>
      <div class="coll-snap mono muted">${esc(c.snapshot)}</div>
      <table class="coll-table"><tbody>
        ${c.sample.map(r => {
    const rest = Object.entries(r.display ?? {})
      .filter(([, v]) => String(v) !== String(r.label))
      .map(([k, v]) => `${k} ${v}`).join(' · ');
    return `<tr><td class="mono">${esc(r.label)}</td>
              <td class="clip muted">${esc(rest)}</td></tr>`;
  }).join('')}
      </tbody></table>
      ${c.rows > c.sample.length
    ? `<div class="coll-more muted">…and ${c.rows - c.sample.length} more in this collection</div>`
    : ''}
    </details>`).join('');
}
export const openRecordDrawer = (id) => {
  current = { kind: 'record', id };
  // Paint immediately from the projection so the drawer opens at once, then
  // fill in the rest. Waiting on the fetch would make every open feel slow for
  // the sake of three fields near the bottom.
  recordDetail = null;
  auditRows = null;
  paint();
  loadRecordDetail(id);
  loadAudit('record', id);
};

/*
  Who decided what, for the thing in front of you.

  Six store modules write an audit row on every verdict, the README calls it an
  invariant, and characterization's own toast tells the analyst "the change is
  in the audit log" — but nothing in the browser read it, so the only way to see
  the trail was to call the API by hand.

  Here rather than in a view of its own. listAudit already filters by target,
  and the question people actually have is about the record or host they are
  looking at: who ruled this out, and when. A global log would be a ninth tab
  answering a question nobody asked in that form.
*/
let auditRows = null;

async function loadAudit(kind, id) {
  auditRows = null;
  try { auditRows = await api(`/api/audit?target=${encodeURIComponent(id)}`); } catch { auditRows = []; }
  if (current?.kind === kind && current.id === id) paint();
}

/*
  Actions are stored namespaced — record.promote, host.verdict — because the
  same verb means different things on different targets. The drawer already says
  which thing is open, so the prefix is noise here and only the verb is shown;
  anything without a phrasing falls back to the verb itself rather than being
  hidden, since a trail that silently omits an action is worse than an ugly one.
*/
const AUDIT_LABEL = {
  promote: 'confirmed', deny: 'denied', archive: 'archived', restore: 'restored',
  verdict: 'set the verdict', update: 'edited', bind: 'bound to a host',
  merge: 'merged', create: 'created', remove: 'removed', correct: 'corrected',
  commit: 'committed', discard: 'discarded', acknowledge: 'acknowledged a gap',
  move: 'moved', reattribute: 'reattributed',
};
const auditVerb = (action) => {
  const verb = String(action ?? '').split('.').pop();
  return AUDIT_LABEL[verb] ?? String(action ?? '').replace(/\./g, ' ');
};

function auditHtml() {
  if (auditRows === null) return '<div class="muted" style="font-size:12px">reading the trail…</div>';
  if (!auditRows.length) {
    // Distinguishable from a failure: nothing has been decided yet.
    return '<div class="muted" style="font-size:12px">Nothing has been adjudicated yet.</div>';
  }
  return `<table class="audit-log">${auditRows.map(a => `
    <tr>
      <td class="mono">${esc(shortTime(a.ts).slice(0, 16))}</td>
      <td>${esc(a.analyst ?? 'unattributed')}</td>
      <td>${esc(auditVerb(a.action))}</td>
    </tr>`).join('')}</table>`;
}

async function loadRecordDetail(id) {
  let full = null;
  try { full = await api(`/api/records/${id}`); } catch { return; }
  // Somebody may have closed it, or opened another, while this was in flight.
  if (current?.kind !== 'record' || current.id !== id) return;
  recordDetail = full;
  paint();
}
/*
  Somebody else filing a record must not wipe a half-typed correction, the same
  way a delta must not repaint over an open comms draft.

  It must, though, re-ask for the record it is showing. recordDetail is fetched
  once when the drawer opens and preferred over the live projection ever after,
  so adjudicating from inside the drawer repainted it from the copy taken
  BEFORE the verdict: the row behind it flipped to filed while the drawer went
  on reading "pending · created by …" and offering Confirm and Deny. The same
  thing happened when a teammate adjudicated a record you had open. The fetch
  is one row and only while a drawer is open.
*/
export const refreshDrawer = (type = '') => {
  if (!current || editingHost) return;
  paint();
  // Only for deltas that could have changed what is on screen. session.delta
  // fires once per streamed token, and a fetch per token would be a request
  // storm for a drawer showing something the turn has not touched.
  if (!/^(record|host|edge)/.test(type)) return;
  if (current.kind === 'record') loadRecordDetail(current.id);
  if (current.kind === 'host') loadHostRecords(current.id);
};

const HOST_VERDICTS = [
  ['confirmed', 'Confirmed compromised', 'bad'],
  ['suspected', 'Suspected', ''],
  ['cleared', 'Cleared', 'ok'],
  ['unknown', 'Reset to unknown', ''],
];

const TRIAGE = ['New', 'Investigating', 'Corroborated', 'Ruled Out'];

function recordCard(r) {
  const thread = threadById(r.thread_id);
  return `
    <div class="rec-item" data-rec="${r.id}">
      <div class="top">
        <span class="${r.time_tier === 'unplaceable' ? 'tier-unplaceable' : r.time_tier === 'approximate' ? 'tier-approximate' : ''}">
          ${esc(r.event_time || 'time not recorded')}
        </span>
        <span class="s-${r.state}">${r.state}</span>
      </div>
      <div style="margin:5px 0 6px">${esc(r.description ?? '')}</div>
      <div class="mono muted">
        ${r.indicator ? esc(r.indicator) + ' · ' : ''}${esc(r.mitre ?? '')}
        ${thread ? ` · <span style="color:${esc(thread.color)}">${esc(thread.key)}</span>` : ''}
      </div>
      <div class="cand row" style="margin-top:8px">
        ${r.state !== 'filed' ? `<button class="ok" data-act="promote" data-id="${r.id}">Confirm</button>` : ''}
        ${r.state !== 'denied' ? `<button class="bad" data-act="deny" data-id="${r.id}">Deny</button>` : ''}
        <button data-act="open" data-id="${r.id}">Detail</button>
      </div>
    </div>`;
}

function hostBody(host) {
  const recs = hostRecords;
  const conns = state.connections.filter(c => c.src === host.ip || c.dst === host.ip);
  return `
    <button class="close" data-act="close">&times;</button>
    <h2>${esc(host.name)}</h2>
    <p class="muted mono">${esc(host.ip ?? 'no address')} ${host.source === 'discovered'
      ? '<span style="color:var(--warn)"> · discovered, not in terrain</span>' : ''}</p>

    <dl>
      <dt>Enclave</dt><dd>${esc(host.enclave ?? '—')}</dd>
      <dt>Segment</dt><dd>${esc(host.segment ?? '—')} ${esc(host.cidr ?? '')}</dd>
      <dt>OS</dt><dd>${esc(host.os || '—')}</dd>
      <dt>Role</dt><dd>${esc(host.role || '—')}</dd>
      <dt>Presence</dt><dd class="p-${esc(host.presence ?? 'unsurveyed')}">${
  esc(host.presence_note || host.presence || 'unsurveyed')}</dd>
      <dt>Domain</dt><dd>${host.domain_joined === 1
    ? 'Domain-joined'
    : host.domain_joined === 0
      ? '<span style="color:var(--warn)">Not domain-joined</span>'
      : '<span class="muted">not established</span>'}</dd>
      ${host.name_conflict ? `<dt>Name conflict</dt>
        <dd style="color:var(--warn)">${esc(host.name_conflict)}</dd>` : ''}
      ${host.observed_from ? `<dt>Seen from</dt><dd class="mono">${
    esc((() => { try { return JSON.parse(host.observed_from).join(' · '); }
      catch { return host.observed_from; } })())}</dd>` : ''}
      <dt>Verdict</dt><dd class="v-${host.verdict}">${esc(host.verdict)}${
  host.verdict_by ? ` — ${esc(host.verdict_by)} at ${esc(shortTime(host.verdict_at))}` : ''}</dd>
      <dt>Evidence</dt><dd>${recs.length} record${recs.length === 1 ? '' : 's'}</dd>
      <dt>Connections</dt><dd>${conns.length ? conns.map(c =>
    `${esc(c.src)} → ${esc(c.dst)} (${c.count})`).join('<br>') : '—'}</dd>
    </dl>

    <label>Host compromise assessment</label>
    <div class="verdicts">
      ${HOST_VERDICTS.map(([v, label, cls]) =>
    `<button class="${cls}" data-act="verdict" data-verdict="${v}" data-id="${host.id}"
       ${host.verdict === v ? 'disabled' : ''}>${label}</button>`).join('')}
    </div>
    <p class="hint">Independent of the records below, and independent of presence:
      denying a record never clears the host, and a host answering a ping is not
      evidence it is clean.</p>

    <div class="verdicts" style="margin-top:14px">
      <button data-act="edithost" data-id="${host.id}">${editingHost ? 'Close editor' : 'Edit asset'}</button>
    </div>
    ${editingHost ? hostEditHtml(host) : ''}

    <h3 style="margin-top:22px;font-size:13px">Latest collections</h3>
    ${collectionsHtml()}

    <h3 style="margin-top:22px;font-size:13px">Evidence on this host</h3>
    ${recs.length ? recs.map(recordCard).join('') : '<p class="muted">Nothing recorded yet.</p>'}`;
}

/**
 * Editing an asset.
 *
 * Terrain rewrites every seeded host at each re-seed, so a correction is
 * stored as a pinned field and laid back on top rather than written into the
 * row and quietly lost on the next restart. Each pinned field says so and
 * reverts on its own, which keeps a later survey able to correct everything
 * nobody has claimed.
 */
function hostEditHtml(host) {
  const pinned = new Map((hostDetail?.overrides ?? []).map(o => [o.field, o]));
  const ev = hostDetail?.evidence ?? { records: 0, characterization: 0 };
  const others = state.hosts.filter(h => h.id !== host.id);
  return `
    <div class="hostedit">
      <div class="task-form-grid">
        ${OVERRIDABLE.map(f => {
    const p = pinned.get(f);
    return `<label>${f}${p ? '<span class="pinchip">pinned</span>' : ''}</label>
          <div class="row">
            <input class="grow" data-hf="${f}" value="${esc(host[f] ?? '')}">
            ${p ? `<button data-act="unpin" data-id="${host.id}" data-field="${f}"
              title="Hand this field back to terrain">revert</button>` : ''}
          </div>
          ${p ? `<label></label><span class="hint">pinned by ${esc(p.set_by ?? '—')} ·
            ${esc(shortTime(p.set_at).slice(0, 16))} · terrain no longer overwrites it</span>` : ''}`;
  }).join('')}
      </div>
      <div class="task-form-actions">
        <button class="primary" data-act="savehost" data-id="${host.id}">Pin changes</button>
        <span class="err" id="host-err"></span>
      </div>

      <label class="steps-label">Merge into another host</label>
      <div class="row">
        <select id="merge-into">
          <option value="">— choose a host —</option>
          ${others.map(h => `<option value="${esc(h.id)}">${esc(h.name)}${
    h.ip ? ` · ${esc(h.ip)}` : ''}${h.enclave ? ` · ${esc(h.enclave)}` : ''}</option>`).join('')}
        </select>
        <button class="bad" data-act="merge" data-id="${host.id}">Merge</button>
      </div>
      <p class="hint">Its ${ev.records} record(s) and ${ev.characterization} baseline row(s) move with it,
        then this host is removed. A host that came from terrain cannot be merged away — the next
        survey would recreate it.</p>

      ${host.source !== 'seeded' && !ev.records && !ev.characterization ? `
        <div class="task-form-actions">
          <button class="bad" data-act="removehost" data-id="${host.id}">Remove this host</button>
          <span class="hint">Carries no evidence, so nothing is orphaned.</span>
        </div>` : ''}
    </div>`;
}

function recordBody(r) {
  const FIELDS = [
    ['Event ID', 'event_id'], ['Event Time', 'event_time'], ['Hostname', 'hostname'],
    ['Source IP', 'source_ip'], ['Destination IP', 'destination_ip'], ['User', 'user'],
    ['Indicator', 'indicator'], ['Command', 'command'], ['PID', 'pid'], ['SHA256', 'sha256'],
    ['MISP / contents', 'misp'], ['Evidence Source', 'evidence_source'],
    ['Confidence', 'confidence'], ['Triage Status', 'triage_status'],
    ['MITRE ATT&CK', 'mitre'], ['Reference', 'reference'],
  ];
  const thread = threadById(r.thread_id);
  return `
    <button class="close" data-act="close">&times;</button>
    <h2>Record</h2>
    <p class="muted">${esc(r.state)} · created by ${esc(r.created_by ?? '—')}${
  r.adjudicated_by ? ` · adjudicated by ${esc(r.adjudicated_by)}` : ''}</p>

    <div style="margin:14px 0;padding:12px;background:#131a24;border:1px solid var(--line);border-radius:8px">
      ${esc(r.description ?? '')}
    </div>

    <label>Bound to host${r.host_id ? '' : '<span class="pinchip warn">unbound</span>'}</label>
    <select data-act="bindhost" data-id="${r.id}">
      <option value="">— not bound to a host —</option>
      ${state.hosts.map(h => `<option value="${esc(h.id)}" ${h.id === r.host_id ? 'selected' : ''}>
        ${esc(h.name)}${h.ip ? ` · ${esc(h.ip)}` : ''}${h.enclave ? ` · ${esc(h.enclave)}` : ''}</option>`).join('')}
    </select>
    <p class="hint">${r.host_id
    ? `The host this finding is about. Any address it names still shows it too, which is how
       the far end of a connection stays visible.${
  r.host_bound_by ? ` Bound by ${esc(r.host_bound_by)}.` : ''}`
    : 'Nothing could place this from its hostname text, so it appears on no host. '
      + 'Pick the right one rather than leaving it to a name match.'}</p>

    <label>Thread</label>
    <select data-act="thread" data-id="${r.id}">
      <option value="">— unassigned —</option>
      ${state.threads.map(t => `<option value="${t.id}" ${t.id === r.thread_id ? 'selected' : ''}>
        ${esc(t.key)} — ${esc(t.name)}</option>`).join('')}
    </select>

    <label>Triage status</label>
    <select data-act="triage" data-id="${r.id}">
      <option value="">—</option>
      ${TRIAGE.map(t => `<option ${t === r.triage_status ? 'selected' : ''}>${t}</option>`).join('')}
    </select>

    <div class="verdicts" style="margin-top:16px">
      ${r.state !== 'filed' ? `<button class="ok" data-act="promote" data-id="${r.id}">Confirm — file it</button>` : ''}
      ${r.state !== 'denied' ? `<button class="bad" data-act="deny" data-id="${r.id}">Deny</button>` : ''}
    </div>

    <dl>
      ${FIELDS.map(([label, key]) => `<dt>${label}</dt><dd>${
    key === 'command' || key === 'misp'
      ? `<span class="mono">${esc(r[key] ?? '—')}</span>` : esc(r[key] ?? '—')}</dd>`).join('')}
      <dt>Timeline</dt><dd>${esc(r.time_tier)}${r.time_parsed ? ` at ${esc(shortTime(r.time_parsed))}` : ''}</dd>
      <dt>Thread</dt><dd>${thread ? esc(thread.name) : '—'}</dd>
    </dl>

    ${r.analyst_notes ? `<label>Analyst notes</label>
      <div style="white-space:pre-wrap;font-size:12.5px">${esc(r.analyst_notes)}</div>` : ''}

    <label style="margin-top:14px">Adjudication</label>
    ${auditHtml()}`;
}

function paint() {
  if (!current) return;
  const d = el();
  const body = current.kind === 'host'
    ? (hostById(current.id) ? hostBody(hostById(current.id)) : null)
    : (() => {
      // The fetched row when it has arrived, the projection until then. Both
      // render; the fuller one simply has more in it.
      const r = (recordDetail?.id === current.id ? recordDetail : null) ?? recordById(current.id);
      // state.records is a cache of what this browser has seen, not the case
      // file, so a record opened from a view that fetched its own rows may not
      // be in it yet. Say so for the moment it takes, rather than showing an
      // empty drawer that reads as a record with nothing in it.
      return r ? recordBody(r) : '<div class="loading">Loading the finding…</div>';
    })();

  if (!body) { closeDrawer(); return; }
  d.innerHTML = body;
  d.hidden = false;
  d.scrollTop = 0;
}

/*
  One delegated listener for the whole drawer, installed once.

  Called by the app rather than installed at import. Registering it on the
  module body made this file — and every view that imports it: map, records,
  sessions, timeline — impossible to load anywhere without a DOM, which is
  most of why the view layer had no tests at all.
*/
export function initDrawer() {
  document.addEventListener('click', async (e) => {
    const btn = e.target.closest('#drawer [data-act]');
    if (!btn) return;
    const { act, id, verdict } = btn.dataset;
    try {
      if (act === 'close') return closeDrawer();

      if (act === 'edithost') {
        editingHost = !editingHost;
        // Overrides and evidence counts are only needed once the editor is open.
        hostDetail = editingHost ? await api(`/api/hosts/${id}`) : null;
        return paint();
      }
      if (act === 'unpin') {
        await api(`/api/hosts/${id}`, { method: 'PATCH', body: { fields: { [btn.dataset.field]: null } } });
        hostDetail = await api(`/api/hosts/${id}`);
        toast(`${btn.dataset.field} is back under terrain control`);
        return paint();
      }
      if (act === 'savehost') {
        const fields = {};
        for (const inp of document.querySelectorAll('#drawer [data-hf]')) {
          const was = hostById(id)?.[inp.dataset.hf] ?? '';
          if (inp.value.trim() !== String(was ?? '')) fields[inp.dataset.hf] = inp.value.trim();
        }
        if (!Object.keys(fields).length) return toast('Nothing changed');
        try {
          await api(`/api/hosts/${id}`, { method: 'PATCH', body: { fields } });
          hostDetail = await api(`/api/hosts/${id}`);
          toast(`Pinned ${Object.keys(fields).join(', ')} — terrain no longer overwrites ${
            Object.keys(fields).length === 1 ? 'it' : 'them'}`);
          return paint();
        } catch (e) { document.querySelector('#host-err').textContent = e.message; return; }
      }
      if (act === 'merge') {
        const into = document.querySelector('#merge-into')?.value;
        if (!into) return toast('Choose a host to merge into', true);
        const reason = prompt('Why are these the same host?');
        if (!reason) return;
        try {
          const out = await api(`/api/hosts/${id}/merge`, { method: 'POST', body: { into, reason } });
          toast(`Merged into ${out.into.name} — ${out.records} record(s) and ` +
            `${out.characterizationRows} baseline row(s) moved`);
          return openHostDrawer(into);
        } catch (e) { document.querySelector('#host-err').textContent = e.message; return; }
      }
      if (act === 'removehost') {
        if (!confirm('Remove this host? It carries no evidence.')) return;
        try {
          await api(`/api/hosts/${id}`, { method: 'DELETE' });
          toast('Host removed');
          return closeDrawer();
        } catch (e) { document.querySelector('#host-err').textContent = e.message; return; }
      }
      if (act === 'open') return openRecordDrawer(id);
      if (act === 'promote') { await api(`/api/records/${id}/promote`, { method: 'POST' }); toast('Confirmed'); }
      if (act === 'deny') { await api(`/api/records/${id}/deny`, { method: 'POST' }); toast('Denied'); }
      if (act === 'verdict') {
        await api(`/api/hosts/${id}/verdict`, { method: 'PATCH', body: { verdict } });
        toast(`Host marked ${verdict}`);
      }
    } catch (err) { toast(err.message, true); }
  });

  // Selects, for the same reason.
  document.addEventListener('change', async (e) => {
    const sel = e.target.closest('#drawer select[data-act]');
    if (!sel) return;
    const { act, id } = sel.dataset;
    try {
      if (act === 'bindhost') {
        await api(`/api/records/${id}/bind`, { method: 'POST', body: { hostId: sel.value || null } });
        toast(sel.value ? 'Bound — this finding now shows on that host only' : 'Unbound');
        return;
      }
      if (act === 'thread') await api(`/api/records/${id}`, { method: 'PATCH', body: { thread_id: sel.value || null } });
      if (act === 'triage') await api(`/api/records/${id}`, { method: 'PATCH', body: { triage_status: sel.value } });
      toast('Saved');
    } catch (err) { toast(err.message, true); }
  });
}
