import { state, filters, api, toast, esc, applyFilters, threadById, preservingFocus } from '../core.js';
import { openRecordDrawer } from './drawer.js';

let root = null;
let stateFilter = 'all';
let archivedRows = [];   // fetched on demand; they are not in the live state

/*
  Matching rows come from the server now.

  Filtering used to run over state.records in the browser, which meant the whole
  case file had to be resident for search to work — and would have silently
  started answering over a subset the moment the bootstrap payload was paged.
  Asking the server means the answer is computed over every record, and the
  total is the server's count rather than the length of what arrived.
*/
const PAGE = 200;
let liveRows = [];
let liveTotal = 0;
/* Whether the last search answered. An empty table means two different things. */
let searchFailed = false;
let searchTimer = null;

const COLS = [
  ['Time', r => r.event_time ?? '—', 'clip'],
  ['Host', r => r.hostname ?? '—', ''],
  ['Src', r => r.source_ip ?? '', 'mono'],
  ['Dst', r => r.destination_ip ?? '', 'mono'],
  ['Indicator', r => r.indicator ?? '', 'clip'],
  ['Description', r => r.description ?? '', 'clip'],
  ['MITRE', r => r.mitre ?? '', 'mono'],
  ['Conf', r => r.confidence ?? '', ''],
];

function rows() {
  /*
    Archived findings are not in state.records at all — the server leaves them
    out of every working read, which is the point of archiving. Looking at them
    is an explicit choice, so they are fetched only when asked for, and they
    stay filtered in the browser because the set is small and bounded.
  */
  if (stateFilter === 'archived') return applyFilters(archivedRows);
  return liveRows;
}

/** Ask the server for the current query. */
async function loadLive() {
  if (stateFilter === 'archived') return;
  const p = new URLSearchParams({ limit: String(PAGE) });
  if (filters.q) p.set('q', filters.q);
  if (stateFilter !== 'all') p.set('state', stateFilter);
  if (filters.thread) p.set('thread', filters.thread);
  try {
    const out = await api(`/api/records/search?${p}`);
    liveRows = out.rows;
    liveTotal = out.total;
    searchFailed = false;
  } catch {
    /*
      Leave the last answer on screen rather than blanking the table under
      somebody mid-read — but say that it is the last answer.

      On a fresh mount liveRows is empty, so a failing search rendered "No
      records yet. Start a session and Claude will propose them." An analyst
      filtering by a new term after that keeps reading pre-failure results with
      nothing to tell them the query stopped running — the same confusion this
      codebase names in its own characterization tests: empty because nobody
      collected, or empty because something ate it. The difference decides
      whether the next person runs a collection or goes looking for a bug.
    */
    searchFailed = true;
    liveTotal = liveRows.length;
  }
  // Inside the promise, not around the call: preservingFocus needs a
  // SYNCHRONOUS repaint, and the wrapper app.js puts around onDelta has long
  // since returned by the time this lands. Wrapping loadArchived instead —
  // which onDelta never calls — left the filter box still losing its caret to
  // any teammate filing a record.
  if (root) preservingFocus(root, paint);
}

/** Denied and still on screen: the set the archive band offers to retire. */
const deniedLive = () => state.records.filter(r => r.state === 'denied');

function paint() {
  const rs = rows();
  root.innerHTML = `
    <div class="bar">
      <input class="grow" id="q" placeholder="Filter host, address, indicator, command, MITRE…" value="${esc(filters.q)}">
      <select id="st">
        ${['all', 'pending', 'filed', 'denied', 'archived'].map(s =>
    `<option value="${s}" ${s === stateFilter ? 'selected' : ''}>${s}</option>`).join('')}
      </select>
      <select id="th">
        <option value="">all threads</option>
        ${state.threads.map(t => `<option value="${t.id}" ${t.id === filters.thread ? 'selected' : ''}>
          ${esc(t.key)} — ${esc(t.name)}</option>`).join('')}
      </select>
      <span class="muted">${stateFilter === 'archived'
    ? `${rs.length} archived`
    : `${rs.length} of ${liveTotal}${liveTotal > rs.length ? ` (first ${rs.length})` : ''}`}</span>
      <a class="btn" href="/api/export/records.xlsx?state=filed">Export workbook</a>
      <a class="btn" href="/api/export/records.csv?state=filed">CSV (filed)</a>
      <a class="btn" href="/api/export/records.csv?state=all">CSV (all)</a>
      <a class="btn" href="/api/export/navigator.json${filters.thread
    ? `?thread=${encodeURIComponent(filters.thread)}` : ''}"
         title="MITRE ATT&amp;CK Navigator layer. Confirmed findings score above proposed ones.">ATT&amp;CK layer</a>
      <a class="btn" href="/api/export/iocs.json"
         title="Confirmed indicators as a MISP event.">IOCs (MISP)</a>
      <a class="btn" href="/api/export/iocs.json?format=stix"
         title="Confirmed indicators as a STIX 2.1 bundle.">IOCs (STIX)</a>
      <a class="btn" href="/api/export/report.md"
         title="The deliverable, assembled from the case file. Confirmed findings only.">Report</a>
    </div>

    ${stateFilter !== 'archived' && deniedLive().length ? `
      <div class="withdrawn-band">
        <div>
          <b>${deniedLive().length} denied finding${deniedLive().length === 1 ? '' : 's'}</b>
          <span class="muted">Denying settled what the evidence showed. Archiving retires it: off
            the timeline, off the map, out of the case file Claude is shown, and out of the
            connections it implied. Nothing is deleted — pick "archived" above to read or restore
            them.</span>
        </div>
        <button id="arch-denied">Archive ${deniedLive().length}</button>
      </div>` : ''}

    ${searchFailed ? `<div class="search-broken">
      The search stopped answering, so what follows is the last answer it gave, not the
      current case file. A filter changed since then has not been applied. Reload; if it
      persists the store may be locked or migrating.</div>` : ''}

    <div class="table-wrap sticky">
      <table>
        <thead><tr>
          ${COLS.map(c => `<th>${c[0]}</th>`).join('')}<th>Thread</th><th>State</th><th></th>
        </tr></thead>
        <tbody>
        ${rs.length === 0
    ? `<tr><td colspan="${COLS.length + 3}" class="muted" style="padding:26px;text-align:center">${
      searchFailed
        ? 'Nothing to show — but the search is failing, so this is not an empty case file.'
        : 'No records yet. Start a session and Claude will propose them.'}</td></tr>`
    : rs.map(r => {
      const t = threadById(r.thread_id);
      return `<tr data-id="${r.id}">
              ${COLS.map(c => `<td class="${c[2]}">${esc(c[1](r))}</td>`).join('')}
              <td>${t ? `<span style="color:${esc(t.color)}">${esc(t.key)}</span>` : '—'}</td>
              <td class="s-${r.state}">${r.state}</td>
              <td style="white-space:nowrap">
                ${stateFilter === 'archived'
    ? `<button data-act="restore" data-id="${r.id}">restore</button>`
    : `${r.state !== 'filed' ? `<button class="ok" data-act="promote" data-id="${r.id}">✓</button>` : ''}
                   ${r.state !== 'denied' ? `<button class="bad" data-act="deny" data-id="${r.id}">✕</button>` : ''}
                   <button data-act="archive" data-id="${r.id}" title="Retire it from the working views">⌫</button>`}
              </td></tr>`;
    }).join('')}
        </tbody>
      </table>
    </div>`;

  root.querySelector('#q').addEventListener('input', (e) => {
    filters.q = e.target.value;
    const caret = e.target.selectionStart;
    // Debounced: a round trip per keystroke would queue answers that arrive out
    // of order, and the last one to land wins rather than the last one typed.
    clearTimeout(searchTimer);
    searchTimer = setTimeout(async () => {
      await loadLive();
      const box = root.querySelector('#q');
      if (box) { box.focus(); try { box.setSelectionRange(caret, caret); } catch { /* no range */ } }
    }, 200);
  });
  root.querySelector('#st').addEventListener('change', (e) => {
    stateFilter = e.target.value;
    if (stateFilter === 'archived') paint(); else loadLive();
  });
  root.querySelector('#th').addEventListener('change', (e) => {
    filters.thread = e.target.value;
    loadLive();
  });

  root.querySelectorAll('tbody tr').forEach(tr => {
    tr.addEventListener('click', (e) => {
      if (e.target.closest('button')) return;
      openRecordDrawer(tr.dataset.id);
    });
  });

  const DONE = { promote: 'Confirmed', deny: 'Denied', archive: 'Archived', restore: 'Restored' };
  root.querySelectorAll('[data-act]').forEach(b => {
    b.addEventListener('click', async (e) => {
      e.stopPropagation();
      try {
        await api(`/api/records/${b.dataset.id}/${b.dataset.act}`, { method: 'POST', body: {} });
        toast(DONE[b.dataset.act] ?? 'Done');
        // Archiving and restoring move a row between two lists the client holds
        // separately, so the archived side has to be re-read.
        if (b.dataset.act === 'archive' || b.dataset.act === 'restore') await loadArchived();
      } catch (err) { toast(err.message, true); }
    });
  });

  root.querySelector('#arch-denied')?.addEventListener('click', async () => {
    const ids = deniedLive().map(r => r.id);
    try {
      const out = await api('/api/records/archive', {
        method: 'POST', body: { ids, reason: 'denied and closed out' } });
      toast(`Archived ${out.archived} finding${out.archived === 1 ? '' : 's'}`);
      await loadArchived();
    } catch (err) { toast(err.message, true); }
  });
}

async function loadArchived() {
  archivedRows = await api('/api/records/archived').catch(() => []);
  if (root) preservingFocus(root, paint);
}

export function mount(el) { root = el; paint(); loadLive(); loadArchived(); }
/* Every view paints into the same element, so a fetch that lands after the
   router has moved on must not paint at all. */
export function unmount() { root = null; }
/* A record changing anywhere changes what this query matches, so the answer is
   re-asked rather than recomputed from a stale local copy. */
export function onDelta() { if (root) loadLive(); }
