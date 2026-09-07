/** Shared client state, API access, and derived lookups. No rendering here. */

export const state = {
  threads: [], hosts: [], records: [], edges: [], connections: [], sessions: [], members: [],
};

/** Cross-view filter state. The timeline brush writes from/to; the map reads it. */
export const filters = {
  thread: '', confidence: '', evidenceOnly: false, unidentifiedOnly: false, from: null, to: null, q: '',
};

// --- tiny event bus --------------------------------------------------------
const handlers = new Map();
export const on = (type, fn) => {
  if (!handlers.has(type)) handlers.set(type, new Set());
  handlers.get(type).add(fn);
  return () => handlers.get(type).delete(fn);
};
export const emit = (type, payload) => {
  for (const fn of handlers.get(type) ?? []) { try { fn(payload); } catch (e) { console.error(e); } }
};

// --- api -------------------------------------------------------------------
export async function api(path, { method = 'GET', body } = {}) {
  const res = await fetch(path, {
    method,
    headers: body ? { 'content-type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401) { location.href = '/login'; throw new Error('unauthenticated'); }
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).error ?? detail; } catch { /* not json */ }
    throw new Error(detail);
  }
  return res.status === 204 ? null : res.json();
}

export function toast(message, bad = false) {
  const el = document.getElementById('toast');
  el.textContent = message;
  el.className = 'toast' + (bad ? ' bad' : '');
  el.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { el.hidden = true; }, 3200);
}

// --- derived lookups -------------------------------------------------------

const ipOf = (v) => {
  if (!v) return null;
  const m = /(\d{1,3}(?:\.\d{1,3}){3})/.exec(String(v));
  return m ? m[1] : null;
};

/**
 * Records belonging to this host.
 *
 * Three ways in, and a record needs only one of them. The binding says which
 * host the finding is ABOUT. Either address says who took part, which is how
 * the rootkit download server 198.51.100.110 lights up from a finding filed
 * against the host that fetched from it.
 *
 * What is gone is the short-name arm. Matching "Web (the other DMZ)" against a
 * host called "Web" put one rootkit finding on two different servers, because
 * the estate has two hosts by that name. Addresses were never ambiguous; names
 * were, so only an exact name counts now.
 */
export function recordsForHost(host) {
  if (!host) return [];
  const name = (host.name ?? '').toLowerCase();
  return state.records.filter(r => {
    if (r.state === 'denied') return false;
    if (r.host_id === host.id) return true;
    if (host.ip && (ipOf(r.source_ip) === host.ip || ipOf(r.destination_ip) === host.ip)) return true;
    if (r.host_id) return false;   // placed elsewhere; a bare name must not claim it back
    const hn = (r.hostname ?? '').toLowerCase();
    return Boolean(name) && Boolean(hn) && hn === name;
  });
}

/** Records nothing can place, so the drawer can offer to bind them by hand. */
export const unboundRecords = () => state.records.filter(r =>
  !r.host_id && r.state !== 'denied' &&
  !state.hosts.some(h => (h.ip && (ipOf(r.source_ip) === h.ip || ipOf(r.destination_ip) === h.ip))
    || (h.name && r.hostname && h.name.toLowerCase() === r.hostname.toLowerCase())));

export const threadById = (id) => state.threads.find(t => t.id === id) ?? null;
export const hostById = (id) => state.hosts.find(h => h.id === id) ?? null;
export const recordById = (id) => state.records.find(r => r.id === id) ?? null;

/** Apply the active filter set to a record list. */
export function applyFilters(records) {
  return records.filter(r => {
    if (filters.thread && r.thread_id !== filters.thread) return false;
    if (filters.confidence && (r.confidence ?? '') !== filters.confidence) return false;
    if (filters.from && (!r.time_parsed || r.time_parsed < filters.from)) return false;
    if (filters.to && (!r.time_parsed || r.time_parsed > filters.to)) return false;
    if (filters.q) {
      const hay = [r.description, r.hostname, r.indicator, r.command, r.analyst_notes, r.mitre,
        r.source_ip, r.destination_ip, r.user].join(' ').toLowerCase();
      if (!hay.includes(filters.q.toLowerCase())) return false;
    }
    return true;
  });
}

export const esc = (s) => String(s ?? '').replace(/[&<>"']/g,
  c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

export const shortTime = (iso) => {
  if (!iso) return '—';
  return iso.replace('T', ' ').replace(/\.\d+Z$/, 'Z');
};

/*
  Which mount is the current one.

  Every view is handed the same #view element and four of them mount
  asynchronously, so a view whose fetches land after somebody has navigated on
  painted itself over whatever they navigated to — and, worse, registered its
  event-bus handlers after the router had already called its unmount. Those
  handlers were unreachable: comms.unmount only runs while the router believes
  comms is mounted, and a later remount overwrites the list without releasing
  the orphans. One raced mount left the chat window repainting over the
  timeline on every message anyone sent, for the life of the page.

  The router bumps this before each mount; a view takes its own number and asks
  before it paints or subscribes.
*/
let mountSeq = 0;
export const beginMount = () => ++mountSeq;
export const thisMount = () => mountSeq;
export const stillMounted = (gen) => gen === mountSeq;

// --- delta application -----------------------------------------------------

const upsert = (list, item) => {
  const i = list.findIndex(x => x.id === item.id);
  if (i >= 0) list[i] = item; else list.push(item);
};

/*
  Repainting without taking the keyboard away from whoever is using it.

  Every view repaints by replacing its innerHTML, so a delta arriving while
  somebody is mid-word destroys the input they are typing into and recreates
  it: focus lands back on the body and the caret resets to the start. With a
  team of twelve on one exercise, somebody else sending evidence for processing
  was enough to do it, and the person typing had no idea why their cursor had
  moved.

  Guarding each view separately was already being attempted in three places and
  missed in a dozen more, so this wraps the one place a delta reaches the DOM.
*/

/** A selector that will still find this element after its parent is rebuilt. */
function stableSelector(root, el) {
  if (el.id) return `#${CSS.escape(el.id)}`;
  const tag = el.tagName.toLowerCase();
  // Most repeated controls here are keyed by a data attribute — a column
  // filter, a coverage reason, a staged host — which survives the rebuild.
  for (const { name, value } of el.attributes) {
    if (name.startsWith('data-')) return `${tag}[${name}="${CSS.escape(value)}"]`;
  }
  if (el.name) return `${tag}[name="${CSS.escape(el.name)}"]`;

  // Nothing nameable: fall back to position, which holds as long as the shape
  // of the view has not changed around it.
  const parts = [];
  for (let node = el; node && node !== root; node = node.parentElement) {
    const i = [...node.parentElement.children].indexOf(node) + 1;
    parts.unshift(`${node.tagName.toLowerCase()}:nth-child(${i})`);
  }
  return parts.length ? parts.join(' > ') : null;
}

const scrollableAncestor = (el, root) => {
  for (let n = el.parentElement; n && n !== root.parentElement; n = n.parentElement) {
    if (n.scrollHeight > n.clientHeight + 1) return n;
  }
  return null;
};

/**
 * Run a repaint, then put the caret back where the person left it.
 *
 * The repaint must be SYNCHRONOUS. Wrapping a function that repaints inside a
 * promise restores the caret before the rebuild happens, which does nothing at
 * all — call this from inside the callback instead, the way the plan and
 * characterization views do.
 *
 * @param {Element} root the container about to be rebuilt
 * @param {() => void} repaint synchronous
 */
export function preservingFocus(root, repaint) {
  const el = document.activeElement;
  const editable = el && root && root.contains(el)
    && (/^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName) || el.isContentEditable);

  if (!editable) { repaint(); return; }

  const selector = stableSelector(root, el);
  // Reading selectionStart throws on input types that have no text range.
  let start = null; let end = null; let dir;
  try { start = el.selectionStart; end = el.selectionEnd; dir = el.selectionDirection; } catch { /* no range */ }
  const ownScroll = el.scrollTop;
  const scroller = scrollableAncestor(el, root);
  const scrollTop = scroller?.scrollTop;
  const scrollSel = scroller ? stableSelector(root, scroller) : null;

  repaint();

  if (!selector) return;
  const next = root.querySelector(selector);
  if (!next || next === el) return;

  next.focus({ preventScroll: true });
  if (start != null) {
    try { next.setSelectionRange(start, end, dir); } catch { /* not a text field */ }
  }
  next.scrollTop = ownScroll;
  if (scrollSel != null && scrollTop != null) {
    const s = root.querySelector(scrollSel);
    if (s) s.scrollTop = scrollTop;
  }
}

export function applyDelta({ type, payload }) {
  switch (type) {
    case 'record.created':
    case 'record.updated':      upsert(state.records, payload); break;
    /*
      A signal carries no array. state.records is a cache of what this browser
      has actually seen now, not a copy of the case file, so a signal leaves it
      alone and the views re-ask for what they draw.
    */
    case 'records.changed':     if (Array.isArray(payload)) state.records = payload; break;
    case 'hosts.changed':       state.hosts = payload; break;
    case 'host.verdict':        upsert(state.hosts, payload); break;
    case 'edge.created':
    case 'edge.updated':        upsert(state.edges, payload); break;
    case 'edges.changed':       state.edges = payload; break;
    case 'connections.changed': state.connections = payload; break;
    case 'session.created':
    case 'session.state':       upsert(state.sessions, payload); break;
    default: break;
  }
  emit(type, payload);
  emit('*', { type, payload });
}
