import { state, api, applyDelta, on, emit, toast, esc, preservingFocus, beginMount } from './core.js';
import * as records from './views/records.js';
import * as sessions from './views/sessions.js';
import * as plan from './views/plan.js';
import * as comms from './views/comms.js';
import * as characterization from './views/characterization.js';
import * as map from './views/map.js';
import * as timeline from './views/timeline.js';
import { closeDrawer, refreshDrawer, initDrawer } from './views/drawer.js';

const VIEWS = { sessions, plan, characterization, map, timeline, records, comms };
const view = document.getElementById('view');

function currentRoute() {
  const r = (location.hash.replace(/^#\/?/, '') || 'sessions').split('/')[0];
  return VIEWS[r] ? r : 'sessions';
}

let mounted = null;

function render() {
  const route = currentRoute();
  for (const a of document.querySelectorAll('#nav a')) {
    a.classList.toggle('active', a.dataset.route === route);
  }
  // Unmount before every mount, including a remount of the same route. An
  // unrecognised hash resolves back to 'sessions', and skipping unmount there
  // stranded the previous view's event-bus handlers permanently.
  if (mounted && VIEWS[mounted].unmount) VIEWS[mounted].unmount();
  mounted = route;
  view.innerHTML = '';
  // Anything a previous mount is still waiting on belongs to a route that is
  // no longer on screen; stillMounted() is how it finds that out.
  beginMount();
  VIEWS[route].mount(view);
}

/* --- the inbox -------------------------------------------------------------- */

let inbox = { items: [], unread: 0, member: null };
let panelOpen = false;

const AGO = (iso) => {
  const secs = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (secs < 90) return 'just now';
  if (secs < 5400) return `${Math.round(secs / 60)}m ago`;
  if (secs < 172800) return `${Math.round(secs / 3600)}h ago`;
  return `${Math.round(secs / 86400)}d ago`;
};

/**
 * @param {{announce?: boolean}} opts announce toasts whatever arrived while
 *   the panel was shut, which is the whole point of being told.
 */
async function refreshInbox({ announce = false } = {}) {
  const before = inbox.unread;
  try { inbox = await api('/api/notifications'); } catch { return; }

  const bell = document.getElementById('bell');
  const count = document.getElementById('bell-count');
  if (!bell) return;
  // The operator token has no roster identity, so it has no inbox to show.
  bell.hidden = !inbox.member;
  bell.classList.toggle('has-unread', inbox.unread > 0);
  count.hidden = inbox.unread === 0;
  count.textContent = String(inbox.unread);

  if (announce && inbox.unread > before) {
    const latest = inbox.items.find(i => !i.read_at);
    if (latest) toast(latest.title);
  }
  if (panelOpen) paintInbox();
}

function paintInbox() {
  const panel = document.getElementById('bell-panel');
  if (!panel) return;
  panel.hidden = !panelOpen;
  if (!panelOpen) return;

  panel.innerHTML = `
    <div class="bell-head">
      <b>Assignments and mentions</b>
      ${inbox.unread ? '<button id="bell-readall">mark all read</button>' : ''}
    </div>
    ${inbox.items.length ? inbox.items.map(i => `
      <button class="bell-item ${i.read_at ? '' : 'unread'}" data-note="${esc(i.id)}"
              data-link="${esc(i.link ?? '')}">
        <span class="t">${esc(i.title)}</span>
        ${i.body ? `<span class="b">${esc(i.body)}</span>` : ''}
        <span class="w">${esc(AGO(i.ts))}</span>
      </button>`).join('')
    : '<div class="bell-empty">Nothing for you yet.</div>'}`;

  panel.querySelector('#bell-readall')?.addEventListener('click', async (e) => {
    e.stopPropagation();
    await api('/api/notifications/read', { method: 'POST', body: {} }).catch(() => {});
    await refreshInbox();
  });
  panel.querySelectorAll('[data-note]').forEach(b => b.addEventListener('click', async () => {
    await api(`/api/notifications/${b.dataset.note}/read`, { method: 'POST', body: {} }).catch(() => {});
    panelOpen = false;
    paintInbox();
    if (b.dataset.link) location.hash = b.dataset.link;
    await refreshInbox();
  }));
}

function wireInbox() {
  const bell = document.getElementById('bell');
  if (!bell) return;
  bell.addEventListener('click', (e) => {
    e.stopPropagation();
    panelOpen = !panelOpen;
    paintInbox();
  });
  // Anywhere else closes it, the way every other menu behaves.
  document.addEventListener('click', (e) => {
    if (!panelOpen || e.target.closest('.bell-wrap')) return;
    panelOpen = false;
    paintInbox();
  });
}

async function updatePendingPill() {
  // A count, not a filter over every record. The shell needs the number and
  // nothing else, and asking for it is what lets the rows stop being shipped.
  let n = 0;
  try { n = (await api('/api/records/counts')).pending ?? 0; } catch { return; }
  const pill = document.getElementById('pending-pill');
  pill.textContent = `${n} pending`;
  pill.hidden = n === 0;
}

/*
  Catch up on whatever was broadcast while this browser was not listening.

  sse.js keeps no replay buffer on purpose — it says so, and says the client is
  expected to re-fetch instead. This is the half that was missing. EventSource
  reconnects by itself and the indicator goes green, so without this a browser
  that missed a verdict looks healthy while showing a case file that is out of
  date: stale and confident, which is worse than visibly disconnected.

  Goes back through applyDelta rather than repainting directly, so every view
  updates by exactly the path a broadcast uses, focus preservation included.
*/
async function resync(dot) {
  try {
    Object.assign(state, await api('/api/state'));
  } catch {
    /*
      Still unreachable, or refused. The connection is open but the picture is
      not current, and the indicator must not claim otherwise — a green dot over
      stale data is the state this whole change exists to remove.
    */
    dot.classList.add('down');
    dot.title = 'connected, but the case file could not be refreshed — reload';
    return;
  }
  applyDelta({ type: 'state.resynced' });
}

function connectSse() {
  const dot = document.getElementById('conn');
  const es = new EventSource('/api/events');
  let everOpened = false;

  es.onopen = () => {
    dot.classList.remove('down'); dot.title = 'live';
    // The first open belongs to boot(), which has just fetched the state. Every
    // later one closes a gap nothing else can see into.
    if (everOpened) resync(dot);
    everOpened = true;
  };
  es.onerror = () => { dot.classList.add('down'); dot.title = 'reconnecting…'; };

  /*
    Hand the socket back when this document goes away.

    An EventSource is a response that never ends, so nothing closes it on its
    own: the browser holds it until the document is collected and the server
    holds a client it is still writing to. Browsers allow six connections per
    host, and six abandoned streams are enough to stop the seventh page load
    getting a socket at all — which is exactly how this was found, with
    tools/screenshots.mjs hanging on its seventh capture every run.

    pagehide rather than unload: unload is ignored where the page can be
    restored from the back-forward cache, which is the case this most needs to
    cover.
  */
  addEventListener('pagehide', () => es.close());
  es.onmessage = (e) => {
    let delta;
    try { delta = JSON.parse(e.data); } catch { return; }

    /*
      The broadcast carries nothing: who was notified and what it said stay on
      the server, so a mention inside a DM is not delivered to every browser on
      the LAN. Each client re-reads its own inbox and finds out whether any of
      it was for them.
    */
    if (delta.type === 'notification.new') { refreshInbox({ announce: true }); return; }

    if (delta.type === 'rate_limit' && delta.payload) {
      const u = Math.round((delta.payload.utilization ?? 0) * 100);
      if (u >= 80) toast(`Claude usage at ${u}% of the ${delta.payload.rateLimitType ?? ''} limit`, true);
      return;
    }
    applyDelta(delta);
  };
}

async function boot() {
  try {
    Object.assign(state, await api('/api/state'));
  } catch (err) {
    view.innerHTML = `<div class="loading">Could not load the store: ${esc(err.message)}</div>`;
    return;
  }

  const analyst = decodeURIComponent(
    (document.cookie.match(/(?:^|;\s*)hunt_analyst=([^;]*)/) ?? [])[1] ?? 'unattributed');

  // Whether this token maps to a roster member decides whether you have a chat
  // window at all, so say which you are rather than only showing a name.
  let mine = null;
  try { mine = await api('/api/me'); } catch { /* handled below */ }
  const who = document.getElementById('who');
  if (mine?.member) {
    who.textContent = `${mine.member.name} · ${mine.member.role}`;
    who.className = 'who';
  } else {
    who.textContent = `${analyst} — operator token, no chat window`;
    who.className = 'who operator';
  }

  document.getElementById('signout').addEventListener('click', async () => {
    await fetch('/api/logout', { method: 'POST' });
    location.href = '/login';
  });

  wireInbox();
  refreshInbox();
  updatePendingPill();
  connectSse();
  render();

  // Any store change refreshes the pending count, the open drawer and the
  // active view. Views that stream (sessions) opt out of full re-render.
  on('*', ({ type }) => {
    updatePendingPill();
    /*
      Both repaints go through preservingFocus. A delta caused by somebody else
      must not move the caret of whoever is typing here — and with a dozen
      people on one exercise, it did: any evidence sent for processing rebuilt
      the active view, dropped focus to the body and reset the caret to zero.
    */
    preservingFocus(document.getElementById('drawer'), () => refreshDrawer(type));
    /*
      A streamed token is not news to anything but the session it belongs to.

      session.delta fires once per token of any teammate's turn and reached
      every view, so a colleague asking Claude a question made the map and the
      records table re-ask the server hundreds of times and rebuild themselves
      under whoever was reading them. The other session events are rare enough
      to be worth passing on; this one never was.
    */
    if (type === 'session.delta' && currentRoute() !== 'sessions') return;
    if (type.startsWith('session.') && currentRoute() === 'sessions') return;
    const v = VIEWS[currentRoute()];
    if (v.onDelta) preservingFocus(view, () => v.onDelta(type));
  });

  window.addEventListener('hashchange', () => { closeDrawer(); render(); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeDrawer(); });
}

// The drawer's delegated listeners, installed once. Called here rather than on
// the drawer's module body so that file can be loaded without a DOM.
initDrawer();

boot();
