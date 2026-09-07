import { state, api, toast, esc, on, shortTime, preservingFocus, thisMount, stillMounted } from '../core.js';
import { renderMarkdown } from '../markdown.js';
import { openRecordDrawer } from './drawer.js';
import { uploadFile } from './comms.js';

let root = null;
let me = null;            // { member, sessionId }
let activeId = null;      // whichever chat is being viewed, mine or not
let messages = [];
let streaming = '';
let mode = 'evidence';    // which button is armed
let pendingFiles = [];    // chosen but not uploaded until send
let unsubs = [];
let usage = null;
/*
  The rail's own rows, asked for rather than filtered out of a local copy of the
  whole case file. The queue is bounded by what the team has not yet adjudicated,
  which is the number this panel exists to make small.
*/
let pendingRows = [];
// paint() runs on every delta, including ones from other analysts adjudicating
// records. Carry the composer across so a colleague confirming a finding does
// not wipe the evidence you were writing up.
let draft = '';
let draftFor = null;

const sessionOf = (memberId) => state.sessions.find(s => s.member_id === memberId) ?? null;
const memberOf = (sessionId) => {
  const s = state.sessions.find(x => x.id === sessionId);
  return s ? state.members.find(m => m.id === s.member_id) ?? null : null;
};
const isMine = () => Boolean(me?.sessionId) && activeId === me.sessionId;

async function select(sessionId) {
  activeId = sessionId;
  streaming = '';
  const detail = await api(`/api/sessions/${sessionId}`);
  messages = detail.messages ?? [];
  paint();
}

// --- roster ----------------------------------------------------------------

function rosterHtml() {
  const teams = [...new Set(state.members.map(m => m.team))];
  return teams.map(team => `
    <div class="roster-team">${esc(team)}</div>
    ${state.members.filter(m => m.team === team).map(m => {
    const s = sessionOf(m.id);
    const mine = me?.member?.id === m.id;
    const busy = s?.state === 'running';
    return `<div class="session-item ${s && s.id === activeId ? 'active' : ''}"
                 data-sid="${s ? s.id : ''}" ${s ? '' : 'style="opacity:.4"'}>
        <div>${esc(m.name)}${mine ? ' <span class="you">you</span>' : ''}
          ${busy ? '<span class="working">working…</span>' : ''}</div>
        <div class="meta">${esc(m.role)}</div>
      </div>`;
  }).join('')}`).join('');
}

// --- transcript ------------------------------------------------------------

/*
  Markdown for what the model wrote; plain text for everything else.

  An analyst's own message is usually a pasted log, and running that through a
  formatter would reflow the one thing they pasted it to preserve. A system
  notice is one line. Only the assistant writes prose with structure in it, so
  only the assistant gets structure back.
*/
const bubbleHtml = (role, content) => (role === 'assistant'
  ? `<div class="bubble md">${renderMarkdown(content)}</div>`
  : `<div class="bubble">${esc(content)}</div>`);

function transcriptHtml() {
  const items = messages.map(m => `
    <div class="msg ${m.role}">
      <div class="role">${m.role === 'assistant' ? 'Claude' : esc(m.role)}${
  m.mode ? ` · ${esc(m.mode)}` : ''}</div>
      ${bubbleHtml(m.role, m.content)}
    </div>`).join('');
  /*
    The streaming bubble stays plain until the turn lands. Half a fence and an
    unclosed list would have the layout jumping on every token, and the reader
    is watching it arrive rather than studying it.
  */
  const live = streaming
    ? `<div class="msg assistant"><div class="role">Claude</div><div class="bubble">${esc(streaming)}</div></div>`
    : '';
  return items + live || '<div class="loading">No messages yet.</div>';
}

function composerHtml(session) {
  if (!isMine()) {
    const owner = memberOf(activeId);
    if (!me?.member) {
      return `<div class="composer readonly">
        Signed in with the operator token, so there is no window of your own. Sign out and use
        your team token to post.
      </div>`;
    }
    return `<div class="composer readonly">
      Viewing ${esc(owner?.name ?? 'another analyst')}'s window. You can read it; only they can post.
    </div>`;
  }
  const busy = session?.state === 'running';
  return `
    <form class="composer" id="cf">
      <div class="composer-modes">
        <button type="button" class="mode ${mode === 'evidence' ? 'on' : ''}" data-mode="evidence"
          title="Judged against the whole case file. May produce records.">Evidence</button>
        <button type="button" class="mode ${mode === 'research' ? 'on' : ''}" data-mode="research"
          title="A question. Records nothing.">Research</button>
        <label class="attach" title="Attach logs or an artifact to this submission">
          Attach<input type="file" id="file" hidden multiple>
        </label>
        ${pendingFiles.map(f => `<span class="pending-file">${esc(f.name)}</span>`).join('')}
        <span class="mode-hint">${mode === 'evidence'
    ? 'Sent with every record already collected. Claude may propose findings.'
    : 'A question only. Nothing is recorded. Baselines are imported from the Characterization tab.'}</span>
      </div>
      <div class="composer-row">
        <textarea id="ta" ${busy ? 'disabled' : ''} placeholder="${busy
    ? 'Claude is working…'
    : mode === 'evidence'
      ? 'Paste the logs or describe what you found, then send as Evidence.'
      : 'Ask your question. Paste a log if you need help reading it.'}"></textarea>
        <button class="primary" type="submit" ${busy ? 'disabled' : ''}>
          ${busy ? '…' : mode === 'evidence' ? 'Send evidence' : 'Ask'}</button>
      </div>
    </form>`;
}

// --- pending rail ----------------------------------------------------------

function pendingCards() {
  const pending = pendingRows;
  const stale = pendingFailed
    ? `<p class="search-broken">The pending queue stopped answering, so this rail is the last
       answer it gave rather than the current one. Reload before reading it as nothing waiting.</p>`
    : '';
  if (pending.length === 0) {
    return stale || `<p class="muted" style="font-size:12.5px">
      Nothing pending. Send evidence and proposals appear here for review.</p>`;
  }
  return stale + pending.map(r => `
    <div class="cand">
      <h4>${esc((r.description ?? '').slice(0, 90))}</h4>
      <dl>
        ${r.hostname ? `<dt>Host</dt><dd>${esc(r.hostname)}</dd>` : ''}
        ${r.event_time ? `<dt>Time</dt><dd>${esc(r.event_time)}</dd>` : ''}
        ${r.indicator ? `<dt>Indicator</dt><dd>${esc(r.indicator)}</dd>` : ''}
        ${r.mitre ? `<dt>MITRE</dt><dd>${esc(r.mitre)}</dd>` : ''}
        ${r.confidence ? `<dt>Confidence</dt><dd>${esc(r.confidence)}</dd>` : ''}
        ${r.created_by ? `<dt>From</dt><dd>${esc(r.created_by)}</dd>` : ''}
      </dl>
      <select data-thread="${r.id}">
        <option value="">— assign a thread —</option>
        ${state.threads.map(t => `<option value="${t.id}" ${t.id === r.thread_id ? 'selected' : ''}>
          ${esc(t.key)} — ${esc(t.name)}</option>`).join('')}
      </select>
      <div class="row">
        <button class="ok" data-act="promote" data-id="${r.id}">Confirm</button>
        <button class="bad" data-act="deny" data-id="${r.id}">Deny</button>
        <button data-act="open" data-id="${r.id}">Edit</button>
      </div>
    </div>`).join('');
}

// --- render ----------------------------------------------------------------

function paint() {
  const session = state.sessions.find(s => s.id === activeId) ?? null;
  const owner = memberOf(activeId);

  const live = root.querySelector('#ta');
  if (live && draftFor === activeId) draft = live.value;
  if (draftFor !== activeId) draft = '';

  root.innerHTML = `
    ${!me?.member ? `<div class="operator-note">
      You are signed in with the <b>operator token</b>, which is nobody's chat window, so every
      session here is read only. Sign out (top right) and sign back in with your own team token
      to use yours.
    </div>` : ''}
    <div class="session-layout">
      <div class="session-list">
        <h2 class="section">Team</h2>
        ${rosterHtml()}
        ${usageHtml()}
      </div>

      <div class="chat">
        ${!session ? '<div class="loading">Select a team member.</div>' : `
          <div class="chat-head">
            <strong>${esc(owner?.name ?? session.title)}</strong>
            <span class="muted">${esc(owner?.role ?? '')}${owner ? ` · ${esc(owner.team)}` : ''}</span>
            ${isMine() ? '<span class="you">your window</span>' : '<span class="ro">read only</span>'}
          </div>
          <div class="transcript" id="tr">${transcriptHtml()}</div>
          ${composerHtml(session)}`}
      </div>

      <div class="rail">
        <h2 class="section">Pending candidates</h2>
        <p class="hint" style="margin-bottom:10px">Anyone can adjudicate. Assign a thread before confirming.</p>
        ${pendingCards()}
      </div>
    </div>`;

  root.querySelectorAll('[data-sid]').forEach(d => d.addEventListener('click', () => {
    if (d.dataset.sid) select(d.dataset.sid).catch(e => toast(e.message, true));
  }));

  root.querySelectorAll('.mode').forEach(b => b.addEventListener('click', () => {
    mode = b.dataset.mode;
    paint();
  }));



  const fileInput = root.querySelector('#file');
  if (fileInput) {
    fileInput.addEventListener('change', () => {
      // Uploaded on send rather than inlined here. The store keeps the artifact
      // so a record can point at it by hash, and the server decides how much of
      // it is safe to put in front of the model — a binary gets described, not
      // decoded.
      pendingFiles = [...fileInput.files].slice(0, 5);
      paint();
    });
  }

  const form = root.querySelector('#cf');
  draftFor = activeId;
  if (form) {
    const ta = root.querySelector('#ta');
    ta.value = draft;
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const text = ta.value.trim();
      const files = pendingFiles;
      if (!text && !files.length) return;
      // Captured before the uploads: a turn belongs to the window it was typed
      // in, and every window on this page is somebody's.
      const sessionId = activeId;
      ta.value = ''; draft = ''; pendingFiles = [];
      // Marked as an echo so the broadcast of the real row can replace it.
      // Keyed by a synthetic id alone it never matched the store's uuid, and
      // every submission rendered twice.
      const echoId = 'local-' + Date.now();
      messages.push({ id: echoId, local: true, role: 'user',
        content: text || `(${files.length} file(s) attached)`, mode });
      streaming = '';
      paint();
      try {
        const fileIds = [];
        for (const f of files) fileIds.push((await uploadFile(f)).id);
        await api(`/api/sessions/${sessionId}/message`, { method: 'POST', body: {
          text, mode, fileIds,
        } });
      } catch (err) {
        /*
          Take the echo back out. It was posted on the assumption the turn would
          land, and leaving it behind after a failure shows the analyst their
          question sitting in the transcript as though it had been asked — the
          one reading under which they will not ask it again.

          The text goes back with it, for the same reason it does in comms: only
          this handler still has it.
        */
        const i = messages.findIndex(m => m.id === echoId);
        if (i >= 0) messages.splice(i, 1);
        if (sessionId === activeId) {
          draft = text; pendingFiles = files;
          const live = root.querySelector('#ta');
          if (live) live.value = text;
          paint();
        }
        toast(err.message, true);
      }
    });
    ta.addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter' && (ev.ctrlKey || ev.metaKey)) form.requestSubmit();
    });
    if (!ta.disabled) ta.focus();
  }

  root.querySelectorAll('.rail [data-act]').forEach(b =>
    b.addEventListener('click', async () => {
      const { act, id } = b.dataset;
      try {
        if (act === 'open') return openRecordDrawer(id);
        await api(`/api/records/${id}/${act}`, { method: 'POST' });
        toast(act === 'promote' ? 'Confirmed' : 'Denied');
      } catch (err) { toast(err.message, true); }
    }));

  root.querySelectorAll('.rail [data-thread]').forEach(sel =>
    sel.addEventListener('change', async () => {
      try {
        await api(`/api/records/${sel.dataset.thread}`, {
          method: 'PATCH', body: { thread_id: sel.value || null },
        });
        toast('Thread assigned');
      } catch (err) { toast(err.message, true); }
    }));

  const tr = root.querySelector('#tr');
  if (tr) tr.scrollTop = tr.scrollHeight;
}


/*
  One shared quota, spent by four people. The runner already warns when Claude
  reports the limit is close, and that warning arrives without any way to see
  where the allowance went — which is the part you need to act on it.

  Turns counts measured turns only. A provider that reports nothing contributes
  no turns rather than a free one, so the figure never quietly understates.
*/
/* Whether the last rail fetch answered. An empty rail means two things. */
let pendingFailed = false;

async function loadPending() {
  try {
    pendingRows = (await api('/api/records/search?state=pending&limit=200')).rows;
    pendingFailed = false;
  } catch {
    /*
      Keep the last rail rather than implying the queue is empty — and say so.
      "Nothing pending" is the strongest claim this page makes: it is what an
      analyst reads to decide there is nothing waiting on them.
    */
    pendingFailed = true;
  }
}

async function loadUsage() {
  // Never let the figures take the view down: they are a footnote and the
  // transcript is the page, so a failure keeps whatever was last known.
  try { usage = await api('/api/usage'); } catch { /* keep the last figures */ }
}

function usageHtml() {
  if (!usage || !usage.total.turns) return '';
  const k = (n) => (n >= 1000 ? `${(n / 1000).toFixed(1)}k` : String(n));
  const rows = usage.byMember
    .map(m => `<div class="usage-row"><span>${esc(m.analyst)}</span>
      <span>${k(m.input_tokens + m.output_tokens)}</span></div>`).join('');
  return `<div class="usage">
    <h2 class="section">Quota</h2>
    <div class="usage-row total"><span>${usage.total.turns} turn${
  usage.total.turns === 1 ? '' : 's'}</span>
      <span>${k(usage.total.input_tokens + usage.total.output_tokens)} tokens</span></div>
    ${rows}
  </div>`;
}

export async function mount(el) {
  root = el;
  const gen = thisMount();
  root.innerHTML = '<div class="loading">Loading team…</div>';

  try { me = await api('/api/me'); } catch { me = null; }
  if (!activeId) activeId = me?.sessionId ?? state.sessions[0]?.id ?? null;
  await Promise.all([loadUsage(), loadPending()]);
  // This is the view mounted at page load, so the window in which somebody can
  // navigate away mid-mount is "the first second after opening the app".
  if (!stillMounted(gen)) return;

  unsubs = [
    on('session.delta', ({ sessionId, text }) => {
      if (sessionId !== activeId) return;
      streaming += text;
      const tr = root.querySelector('#tr');
      if (tr) { tr.innerHTML = transcriptHtml(); tr.scrollTop = tr.scrollHeight; }
    }),
    on('session.message', ({ sessionId, message }) => {
      if (sessionId !== activeId) return;
      // Reconcile against the optimistic echo first: the server's row is the
      // same message under a real id, so replace rather than append.
      // Oldest echo first, and not matched on content: the server appends any
      // attached file's text to the body, so the strings will not be equal.
      const echo = message.role === 'user' ? messages.findIndex(m => m.local) : -1;
      if (echo >= 0) messages[echo] = message;
      else if (!messages.some(m => m.id === message.id)) messages.push(message);
      streaming = '';
      preservingFocus(root, paint);
    }),
    on('session.tool', ({ sessionId, name }) => {
      if (sessionId !== activeId) return;
      toast(`Claude called ${name.replace('mcp__hunt__', '')}`);
    }),
    /*
      Somebody else filing a record repaints this view, and the composer is
      the box people spend the most time typing into on this server. Through
      preservingFocus so their caret survives it.
    */
    // A turn ending is the only thing that moves the quota figures, so it is
    // the only thing that refetches them.
    on('session.state', async () => { await loadUsage(); preservingFocus(root, paint); }),
    // The rail is a query now, so a record changing anywhere means re-asking.
    on('records.changed', async () => { await loadPending(); preservingFocus(root, paint); }),
    on('record.created', async () => { await loadPending(); preservingFocus(root, paint); }),
    on('record.updated', async () => { await loadPending(); preservingFocus(root, paint); }),
  ];

  if (activeId) select(activeId).catch(() => paint());
  else paint();
}

export function unmount() {
  unsubs.forEach(u => u());
  unsubs = [];
  root = null;
}
