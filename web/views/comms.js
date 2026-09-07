import { state, api, toast, esc, on, shortTime, preservingFocus, thisMount, stillMounted } from '../core.js';

let root = null;
let channels = [];
let activeId = null;
let messages = [];
let pending = null;      // a chosen file, uploaded on send
let unsubs = [];
// paint() replaces the whole subtree, and it runs on every incoming message.
// Without carrying the composer across, anyone else posting to a busy channel
// silently deletes the paragraph you were partway through typing.
let draft = '';
let draftFor = null;     // the channel the surviving draft belongs to

const me = () => decodeURIComponent(
  (document.cookie.match(/(?:^|;\s*)hunt_analyst=([^;]*)/) ?? [])[1] ?? '');

const KB = (n) => (n < 1024 ? `${n} B` : n < 1048576 ? `${Math.round(n / 1024)} KB` : `${(n / 1048576).toFixed(1)} MB`);

async function load() {
  channels = await api('/api/chat/channels');
  if (!activeId || !channels.some(c => c.id === activeId)) activeId = channels[0]?.id ?? null;
}

async function openChannel(id) {
  activeId = id;
  messages = await api(`/api/chat/${id}/messages`);
  await load();
  paint();
}

/** @Name highlighted, and highlighted differently when it is you. */
function renderBody(text, mentions) {
  let html = esc(text);
  for (const name of mentions ?? []) {
    html = html.replace(new RegExp(`@${name}\\b`, 'ig'),
      (mm) => `<span class="mention ${name === me() ? 'me' : ''}">${esc(mm)}</span>`);
  }
  return html;
}

function messageHtml(m) {
  const mine = m.author === me();
  const tagged = (m.mentions ?? []).includes(me());
  return `
    <div class="chat-msg ${mine ? 'own' : ''} ${tagged ? 'tagged' : ''}">
      <div class="chat-meta">
        <b>${esc(m.author)}</b>
        <span class="muted">${esc(shortTime(m.ts).slice(0, 16))}</span>
      </div>
      ${m.body ? `<div class="chat-body">${renderBody(m.body, m.mentions)}</div>` : ''}
      ${m.file ? `<a class="file-card" href="/api/files/${esc(m.file.id)}" download="${esc(m.file.name)}">
        <span class="fname">${esc(m.file.name)}</span>
        <span class="fmeta">${KB(m.file.size)} · sha256 ${esc(m.file.sha256.slice(0, 12))}…</span>
      </a>` : ''}
    </div>`;
}

function channelLabel(c) {
  if (c.kind === 'team') return 'Whole team';
  if (c.kind === 'dm') return c.members.filter(x => x !== me()).join(', ') || c.name;
  return c.name;
}

function paint() {
  const active = channels.find(c => c.id === activeId);

  // Rescue the in-flight draft before innerHTML discards it. A draft belongs
  // to the channel it was typed in and does not follow you to another one.
  const live = root.querySelector('#ta');
  if (live && draftFor === activeId) draft = live.value;
  if (draftFor !== activeId) draft = '';

  root.innerHTML = `
    <div class="comms-layout">
      <div class="session-list">
        <button class="primary" id="new-dm" style="width:100%;margin-bottom:6px">New direct message</button>
        <button id="new-group" style="width:100%;margin-bottom:10px">New group</button>
        ${['team', 'group', 'dm'].map(kind => {
    const set = channels.filter(c => c.kind === kind);
    if (!set.length) return '';
    return `<div class="roster-team">${kind === 'team' ? 'All' : kind === 'group' ? 'Groups' : 'Direct'}</div>
      ${set.map(c => `
        <div class="session-item ${c.id === activeId ? 'active' : ''}" data-ch="${esc(c.id)}">
          <div>${esc(channelLabel(c))}
            ${c.unread ? `<span class="unread">${c.unread}</span>` : ''}</div>
          <div class="meta">${c.kind === 'team' ? 'everyone'
      : `${c.members.length} member${c.members.length === 1 ? '' : 's'}`}${
      c.lastAuthor ? ` · ${esc(c.lastAuthor)}` : ''}</div>
        </div>`).join('')}`;
  }).join('')}
      </div>

      <div class="chat">
        ${!active ? '<div class="loading">No conversation selected.</div>' : `
          <div class="chat-head">
            <strong>${esc(channelLabel(active))}</strong>
            <span class="muted">${active.kind === 'team' ? 'visible to everyone'
      : active.kind === 'dm' ? 'private to you both' : esc(active.members.join(', '))}</span>
          </div>
          <div class="transcript" id="tr">
            ${messages.length ? messages.map(messageHtml).join('')
      : '<div class="loading">Nothing here yet.</div>'}
          </div>
          <form class="composer" id="cf">
            ${pending ? `<div class="pending-file">
              ${esc(pending.name)} <span class="muted">${KB(pending.size)}</span>
              <button type="button" id="drop-file">remove</button></div>` : ''}
            <div class="composer-row">
              <textarea id="ta" placeholder="Message. Use @name to tag someone."></textarea>
              <label class="attach" title="Attach a file">Attach<input type="file" id="file" hidden></label>
              <button class="primary" type="submit">Send</button>
            </div>
            <div class="mention-hint">${state.members.map(m =>
        `<button type="button" class="mtag" data-tag="${esc(m.name)}">@${esc(m.name)}</button>`).join('')}</div>
          </form>`}
      </div>
    </div>`;

  root.querySelectorAll('[data-ch]').forEach(d =>
    d.addEventListener('click', () => openChannel(d.dataset.ch).catch(e => toast(e.message, true))));

  root.querySelector('#new-dm').addEventListener('click', async () => {
    const who = prompt(`Direct message who?\n${state.members.map(m => m.name).join(', ')}`);
    if (!who) return;
    try {
      const c = await api('/api/chat/channels', { method: 'POST', body: { kind: 'dm', members: [who.trim()] } });
      await load(); await openChannel(c.id);
    } catch (e) { toast(e.message, true); }
  });

  root.querySelector('#new-group').addEventListener('click', async () => {
    const name = prompt('Group name');
    if (!name) return;
    const who = prompt(`Members, comma separated\n${state.members.map(m => m.name).join(', ')}`);
    if (who === null) return;
    const members = who.split(',').map(x => x.trim()).filter(Boolean);
    try {
      const c = await api('/api/chat/channels', { method: 'POST', body: { kind: 'group', name, members } });
      await load(); await openChannel(c.id);
    } catch (e) { toast(e.message, true); }
  });

  const form = root.querySelector('#cf');
  if (!form) { draftFor = activeId; return; }
  const ta = root.querySelector('#ta');
  ta.value = draft;
  draftFor = activeId;

  root.querySelectorAll('.mtag').forEach(b => b.addEventListener('click', () => {
    ta.value += `${ta.value && !ta.value.endsWith(' ') ? ' ' : ''}@${b.dataset.tag} `;
    ta.focus();
  }));

  root.querySelector('#file').addEventListener('change', (e) => {
    pending = e.target.files?.[0] ?? null;
    paint();
  });
  root.querySelector('#drop-file')?.addEventListener('click', () => { pending = null; paint(); });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const body = ta.value.trim();
    if (!body && !pending) return;
    const file = pending;
    // Captured before anything is awaited: where this was written, not where
    // the view has got to by the time it lands.
    const channelId = activeId;
    ta.value = ''; draft = ''; pending = null;
    try {
      await sendComposed(channelId, { body, file });
    } catch (err) {
      /*
        Put it back. Clearing optimistically is right — the message almost
        always sends, and watching your own text sit there is worse — but a
        failure used to consume it, and the longer the message the more it
        cost. It goes back to the channel it was written in, and into the
        textarea only if that is still the one on screen.
      */
      draft = body; draftFor = channelId;
      if (channelId === activeId) {
        const live = root.querySelector('#ta');
        if (live) live.value = body;
      }
      pending = file;
      toast(err.message, true);
    }
  });
  ta.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter' && !ev.shiftKey) { ev.preventDefault(); form.requestSubmit(); }
  });
  ta.focus();

  const tr = root.querySelector('#tr');
  if (tr) tr.scrollTop = tr.scrollHeight;
}

/**
 * Send one composed message to a fixed destination.
 *
 * The channel is an argument rather than a read of `activeId`, because the
 * upload below is long enough for somebody to click another conversation while
 * it runs. Reading the destination afterwards posted the message into whatever
 * was on screen by then — and a direct message is described to its author as
 * private to you both, so that is a disclosure rather than a misfiling.
 *
 * Throws rather than reporting. Only the caller still holds the text, so only
 * the caller can put it back.
 */
export async function sendComposed(channelId, { body, file } = {}) {
  const fileId = file ? (await uploadFile(file)).id : null;
  await api(`/api/chat/${channelId}/messages`, { method: 'POST', body: { body, fileId } });
}

/** Raw body plus a header, rather than multipart: one file, no parser needed. */
export async function uploadFile(file) {
  const res = await fetch('/api/files', {
    method: 'POST',
    headers: {
      'content-type': file.type || 'application/octet-stream',
      'x-file-name': encodeURIComponent(file.name),
    },
    body: file,
  });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error ?? 'upload failed');
  return res.json();
}

export async function mount(el) {
  root = el;
  // Taken before the first await: everything below belongs to this mount, and
  // the router may have moved on by the time any of it comes back.
  const gen = thisMount();
  root.innerHTML = '<div class="loading">Loading conversations…</div>';
  try { await load(); } catch (e) {
    if (!stillMounted(gen)) return;
    root.innerHTML = `<div class="loading">Could not load comms: ${esc(e.message)}</div>`;
    return;
  }
  const opening = activeId;
  if (opening) { try { messages = await api(`/api/chat/${opening}/messages`); } catch { messages = []; } }
  if (!stillMounted(gen)) return;
  paint();

  unsubs = [
    on('chat.message', async ({ channelId, message }) => {
      if (channelId === activeId) {
        /*
          A private channel sends the id and nothing else, so its body never
          crosses a stream every browser is listening to. Re-read it here: the
          route enforces membership, so this is the only place the body is
          allowed to arrive.
        */
        if (!message) {
          try { messages = await api(`/api/chat/${channelId}/messages`); } catch { /* keep what we have */ }
        } else if (!messages.some(x => x.id === message.id)) {
          messages.push(message);
        }
        // Mark it read without re-reading it. The message is already in hand
        // from the broadcast; fetching the channel again to get the read
        // side effect meant pulling three hundred messages per new one.
        await api(`/api/chat/${channelId}/read`, { method: 'POST', body: {} }).catch(() => {});
      }
      /*
        No toast here any more. The inbox in the header announces mentions from
        wherever you are in the app, so doing it again on this one page was two
        toasts for one event — and the old one never fired at all unless you
        were already looking at Comms, which is the case where you need telling
        least.
      */
      await load();
      preservingFocus(root, paint);
    }),
    on('chat.channel', async () => { await load(); preservingFocus(root, paint); }),
  ];
}

export function unmount() { unsubs.forEach(u => u()); unsubs = []; root = null; }
