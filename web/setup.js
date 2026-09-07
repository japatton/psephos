/**
 * The setup wizard.
 *
 * Six steps, each writing to the profile as it completes, so a closed tab
 * loses at most the step in progress. Nothing takes effect until the last one:
 * until then the server is still in setup mode and the store holds nothing.
 *
 * Kept deliberately plain — no framework, one render function, the same
 * vanilla ESM as the rest of web/. Someone standing a server up on a range at
 * 0600 should be able to read this file and know what it did.
 */
const $ = (sel) => document.querySelector(sel);
const el = () => $('#wiz');

const esc = (s) => String(s ?? '').replace(/[&<>"']/g,
  c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function toast(message, bad = false) {
  const t = $('#toast');
  t.textContent = message;
  t.className = 'toast' + (bad ? ' bad' : '');
  t.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { t.hidden = true; }, 4000);
}

async function api(path, body) {
  const res = await fetch(path, {
    method: body ? 'POST' : 'GET',
    headers: body ? { 'content-type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401) { location.href = '/login'; throw new Error('unauthenticated'); }
  const out = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(out.error || `HTTP ${res.status}`);
  return out;
}

const STEPS = ['Model', 'Mission', 'Briefing', 'Team', 'Terrain', 'Plan'];

/*
  Everything the operator has typed but not yet committed. Reloading rereads
  the server's view of what is on disk, so this only has to survive the walk
  from one step to the next.
*/
const draft = {
  step: 0,
  code: null,
  model: { provider: 'cli', model: '', baseUrl: '', key: '' },
  mission: { name: '', week: '' },
  briefing: '',
  members: [{ name: '', role: '', team: '' }],
  paste: '',
  terrain: null,
  terrainPreview: null,
  finished: null,   // the result of the last step; render stops here once set
  busy: false,
};
let state = null;

// --- chrome -------------------------------------------------------------------

const rail = () => `
  <ol class="wiz-rail">
    ${STEPS.map((s, i) => `<li class="${i === draft.step ? 'on' : ''} ${
  i < draft.step ? 'done' : ''}">${i + 1}. ${s}</li>`).join('')}
  </ol>`;

const nav = (backLabel, nextLabel, nextAct, extra = '') => `
  <div class="wiz-nav">
    ${draft.step > 0 ? `<button data-act="back">${backLabel ?? 'Back'}</button>` : '<span></span>'}
    ${extra}
    ${nextAct ? `<button class="primary" data-act="${nextAct}" ${draft.busy ? 'disabled' : ''}>
      ${draft.busy ? 'Working…' : nextLabel}</button>` : ''}
  </div>`;

// --- steps --------------------------------------------------------------------

function stepModel() {
  const m = draft.model;
  const card = (id, title, body) => `
    <label class="wiz-card ${m.provider === id ? 'on' : ''}">
      <input type="radio" name="provider" value="${id}" ${m.provider === id ? 'checked' : ''}>
      <b>${title}</b>
      <p>${body}</p>
    </label>`;

  return `
    <h1>Which model runs the turns?</h1>
    <p class="lede">Whatever you pick is checked for real before it is saved. A backend that
      cannot answer now will not start answering at the first piece of evidence.</p>

    ${card('cli', 'Claude CLI on this machine',
    'The CLI holds its own login, so this server never sees a credential. Best option '
    + 'where the machine has the CLI installed and signed in.')}
    ${card('anthropic', 'Anthropic API key',
    'A key you paste here, stored at <code>data/model.json</code> with owner-only '
    + 'permissions. Never sent to a browser and never logged.')}
    ${card('openai', 'OpenAI-compatible endpoint',
    'Anything speaking the OpenAI chat API — OpenAI, Azure, vLLM, Ollama, LM Studio. '
    + 'This is the one for a range with no route out.')}

    ${m.provider !== 'cli' ? `
      <div class="task-form-grid" style="margin-top:16px">
        ${m.provider === 'openai' ? `
          <label>base URL</label>
          <input data-f="baseUrl" value="${esc(m.baseUrl)}" placeholder="http://10.0.0.5:8000/v1">` : ''}
        <label>model</label>
        <input data-f="model" value="${esc(m.model)}"
          placeholder="${m.provider === 'anthropic' ? 'claude-opus-4-6' : 'gpt-4o'}">
        <label>API key</label>
        <input data-f="key" type="password" value="${esc(m.key)}" placeholder="paste it here">
      </div>` : ''}

    <div id="probe">${draft.probeError
    ? `<p class="err">${esc(draft.probeError)}</p>`
    : ''}</div>
    ${nav(null, 'Check and continue', 'model')}`;
}

function stepMission() {
  return `
    <h1>What is this engagement?</h1>
    <p class="lede">The name appears in the header and in every prompt the model sees.</p>
    <div class="task-form-grid">
      <label>name</label>
      <input data-f="name" value="${esc(draft.mission.name)}" placeholder="Northern Watch 27-1">
      <label>period</label>
      <input data-f="week" value="${esc(draft.mission.week)}" placeholder="Week 2 — Linux and OT/ICS">
    </div>
    <p class="hint">A folder is created under <code>missions/</code> from the name. It is
      gitignored, so none of this leaves the machine.</p>
    ${nav(null, 'Continue', 'mission')}`;
}

const BRIEFING_HINT = [
  'Audit gaps: which event IDs are absent estate-wide',
  'Sensor coverage: when endpoint sensors were deployed, and whether absence before that means anything',
  'Duplicated telemetry: anything that inflates raw counts',
  'Exercise scaffolding: emulation traffic that is not the adversary',
];

function stepBriefing() {
  return `
    <h1>What must the model not assume?</h1>
    <p class="lede">One line each. This goes into every prompt, and it is the difference between
      "no evidence found" and "no telemetry exists to find it" — the mistake that turns an audit
      gap into a clean bill of health.</p>
    <textarea data-f="briefing" rows="9"
      placeholder="${esc(BRIEFING_HINT.join('\n'))}">${esc(draft.briefing)}</textarea>
    <p class="hint">Leave it empty if you genuinely have nothing yet; it is editable later in
      <code>missions/${esc(draft.code ?? '<mission>')}/mission.json</code>.</p>
    ${nav(null, 'Continue', 'briefing')}`;
}

function stepTeam() {
  return `
    <h1>Who is on the team?</h1>
    <p class="lede">Each person gets a login token and their own chat window. The order here is
      the order they appear in the app, so put the chain of command in the order you want to
      read it.</p>
    <table class="wiz-table">
      <thead><tr><th>name</th><th>role</th><th>team</th><th></th></tr></thead>
      <tbody>
        ${draft.members.map((m, i) => `
          <tr>
            <td><input data-row="${i}" data-f="name" value="${esc(m.name)}" placeholder="Okafor"></td>
            <td><input data-row="${i}" data-f="role" value="${esc(m.role)}" placeholder="Host Analyst"></td>
            <td><input data-row="${i}" data-f="team" value="${esc(m.team)}" placeholder="Bravo"></td>
            <td><button data-act="drop" data-row="${i}" title="Remove">&times;</button></td>
          </tr>`).join('')}
      </tbody>
    </table>
    <button data-act="addrow">+ Add person</button>
    <p class="hint">Tokens are generated at the end, not now, and printed to the console you
      started the server from.</p>
    ${nav(null, 'Continue', 'roster')}`;
}

function stepTerrain() {
  const p = draft.terrainPreview;
  return `
    <h1>What does the network look like?</h1>
    <p class="lede">Paste whatever your inventory actually is — a survey dump, a spreadsheet
      copy, nmap output, a wiki table — and it gets read into the map. Or upload a
      <code>terrain.json</code>, or start with nothing.</p>

    <textarea data-f="paste" rows="10"
      placeholder="Paste the inventory here">${esc(draft.paste)}</textarea>

    <div class="wiz-nav" style="justify-content:flex-start;gap:8px">
      <button class="primary" data-act="structure" ${draft.busy ? 'disabled' : ''}>
        ${draft.busy ? 'Reading…' : 'Read this into terrain'}</button>
      <label class="filebtn">Upload terrain.json<input type="file" id="tfile" accept=".json" hidden></label>
      <button data-act="noterrain">Start with no inventory</button>
    </div>

    ${p ? `
      <div class="wiz-preview">
        <h3>${p.hosts} host${p.hosts === 1 ? '' : 's'} across ${p.enclaves.length} enclave${
  p.enclaves.length === 1 ? '' : 's'}</h3>
        <p class="hint">Your paste had ${p.sourceLines} non-empty lines. If that number and the
          host count are wildly apart, something was dropped — read it again rather than
          accepting it.</p>
        ${p.enclaves.map(e => `<div class="wiz-enc"><b>${esc(e.name)}</b>
          ${e.segments.map(s => `<span>${esc(s.name)} · ${s.hosts}</span>`).join('')}</div>`).join('')}
        <div class="wiz-nav">
          <button data-act="structure">Read it again</button>
          <button class="primary" data-act="terrain">Accept and continue</button>
        </div>
      </div>` : ''}

    ${nav(null, null, null)}`;
}

function stepPlan() {
  return `
    <h1>And the hunt plan?</h1>
    <p class="lede">The plan is edited in the app all week; this is only the starting point.</p>
    <div class="wiz-nav" style="justify-content:flex-start;gap:8px;flex-wrap:wrap">
      <button class="primary" data-act="plandoctrine" ${draft.busy ? 'disabled' : ''}>
        ${draft.busy ? 'Building…' : 'Start from the CPT doctrinal frame'}</button>
      <label class="filebtn">Upload a plan.json<input type="file" id="pfile" accept=".json" hidden></label>
      <button data-act="planexample">Copy the example plan</button>
      <button data-act="planempty">Start empty</button>
    </div>
    <p class="hint">The doctrinal frame is 44 tactical tasks across M0 prepare, M1 network, host
      and vulnerability characterisation, M2 hunt, M3 respond and M4 hand over — each phase
      carrying its tactical objective and MOEs. Every task names a <em>category</em> of terrain,
      such as domain controllers or the IT/OT boundary, for you to fill in with your own hosts.
      The example is four tasks showing the shape. Empty is fine too; tasks can be written in
      the app.</p>
    ${nav(null, null, null)}`;
}

function done(out) {
  return `
    <h1>${esc(out.code)} is live</h1>
    <p class="lede">${out.members} member${out.members === 1 ? '' : 's'} created,
      ${out.tasks} task${out.tasks === 1 ? '' : 's'} imported.</p>
    <p>Each person's login token is printed in the console you started the server from. They are
      not shown here, and they are not recoverable from the browser.</p>
    <div class="wiz-nav"><span></span>
      <a class="btn primary" href="/">Open Psephos</a></div>`;
}

const VIEWS = [stepModel, stepMission, stepBriefing, stepTeam, stepTerrain, stepPlan];

function render() {
  // Once setup has finished there is nothing to go back to, and the repaint
  // that follows every action would otherwise wipe the closing screen and put
  // the operator back on a step whose button no longer has a route to call.
  el().innerHTML = draft.finished ? done(draft.finished) : rail() + VIEWS[draft.step]();
}

// --- events --------------------------------------------------------------------

document.addEventListener('input', (e) => {
  const f = e.target.dataset?.f;
  if (!f) return;
  const row = e.target.dataset.row;
  if (row !== undefined) { draft.members[+row][f] = e.target.value; return; }
  if (draft.step === 0) draft.model[f] = e.target.value;
  else if (draft.step === 1) draft.mission[f] = e.target.value;
  else if (draft.step === 2) draft.briefing = e.target.value;
  else if (f === 'paste') draft.paste = e.target.value;
});

document.addEventListener('change', async (e) => {
  if (e.target.name === 'provider') {
    draft.model.provider = e.target.value;
    return render();
  }
  if (e.target.id === 'tfile' || e.target.id === 'pfile') {
    const file = e.target.files?.[0];
    if (!file) return;
    let parsed;
    try {
      parsed = JSON.parse(await file.text());
    } catch (err) { return toast(`${file.name} is not valid JSON: ${err.message}`, true); }

    try {
      if (e.target.id === 'tfile') {
        const out = await api('/api/setup/terrain', { code: draft.code, terrain: parsed });
        toast(`${out.hosts} hosts across ${out.enclaves} enclaves`);
        draft.step = 5;
      } else {
        const out = await api('/api/setup/plan', { code: draft.code, plan: parsed });
        return finish(out.tasks);
      }
      render();
    } catch (err) { toast(err.message, true); }
  }
});

async function finish(tasks) {
  draft.busy = true; render();
  const out = await api('/api/setup/finish', { code: draft.code });
  try { sessionStorage.removeItem(REMEMBERED); } catch { /* private mode */ }
  draft.finished = { ...out, tasks: out.tasks ?? tasks };
  draft.busy = false;
  render();
}

document.addEventListener('click', async (e) => {
  const btn = e.target.closest('button');
  if (!btn) return;
  const act = btn.dataset.act;
  if (!act) return;
  e.preventDefault();

  const run = async (fn) => {
    draft.busy = true; render();
    try { await fn(); } catch (err) { toast(err.message, true); }
    draft.busy = false; render();
  };

  if (act === 'back') { draft.step--; return render(); }
  if (act === 'addrow') { draft.members.push({ name: '', role: '', team: '' }); return render(); }
  if (act === 'drop') {
    draft.members.splice(+btn.dataset.row, 1);
    if (!draft.members.length) draft.members.push({ name: '', role: '', team: '' });
    return render();
  }

  if (act === 'model') {
    return run(async () => {
      const out = await api('/api/setup/model', draft.model);
      /*
        Held in the draft rather than written straight into #probe. The throw
        below reaches run()'s handler, which toasts and re-renders — so the
        server's actual reason (wrong port, bad key, TLS) was painted and
        erased in the same tick, and the operator standing the server up saw
        only a four-second "that backend did not answer".
      */
      draft.probeError = out.ok ? null : out.probe.detail;
      if (!out.ok) throw new Error('that backend did not answer');
      toast(out.probe.detail);
      draft.step = 1;
    });
  }

  if (act === 'mission') {
    return run(async () => {
      if (!draft.mission.name.trim()) throw new Error('the mission needs a name');
      const out = await api('/api/setup/mission', { ...draft.mission, briefing: [] });
      saveCode(out.code);
      draft.step = 2;
    });
  }

  if (act === 'briefing') {
    return run(async () => {
      await api('/api/setup/mission', { code: draft.code, ...draft.mission, briefing: draft.briefing });
      draft.step = 3;
    });
  }

  if (act === 'roster') {
    return run(async () => {
      const out = await api('/api/setup/roster', { code: draft.code, members: draft.members });
      toast(`${out.members} on the roster`);
      draft.step = 4;
    });
  }

  if (act === 'structure') {
    return run(async () => {
      if (!draft.paste.trim()) throw new Error('nothing pasted yet');
      const out = await api('/api/setup/terrain/structure', { text: draft.paste });
      draft.terrain = out.terrain;
      draft.terrainPreview = out;
    });
  }

  if (act === 'terrain') {
    return run(async () => {
      const out = await api('/api/setup/terrain', { code: draft.code, terrain: draft.terrain });
      toast(`${out.hosts} hosts written`);
      draft.step = 5;
    });
  }

  if (act === 'noterrain') {
    return run(async () => {
      await api('/api/setup/terrain/empty', { code: draft.code });
      draft.step = 5;
    });
  }

  const PLAN_SOURCE = { plandoctrine: 'doctrine', planexample: 'example', planempty: 'empty' };
  if (PLAN_SOURCE[act]) {
    return run(async () => {
      const out = await api('/api/setup/plan', { code: draft.code, from: PLAN_SOURCE[act] });
      await finish(out.tasks);
    });
  }
});

// --- start ----------------------------------------------------------------------

/*
  Resume rather than restart. The mission code is the only thing the server
  cannot work out on its own — a half-built profile is just a directory — so it
  is kept in sessionStorage and everything else is read back from disk.
*/
const REMEMBERED = 'hunt-setup-code';
const saveCode = (code) => {
  draft.code = code;
  try { sessionStorage.setItem(REMEMBERED, code); } catch { /* private mode */ }
};

let remembered = null;
try { remembered = sessionStorage.getItem(REMEMBERED); } catch { /* private mode */ }

state = await api('/api/setup/state' + (remembered ? `?code=${encodeURIComponent(remembered)}` : ''));
draft.model.provider = state.model.provider;
draft.model.model = state.model.model ?? '';
draft.model.baseUrl = state.model.baseUrl ?? '';

if (remembered && state.mission) {
  draft.code = remembered;
  draft.mission = { name: state.mission.name ?? '', week: state.mission.week ?? '' };
  draft.briefing = (state.mission.briefing ?? []).join('\n');
  if (state.roster?.members?.length) draft.members = state.roster.members;

  // The first step that is not done. Model counts as done when the CLI is
  // selected, because the CLI needs no configuration of ours.
  const order = ['model', 'mission', 'roster', 'terrain', 'plan'];
  const stepOf = { model: 0, mission: 1, roster: 3, terrain: 4, plan: 5 };
  const firstUndone = order.find(k => !state.done[k]);
  draft.step = firstUndone ? stepOf[firstUndone] : 5;
  if (state.done.mission && !state.mission.briefing?.length) draft.step = Math.min(draft.step, 2);
}

render();
