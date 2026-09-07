/**
 * The add and edit form for hunt plan tasks.
 *
 * Split out of plan.js because a full field editor is about as much markup as
 * the rest of that view put together, and the two have nothing to say to each
 * other beyond "here is a task, give me back a patch".
 *
 * List fields are edited one item per line rather than as chips. Commands
 * contain commas and quotes, so a comma-separated control would mangle exactly
 * the field analysts most need to paste into.
 */
import { state, esc } from '../core.js';

const PRIORITIES = ['low', 'normal', 'high'];

/** Textareas hold one item per line; blank lines are not items. */
const linesOf = (arr) => (arr ?? []).join('\n');
const toLines = (v) => String(v ?? '').split('\n').map(s => s.trim()).filter(Boolean);

const LISTS = [
  ['mitre', 'MITRE techniques', 'T1110.003'],
  ['tools', 'Tools', 'Kibana'],
  ['dataSources', 'Data sources', 'Security 4771'],
  ['terrain', 'Terrain', '10.0.1.0/24'],
  ['references', 'References', 'MITRE T1110.003'],
];

const TEXTS = [
  ['intent', 'Intent', 'Why this task exists and what it is for.'],
  ['evidenceExpected', 'Evidence expected', 'What a completed run of this should produce.'],
  ['analysis', 'Analysis', ''],
  ['doNext', 'Do next', ''],
];

function stepRow(s, i) {
  return `
    <div class="step-edit" data-step="${i}">
      <div class="step-edit-head">
        <span class="mono muted">${i + 1}</span>
        <button type="button" data-step-act="up" title="Move up">↑</button>
        <button type="button" data-step-act="down" title="Move down">↓</button>
        <button type="button" data-step-act="del" title="Remove step">✕</button>
      </div>
      <textarea data-f="text" rows="3" placeholder="What the analyst does.">${esc(s.text ?? '')}</textarea>
      <div class="step-edit-meta">
        <input data-f="tooling" placeholder="Tooling — Kibana · Zeek" value="${esc(s.tooling ?? '')}">
        <input data-f="expect" placeholder="Expect — what a clean result looks like" value="${esc(s.expect ?? '')}">
      </div>
    </div>`;
}

/**
 * @param {object} o
 * @param {object|null} o.task   existing task when editing, null when adding
 * @param {string} o.phaseKey    phase to add into (add mode)
 * @param {Array}  o.phases      [{key,name}] for the phase picker
 */
export function formHtml({ task, phaseKey, phases }) {
  const t = task ?? {};
  const adding = !task;
  const teams = ['', ...new Set(state.members.map(m => m.team))];
  const steps = t.steps ?? [];
  const current = adding ? phaseKey : t.phaseKey;

  return `
    <form class="task-form" id="tf">
      <div class="task-form-grid">
        <label>Title</label>
        <input data-f="title" required value="${esc(t.title ?? '')}" placeholder="Kerberoast sweep on the DCs">

        <label>Phase</label>
        <div class="row">
          <select data-f="phaseKey">
            ${phases.map(p => `<option value="${esc(p.key)}" ${p.key === current ? 'selected' : ''}>
              ${esc(p.key)} — ${esc(p.name)}</option>`).join('')}
          </select>
          ${adding ? '<button type="button" id="newphase">+ new phase</button>' : ''}
        </div>

        ${adding ? `
          <label></label>
          <div class="newphase-fields" id="npf" hidden>
            <input id="np-key" placeholder="Key — M5">
            <input id="np-name" placeholder="Name — Thread E · OT pivot">
            <textarea id="np-intent" rows="2" placeholder="Phase intent. Mission-phase MOEs live here."></textarea>
          </div>` : ''}

        <label>Key</label>
        ${adding
    ? '<input data-f="key" placeholder="auto from the title" class="mono">'
    : `<div class="mono muted key-fixed">${esc(t.taskKey ?? '')}
         <span class="hint">immutable — completion history is keyed on it</span></div>`}

        <label>Priority</label>
        <div class="row">
          <select data-f="priority">
            ${PRIORITIES.map(p => `<option ${p === (t.priority ?? 'normal') ? 'selected' : ''}>${p}</option>`).join('')}
          </select>
          <select data-f="team">
            ${teams.map(tm => `<option value="${esc(tm)}" ${tm === (t.team ?? '') ? 'selected' : ''}>
              ${tm ? esc(tm) : '— no team —'}</option>`).join('')}
          </select>
        </div>

        ${TEXTS.map(([f, label, ph]) => `
          <label>${label}</label>
          <textarea data-f="${f}" rows="${f === 'intent' ? 3 : 2}" placeholder="${esc(ph)}">${esc(t[f] ?? '')}</textarea>
        `).join('')}

        ${LISTS.map(([f, label, ph]) => `
          <label>${label}<span class="hint">one per line</span></label>
          <textarea data-f="${f}" data-list="1" rows="2" placeholder="${esc(ph)}">${esc(linesOf(t[f]))}</textarea>
        `).join('')}

        <label>Commands<span class="hint">one per line</span></label>
        <textarea data-f="commands" data-list="1" rows="3" class="mono"
          placeholder="Get-ADUser -Filter * -Properties whenCreated">${esc(linesOf(t.commands))}</textarea>
      </div>

      <label class="steps-label">Procedure</label>
      <div id="steps">${steps.map(stepRow).join('')}</div>
      <button type="button" id="addstep">+ step</button>

      <div class="task-form-actions">
        <button class="primary" type="submit">${adding ? 'Add task' : 'Save changes'}</button>
        <button type="button" id="cancel">Cancel</button>
        <span class="err" id="tf-err"></span>
      </div>
    </form>`;
}

/** Collect the form into a patch the API accepts. */
export function readForm(root) {
  const out = {};
  for (const el of root.querySelectorAll('#tf [data-f]')) {
    const f = el.dataset.f;
    out[f] = el.dataset.list ? toLines(el.value) : el.value.trim();
  }
  out.steps = [...root.querySelectorAll('#steps .step-edit')].map(d => ({
    text: d.querySelector('[data-f="text"]').value.trim(),
    tooling: d.querySelector('[data-f="tooling"]').value.trim(),
    expect: d.querySelector('[data-f="expect"]').value.trim(),
  })).filter(s => s.text);
  if (out.key === '') delete out.key;
  return out;
}

/** New-phase fields, or null when the analyst did not open that section. */
export function readNewPhase(root) {
  const box = root.querySelector('#npf');
  if (!box || box.hidden) return null;
  const key = root.querySelector('#np-key').value.trim();
  const name = root.querySelector('#np-name').value.trim();
  if (!key && !name) return null;
  return { key, name, intent: root.querySelector('#np-intent').value.trim() };
}

/** Step add/remove/reorder. Rebinds itself after each change. */
export function bindSteps(root) {
  const box = root.querySelector('#steps');
  if (!box) return;

  const renumber = () => {
    [...box.querySelectorAll('.step-edit')].forEach((d, i) => {
      d.dataset.step = i;
      d.querySelector('.mono').textContent = String(i + 1);
    });
  };

  root.querySelector('#addstep')?.addEventListener('click', () => {
    box.insertAdjacentHTML('beforeend', stepRow({}, box.children.length));
    renumber();
    box.lastElementChild.querySelector('[data-f="text"]').focus();
  });

  box.addEventListener('click', (e) => {
    const b = e.target.closest('[data-step-act]');
    if (!b) return;
    const row = b.closest('.step-edit');
    if (b.dataset.stepAct === 'del') row.remove();
    if (b.dataset.stepAct === 'up' && row.previousElementSibling) {
      row.parentNode.insertBefore(row, row.previousElementSibling);
    }
    if (b.dataset.stepAct === 'down' && row.nextElementSibling) {
      row.parentNode.insertBefore(row.nextElementSibling, row);
    }
    renumber();
  });
}

/** Show/hide the inline new-phase fields and keep the picker consistent. */
export function bindNewPhase(root) {
  const btn = root.querySelector('#newphase');
  const box = root.querySelector('#npf');
  if (!btn || !box) return;
  btn.addEventListener('click', () => {
    box.hidden = !box.hidden;
    btn.textContent = box.hidden ? '+ new phase' : 'use an existing phase';
    root.querySelector('[data-f="phaseKey"]').disabled = !box.hidden;
    if (!box.hidden) root.querySelector('#np-key').focus();
  });
}
