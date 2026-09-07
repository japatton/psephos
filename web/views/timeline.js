import { state, filters, api, toast, esc, threadById, recordById, preservingFocus, thisMount, stillMounted } from '../core.js';
import { openRecordDrawer } from './drawer.js';

let root = null;
/* The findings on screen, and how many matched in total. */
let rows = [];
let total = 0;
const PAGE = 2000;

/* Whether the last fetch answered. An empty axis means two different things. */
let loadFailed = false;

async function load() {
  const p = new URLSearchParams({ limit: String(PAGE) });
  if (filters.q) p.set('q', filters.q);
  if (filters.thread) p.set('thread', filters.thread);
  if (filters.confidence) p.set('confidence', filters.confidence);
  if (filters.from) p.set('from', filters.from);
  if (filters.to) p.set('to', filters.to);
  try {
    const out = await api(`/api/records/search?${p}`);
    rows = out.rows; total = out.total;
    loadFailed = false;
  } catch {
    /*
      Keep what is drawn rather than emptying the axis — and say so. "No
      records carry a usable time yet" is a real state of a real case file, and
      rendering it because the query failed sends an analyst looking for a
      collection problem that is not there.
    */
    loadFailed = true;
  }
}
let fitAll = false;      // false: open on where the activity actually is

const LANE_H = 46;
const R = 6;             // mark radius
const STEP = 2 * R + 2.5;
const MARGIN = { top: 14, right: 26, bottom: 34, left: 150 };

function lanes() {
  const ls = state.threads.map(t => ({ id: t.id, label: `${t.key} — ${t.name.replace(/^Thread \w+ — /, '')}`, color: t.color }));
  ls.push({ id: null, label: 'Unassigned', color: '#6e7681' });
  return ls;
}

/*
  The marks this view draws, asked for rather than filtered out of a local copy
  of every finding.

  Capped, and the cap is a feature as much as a payload decision: a timeline
  with ten thousand marks on it is not a timeline, and paintMeta already tells
  the analyst how many are shown. What it must not do is imply the rest are not
  there, so the total comes back with the page.
*/
function partition() {
  const rs = rows.filter(r => r.state !== 'denied');
  return {
    placed: rs.filter(r => r.time_parsed),
    unplaceable: rs.filter(r => !r.time_parsed),
  };
}

/**
 * The stretch of time most of the evidence is actually in.
 *
 * Fitting the full extent sounds neutral and is not. Two records from a
 * month-old compromise and twelve from the night everyone is working put 86%
 * of the marks in the last 10% of the width, eight of them on one pixel. The
 * chart was drawing everything and showing nothing.
 *
 * Runs are split where the spacing jumps far above the typical gap, and the
 * run holding the most records wins; a tie goes to the more recent one,
 * because that is the one a hunt is about. Nothing is discarded — what falls
 * outside is counted and offered.
 */
function densestSpan(times) {
  const t = [...times].map(Number).sort((a, b) => a - b);
  if (t.length < 3) return [t[0], t[t.length - 1]];

  const gaps = t.slice(1).map((v, i) => v - t[i]);
  const positive = gaps.filter(g => g > 0).sort((a, b) => a - b);
  const median = positive.length ? positive[Math.floor(positive.length / 2)] : 0;
  // Far bigger than the usual spacing, and never less than a day — otherwise
  // an evening's lull would read as a break between two separate campaigns.
  const breakAt = Math.max(median * 8, 24 * 36e5);

  const runs = [];
  let start = 0;
  for (let i = 0; i < gaps.length; i++) {
    if (gaps[i] >= breakAt) { runs.push([start, i]); start = i + 1; }
  }
  runs.push([start, t.length - 1]);

  let best = runs[0];
  for (const r of runs) {
    const n = r[1] - r[0] + 1;
    const bn = best[1] - best[0] + 1;
    if (n > bn || (n === bn && t[r[0]] > t[best[0]])) best = r;
  }
  return [t[best[0]], t[best[1]]];
}

/**
 * Where every mark sits, and how tall each lane has to be to hold them.
 *
 * Marks closer together than a circle's width stack upwards instead of being
 * drawn on top of each other. Eight records shared a single point before this,
 * which meant seven of them could not be clicked and nobody could see they
 * were there. Lanes grow to fit their tallest stack rather than the stack
 * spilling into the neighbouring thread.
 */
function layout(visible, x, ls) {
  const rowsFor = new Map(ls.map(l => [l.id, []]));
  const slot = new Map();
  const known = new Set(ls.map(l => l.id));

  for (const r of [...visible].sort((a, b) => new Date(a.time_parsed) - new Date(b.time_parsed))) {
    const key = known.has(r.thread_id) ? r.thread_id : null;
    const cx = x(new Date(r.time_parsed));
    const rows = rowsFor.get(key);
    let i = 0;
    while (rows[i] && rows[i].some(v => Math.abs(v - cx) < STEP)) i++;
    (rows[i] ??= []).push(cx);
    slot.set(r.id, { key, row: i, cx });
  }

  const depth = new Map([...rowsFor].map(([k, rows]) => [k, Math.max(1, rows.length)]));
  const heights = ls.map(l => Math.max(LANE_H, depth.get(l.id) * STEP + 16));
  const tops = [];
  let y = MARGIN.top;
  for (const h of heights) { tops.push(y); y += h; }

  const centre = (r) => {
    const s = slot.get(r.id);
    const i = ls.findIndex(l => l.id === s.key);
    const n = depth.get(s.key);
    return { cx: s.cx, cy: tops[i] + heights[i] / 2 - ((n - 1) * STEP) / 2 + s.row * STEP };
  };
  return { centre, heights, tops, bottom: y };
}

/** What the last draw could not show, so paintMeta can say so out loud. */
let omitted = { outside: 0, unlinkable: 0, offWindowLinks: 0, span: null };

function draw() {
  const { placed } = partition();
  const svgEl = root.querySelector('#tl');
  const ls = lanes();
  const w = svgEl.clientWidth || 900;

  const svg = d3.select(svgEl);
  svg.selectAll('*').remove();

  if (placed.length === 0) {
    svgEl.setAttribute('height', MARGIN.top + ls.length * LANE_H + MARGIN.bottom);
    svg.append('text').attr('x', w / 2).attr('y', 60).attr('text-anchor', 'middle')
      .attr('fill', '#8b949e').style('font-size', '13px')
      .text('No records carry a usable time yet.');
    omitted = { outside: 0, unlinkable: 0, offWindowLinks: 0, span: null };
    return;
  }

  const times = placed.map(r => +new Date(r.time_parsed));
  const [lo, hi] = fitAll ? [Math.min(...times), Math.max(...times)] : densestSpan(times);
  const pad = Math.max(36e5, (hi - lo) * 0.06);
  const domain = [new Date(lo - pad), new Date(hi + pad)];
  const x = d3.scaleTime().domain(domain).range([MARGIN.left, w - MARGIN.right]);

  // Anything outside the window is not drawn off the end of the chart; it is
  // left out and counted, and "fit all" brings it back.
  const visible = placed.filter(r => {
    const t = +new Date(r.time_parsed);
    return t >= +domain[0] && t <= +domain[1];
  });

  const { centre, heights, tops, bottom } = layout(visible, x, ls);
  svgEl.setAttribute('height', bottom + MARGIN.bottom);

  const laneG = svg.append('g');
  ls.forEach((l, i) => {
    laneG.append('rect')
      .attr('x', MARGIN.left).attr('y', tops[i])
      .attr('width', w - MARGIN.left - MARGIN.right).attr('height', heights[i])
      .attr('fill', i % 2 ? '#131a24' : 'transparent');
    laneG.append('text').attr('class', 'lane-label')
      .attr('x', MARGIN.left - 10).attr('y', tops[i] + heights[i] / 2 + 4)
      .attr('text-anchor', 'end')
      .attr('fill', l.color)
      .text(l.label.length > 24 ? l.label.slice(0, 23) + '…' : l.label);
  });

  svg.append('g').attr('class', 'tl-axis')
    .attr('transform', `translate(0,${bottom})`)
    .call(d3.axisBottom(x).ticks(Math.max(3, Math.floor(w / 140))));

  /*
    The brush goes down BEFORE the marks. Its overlay rect takes every pointer
    event in the plot, so with it on top a click never reached a circle and
    openRecordDrawer was unreachable from this page — the marks looked
    clickable, had a cursor and a handler, and did nothing. Underneath, a drag
    started anywhere but exactly on a mark still brushes, and a click on a mark
    opens the record.
  */
  // Brushing publishes the window to shared filter state; the map reads it.
  svg.append('g').attr('class', 'brush')
    .call(d3.brushX()
      .extent([[MARGIN.left, MARGIN.top], [w - MARGIN.right, bottom]])
      .on('end', (e) => {
        if (!e.selection) { filters.from = filters.to = null; }
        else {
          const [a, b] = e.selection.map(x.invert);
          filters.from = a.toISOString();
          filters.to = b.toISOString();
        }
        // Redraw, not just the caption. Every other control on this view does
        // both; brushing alone left the chart showing records the summary line
        // had already filtered out. Deferred by a tick because draw() clears
        // the SVG, and tearing out the brush's own node mid-dispatch is not
        // something d3-brush is owed.
        setTimeout(() => { draw(); paintMeta(); }, 0);
      }));

  /*
    Confirmed causality, and an honest count of what could not be drawn.
    Twenty-one links were confirmed and fifteen appeared; the other six had an
    endpoint that was denied or never carried a time, and the chart said
    nothing. A link an analyst signed off on going missing without comment is
    the failure this whole file is supposed to prevent.
  */
  const byId = new Map(visible.map(r => [r.id, r]));
  /*
    Judged against every record that could ever be placed, not against what
    survived the thread filter and the window. Otherwise brushing to two
    records reported twenty links as unplottable, which reads as a data
    problem when it is just the view being narrow.
  */
  const everPlaceable = new Set(rows
    .filter(r => r.state !== 'denied' && r.time_parsed).map(r => r.id));
  const confirmed = state.edges.filter(e => e.status === 'confirmed');
  const drawable = (e) => byId.has(e.src_record_id) && byId.has(e.dst_record_id);
  const plottable = (e) => everPlaceable.has(e.src_record_id) && everPlaceable.has(e.dst_record_id);

  const arcs = confirmed.filter(drawable);
  const outOfView = confirmed.filter(e => !drawable(e) && plottable(e));
  const unplottable = confirmed.filter(e => !plottable(e));

  omitted = {
    outside: placed.length - visible.length,
    unlinkable: unplottable.length,
    offWindowLinks: outOfView.length,
    span: [domain[0], domain[1]],
  };

  svg.append('g').selectAll('path').data(arcs).join('path')
    .attr('fill', 'none').attr('stroke', 'var(--purple)').attr('stroke-width', 1.4)
    .attr('opacity', 0.75)
    .attr('d', e => {
      const a = centre(byId.get(e.src_record_id));
      const b = centre(byId.get(e.dst_record_id));
      const my = Math.min(a.cy, b.cy) - 16;
      return `M${a.cx},${a.cy} C${a.cx},${my} ${b.cx},${my} ${b.cx},${b.cy}`;
    })
    .append('title').text(e => `${e.kind}${e.rationale ? ': ' + e.rationale : ''}`);

  svg.append('g').selectAll('circle').data(visible, r => r.id).join('circle')
    .attr('cx', r => centre(r).cx)
    .attr('cy', r => centre(r).cy)
    .attr('r', R)
    // Filled means adjudicated. Hollow means nobody has signed off yet.
    .attr('fill', r => (r.state === 'filed' ? (threadById(r.thread_id)?.color ?? 'var(--dim)') : 'transparent'))
    .attr('stroke', r => threadById(r.thread_id)?.color ?? 'var(--dim)')
    .attr('stroke-width', 1.8)
    // Dashed means the time is approximate — a tilde, a bare date, a cron expression.
    .attr('stroke-dasharray', r => (r.time_tier === 'approximate' ? '2.5,2' : null))
    .style('cursor', 'pointer')
    .on('click', (e, r) => openRecordDrawer(r.id))
    .append('title')
    .text(r => `${r.event_time ?? ''}
${r.hostname ?? ''}
${(r.description ?? '').slice(0, 160)}` +
      `
${r.time_tier === 'approximate' ? '(approximate position)' : ''}`);

}

function paintMeta() {
  const { placed, unplaceable } = partition();
  const meta = root.querySelector('#tlmeta');
  if (meta) {
    /*
      Everything the chart is not showing, said plainly. The tray already does
      this for records with no usable time; arcs and off-window marks were the
      two that vanished quietly.
    */
    const bits = [loadFailed
      ? `${placed.length - omitted.outside} shown — STALE, the search stopped answering`
      : `${placed.length - omitted.outside} shown`];
    if (omitted.outside) bits.push(`${omitted.outside} outside this window`);
    if (unplaceable.length) bits.push(`${unplaceable.length} without a usable time`);
    if (omitted.offWindowLinks) {
      bits.push(`${omitted.offWindowLinks} link${omitted.offWindowLinks === 1 ? '' : 's'} outside this view`);
    }
    if (omitted.unlinkable) {
      bits.push(`${omitted.unlinkable} confirmed link${omitted.unlinkable === 1 ? '' : 's'} cannot be drawn`);
    }
    if (filters.from) bits.push(`filter ${filters.from.slice(0, 16)} → ${filters.to.slice(0, 16)}`);
    meta.textContent = bits.join(' · ');
    meta.title = omitted.unlinkable
      ? 'A link is only drawn when both of its records are on the chart. These have an endpoint '
        + 'that was denied, archived, or never carried a usable time.'
      : '';
  }
  const fit = root.querySelector('#fit');
  if (fit) {
    fit.textContent = fitAll ? 'Focus activity' : 'Fit all';
    fit.title = fitAll
      ? 'Return to the stretch of time most of the evidence is in'
      : 'Widen the axis to every record, including outliers far from the rest';
  }
  const tray = root.querySelector('#tray');
  if (tray) tray.innerHTML = trayHtml(unplaceable);
  const links = root.querySelector('#links');
  if (links) links.innerHTML = linksHtml();
  bindTray();
  bindLinks();
}

function trayHtml(unplaceable) {
  if (unplaceable.length === 0) return '';
  return `<details ${unplaceable.length ? '' : 'hidden'}>
      <summary>${unplaceable.length} record${unplaceable.length === 1 ? '' : 's'} with no usable time — not dropped, listed here</summary>
      <div class="table-wrap" style="margin-top:10px">
        <table><thead><tr><th>Recorded as</th><th>Host</th><th>Description</th><th>State</th></tr></thead>
        <tbody>${unplaceable.map(r => `<tr data-id="${r.id}" style="cursor:pointer">
          <td class="tier-unplaceable">${esc(r.event_time ?? '—')}</td>
          <td>${esc(r.hostname ?? '—')}</td>
          <td class="clip">${esc(r.description ?? '')}</td>
          <td class="s-${r.state}">${r.state}</td></tr>`).join('')}
        </tbody></table>
      </div>
    </details>`;
}

function bindTray() {
  root.querySelectorAll('#tray tbody tr').forEach(tr =>
    tr.addEventListener('click', () => openRecordDrawer(tr.dataset.id)));
}

/**
 * Proposed causality awaiting a human call. Confirmed links become arcs on the
 * chart above; until someone signs off, an inferred link is not part of the
 * attack chain.
 */
function linksHtml() {
  const proposed = state.edges.filter(e => e.status === 'proposed');
  if (proposed.length === 0) return '';
  const label = (id) => {
    const r = recordById(id);
    if (!r) return '(missing record)';
    return `${r.hostname ?? 'unknown host'} — ${(r.description ?? '').slice(0, 60)}`;
  };
  return `
    <div class="tray">
      <h2 class="section" style="color:var(--purple)">
        ${proposed.length} proposed link${proposed.length === 1 ? '' : 's'} awaiting your call
      </h2>
      ${proposed.map(e => `
        <div class="cand" style="border-color:#3b2a58;background:#191428">
          <h4>${esc(e.kind)}</h4>
          <dl>
            <dt>From</dt><dd>${esc(label(e.src_record_id))}</dd>
            <dt>To</dt><dd>${esc(label(e.dst_record_id))}</dd>
            ${e.rationale ? `<dt>Rationale</dt><dd>${esc(e.rationale)}</dd>` : ''}
            <dt>Proposed by</dt><dd>${esc(e.created_by ?? '—')}</dd>
          </dl>
          <div class="row">
            <button class="ok" data-edge="${e.id}" data-act="confirm">Confirm link</button>
            <button class="bad" data-edge="${e.id}" data-act="deny">Deny</button>
          </div>
        </div>`).join('')}
    </div>`;
}

function bindLinks() {
  root.querySelectorAll('[data-edge]').forEach(b =>
    b.addEventListener('click', async () => {
      try {
        await api(`/api/edges/${b.dataset.edge}/${b.dataset.act}`, { method: 'POST' });
        toast(b.dataset.act === 'confirm' ? 'Link confirmed' : 'Link denied');
      } catch (err) { toast(err.message, true); }
    }));
}

function paint() {
  root.innerHTML = `
    <div class="bar">
      <select id="th">
        <option value="">all threads</option>
        ${state.threads.map(t => `<option value="${t.id}" ${t.id === filters.thread ? 'selected' : ''}>
          ${esc(t.key)} — ${esc(t.name)}</option>`).join('')}
      </select>
      <button id="fit">Fit all</button>
      <button id="clear">Clear time window</button>
      <span class="muted" id="tlmeta"></span>
    </div>
    <div class="tl-wrap">
      <svg id="tl"></svg>
      <div class="tray" id="tray"></div>
      <div id="links"></div>
    </div>
    <p class="hint">Opens on the stretch of time most of the evidence is in, because fitting a
      month-old outlier alongside a night's work leaves the night unreadable — Fit all widens it.
      Filled marks are adjudicated · hollow are pending · dashed outline means the recorded time
      was approximate · marks at the same moment stack rather than hide each other · purple arcs
      are confirmed causality · drag across to set a time window the Network Map will follow.</p>`;

  /*
    Both of these change what the SERVER would return, so both re-ask it.

    The marks used to be filtered in the browser and these handlers only
    redrew; when the query moved server-side they were left as they were. So
    picking a thread did nothing visible, and then applied itself the next time
    any unrelated delta happened to call load() — the analyst watches a filter
    do nothing, then watches the chart empty itself for no reason. Clearing the
    window was worse: the control that exists to bring evidence back left it
    off the chart, with nothing on screen saying a filter was still in force.
  */
  root.querySelector('#th').addEventListener('change', e => {
    filters.thread = e.target.value;
    load().then(() => { if (root) { draw(); paintMeta(); } });
  });
  root.querySelector('#clear').addEventListener('click', () => {
    filters.from = filters.to = null;
    load().then(() => { if (root) { draw(); paintMeta(); } });
  });
  root.querySelector('#fit').addEventListener('click', () => {
    fitAll = !fitAll; draw(); paintMeta();
  });

  draw();
  paintMeta();
}

export function mount(el) {
  root = el;
  const gen = thisMount();
  paint();                                   // the axis and the bar, at once
  load().then(() => { if (stillMounted(gen)) paint(); }); // then the marks
}

export function unmount() { root = null; }
export function onDelta() {
  // A record changing anywhere changes what this query matches, so it is
  // re-asked rather than redrawn from a copy that is no longer current.
  // Inside the promise, per plan.js: the caller's wrapper has already returned
  // by the time this repaints.
  if (root) load().then(() => {
    if (root) preservingFocus(root, () => { draw(); paintMeta(); });
  });
}
