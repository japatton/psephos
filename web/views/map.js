import { state, filters, esc, api, toast, preservingFocus, thisMount, stillMounted } from '../core.js';
import { openHostDrawer, openRecordDrawer } from './drawer.js';

let root = null;
let sim = null;
let evidence = {};   // host id -> findings touching it, from the server
let unplaced = [];   // findings nothing could place
const expanded = new Set();   // segment keys the analyst has opened
let seeded = false;           // auto-expand evidence segments once, on first mount
let adding = false;           // the add-host form is open
let showUnplaced = false;     // the list of findings sitting on no host
let offMap = { unroutable: 0, external: 0 };   // what the last graph could not place
let withdrawn = [];           // hosts whose only evidence was denied
let archived = [];            // taken off the map, kept on file
let showArchived = false;

/*
  Map or list.

  The graph answers "what is next to what", which is what you want when
  reasoning about lateral movement. It is a poor way to answer "where is
  SITE-DC" among a hundred and eighty hosts, or "show me everything that never
  answered" — those are scanning questions, and a sorted table is the right
  shape for them. Both read the same filtered host set, so switching views
  never changes what is in scope, only how it is laid out.
*/
/*
  Which view, and how the table is sorted, are remembered per browser.

  Not the filter box: that is a question someone typed to answer one thing, and
  restoring it means reloading into a list that hides most of the estate with
  nothing on screen to say why. Storage is wrapped because a locked-down
  browser throws on access rather than returning null, and a preference is
  never worth failing a page load over.
*/
const PREFS = 'hunt.map.prefs';
const SORTABLE = new Set(['name', 'ip', 'enclave', 'segment', 'os', 'role',
  'presence', 'verdict', 'evidence']);

function loadPrefs() {
  try {
    const p = JSON.parse(localStorage.getItem(PREFS) ?? '{}');
    return {
      view: p.view === 'list' ? 'list' : 'map',
      // Validated rather than trusted: a stored column that no longer exists
      // would sort by undefined and quietly scramble the order.
      sort: SORTABLE.has(p.sortBy)
        ? { by: p.sortBy, dir: p.sortDir === -1 ? -1 : 1 }
        : { by: 'enclave', dir: 1 },
    };
  } catch {
    return { view: 'map', sort: { by: 'enclave', dir: 1 } };
  }
}

function savePrefs() {
  try {
    localStorage.setItem(PREFS, JSON.stringify({ view, sortBy: sort.by, sortDir: sort.dir }));
  } catch { /* storage disabled; the preference just does not persist */ }
}

const prefs = loadPrefs();
let view = prefs.view;        // 'map' | 'list'
let sort = prefs.sort;
let find = '';                // free-text filter, list view only — deliberately not stored

const UNMAPPED = 'Unmapped';
const segKey = (h) => `${h.enclave ?? UNMAPPED}//${h.segment ?? h.name}`;
const ipOf = (v) => { const m = /(\d{1,3}(?:\.\d{1,3}){3})/.exec(String(v ?? '')); return m ? m[1] : null; };

/**
 * records-per-host, computed once per repaint rather than per node.
 *
 * The same rule the drawer uses, and for the same reason: the binding, either
 * address, or an exact name. Counting short names here as well meant the badge
 * on a node and the list inside its drawer disagreed — two hosts named "Web"
 * each showed a finding that belonged to only one of them.
 */
function evidenceIndex() {
  return (host) => evidence[host.id] ?? 0;
}

/*
  The counts come from the server now.

  This used to fold the whole records array down to a number per host, which is
  the only thing the map ever wanted it for — and the reason every browser was
  sent every finding on every load. The rule itself did not change and did not
  move: store/records.js carries the same one, pinned against this transcription
  in evidence-index.test.js.

  Kept when a refetch fails rather than blanked. A momentary network failure
  should not take every badge off the map and imply the estate is clean.
*/
/* Whether the last evidence fetch answered. An empty map means two things. */
let evidenceFailed = false;

async function loadEvidence() {
  const p = new URLSearchParams();
  if (filters.q) p.set('q', filters.q);
  if (filters.thread) p.set('thread', filters.thread);
  if (filters.confidence) p.set('confidence', filters.confidence);
  if (filters.from) p.set('from', filters.from);
  if (filters.to) p.set('to', filters.to);
  try {
    const [ev, un] = await Promise.all([
      api(`/api/records/evidence-by-host?${p}`),
      api('/api/records/unplaced'),
    ]);
    evidence = ev; unplaced = un;
    evidenceFailed = false;
  } catch {
    /*
      Keep the last picture rather than blanking every badge — and say that it
      is the last picture. "0 of 13 hosts carry evidence" is what a clean
      estate looks like, and rendering it because the query failed tells an
      analyst the opposite of what happened.
    */
    evidenceFailed = true;
  }
}

/**
 * Presence rides on the outline so the fill can keep meaning evidence and
 * verdict. A host that answered but cannot be identified gets a bright ring;
 * one that never answered is drawn hollow-dashed.
 */
function strokeFor(d) {
  // Alive, and the domain has no record of it. Three sources disagreeing with
  // its existence is the strongest signal the map can carry.
  if (d.presence === 'alive-unidentified' && d.domainJoined === 0) {
    return { color: 'var(--bad)', width: 3, dash: null };
  }
  if (d.presence === 'alive-unidentified') return { color: 'var(--warn)', width: 2.6, dash: null };
  if (d.presence === 'unanswered') return { color: '#4b5563', width: 1.2, dash: '2,3' };
  if (d.presence === 'evidence-only') return { color: 'var(--purple)', width: 1.8, dash: null };
  // Named by a finding that is now denied or gone. Left on the map because
  // deleting somebody's host behind their back is worse, but it must not keep
  // claiming evidence it no longer has.
  if (d.presence === 'evidence-withdrawn') return { color: '#4b5563', width: 1.6, dash: '1,3' };
  // An address outside the estate entirely. Hollow, so it never reads as
  // inventory, and dashed because nothing here was surveyed.
  if (d.presence === 'external') return { color: 'var(--bad)', width: 2.2, dash: '3,2' };
  if (d.kind === 'segment') return { color: '#5a6673', width: 1.5, dash: '3,2' };
  return { color: '#0d1117', width: 1.2, dash: null };
}

/** Plain words for the values the map draws as outlines. */
const PRESENCE_LABEL = {
  confirmed: 'confirmed at recorded address',
  relocated: 'alive at a different address',
  unanswered: 'no response',
  'alive-named': 'alive, named',
  'alive-unidentified': 'alive but unidentified',
  'evidence-only': 'named in evidence, not surveyed',
  external: 'not in terrain — an address outside the estate',
  'evidence-withdrawn': 'named only by evidence that was denied or removed',
  unsurveyed: 'not surveyed',
};

function colorFor(verdict, evidence) {
  if (verdict === 'confirmed') return 'var(--bad)';
  if (verdict === 'suspected') return 'var(--warn)';
  if (verdict === 'cleared') return 'var(--ok)';
  return evidence > 0 ? 'var(--warn)' : '#3d4653';
}

/** Collapse hosts into segment nodes unless the analyst opened that segment. */
function buildGraph() {
  const evidenceOf = evidenceIndex();
  const withdrawnIds = new Set(withdrawn.map(h => h.id));
  const segments = new Map();

  for (const h of state.hosts) {
    const key = segKey(h);
    if (!segments.has(key)) {
      segments.set(key, {
        key,
        enclave: h.enclave ?? UNMAPPED,
        segment: h.segment ?? UNMAPPED,
        cidr: h.cidr ?? '',
        hosts: [],
      });
    }
    segments.get(key).hosts.push(h);
  }

  const nodes = [];
  const nodeForIp = new Map();

  for (const seg of segments.values()) {
    const evidence = seg.hosts.reduce((n, h) => n + evidenceOf(h), 0);
    const anyDiscovered = seg.hosts.some(h => h.source === 'discovered');
    const open = expanded.has(seg.key) || seg.enclave === UNMAPPED;

    if (filters.evidenceOnly && evidence === 0) continue;
    if (filters.unidentifiedOnly &&
      !seg.hosts.some(h => h.presence === 'alive-unidentified')) continue;

    if (open) {
      for (const h of seg.hosts) {
        const ev = evidenceOf(h);
        if (filters.evidenceOnly && ev === 0) continue;
        if (filters.unidentifiedOnly && h.presence !== 'alive-unidentified') continue;
        const n = {
          id: 'h:' + h.id, kind: 'host', host: h, enclave: seg.enclave,
          label: h.name, r: 7 + Math.min(6, ev),
          color: colorFor(h.verdict, ev), evidence: ev,
          discovered: h.source === 'discovered',
          /*
            A host that exists only because a finding named it, where that
            finding has since been denied, is still wearing the purple "named
            in evidence" ring while carrying no evidence at all — which is what
            makes it look like a node that ought to connect to something.

            Taken from the server's own list rather than inferred from a zero
            on screen. Two hosts here show no findings but hold baseline rows,
            and calling those "denied or removed" would be a second wrong
            claim replacing the first. The ring now marks exactly the set the
            Archive button acts on.
          */
          presence: withdrawnIds.has(h.id)
            ? 'evidence-withdrawn' : (h.presence || 'unsurveyed'),
          domainJoined: h.domain_joined,
        };
        nodes.push(n);
        if (h.ip) nodeForIp.set(h.ip, n);
      }
    } else {
      const worst = seg.hosts.some(h => h.verdict === 'confirmed') ? 'confirmed'
        : seg.hosts.some(h => h.verdict === 'suspected') ? 'suspected' : 'unknown';
      const n = {
        id: 's:' + seg.key, kind: 'segment', seg, enclave: seg.enclave,
        label: `${seg.segment} (${seg.hosts.length})`,
        r: 11 + Math.min(9, seg.hosts.length * 0.7),
        color: colorFor(worst, evidence), evidence, discovered: anyDiscovered,
        // A collapsed segment must still advertise that something inside it
        // answered and nobody knows what it is.
        presence: seg.hosts.some(h => h.presence === 'alive-unidentified')
          ? 'alive-unidentified' : 'mixed',
        domainJoined: seg.hosts.some(h => h.presence === 'alive-unidentified' && h.domain_joined === 0)
          ? 0 : null,
      };
      nodes.push(n);
      for (const h of seg.hosts) if (h.ip) nodeForIp.set(h.ip, n);
    }
  }

  /*
    Derived connections, routed to whichever node currently represents the
    address — and an address terrain has never heard of gets a node of its own
    rather than taking its connection down with it.

    Both endpoints had to be in terrain before, so the two most important links
    in the case file were dropped in silence: live established SSH sessions
    into the compromised web server from two external addresses. A hunt map
    that omits where the adversary is coming from is failing at the one thing
    it is for.
  */
  const linkCounts = new Map();
  const externals = new Map();
  let unroutable = 0;

  const offTerrain = (ip) => {
    if (!externals.has(ip)) {
      const n = {
        id: 'x:' + ip, kind: 'external', enclave: 'Off terrain', label: ip, ip,
        r: 9, color: 'transparent', evidence: 0,
        discovered: true,             // a diamond: this is not inventory
        presence: 'external', domainJoined: null, links: 0,
      };
      externals.set(ip, n);
      nodes.push(n);
    }
    return externals.get(ip);
  };

  for (const c of state.connections) {
    const s = nodeForIp.get(c.src);
    const t = nodeForIp.get(c.dst);
    // Nothing on the map to attach to — usually because a filter removed the
    // only end that was ever on it. Counted rather than ignored.
    if (!s && !t) { unroutable++; continue; }
    const sn = s ?? offTerrain(c.src);
    const tn = t ?? offTerrain(c.dst);
    if (sn === tn) continue;
    sn.links = (sn.links ?? 0) + 1;
    tn.links = (tn.links ?? 0) + 1;
    const k = `${sn.id}|${tn.id}`;
    linkCounts.set(k, (linkCounts.get(k) ?? 0) + c.count);
  }
  offMap = { unroutable, external: externals.size };
  const links = [...linkCounts].map(([k, count]) => {
    const [source, target] = k.split('|');
    return { source, target, count };
  });

  return { nodes, links };
}

function enclaveCentres(nodes, w, h) {
  const names = [...new Set(nodes.map(n => n.enclave))].sort();
  const centres = new Map();
  const R = Math.min(w, h) * 0.33;
  names.forEach((name, i) => {
    if (names.length === 1) { centres.set(name, { x: w / 2, y: h / 2 }); return; }
    const a = (i / names.length) * Math.PI * 2 - Math.PI / 2;
    centres.set(name, { x: w / 2 + Math.cos(a) * R, y: h / 2 + Math.sin(a) * R });
  });
  return centres;
}

function draw() {
  // Retire the previous simulation first. Clearing the SVG does not stop d3's
  // timer, so without this every delta leaves another n-body sim ticking
  // against detached nodes for as long as the page is open.
  if (sim) { sim.stop(); sim = null; }
  const svgEl = root.querySelector('#graph');
  // Nothing to draw into when the list is showing. refresh() already routes
  // by view, so reaching here without an svg means a caller went straight to
  // draw() — cheaper to shrug than to throw halfway through a repaint.
  if (!svgEl) return;
  const w = svgEl.clientWidth || 900;
  const h = svgEl.clientHeight || 600;
  const { nodes, links } = buildGraph();
  const centres = enclaveCentres(nodes, w, h);

  const svg = d3.select(svgEl);
  svg.selectAll('*').remove();

  svg.append('defs').append('marker')
    .attr('id', 'arrow').attr('viewBox', '0 -5 10 10').attr('refX', 20)
    .attr('markerWidth', 5).attr('markerHeight', 5).attr('orient', 'auto')
    .append('path').attr('d', 'M0,-4L9,0L0,4').attr('fill', '#41505f');

  const g = svg.append('g');
  svg.call(d3.zoom().scaleExtent([0.25, 4]).on('zoom', (e) => g.attr('transform', e.transform)));

  // Enclave name behind everything, so clusters are identifiable at any zoom.
  g.append('g').selectAll('text').data([...centres]).join('text')
    .attr('class', 'enclave-label').attr('text-anchor', 'middle')
    .attr('x', d => d[1].x).attr('y', d => d[1].y).text(d => d[0]);

  const link = g.append('g').selectAll('line').data(links).join('line')
    .attr('stroke', '#41505f')
    .attr('stroke-width', d => Math.min(5, 1 + Math.log2(d.count + 1)))
    .attr('marker-end', 'url(#arrow)');

  const node = g.append('g').selectAll('g').data(nodes, d => d.id).join('g')
    .style('cursor', 'pointer')
    .call(d3.drag()
      .on('start', (e, d) => { if (!e.active) sim.alphaTarget(0.25).restart(); d.fx = d.x; d.fy = d.y; })
      .on('drag', (e, d) => { d.fx = e.x; d.fy = e.y; })
      .on('end', (e, d) => { if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; }));

  // Discovered hosts are diamonds: an address the terrain does not know is a
  // finding in its own right and should not look like ordinary inventory.
  node.filter(d => d.discovered).append('rect')
    .attr('width', d => d.r * 1.7).attr('height', d => d.r * 1.7)
    .attr('x', d => -d.r * 0.85).attr('y', d => -d.r * 0.85)
    .attr('transform', 'rotate(45)')
    .attr('fill', d => d.color)
    // Diamonds carry presence on the outline too. Discovered hosts are exactly
    // the ones whose presence matters most, so skipping them here would hide
    // the annotation on the nodes it was added for.
    .attr('stroke', d => strokeFor(d).color)
    .attr('stroke-width', d => Math.max(1.5, strokeFor(d).width))
    .attr('stroke-dasharray', d => strokeFor(d).dash);

  node.filter(d => !d.discovered).append('circle')
    .attr('r', d => d.r)
    .attr('fill', d => d.color)
    .attr('stroke', d => strokeFor(d).color)
    .attr('stroke-width', d => strokeFor(d).width)
    .attr('stroke-dasharray', d => strokeFor(d).dash);

  node.append('title').text(d => {
    if (d.kind === 'segment') {
      return `${d.seg.enclave} · ${d.seg.segment} ${d.seg.cidr}`
        + `\n${d.seg.hosts.length} hosts, ${d.evidence} findings\nclick to expand`;
    }
    if (d.kind === 'external') {
      return `${d.ip}\nnot in terrain — an address outside the estate`
        + `\n${d.links} connection${d.links === 1 ? '' : 's'} in the evidence`;
    }
    // Presence is on the tooltip too. The outline carries it, but an analyst
    // should not have to decode a dash pattern to find out why a node is grey.
    return `${d.host.name}\n${d.host.ip ?? 'no address'}`
      + `\n${d.evidence} findings · ${d.host.verdict}`
      + `\n${PRESENCE_LABEL[d.presence] ?? d.presence}`;
  });

  node.append('text').attr('class', 'node-label')
    .attr('text-anchor', 'middle').attr('dy', d => d.r + 11)
    .text(d => (d.label.length > 22 ? d.label.slice(0, 21) + '…' : d.label));

  node.on('click', (e, d) => {
    e.stopPropagation();
    if (d.kind === 'segment') { expanded.add(d.seg.key); draw(); paintCounts(); return; }
    // An external address has no host record to open; its story is in the
    // findings that named it, and the tooltip says how many there are.
    if (d.kind === 'external') return;
    openHostDrawer(d.host.id);
  });

  sim = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(links).id(d => d.id).distance(70).strength(0.35))
    .force('charge', d3.forceManyBody().strength(-260))
    .force('collide', d3.forceCollide().radius(d => d.r + 14))
    .force('x', d3.forceX(d => centres.get(d.enclave)?.x ?? w / 2).strength(0.14))
    .force('y', d3.forceY(d => centres.get(d.enclave)?.y ?? h / 2).strength(0.14))
    .on('tick', () => {
      link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
      node.attr('transform', d => `translate(${d.x},${d.y})`);
    });
}

/**
 * The hosts both views agree on.
 *
 * The same filters the graph applies, minus the segment-level rollup: a list
 * has no collapsed segments to hide behind, so every host that survives the
 * filters is a row.
 */
function visibleHosts(evidenceOf) {
  return state.hosts.filter((h) => {
    const ev = evidenceOf(h);
    if (filters.evidenceOnly && ev === 0) return false;
    if (filters.unidentifiedOnly && h.presence !== 'alive-unidentified') return false;
    if (!find) return true;
    const hay = [h.name, h.ip, h.enclave, h.segment, h.os, h.role, h.presence]
      .filter(Boolean).join(' ').toLowerCase();
    return hay.includes(find.toLowerCase());
  });
}

/** Sort an address numerically, so .9 comes before .10. */
const ipKey = (ip) => (ip ?? '').split('.').map(n => String(n).padStart(3, '0')).join('.');

const COLUMNS = [
  ['name', 'Host'],
  ['ip', 'Address'],
  ['enclave', 'Enclave'],
  ['segment', 'Segment'],
  ['os', 'OS'],
  ['role', 'Role'],
  ['presence', 'Presence'],
  ['verdict', 'Verdict'],
  ['evidence', 'Evidence'],
];

function sortHosts(hosts, evidenceOf) {
  const value = (h, by) => {
    if (by === 'evidence') return evidenceOf(h);
    if (by === 'ip') return ipKey(h.ip);
    return (h[by] ?? '').toString().toLowerCase();
  };
  return [...hosts].sort((a, b) => {
    const x = value(a, sort.by);
    const y = value(b, sort.by);
    if (x < y) return -sort.dir;
    if (x > y) return sort.dir;
    // Ties fall back to name, so the order is stable and a repaint does not
    // shuffle rows under someone's cursor.
    return (a.name ?? '').localeCompare(b.name ?? '');
  });
}

function listHtml(evidenceOf) {
  const rows = sortHosts(visibleHosts(evidenceOf), evidenceOf);
  const arrow = (key) => (sort.by === key ? (sort.dir === 1 ? ' ▲' : ' ▼') : '');

  return `
    <div class="hostlist">
      <div class="bar" style="border:0;padding-left:0">
        <input id="hl-find" class="grow" placeholder="filter by name, address, enclave, OS, role…"
          value="${esc(find)}" style="max-width:380px">
        <span class="muted">${rows.length} of ${state.hosts.length} hosts</span>
      </div>
      <div class="hostlist-scroll">
        <table class="hosttable">
          <thead><tr>
            ${COLUMNS.map(([key, label]) =>
    `<th data-sort="${key}" class="${sort.by === key ? 'on' : ''}">${label}${arrow(key)}</th>`).join('')}
          </tr></thead>
          <tbody>
            ${rows.map((h) => {
    const ev = evidenceOf(h);
    return `<tr data-host="${esc(h.id)}" class="v-row-${esc(h.verdict ?? 'unknown')}">
              <td>${esc(h.name)}${h.source === 'discovered'
      ? ' <span class="pinchip">discovered</span>' : ''}</td>
              <td class="mono">${esc(h.ip ?? '—')}</td>
              <td>${esc(h.enclave ?? '—')}</td>
              <td>${esc(h.segment ?? '—')}</td>
              <td>${esc(h.os || '—')}</td>
              <td>${esc(h.role || '—')}</td>
              <td class="p-${esc(h.presence ?? 'unsurveyed')}">${
  esc(PRESENCE_LABEL[h.presence] ?? h.presence ?? 'not surveyed')}</td>
              <td class="v-${esc(h.verdict ?? 'unknown')}">${esc(h.verdict ?? 'unknown')}</td>
              <td class="num">${ev || ''}</td>
            </tr>`;
  }).join('')}
          </tbody>
        </table>
        ${rows.length ? '' : '<p class="hint" style="padding:14px">No host matches these filters.</p>'}
      </div>
    </div>`;
}

/**
 * Wire the table up.
 *
 * Separate from paint because typing in the filter box re-renders only the
 * table: a full repaint would rebuild the input and take the caret with it,
 * which makes the box unusable after the first character.
 */
function rewireList() {
  for (const th of root.querySelectorAll('.hosttable th[data-sort]')) {
    th.addEventListener('click', () => {
      const by = th.dataset.sort;
      // The same column flips direction; a new one starts ascending, which is
      // what every other table anyone has used does.
      sort = sort.by === by ? { by, dir: -sort.dir } : { by, dir: 1 };
      savePrefs();
      repaintList();
    });
  }
  for (const tr of root.querySelectorAll('.hosttable tbody tr')) {
    tr.addEventListener('click', () => openHostDrawer(tr.dataset.host));
  }

  const box = root.querySelector('#hl-find');
  if (!box) return;
  box.addEventListener('input', (e) => {
    find = e.target.value;
    repaintList();
    const again = root.querySelector('#hl-find');
    again.focus();
    again.setSelectionRange(find.length, find.length);
  });
}

/**
 * Re-render whichever view is showing.
 *
 * The filter controls are shared, so they cannot call draw() directly: in list
 * view there is no graph to draw into, and the checkbox silently did nothing.
 */
function refresh() {
  // The counts are filtered server-side, so a filter change has to re-ask
  // before it repaints or the badges describe the previous query.
  loadEvidence().then(() => {
    if (!root) return;
    /*
      Wrapped here rather than relying on the caller, the way plan.js does.
      app.js runs every onDelta through preservingFocus, but that only covers a
      repaint on its stack — this one is inside a promise, so the wrapper had
      restored and returned long before the list was rebuilt, and the host
      filter lost the caret every time anybody else touched the case file.
    */
    preservingFocus(root, () => {
      if (view === 'list') repaintList(); else { draw(); paintCounts(); }
    });
  });
}

/**
 * What the graph could not place, written after it has been built.
 *
 * The bar is rendered before draw() runs, so anything the graph discovers has
 * to be written back rather than interpolated — the first attempt read the
 * previous repaint's numbers and quietly showed nothing at all.
 */
function paintCounts() {
  const el = root?.querySelector('#mapmeta');
  if (!el) return;
  const withEvidence = state.hosts.filter(h => evidenceIndex()(h) > 0).length;
  const bits = [evidenceFailed
    ? `evidence counts are stale — the query stopped answering (last: ${withEvidence} of ${state.hosts.length})`
    : `${withEvidence} of ${state.hosts.length} hosts carry evidence`];
  if (offMap.external) {
    bits.push(`${offMap.external} address${offMap.external === 1 ? '' : 'es'} outside terrain`);
  }
  if (offMap.unroutable) {
    bits.push(`${offMap.unroutable} connection${offMap.unroutable === 1 ? '' : 's'} with nothing on the map to attach to`);
  }
  el.textContent = bits.join(' · ');
}

function repaintList() {
  const current = root.querySelector('.hostlist');
  if (!current) return;
  current.outerHTML = listHtml(evidenceIndex());
  rewireList();
}

function setView(next) {
  if (view === next) return;
  view = next;
  savePrefs();
  // The force simulation keeps ticking otherwise, burning a core to lay out a
  // graph nobody is looking at.
  if (sim) { sim.stop(); sim = null; }
  paint();
}

function paint() {
  const evidenceOf = evidenceIndex();
  const withEvidence = state.hosts.filter(h => evidenceOf(h) > 0).length;


  root.innerHTML = `
    <div class="bar">
      <select id="th">
        <option value="">all threads</option>
        ${state.threads.map(t => `<option value="${t.id}" ${t.id === filters.thread ? 'selected' : ''}>
          ${esc(t.key)} — ${esc(t.name)}</option>`).join('')}
      </select>
      <select id="cf">
        <option value="">any confidence</option>
        ${['High', 'Medium', 'Low'].map(c =>
    `<option ${c === filters.confidence ? 'selected' : ''}>${c}</option>`).join('')}
      </select>
      <label style="display:flex;align-items:center;gap:6px;margin:0;text-transform:none;font-size:12.5px">
        <input type="checkbox" id="eo" style="width:auto" ${filters.evidenceOnly ? 'checked' : ''}> evidence only
      </label>
      <label style="display:flex;align-items:center;gap:6px;margin:0;text-transform:none;font-size:12.5px">
        <input type="checkbox" id="uo" style="width:auto" ${filters.unidentifiedOnly ? 'checked' : ''}> alive but unidentified
      </label>
      <span class="viewtoggle">
        <button id="v-map" class="${view === 'map' ? 'on' : ''}">Map</button><button
          id="v-list" class="${view === 'list' ? 'on' : ''}">List</button>
      </span>
      ${view === 'map' ? `
        <button id="expand">Expand all</button>
        <button id="collapse">Collapse all</button>` : ''}
      <button id="addhost">+ Add host</button>
      ${unplaced.length ? `<button id="unplaced" class="warnbtn">${unplaced.length} unplaced
        finding${unplaced.length === 1 ? '' : 's'}</button>` : ''}
      <span class="muted ${evidenceFailed ? 'stale' : ''}" id="mapmeta">${evidenceFailed
    ? `evidence counts are stale — the query stopped answering (last: ${withEvidence} of ${state.hosts.length})`
    : `${withEvidence} of ${state.hosts.length} hosts carry evidence`}</span>
      ${filters.from ? `<span class="muted">· window ${esc(filters.from.slice(0, 16))} → ${esc((filters.to ?? '').slice(0, 16))}</span>` : ''}
    </div>

    ${adding ? `
      <div class="addhost">
        <div class="task-form-grid">
          <label>name</label><input id="nh-name" placeholder="SITE-WEB-2">
          <label>address</label><input id="nh-ip" placeholder="10.0.1.13">
          <label>enclave</label><input id="nh-enclave" value="${esc(state.hosts[0]?.enclave ?? '')}">
          <label>segment</label><input id="nh-segment">
          <label>role</label><input id="nh-role">
        </div>
        <div class="task-form-actions">
          <button class="primary" id="nh-save">Add to the map</button>
          <button id="nh-cancel">Cancel</button>
          <span class="hint">Added by hand, so a terrain re-seed leaves it alone.</span>
          <span class="err" id="nh-err"></span>
        </div>
      </div>` : ''}

    ${showUnplaced && unplaced.length ? `
      <div class="unplaced-list">
        <p class="hint" style="margin:0 0 8px">Nothing in these findings names a host the map knows,
          or the name answers for more than one. Open one and bind it — guessing is what put a single
          finding on two servers.</p>
        ${unplaced.map(r => `<button class="unplaced-row" data-rec="${esc(r.id)}">
          <b>${esc(r.hostname || r.source_ip || '(no host named)')}</b>
          <span>${esc((r.description ?? '').slice(0, 110))}</span>
        </button>`).join('')}
      </div>` : ''}

    ${withdrawn.length ? `
      <div class="withdrawn-band">
        <div>
          <b>${withdrawn.length} host${withdrawn.length === 1 ? '' : 's'} named only by evidence that was denied</b>
          <span class="muted">Each of these exists because a finding pointed at it, and that finding
            has since been denied. They carry nothing now. Archiving takes them off the map and
            keeps them on file, so the denied findings that explain them are not orphaned.</span>
        </div>
        <div class="withdrawn-names">${withdrawn.slice(0, 12).map(h =>
    `<span class="mono">${esc(h.name)}</span>`).join('')}${withdrawn.length > 12 ? ' …' : ''}</div>
        <button class="primary" id="arch-all">Archive ${withdrawn.length}</button>
      </div>` : ''}

    ${archived.length ? `
      <div class="bar">
        <span class="muted">${archived.length} host${archived.length === 1 ? '' : 's'} archived</span>
        <button id="arch-toggle">${showArchived ? 'hide' : 'show'}</button>
        ${showArchived ? archived.map(h => `<span class="archived-chip">
          <span class="mono">${esc(h.name)}</span>
          <button data-restore="${esc(h.id)}" title="Put it back on the map">restore</button>
        </span>`).join('') : ''}
      </div>` : ''}

    ${view === 'list' ? listHtml(evidenceOf) : `
    <div class="map-wrap">
      <svg id="graph"></svg>
      <div class="legend">
        <div><i style="background:#3d4653"></i> seeded, no evidence</div>
        <div><i style="background:var(--warn)"></i> evidence, unadjudicated</div>
        <div><i style="background:var(--bad)"></i> confirmed compromised</div>
        <div><i style="background:var(--ok)"></i> cleared</div>
        <div><i style="background:#8b949e;border-radius:2px;transform:rotate(45deg)"></i> discovered, not in terrain</div>
        <div style="margin-top:7px;border-top:1px solid var(--line);padding-top:6px">
          <i style="background:transparent;border:3px solid var(--bad)"></i> alive, no DNS, no AD</div>
        <div><i style="background:transparent;border:2px solid var(--warn)"></i> alive but unidentified</div>
        <div><i style="background:transparent;border:1px dashed #4b5563"></i> no response at recorded address</div>
        <div><i style="background:transparent;border:2px solid var(--purple)"></i> named in evidence, not surveyed</div>
        <div><i style="background:transparent;border:1px dotted #4b5563"></i> evidence denied or removed</div>
        <div><i style="background:transparent;border:2px dashed var(--bad);border-radius:2px;transform:rotate(45deg)"></i>
          address outside the estate</div>
        <div style="margin-top:6px;color:var(--dim)">outline = presence · fill = evidence and verdict</div>
      </div>
    </div>`}`;

  root.querySelector('#th').addEventListener('change', e => { filters.thread = e.target.value; refresh(); });
  root.querySelector('#cf').addEventListener('change', e => { filters.confidence = e.target.value; refresh(); });
  root.querySelector('#eo').addEventListener('change', e => { filters.evidenceOnly = e.target.checked; refresh(); });
  root.querySelector('#uo').addEventListener('change', e => { filters.unidentifiedOnly = e.target.checked; refresh(); });
  root.querySelector('#expand')?.addEventListener('click', () => {
    for (const h of state.hosts) expanded.add(segKey(h));
    draw(); paintCounts();
  });
  root.querySelector('#collapse')?.addEventListener('click', () => { expanded.clear(); draw(); paintCounts(); });

  root.querySelector('#arch-all')?.addEventListener('click', async () => {
    try {
      const out = await api('/api/hosts/archive-withdrawn', { method: 'POST', body: {} });
      await loadArchiveState();
      toast(`Archived ${out.archived} host${out.archived === 1 ? '' : 's'}`);
      paint();
    } catch (e) { toast(e.message, true); }
  });
  root.querySelector('#arch-toggle')?.addEventListener('click', () => {
    showArchived = !showArchived; paint();
  });
  root.querySelectorAll('[data-restore]').forEach(b => b.addEventListener('click', async () => {
    try {
      await api(`/api/hosts/${b.dataset.restore}/restore`, { method: 'POST', body: {} });
      await loadArchiveState();
      paint();
    } catch (e) { toast(e.message, true); }
  }));

  root.querySelector('#v-map').addEventListener('click', () => setView('map'));
  root.querySelector('#v-list').addEventListener('click', () => setView('list'));
  rewireList();
  root.querySelector('#addhost').addEventListener('click', () => { adding = !adding; paint(); });
  root.querySelector('#unplaced')?.addEventListener('click', () => {
    showUnplaced = !showUnplaced; paint();
  });
  for (const b of root.querySelectorAll('.unplaced-row')) {
    b.addEventListener('click', () => openRecordDrawer(b.dataset.rec));
  }
  root.querySelector('#nh-cancel')?.addEventListener('click', () => { adding = false; paint(); });
  root.querySelector('#nh-save')?.addEventListener('click', async () => {
    const val = (id) => root.querySelector(`#nh-${id}`).value.trim() || null;
    try {
      const host = await api('/api/hosts', {
        method: 'POST',
        body: { name: val('name'), ip: val('ip'), enclave: val('enclave'),
          segment: val('segment'), role: val('role') },
      });
      adding = false;
      toast(`${host.name} added`);
      openHostDrawer(host.id);
    } catch (e) { root.querySelector('#nh-err').textContent = e.message; }
  });

  // Only the graph needs laying out; the table is already in the DOM.
  if (view === 'map') { draw(); paintCounts(); }
}

/**
 * The two host sets the graph cannot work out for itself.
 *
 * Both are computed on the server against every record, denied ones included,
 * rather than from the filtered view — a thread filter must never change which
 * hosts are eligible to be archived.
 */
async function loadArchiveState() {
  const [w, a] = await Promise.all([
    api('/api/hosts/withdrawn').catch(() => []),
    api('/api/hosts/archived').catch(() => []),
  ]);
  withdrawn = w;
  archived = a;
}

export function mount(el) {
  root = el;
  const gen = thisMount();
  loadArchiveState().then(() => { if (stillMounted(gen)) paint(); });
  loadEvidence().then(() => {
    // The router may have moved on while these were in flight, and every view
    // paints into the same element.
    if (!stillMounted(gen)) return;
    // Segments holding evidence open on the first visit, and that decision
    // needs the counts, so it waits for them rather than seeding from nothing.
    if (!seeded) {
      const evidenceOf = evidenceIndex();
      for (const h of state.hosts) if (evidenceOf(h) > 0) expanded.add(segKey(h));
      seeded = true;
    }
    paint();
  });
  paint();
}

export function onDelta() {
  // A delta changes what the rows say, not only where the dots sit.
  if (root) refresh();
}
export function unmount() { if (sim) sim.stop(); sim = null; root = null; }
