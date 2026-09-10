import { test, before, after } from 'node:test';
import assert from 'node:assert';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { openDb, initSchema } from '../store/db.js';
import { seedAll } from '../store/seed.js';
import { createRecord } from '../store/records.js';
import { proposeEdge } from '../store/edges.js';
import { listThreads } from '../store/threads.js';
import { createServer } from '../server/http.js';
import { closeAll } from '../server/sse.js';
import { findBrowser, launch, sleep } from '../tools/cdp.mjs';

/*
  The view layer, executed.

  Nothing else in this suite runs a line of it. A version of sessions.js that
  called an undefined function shipped with 594 tests passing, because a test
  that imports a module proves it parses and nothing more — the reference error
  was inside mount(), which only a browser ever calls.

  So this loads each view in headless Chrome and asks two questions: did it
  throw, and did it paint. Both are things the suite could not previously see at
  all, and between them they would have failed loudly on that commit.

  Not a substitute for unit tests. It says a view renders without exploding; it
  says nothing about whether what it rendered is right. That is deliberate — the
  cheapest test that catches the class of bug that was actually escaping.
*/

const VIEWS = [
  'sessions', 'plan', 'characterization', 'map', 'timeline', 'records', 'comms',
];

/*
  A browser is a property of the machine, not of the code. A laptop without
  Chrome should not turn a green suite red — that trains people to ignore it —
  so this skips, loudly enough to notice in the output.
*/
const exe = findBrowser();
const skip = exe ? false : 'no Edge or Chrome on this machine';

let DIR, db, server, base, page;
const TOKEN = 'smoke-token-not-a-real-secret';

before(async () => {
  if (skip) return;

  DIR = mkdtempSync(join(tmpdir(), 'huntsmoke-'));
  db = openDb(join(DIR, 'hunt.db'));
  initSchema(db);
  // The committed example profile: terrain, roster, plan and threads, so every
  // view has something to draw rather than an empty state that cannot be told
  // apart from a view that failed.
  seedAll(db);

  const threadId = listThreads(db)[0]?.id ?? null;
  const seeded = [
    { description: 'schtasks created a task in ProgramData', hostname: 'EX-DC',
      indicator: 'schtasks.exe', mitre: 'T1053.005', event_time: '2026-08-26 04:12:00Z',
      // Deliberately a field the bootstrap projection leaves out, so the drawer
      // test below is actually proving the fetch rather than reading the cache.
      analyst_notes: 'ONLY-IN-THE-FULL-ROW confirmed against the scheduled task list' },
    { description: 'beacon to an external host', hostname: 'EX-WEB',
      destination_ip: '203.0.113.25', mitre: 'T1071.001', event_time: '2026-08-26 05:01:00Z' },
  ].map(r => createRecord(db, r, { analyst: 'smoke', threadId }));

  /*
    One proposed link, so the timeline's adjudication tray has a card on it.
    Nothing else in this fixture puts one there, and the tray is the only place
    in the application that asks somebody to make a call about causality.
  */
  proposeEdge(db, {
    srcRecordId: seeded[0].id, dstRecordId: seeded[1].id, kind: 'caused',
    rationale: 'The scheduled task is what started the beacon.',
  }, 'smoke');

  server = createServer({ db, token: TOKEN, runtime: { setup: false } });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;

  page = await launch({ width: 1400, height: 900 });
  await page.metrics();
  await page.setCookie('hunt_token', TOKEN, base);
});

after(async () => {
  page?.close();
  server?.close();
  try { db?.close(); } catch { /* already closed */ }
  if (DIR) rmSync(DIR, { recursive: true, force: true });
});

/*
  Switch views the way the app does, by changing the hash, rather than by
  reloading the document.

  Faithful, and also the difference between a fast suite and an unusable one.
  Each full load opens its own EventSource, and the browser allows six
  connections to one origin: the seventh view took 56 seconds to navigate
  because it was queued behind six SSE streams belonging to pages that were no
  longer on screen. A person clicking the navigation never does that — the
  document is loaded once and the router swaps the view under it.

  Waits on the router rather than on a timer: the active nav link is set before
  mount() runs, so "the route changed and something is on screen" is a real
  signal where a sleep is a guess.
*/
async function show(view) {
  await page.evaluate(`(() => {
    window.__errors.length = 0;   // attribute what follows to this view alone
    location.hash = '#/${view}';
  })()`);

  const until = Date.now() + 15000;
  while (Date.now() < until) {
    const painted = await page.evaluate(`(() => {
      const on = document.querySelector('#nav a.active')?.dataset.route === '${view}';
      const v = document.querySelector('#view');
      if (!on || !v) return false;
      if (v.querySelector(':scope > .loading')) return false;
      return v.textContent.trim().length > 40;
    })()`);
    if (painted === true) return true;
    await sleep(100);
  }
  return false;
}

/* One cold load, because everything below assumes the shell came up at all and
   a failure there should say so rather than appearing as seven broken views. */
test('the shell boots from cold', { skip }, async () => {
  await page.goto(`${base}/#/sessions`);
  assert.ok(await page.ready(), 'the shell never rendered');
  const errors = await page.errors();
  assert.deepEqual(errors, [], `booting threw: ${errors.join(' | ')}`);
});

for (const view of VIEWS) {
  test(`${view} mounts in a browser without throwing`, { skip }, async () => {
    const painted = await show(view);
    // Settle: the map runs a force simulation and several views finish their
    // fetches after the first paint, and an error thrown then is still an error.
    await sleep(view === 'map' ? 900 : 250);

    const errors = await page.errors();
    assert.deepEqual(errors, [], `${view} threw: ${errors.join(' | ')}`);
    assert.ok(painted, `${view} never rendered anything`);
  });
}

/*
  The shell itself, which is the one thing every view depends on and which no
  per-view test would isolate: a broken router leaves all seven failing with the
  same message and none of them saying why.
*/
test('the shell routes to every view it advertises', { skip }, async () => {
  await show('records');

  const nav = await page.evaluate(
    '[...document.querySelectorAll("nav a, header a")].map(a => a.textContent.trim())');
  assert.ok(nav.length >= VIEWS.length,
    `the navigation is missing entries: ${JSON.stringify(nav)}`);
});

/*
  The coverage mode. A matrix of several hundred cells inside an existing view,
  which is the kind of thing that renders in a test and is unusable in a browser,
  so this asserts it draws cells rather than only that it did not throw.
*/
test('the plan view can show coverage, and the matrix draws', { skip }, async () => {
  await show('plan');

  const switched = await page.evaluate(`(() => {
    const b = document.querySelector('#view [data-mode="coverage"]');
    if (!b) return 'no coverage toggle';
    b.click();
    return true;
  })()`);
  assert.equal(switched, true, String(switched));

  const until = Date.now() + 8000;
  let grid = null;
  while (Date.now() < until) {
    await sleep(200);
    grid = await page.evaluate(`(() => {
      const cells = document.querySelectorAll('#view .cov-cell');
      const tactics = document.querySelectorAll('#view .cov-tactic');
      return { cells: cells.length, tactics: tactics.length };
    })()`);
    if (grid.cells > 100) break;
  }
  assert.ok(grid.cells > 100, `the matrix drew ${grid.cells} cells`);
  assert.ok(grid.tactics > 5, 'tactics should be grouped');

  const errors = await page.errors();
  assert.deepEqual(errors, [], `coverage threw: ${errors.join(' | ')}`);
});

/*
  The matrix is the way into the bank. Nobody browses eight hundred entries; a
  gap is what makes one of them relevant, which is why adding happens from the
  cell rather than from a catalogue page.
*/
/*
  A plan id ATT&CK has revoked.

  Not hypothetical: this banner found five in the repository's own plan files
  when it was written — T1070.001 and T1562.002 in mission-phases.mjs, T0855,
  T0812 and T0857 in expansion.mjs, all revoked into the T1685 and T16xx series.
  They are migrated now, so T1070.001 survives here only as a fixture. An id like
  that colours no cell and counts toward no state, so before this banner existed
  the plan looked like it covered ground the matrix could not show it covering,
  and nothing said otherwise.

  Seeded through the API rather than added to the seed plan, because changing
  product content to make a test pass is how the content stops being true.
*/
/*
  Seven full page loads in a row.

  show() changes the hash on one document, so nothing above this exercises what
  happens across real navigations — and across real navigations there was a
  ceiling. Each load opens an EventSource, an EventSource is a response that
  never ends, and a browser allows six connections per host: six abandoned
  streams and the seventh page load never gets a socket. The symptom was
  tools/screenshots.mjs hanging on its seventh capture, every run, which looked
  like a flaky screenshot tool for as long as nobody counted.

  Seven is the number that matters because seven is what the tool needs. Eight
  are done here so the test still means something if a view is ever added.
*/
/*
  Somebody else's delta must not take the keyboard away.

  Every view rebuilds its DOM to repaint, so a delta arriving mid-word destroys
  the input being typed into and recreates it — focus lands on the body and the
  caret resets. core.js's preservingFocus exists for this, and its own comment
  says the repaint it wraps must be synchronous, so a view that re-asks the
  server has to call it from inside the promise. plan.js and
  characterization.js did; map, records and timeline called it from the outside,
  where the wrapper had already restored and returned before the rebuild.

  Driven through the real delta path rather than by calling paint directly,
  because the bug was in when the wrapper ran and not in what it did.
*/
/*
  The adjudication trail reaches the browser.

  Six store modules write an audit row on every verdict, the README calls that
  an invariant, and characterization's own toast tells the analyst the change is
  in the audit log — but nothing read it, so the trail existed only for whoever
  would call the API by hand. Asserted through the drawer because that is where
  it now lives, and against a demo store that has real verdicts in it.
*/
/*
  A broken search must not read as an empty case file.

  loadLive swallowed the failure and left liveRows as it found it — empty on a
  fresh mount — so a failing /api/records/search rendered "No records yet. Start
  a session and Claude will propose them." An analyst filtering by a new term
  after that keeps reading pre-failure results with nothing to say the query
  stopped running. It is the distinction this codebase makes about its own
  hunts, in the one view that did not make it.
*/
test('a records view whose search fails says so rather than looking empty', { skip }, async () => {
  await show('records');

  // Break the endpoint for this page only, then re-ask.
  await page.evaluate(`(() => {
    const real = window.fetch;
    window.__restoreFetch = () => { window.fetch = real; };
    window.fetch = (u, o) => (String(u).includes('/api/records/search')
      ? Promise.resolve(new Response('{"error":"locked"}', { status: 500 }))
      : real(u, o));
  })()`);
  await page.evaluate(`import('/core.js').then(m => m.emit('*', { type: 'record.created' }))`);

  let text = '';
  const until = Date.now() + 8000;
  while (Date.now() < until) {
    await sleep(200);
    text = await page.evaluate(`document.getElementById('view')?.textContent ?? ''`);
    if (/stopped answering/.test(text)) break;
  }
  await page.evaluate(`window.__restoreFetch?.()`);

  assert.match(text, /stopped answering/,
    'a failing search still reads as an empty case file');
  assert.ok(!/No records yet/.test(text),
    'the empty-case-file wording must not show when the query never ran');
});

test('a record drawer shows who adjudicated it', { skip }, async () => {
  await show('records');
  const opened = await page.evaluate(`(() => {
    const row = document.querySelector('#view tbody tr[data-id], #view tr[data-id]');
    if (!row) return 'no record row';
    row.click();
    return true;
  })()`);
  assert.equal(opened, true, String(opened));

  let text = '';
  const until = Date.now() + 8000;
  while (Date.now() < until) {
    await sleep(200);
    text = await page.evaluate(`document.getElementById('drawer')?.textContent ?? ''`);
    if (/Adjudication/.test(text) && !/reading the trail/.test(text)) break;
  }
  assert.match(text, /Adjudication/, 'the drawer never rendered the trail');
  assert.ok(!/reading the trail/.test(text), 'the trail never finished loading');

  const errors = await page.errors();
  assert.deepEqual(errors, [], `the drawer threw: ${errors.join(' | ')}`);
});

test('a delta does not move the caret out of a filter box', { skip }, async () => {
  await show('map');
  const listed = await page.evaluate(`(() => {
    const b = document.querySelector('#view #v-list');
    if (!b) return 'no list toggle';
    b.click();
    return true;
  })()`);
  assert.equal(listed, true, String(listed));
  await sleep(500);

  const typed = await page.evaluate(`(() => {
    const box = document.querySelector('#view #hl-find');
    if (!box) return 'no filter box';
    box.focus();
    box.value = 'WKS';
    box.setSelectionRange(3, 3);
    return document.activeElement === box;
  })()`);
  assert.equal(typed, true, String(typed));

  // A record changing somewhere else in the estate, which is what a teammate
  // filing evidence looks like from here.
  // Straight through the module's own bus, which is what an SSE delta reaches.
  await page.evaluate(`import('/core.js').then(m => m.emit('*', { type: 'record.created' }))`);
  await sleep(900);

  const still = await page.evaluate(`(() => {
    const el = document.activeElement;
    return { tag: el?.tagName ?? null, caret: (() => { try { return el.selectionStart; } catch { return null; } })() };
  })()`);
  assert.notEqual(still.tag, 'BODY',
    'the delta dropped focus to the body — preservingFocus ran before the repaint');
});

test('the eighth page load still gets a connection', { skip }, async () => {
  const views = ['sessions', 'plan', 'characterization', 'map',
    'timeline', 'records', 'comms', 'sessions'];
  for (const [i, v] of views.entries()) {
    try {
      await page.goto(`${base}/#/${v}`);
    } catch (err) {
      assert.fail(`page load ${i + 1} of ${views.length} (#/${v}) never completed: ${err.message}`
        + ' — an abandoned EventSource is holding a connection past navigation');
    }
  }
  // And the last one is a working page, not merely a load event.
  assert.equal(await show('sessions'), true, 'the view after eight loads did not paint');
});

test('a plan id ATT&CK has revoked is called out, not silently dropped', { skip }, async () => {
  await show('plan');

  const created = await page.evaluate(`(await fetch('/api/plan/task', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      phaseKey: 'P1', title: 'names a revoked technique', mitre: ['T1070.001'],
    }),
  })).status`);
  assert.equal(created, 201, `seeding the revoked-id task failed: ${created}`);

  await page.evaluate(`document.querySelector('#view [data-mode="coverage"]').click()`);

  let banner = '';
  const until = Date.now() + 8000;
  while (Date.now() < until && !banner) {
    await sleep(200);
    banner = await page.evaluate(
      `document.querySelector('#view .cov-orphans')?.textContent?.trim() ?? ''`);
  }
  assert.ok(banner.includes('T1070.001'),
    `the revoked id was not named in the coverage header, got: ${banner.slice(0, 160)}`);

  // And it must not be counted as covered, which is the reason it is called out.
  const counted = await page.evaluate(
    `!!document.querySelector('#view .cov-cell[data-bank="T1070.001"]')`);
  assert.equal(counted, false, 'a revoked id drew a cell, so it is in the matrix after all');

  const errors = await page.errors();
  assert.deepEqual(errors, [], `the orphan banner threw: ${errors.join(' | ')}`);
});

test('an uncovered technique offers its bank entry and can be added', { skip }, async () => {
  await show('plan');
  await page.evaluate(`document.querySelector('#view [data-mode="coverage"]').click()`);

  let ready = false;
  const until = Date.now() + 8000;
  while (Date.now() < until && !ready) {
    await sleep(200);
    ready = await page.evaluate(`document.querySelectorAll('#view .cov-cell').length > 100`);
  }
  assert.ok(ready, 'the matrix never drew');

  const before = await page.evaluate(
    `(await (await fetch('/api/plan')).json()).tasks.length`);

  // Remember which cell this is: a stub drawn into the plan should read
  // differently afterwards, and that is worth checking, not just assuming.
  const bankId = await page.evaluate(
    `document.querySelector('#view .cov-cell.cov-none')?.dataset.bank`);
  assert.ok(bankId, 'no uncovered cell to draw from');

  await page.evaluate(`document.querySelector('#view .cov-cell.cov-none').click()`);
  await sleep(600);

  const panel = await page.evaluate(
    `(document.querySelector('#view .cov-panel')?.textContent ?? '').slice(0, 200)`);
  assert.ok(panel.length > 20, 'clicking a gap showed no entry');

  await page.evaluate(`document.querySelector('#view .cov-panel [data-add]').click()`);
  await sleep(800);

  const after = await page.evaluate(
    `(await (await fetch('/api/plan')).json()).tasks.length`);
  assert.equal(after, before + 1, 'adding from the bank did not reach the plan');

  // The whole point of drawing from the gap is that the gap closes: the cell
  // that was cov-none, naming nothing, should now read cov-named.
  const cellClass = await page.evaluate(
    `document.querySelector('#view .cov-cell[data-bank="${bankId}"]')?.className`);
  assert.ok(cellClass?.includes('cov-named'),
    `drawn cell should read cov-named, got: ${cellClass}`);

  /*
    Coverage caching. The from-bank add above reloads coverage itself, which
    would pass even if nothing else ever refreshed it. This checks the
    mechanism that was actually missing: a plain task naming a technique —
    added the ordinary way, through /api/plan/task, not drawn from the bank —
    arrives as an SSE delta while Coverage is still the view on screen, and
    the grid has to notice on its own. Before the fix, coverage was module
    state touched only by the mode toggle and by the bank-add's own reload, so
    this delta reached onDelta and did nothing to it.
  */
  const bankId2 = await page.evaluate(
    `document.querySelector('#view .cov-cell.cov-none')?.dataset.bank`);
  assert.ok(bankId2, 'no second uncovered cell to probe the live-delta path with');
  assert.notEqual(bankId2, bankId, 'need a technique distinct from the one already drawn above');

  const planForProbe = await (await fetch(`${base}/api/plan`,
    { headers: { cookie: `hunt_token=${TOKEN}` } })).json();
  const probePhase = planForProbe.tasks[0]?.phaseKey;
  assert.ok(probePhase, 'no phase available to add the probe task into');
  await fetch(`${base}/api/plan/task`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: `hunt_token=${TOKEN}` },
    body: JSON.stringify({ phaseKey: probePhase, title: `${bankId2} named without depth`, mitre: [bankId2] }),
  });

  let cellClass2 = null;
  const untilCov = Date.now() + 8000;
  while (Date.now() < untilCov) {
    await sleep(200);
    cellClass2 = await page.evaluate(
      `document.querySelector('#view .cov-cell[data-bank="${bankId2}"]')?.className`);
    if (cellClass2?.includes('cov-named')) break;
  }
  assert.ok(cellClass2?.includes('cov-named'),
    `a plain task naming ${bankId2}, added while Coverage stayed on screen, should repaint the grid `
    + `live via the SSE delta — got class: ${cellClass2}`);

  // Task 5 shipped with nothing exercising Coverage -> Plan without a reload;
  // the mode toggle is module-level state and a stale render there would be
  // invisible to every other test, which always starts from a fresh goto().
  //
  // A bare length check on #view's text cannot catch a skipped repaint: with
  // mode flipped but paint() never called, #view simply keeps the several-
  // hundred-cell coverage matrix (and open panel) from before, which clears
  // any length threshold without the board ever having rendered. Assert on
  // the shape of the DOM in both directions instead — the coverage grid is
  // gone, and a Plan-only affordance is back — so a stale DOM and a repaint
  // that runs but renders nothing each fail with a distinct message.
  await page.evaluate(`document.querySelector('#view [data-mode="plan"]').click()`);
  await sleep(300);
  const covCells = await page.evaluate(`document.querySelectorAll('#view .cov-cell').length`);
  assert.equal(covCells, 0,
    `switching to Plan left ${covCells} .cov-cell node(s) in #view: the coverage matrix was never cleared (stale DOM, no repaint)`);

  const addTaskButtons = await page.evaluate(`document.querySelectorAll('#view .addtask').length`);
  assert.ok(addTaskButtons > 0,
    'switching to Plan rendered no .addtask affordance: the repaint either never ran or ran and produced nothing');

  const boardLen = await page.evaluate(`document.querySelector('#view')?.textContent.trim().length`);
  assert.ok(boardLen > 40, 'the board never rendered after switching back from Coverage');

  /*
    Regression for the .addtask[data-add] scoping. The cov-panel's "Add to the
    plan" button drawn above also carries data-add (a bank id, not a phase
    key); an unscoped [data-add] selector would wire the addtask handler onto
    it too, sticking `editing` on a slot that never clears — bogus but with no
    visible symptom right away, because onDelta is the only thing that checks
    `editing`, and this is the first delta since. Prove a live update still
    lands rather than trusting the selector stayed scoped.
  */
  const probeTitle = 'Live-update regression probe';
  const planAfterAdd = await (await fetch(`${base}/api/plan`,
    { headers: { cookie: `hunt_token=${TOKEN}` } })).json();
  const probePhase2 = planAfterAdd.tasks[0]?.phaseKey;
  assert.ok(probePhase2, 'no phase available for the live-update probe');
  await fetch(`${base}/api/plan/task`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: `hunt_token=${TOKEN}` },
    body: JSON.stringify({ phaseKey: probePhase2, title: probeTitle }),
  });

  let seenProbe = false;
  const untilProbe = Date.now() + 8000;
  while (Date.now() < untilProbe && !seenProbe) {
    await sleep(200);
    seenProbe = await page.evaluate(
      `document.querySelector('#view')?.textContent.includes(${JSON.stringify(probeTitle)}) ?? false`);
  }
  assert.ok(seenProbe,
    'a plan change after drawing from the bank never reached the board — an unscoped [data-add] '
    + 'would stick `editing` on a bogus slot and silently drop every delta afterwards');

  const errors = await page.errors();
  assert.deepEqual(errors, [], `adding threw: ${errors.join(' | ')}`);
});

/*
  ICS. The design spec is explicit that it is not a fourth category but a
  second matrix, rendered through the same code Enterprise uses — so the thing
  worth proving is not that a matrix draws (the Enterprise test above already
  shows that), but that switching domain actually re-fetches ICS rather than
  repainting Enterprise's cells under an ICS-labelled toggle.

  Not an id-prefix check: ATT&CK for ICS's newer techniques (Impair Process
  Control, added after the T0xxx block filled up) carry ordinary T1xxx ids
  shared with Enterprise's own numbering, so "every id starts with T0" is
  false of the real matrix and would be testing a belief about MITRE's
  numbering rather than this code. T0800 ("Activate Firmware Update Mode") has
  no Enterprise equivalent and 97 ICS techniques is nowhere near Enterprise's
  several hundred, so both are checked instead.
*/
test('coverage switches to the ICS domain and draws its own matrix', { skip }, async () => {
  await show('plan');
  await page.evaluate(`document.querySelector('#view [data-mode="coverage"]').click()`);

  const untilEnt = Date.now() + 8000;
  let entCells = 0;
  while (Date.now() < untilEnt) {
    await sleep(200);
    entCells = await page.evaluate(`document.querySelectorAll('#view .cov-cell').length`);
    if (entCells > 100) break;
  }
  assert.ok(entCells > 100, 'Enterprise matrix never drew as a baseline to switch away from');

  await page.evaluate(`document.querySelector('#view [data-domain="ics"]').click()`);

  const untilIcs = Date.now() + 8000;
  let ids = [];
  while (Date.now() < untilIcs) {
    await sleep(200);
    ids = await page.evaluate(
      `[...document.querySelectorAll('#view .cov-cell')].map(b => b.dataset.bank)`);
    if (ids.includes('T0800')) break;
  }
  assert.ok(ids.includes('T0800'),
    `T0800 (ICS-only, no Enterprise equivalent) never appeared — got ${ids.length} cells`);
  assert.ok(ids.length < entCells,
    `ICS (97 techniques) should draw far fewer cells than Enterprise, got ${ids.length} vs ${entCells}`);

  const onDomain = await page.evaluate(
    `document.querySelector('#view [data-domain="ics"]')?.className`);
  assert.ok(onDomain?.includes('on'), 'the ICS toggle should read as the selected one');

  // Exercises openBankEntry's domain fix directly: a domain-blind lookup would
  // search /api/bank?domain=enterprise for a T0xxx id, find nothing there, and
  // leave the panel permanently empty.
  const clickedId = await page.evaluate(`document.querySelector('#view .cov-cell')?.dataset.bank`);
  assert.ok(clickedId, 'no ICS cell to click');
  await page.evaluate(`document.querySelector('#view .cov-cell').click()`);
  await sleep(500);
  const panelText = await page.evaluate(`document.querySelector('#view .cov-panel')?.textContent ?? ''`);
  assert.ok(panelText.includes(clickedId),
    `clicking an ICS cell should open its own entry, got panel: ${panelText.slice(0, 160)}`);

  const errors = await page.errors();
  assert.deepEqual(errors, [], `ICS coverage threw: ${errors.join(' | ')}`);
});

/*
  Practice. No ATT&CK id and no tactics, so this proves the other branch of
  coverage entirely: grouped by category rather than gridded by tactic, and
  drawing one still reaches the plan through the same from-bank endpoint. Also
  the regression this task exists to close in miniature — six tasks shipped
  authored tradecraft that no UI could reach at all.
*/
test('coverage lists Practice by category and can draw one into the plan', { skip }, async () => {
  await show('plan');
  await page.evaluate(`document.querySelector('#view [data-mode="coverage"]').click()`);
  await page.evaluate(`document.querySelector('#view [data-domain="practice"]').click()`);

  const until = Date.now() + 8000;
  let items = 0;
  while (Date.now() < until) {
    await sleep(200);
    items = await page.evaluate(`document.querySelectorAll('#view .prac-item').length`);
    if (items >= 3) break;
  }
  assert.equal(items, 3, `expected all three authored practice entries, got ${items}`);

  // Not a matrix at all: a leftover .cov-cell would mean the domain switch
  // never actually swapped which renderer ran.
  const covCells = await page.evaluate(`document.querySelectorAll('#view .cov-cell').length`);
  assert.equal(covCells, 0, 'Practice should render no matrix cells');

  const categories = await page.evaluate(
    `[...document.querySelectorAll('#view .cov-tactic h3')].map(h => h.textContent.trim())`);
  assert.equal(categories.length, 3,
    `expected three category groups (telemetry, hypothesis, deconfliction), got: ${JSON.stringify(categories)}`);

  const before = await (await fetch(`${base}/api/plan`,
    { headers: { cookie: `hunt_token=${TOKEN}` } })).json();

  const firstId = await page.evaluate(`document.querySelector('#view .prac-item')?.dataset.bank`);
  assert.ok(firstId?.startsWith('PRAC-'), `expected a practice id, got ${firstId}`);

  await page.evaluate(`document.querySelector('#view .prac-item').click()`);
  await sleep(500);

  const panelText = await page.evaluate(`document.querySelector('#view .cov-panel')?.textContent ?? ''`);
  // Every practice entry is authored by construction: the stub copy written
  // for a generated technique with nothing behind it must never show here.
  assert.ok(panelText.includes('Written here and reviewed against this estate'),
    `a practice entry should read as authored, got: ${panelText.slice(0, 160)}`);
  assert.ok(!panelText.includes('not yet reviewed'),
    'a practice entry rendered the drafted caveat; every one of them is authored');
  assert.ok(!panelText.includes('No authored task for this one'),
    'a practice entry rendered the stub copy meant for an unauthored technique');
  /*
    And the argument itself, not a step count. The panel is where somebody
    decides whether an entry is worth drawing, and "4 steps" does not help them
    decide anything.
  */
  assert.ok(panelText.includes('confident false negative'),
    `the authored intent did not reach the panel, got: ${panelText.slice(0, 200)}`);

  await page.evaluate(`document.querySelector('#view .cov-panel [data-add]').click()`);
  await sleep(800);

  const after = await (await fetch(`${base}/api/plan`,
    { headers: { cookie: `hunt_token=${TOKEN}` } })).json();
  assert.equal(after.tasks.length, before.tasks.length + 1,
    'drawing a practice entry did not reach the plan');

  // The whole point of showing what is already drawn: the entry just added
  // should now read prac-drawn rather than plain.
  const until2 = Date.now() + 8000;
  let drawnClass = null;
  while (Date.now() < until2) {
    await sleep(200);
    drawnClass = await page.evaluate(
      `document.querySelector('#view .prac-item[data-bank="${firstId}"]')?.className`);
    if (drawnClass?.includes('prac-drawn')) break;
  }
  assert.ok(drawnClass?.includes('prac-drawn'),
    `the drawn practice entry should read prac-drawn, got: ${drawnClass}`);

  const errors = await page.errors();
  assert.deepEqual(errors, [], `Practice coverage threw: ${errors.join(' | ')}`);
});

/*
  The drawer's listeners are delegated and installed once, by initDrawer(). They
  used to be registered on the drawer module's body, which is what made that
  file — and the four views importing it — impossible to load without a DOM.

  Moving them created a failure nothing else would notice: forget the call and
  the drawer still opens, still renders, and simply stops responding. So this
  clicks one of them rather than trusting that the wiring survived.
*/
test('the drawer opens and its delegated buttons still respond', { skip }, async () => {
  await show('records');

  const opened = await page.evaluate(`(() => {
    const row = document.querySelector('#view tbody tr[data-id]');
    if (!row) return 'no record row to click';
    row.click();
    return true;
  })()`);
  assert.equal(opened, true, String(opened));
  await sleep(300);

  assert.equal(await page.evaluate(
    'document.getElementById("drawer")?.hidden === false'), true, 'the drawer never opened');

  // The delegated handler, which is the thing initDrawer installs.
  await page.evaluate('document.querySelector(\'#drawer [data-act="close"]\')?.click()');
  await sleep(300);
  assert.equal(await page.evaluate('document.getElementById("drawer")?.hidden === true'), true,
    'the close button did nothing — initDrawer was probably never called');

  const errors = await page.errors();
  assert.deepEqual(errors, [], `the drawer threw: ${errors.join(' | ')}`);
});

/*
  The sign-in splash. It is armed by a flag login.html leaves in sessionStorage
  and nothing else ever sets one, so every other test here loads a shell that
  never runs it — the first thing every user sees would be the one piece of the
  front end that nothing executes.

  Three things it has to do: consume the flag so a reload does not replay it,
  leave the shell rendering underneath it, and leave.
*/
test('the sign-in splash plays once, over a live shell, and gets out of the way', { skip }, async () => {
  await page.evaluate(`sessionStorage.setItem('psephos.splash', '1')`);
  await page.goto(`${base}/#/sessions`);

  // Either still on screen, or already run and ended: the load event is not
  // ordered against the splash's own clock, and a slow machine must not fail.
  const ran = await page.evaluate(`
    document.documentElement.classList.contains('splashing')
      || document.getElementById('splash')?.classList.contains('go')`);
  assert.equal(ran, true, 'the splash never showed');
  assert.equal(await page.evaluate(`sessionStorage.getItem('psephos.splash')`), null,
    'the flag survived, so every reload would replay the splash');

  assert.ok(await page.ready(), 'the shell did not render under the splash');

  // A key press skips it; failing that, its own cap ends it. Either way it
  // has to be gone well inside the time the shell took to appear.
  await page.send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Escape', code: 'Escape' });
  const until = Date.now() + 3000;
  let gone = false;
  while (!gone && Date.now() < until) {
    gone = await page.evaluate(`!document.documentElement.classList.contains('splashing')`);
    if (!gone) await sleep(100);
  }
  assert.ok(gone, 'the splash never ended');

  const errors = await page.errors();
  assert.deepEqual(errors, [], `the splash threw: ${errors.join(' | ')}`);
});

/*
  The drawer shows more than the bootstrap carries.

  state.records is a projection now — no analyst notes, command or hash, which
  are most of a record's weight and which nothing renders until a record is
  opened. The drawer fetches the whole row when it opens one, and if that fetch
  ever stops happening the drawer does not fail: it quietly renders a record with
  its notes missing, which reads as a record that has none.
*/
test('opening a record fetches the fields the bootstrap left out', { skip }, async () => {
  await show('records');

  const opened = await page.evaluate(`(() => {
    const row = document.querySelector('#view tbody tr[data-id]');
    if (!row) return 'no record row';
    row.click();
    return true;
  })()`);
  assert.equal(opened, true, String(opened));

  // The projection cannot supply this, so its presence is the fetch.
  const until = Date.now() + 8000;
  let seen = false;
  while (Date.now() < until && !seen) {
    await sleep(200);
    seen = await page.evaluate(
      `(document.getElementById('drawer')?.textContent ?? '').includes('ONLY-IN-THE-FULL-ROW')`);
  }
  assert.ok(seen, 'the drawer rendered without the fields it has to fetch');

  const errors = await page.errors();
  assert.deepEqual(errors, [], `the drawer threw: ${errors.join(' | ')}`);
});

/*
  Resync after a dropped connection.

  sse.js states the contract in its own docstring: there is no server-side replay
  buffer, and a client that misses events is expected to reconnect and re-fetch
  /api/state. EventSource reconnects on its own and the indicator goes green, so
  a browser that missed a verdict looks healthy while showing a case file that is
  quietly out of date — stale and confident, which is the bad kind.

  Driven by closing the SSE clients from the server rather than by faking an
  event, so this exercises the reconnect the browser actually performs.
*/
test('a client that loses its connection re-fetches the case file', { skip }, async () => {
  await page.goto(`${base}/#/records`);
  assert.ok(await page.ready(), 'the shell never rendered');

  const stateFetches = () => page.evaluate(
    `performance.getEntriesByType('resource').filter(e => e.name.includes('/api/state')).length`);

  const before = await stateFetches();
  assert.equal(before, 1, 'boot should fetch the state exactly once');

  closeAll();   // every open SSE response ends; the browser will reconnect

  // retry is 2000ms, so allow for the reconnect plus the fetch it triggers.
  const until = Date.now() + 12000;
  let after = before;
  while (Date.now() < until && after <= before) {
    await sleep(250);
    after = await stateFetches();
  }
  assert.ok(after > before,
    'the connection came back and the client kept whatever it had, so a verdict '
    + 'reached while it was down is still missing');

  const errors = await page.errors();
  assert.deepEqual(errors, [], `resync threw: ${errors.join(' | ')}`);
});

/*
  And the case where the reconnect succeeds but the refresh does not.

  This is the branch that keeps the indicator honest. The stream is back, so the
  dot would otherwise go green while the case file is still whatever it was
  before the gap — precisely the state this change exists to remove, reached by
  a different route. Written because I reasoned about it rather than saw it.
*/
test('a reconnect whose refresh fails does not report itself as live', { skip }, async () => {
  await page.goto(`${base}/#/records`);
  assert.ok(await page.ready());

  // Refuse only the state fetch, so the stream still reconnects normally.
  await page.evaluate(`(() => {
    const real = window.fetch;
    window.fetch = (u, o) => (String(u).includes('/api/state')
      ? Promise.reject(new Error('refused for the test'))
      : real(u, o));
  })()`);

  closeAll();

  const until = Date.now() + 12000;
  let dot = null;
  while (Date.now() < until) {
    await sleep(250);
    dot = await page.evaluate(`(() => {
      const d = document.getElementById('conn');
      return d ? { down: d.classList.contains('down'), title: d.title } : null;
    })()`);
    if (dot?.down && /refresh|reload/i.test(dot.title)) break;
  }
  assert.ok(dot?.down, `the indicator claimed live over a failed refresh: ${JSON.stringify(dot)}`);
  assert.match(dot.title, /refresh|reload/i, 'the title should say what is wrong');

  await page.goto(`${base}/#/records`);   // drop the patched fetch
});

/*
  The plan view's own regression: a phaseless plan still paints. The seeded
  filter bar alone clears the 40-character threshold the generic mount test
  uses, so that test would pass even if phaseList() derived zero phases and
  every task row, step list, and add-task affordance never rendered. This
  looks for one of the seeded example tasks by name, which only appears if a
  phase actually made it onto the board.
*/
test('the plan view renders its seeded phases and tasks, not just its shell', { skip }, async () => {
  await show('plan');
  await sleep(250);

  const errors = await page.errors();
  assert.deepEqual(errors, [], `plan threw: ${errors.join(' | ')}`);

  const rendered = await page.evaluate(
    'document.querySelector("#view")?.textContent.includes("Survey and reconcile the terrain") ?? false');
  assert.equal(rendered, true, 'no seeded task title found — the board rendered no phases');
});

/*
  The regression this harness was built for. sessions.js is the view that
  shipped broken, and its quota panel is the code that broke it — a reference
  error inside mount(), invisible to every other kind of test here.
*/
test('the sessions view reaches its own data, not just its shell', { skip }, async () => {
  await show('sessions');
  await sleep(250);

  const errors = await page.errors();
  assert.deepEqual(errors, [], `sessions threw: ${errors.join(' | ')}`);

  const roster = await page.evaluate(
    'document.querySelector("#view")?.textContent.includes("Reyes") ?? false');
  assert.equal(roster, true, 'the roster never arrived, so mount() did not finish');
});

/*
  A view that is still loading must not paint over the one you navigated to.

  Every view is handed the same #view element and four of them mount
  asynchronously, so a mount whose fetches landed after a click repainted over
  the new view — and, worse, registered its event-bus handlers after the router
  had already called its unmount. Those handlers were then unreachable: comms
  unmounts only while the router believes comms is mounted, and a later remount
  overwrites the list without releasing the orphans. One raced mount left the
  chat window replacing the timeline on every message anyone sent, for the life
  of the page.
*/
test('a view left mid-mount does not paint over the one you switched to', { skip }, async () => {
  await page.goto(`${base}/#/records`);
  assert.ok(await page.ready(), 'the shell never rendered');

  // Hold comms' first fetch open long enough to navigate away underneath it.
  await page.evaluate(`(() => {
    const real = window.fetch;
    window.fetch = (u, o) => (String(u).includes('/api/chat/channels')
      ? new Promise(r => setTimeout(() => r(real(u, o)), 700))
      : real(u, o));
  })()`);

  await page.evaluate(`(() => { location.hash = '#/comms'; })()`);
  await sleep(120);
  await page.evaluate(`(() => { location.hash = '#/map'; })()`);
  await sleep(1600);

  const after = await page.evaluate(`(() => ({
    route: document.querySelector('#nav a.active')?.dataset.route,
    comms: Boolean(document.querySelector('#view .comms-layout')),
    map: Boolean(document.querySelector('#view #mapmeta')),
  }))()`);
  assert.equal(after.route, 'map');
  assert.equal(after.comms, false, 'the abandoned view painted itself over the current one');
  assert.equal(after.map, true, 'the map never came back');

  // And the orphan must not be listening either: a real message on the wire.
  await page.evaluate(`fetch('/api/chat/team/messages', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ body: 'a message from somebody else' }),
  })`);
  await sleep(900);

  const later = await page.evaluate(`(() => ({
    route: document.querySelector('#nav a.active')?.dataset.route,
    comms: Boolean(document.querySelector('#view .comms-layout')),
    map: Boolean(document.querySelector('#view #mapmeta')),
  }))()`);
  assert.equal(later.comms, false,
    'a handler belonging to an abandoned mount repainted over the current view');
  assert.equal(later.map, true);

  await page.goto(`${base}/#/records`);   // drop the patched fetch
});

/*
  Adjudicating from inside the drawer has to change what the drawer says.

  recordDetail is fetched once when the drawer opens and preferred over the
  live projection ever after, so confirming a finding repainted the drawer from
  the copy taken BEFORE the verdict: the table behind it flipped to filed while
  the drawer went on reading "pending · created by …" and offering Confirm and
  Deny. A teammate adjudicating a record you had open did the same thing.
*/
test('confirming from the drawer updates the drawer, not just the table', { skip }, async () => {
  await page.goto(`${base}/#/records`);
  assert.ok(await page.ready(), 'the shell never rendered');
  await sleep(600);

  const opened = await page.evaluate(`(() => {
    const row = [...document.querySelectorAll('#view tbody tr')]
      .find(tr => tr.querySelector('.s-pending'));
    if (!row) return 'no pending row on screen';
    row.click();
    return true;
  })()`);
  assert.equal(opened, true, String(opened));
  await sleep(600);

  const before = await page.evaluate(
    `document.querySelector('#drawer')?.textContent.replace(/\\s+/g, ' ').slice(0, 120) ?? ''`);
  assert.match(before, /pending/, 'the fixture must open on a pending finding');

  const clicked = await page.evaluate(`(() => {
    const b = document.querySelector('#drawer [data-act="promote"]');
    if (!b) return 'no confirm button in the drawer';
    b.click();
    return true;
  })()`);
  assert.equal(clicked, true, String(clicked));
  await sleep(900);

  const after = await page.evaluate(`(() => ({
    text: document.querySelector('#drawer')?.textContent.replace(/\\s+/g, ' ').slice(0, 160) ?? '',
    stillOffersConfirm: Boolean(document.querySelector('#drawer [data-act="promote"]')),
  }))()`);
  assert.match(after.text, /filed/, `the drawer still reads: ${after.text}`);
  assert.equal(after.stillOffersConfirm, false,
    'the drawer went on offering Confirm for a finding already confirmed');
});

/*
  The timeline's filters change what the SERVER would return, so they have to
  re-ask it. The marks moved server-side and these two handlers were left
  redrawing a list they no longer own: picking a thread did nothing visible,
  and then applied itself the next time any unrelated delta called load().
*/
test('the timeline thread filter re-queries rather than redrawing', { skip }, async () => {
  await page.goto(`${base}/#/timeline`);
  assert.ok(await page.ready(), 'the shell never rendered');
  await sleep(900);

  const marks = () => page.evaluate(`document.querySelectorAll('#view svg circle').length`);
  const before = await marks();
  assert.ok(before > 0, 'the fixture must put marks on the chart');

  /*
    The LAST thread, not merely a different one: the seeded findings are all in
    the first, so picking that changes nothing and would prove nothing either.
  */
  const picked = await page.evaluate(`(() => {
    const sel = document.querySelector('#view #th');
    if (!sel) return 'no thread selector';
    const withValue = [...sel.options].filter(o => o.value);
    if (withValue.length < 2) return 'the fixture needs more than one thread';
    sel.value = withValue.at(-1).value;
    sel.dispatchEvent(new Event('change', { bubbles: true }));
    return true;
  })()`);
  assert.equal(picked, true, String(picked));

  const until = Date.now() + 4000;
  let after = before;
  while (Date.now() < until && after === before) { await sleep(150); after = await marks(); }
  assert.equal(after, 0,
    'picking a thread with no findings left them on the chart, so the filter never reached the server');
});

/*
  The proposed-link card has to name both of its records.

  It resolved them through recordById(), which reads state.records — a cache of
  whatever this browser has happened to be sent, and empty on a cold load of
  this view, because the timeline asks the server for its own rows and search
  moved server-side. So the one card in the application that asks an analyst to
  adjudicate causality rendered "(missing record)" at both ends, on records that
  were sitting in the store the whole time. It shipped that way in this
  repository's own published screenshot.

  Asserting on the hostnames rather than on the absence of the old string: a
  card that named neither end is the bug, whatever wording it used to say so.
*/
test('a proposed link names both of its records', { skip }, async () => {
  await page.goto(`${base}/#/timeline`);
  assert.ok(await page.ready(), 'the shell never rendered');

  const until = Date.now() + 8000;
  let tray = '';
  while (Date.now() < until) {
    await sleep(200);
    tray = await page.evaluate(
      `document.querySelector('#view #links')?.textContent.replace(/\\s+/g, ' ').trim() ?? ''`);
    if (/awaiting your call/.test(tray)) break;
  }
  assert.match(tray, /awaiting your call/, 'the fixture must put a proposed link in the tray');

  assert.match(tray, /EX-DC — schtasks created a task in ProgramData/,
    `the From end went unnamed: ${tray}`);
  assert.match(tray, /EX-WEB — beacon to an external host/,
    `the To end went unnamed: ${tray}`);

  const errors = await page.errors();
  assert.deepEqual(errors, [], `the link tray threw: ${errors.join(' | ')}`);
});

/*
  A search that stops answering must not read as an empty case file.

  The banner went into the records table and nowhere else, leaving the three
  views that make the strongest claims — nothing pending, no timed evidence, a
  clean estate — rendering their empty states with a green connection dot.
*/
test('a failing search says so in the timeline, the rail and the map', { skip }, async () => {
  await page.goto(`${base}/#/records`);
  assert.ok(await page.ready());
  await page.evaluate(`(() => {
    const real = window.fetch;
    window.fetch = (u, o) => (/\\/api\\/records\\/(search|evidence-by-host)/.test(String(u))
      ? Promise.resolve(new Response('{"error":"broken"}', { status: 500 }))
      : real(u, o));
  })()`);

  await page.evaluate(`(() => { location.hash = '#/timeline'; })()`);
  await sleep(1200);
  const timeline = await page.evaluate(`document.querySelector('#view')?.textContent ?? ''`);
  assert.match(timeline, /STALE|stopped answering/,
    'the timeline reported an empty axis while the query was failing');

  await page.evaluate(`(() => { location.hash = '#/sessions'; })()`);
  await sleep(1200);
  const rail = await page.evaluate(`document.querySelector('#view')?.textContent ?? ''`);
  assert.match(rail, /stopped answering/,
    'the pending rail said nothing was waiting while the query was failing');

  await page.evaluate(`(() => { location.hash = '#/map'; })()`);
  await sleep(1500);
  const map = await page.evaluate(`document.querySelector('#view')?.textContent ?? ''`);
  assert.match(map, /stale/,
    'the map reported a clean estate while the counts were failing');

  await page.goto(`${base}/#/records`);   // drop the patched fetch
});

/*
  Typing in the records filter while somebody else files a finding.

  onDelta re-asks the server and repaints from inside the promise, so the
  wrapper app.js puts around onDelta has long since returned — preservingFocus
  has to be called there, and was instead wrapped around loadArchived, which
  onDelta never calls.
*/
test('a teammate filing a finding does not take the caret out of the filter box', { skip }, async () => {
  await page.goto(`${base}/#/records`);
  assert.ok(await page.ready());
  await sleep(600);

  // Through the event, so the view's own filter state matches what is typed;
  // setting .value alone would leave the repaint restoring an empty box.
  await page.evaluate(`(() => {
    const q = document.querySelector('#view #q');
    q.focus();
    q.value = 'sch';
    q.dispatchEvent(new Event('input', { bubbles: true }));
  })()`);
  /*
    Let the box's own debounce finish first. It restores the caret itself after
    the search it schedules, so measuring inside that window would credit this
    fix for something the typing path already does — and the mutation would
    survive. What is being tested is the repaint nobody here asked for.
  */
  await sleep(800);
  await page.evaluate(`(() => {
    const q = document.querySelector('#view #q');
    q.focus();
    q.setSelectionRange(3, 3);
  })()`);

  // Somebody else, on another browser, files something.
  await page.evaluate(`fetch('/api/records', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ description: 'filed by a colleague', hostname: 'EX-WEB' }),
  })`);
  await sleep(1200);

  const focus = await page.evaluate(`(() => ({
    id: document.activeElement?.id ?? '',
    caret: document.activeElement?.selectionStart ?? null,
  }))()`);
  assert.equal(focus.id, 'q', 'the repaint took the keyboard away from whoever was typing');
  assert.equal(focus.caret, 3, 'the caret jumped');
});

/*
  The sign-in page, after ten wrong attempts.

  The limiter answers 429 to everything for the next minute, correct token
  included, and login.html branched only on 204 — so an analyst who mistyped
  their eight-character token ten times and then typed it correctly was told
  the token was not recognised. The natural response, trying again, looks
  identical to the limiter.
*/
test('a rate-limited sign-in does not report the token as wrong', { skip }, async () => {
  await page.goto(`${base}/login`);
  await sleep(300);

  await page.evaluate(`(() => {
    window.fetch = () => Promise.resolve(new Response(null, { status: 429 }));
  })()`);
  await page.evaluate(`(() => {
    document.getElementById('token').value = 'whatever';
    document.getElementById('f').dispatchEvent(new Event('submit', { cancelable: true }));
  })()`);
  await sleep(400);

  const shown = await page.evaluate(`(() => {
    const e = document.getElementById('err');
    return { hidden: e.hidden, text: e.textContent.trim() };
  })()`);
  assert.equal(shown.hidden, false, 'nothing was said at all');
  assert.doesNotMatch(shown.text, /^Token not recognised/,
    'a correct token was reported as wrong because the limiter had refused it');
  assert.match(shown.text, /Too many attempts/);

  await page.goto(`${base}/#/records`);
});
