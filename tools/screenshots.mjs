/**
 * Capture the README screenshots from a running server.
 *
 *   node tools/screenshots.mjs --url http://127.0.0.1:8799 --token CPX99GZ7
 *
 * Point it at a demo instance, never at a live one. The images are committed
 * and pushed, so anything on screen is published: run tools/demo-data.mjs
 * against a scratch store and screenshot that.
 *
 * Drives headless Edge or Chrome over the DevTools protocol rather than
 * through a screenshot library, because the whole point of this repository is
 * that it installs nothing. Node 24 has a WebSocket client built in and the
 * browser is already on the machine, so there is nothing to add.
 *
 * Signs in by setting the cookie directly. There is no query-parameter login
 * and there should not be one — a token in a URL ends up in history, in logs
 * and in screenshots.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { findBrowser, launch, sleep } from './cdp.mjs';
import { join } from 'node:path';

const arg = (name, fallback) => {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 ? process.argv[i + 1] : fallback;
};

const BASE = arg('url', 'http://127.0.0.1:8799').replace(/\/$/, '');
const TOKEN = arg('token');
const OUT = arg('out', 'docs/screenshots');
const WIDTH = Number(arg('width', 1680));
const HEIGHT = Number(arg('height', 1020));

if (!TOKEN) {
  console.error('--token is required: a member token from the demo server banner');
  process.exit(1);
}

/*
  A guard, not a courtesy. Screenshotting the live server is the one mistake
  this tool could make that cannot be taken back once the images are pushed,
  and 8787 is the default the real one runs on.
*/
if (/:8787(\/|$)/.test(BASE) && !process.argv.includes('--yes-this-is-a-demo')) {
  console.error('that is the default port of a real server; start a demo instance instead');
  process.exit(1);
}

const exe = findBrowser();
if (!exe) {
  console.error('no Edge or Chrome found; add its path to BROWSERS in tools/cdp.mjs');
  process.exit(1);
}

/*
  The shots.

  `settle` is extra time after the view reports itself ready, for the views
  that keep moving afterwards — the map runs a force simulation and the
  timeline animates into its default zoom.

  `height` trims the frame to what the view actually fills. A short view
  photographed at full height is two thirds empty background, which reads as a
  broken page rather than a small case.

  `click` is a selector clicked before the capture, for the state that is worth
  showing but is not the default one. Only the plan needs it: every task is
  collapsed until you open it, so the default screenshot shows titles and none
  of what a task holds.
*/
const SHOTS = [
  { name: 'sessions', hash: '#/sessions' },
  { name: 'plan', hash: '#/plan', click: '[data-expand="DEM-p1-persist"]', height: 1180 },
  /*
    The matrix with a gap opened, because the two halves only make sense
    together: the grid says what the plan does not cover, and the panel says
    what the bank offers behind one of those gaps. clickSettle is longer than
    the default — the matrix is several hundred cells and the entry behind a
    cell is fetched.
  */
  {
    name: 'coverage', hash: '#/plan', height: 1220, clickSettle: 900,
    click: ['[data-mode="coverage"]', '.cov-cell.cov-none'],
  },
  { name: 'characterization', hash: '#/characterization', settle: 900 },
  { name: 'map', hash: '#/map', settle: 3500 },
  { name: 'timeline', hash: '#/timeline', height: 800 },
  { name: 'records', hash: '#/records', height: 700 },
  { name: 'comms', hash: '#/comms' },
];

// --- drive it ---------------------------------------------------------------

const page = await launch({ width: WIDTH, height: HEIGHT, exe });
const { send, once, evaluate, metrics, ready } = page;

await send('Network.setCookie', {
  name: 'hunt_token', value: TOKEN, domain: new URL(BASE).hostname, path: '/',
});

/* deviceScaleFactor 2: the images are read at full width in the README, and a
   1x capture of a dense table is unreadable there. */
const shotMetrics = (h) => send('Emulation.setDeviceMetricsOverride', {
  width: WIDTH, height: h, deviceScaleFactor: 2, mobile: false,
});
await shotMetrics(HEIGHT);

mkdirSync(OUT, { recursive: true });
const failures = [];

for (const shot of SHOTS) {
  /*
    Through about:blank each time. A hash change on the same document is a
    same-document navigation, so there is no load event to wait for and the
    capture races the render.
  */
  // Before navigating, so the view lays out at the height it is photographed
  // at rather than reflowing under the capture.
  await shotMetrics(shot.height ?? HEIGHT);

  await page.goto(`${BASE}/${shot.hash}`);

  const ok = await ready();
  if (!ok) failures.push(`${shot.name}: view never finished loading`);
  await sleep(shot.settle ?? 400);

  /*
    A missing selector is a failure, not a shrug. The whole reason for the
    click is that the default state does not show the thing worth showing, so
    silently photographing the default state is the one outcome to avoid.

    A list rather than one selector, because some states take more than one
    step to reach — the coverage matrix needs its mode chosen and then a cell
    opened, and photographing either half alone shows less than the view does.
    Each step is checked separately so a failure names the one that missed.
  */
  for (const sel of [shot.click ?? []].flat()) {
    const { result } = await send('Runtime.evaluate', {
      expression: `(() => {
        const el = document.querySelector(${JSON.stringify(sel)});
        if (!el) return false;
        el.click();
        return true;
      })()`,
      returnByValue: true,
    });
    if (result.value !== true) failures.push(`${shot.name}: nothing matched ${sel}`);
    await sleep(shot.clickSettle ?? 400);
  }

  // Console errors are worth knowing about in a screenshot run: a view that
  // half-rendered still photographs, and the image looks deliberate.
  const errs = await page.errors();
  if (errs.length) failures.push(`${shot.name}: ${errs.join(' | ')}`);

  const { data } = await send('Page.captureScreenshot', { format: 'png' });
  const file = join(OUT, `${shot.name}.png`);
  writeFileSync(file, Buffer.from(data, 'base64'));
  console.log(`  ${file}  ${(Buffer.from(data, 'base64').length / 1024).toFixed(0)} KB`);
}

page.close();

if (failures.length) {
  console.error('\n  problems:');
  for (const f of failures) console.error(`    ${f}`);
  process.exit(1);
}
console.log(`\n  ${SHOTS.length} screenshots in ${OUT}`);
