/**
 * Record a headless browser session to frames, over the DevTools protocol.
 *
 *   node tools/record-demo.mjs --reel --url http://127.0.0.1:8799 --token XXXXXXXX
 *   node tools/record-demo.mjs --tour --url ... --token ... --setup-url ... --setup-token ...
 *
 * Same argument as tools/screenshots.mjs: point it at a demo instance, never a
 * live one, because what is on screen ends up published. Start one with
 * tools/demo-data.mjs.
 *
 * The frames are written as JPEGs with the timestamps the browser reported, and
 * an ffmpeg concat script beside them, so the encode preserves the real timing
 * rather than assuming a frame rate. ffmpeg is the one thing here that is not
 * in the box; the command is printed at the end rather than run, so a machine
 * without it still produces the frames.
 *
 * A screencast needs a persistent event listener and an ack per frame, which is
 * the one thing tools/cdp.mjs (built for one-shot waits) does not do, so this
 * opens its own socket rather than bending that one out of shape.
 *
 * There is no cursor in a headless capture and no audio anywhere, so both are
 * drawn: a synthetic pointer that moves to whatever is about to be clicked, and
 * a caption bar. Neither is in the application — they are injected into the
 * page, and they are why a silent recording is followable at all.
 */
import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';

export const sleep = (ms) => new Promise(r => setTimeout(r, ms));

const BROWSERS = [
  '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/Applications/Chromium.app/Contents/MacOS/Chromium',
];
export const findBrowser = () => BROWSERS.find(p => existsSync(p)) ?? null;

/* Injected into every document: a caption bar, a synthetic cursor, and a
   click ripple. The recording has no pointer and no audio, so this is how a
   viewer sees where something was clicked and reads what is happening. */
const OVERLAY = String.raw`
(() => {
  /* Defined immediately and building their own DOM on first use: this runs at
     document-start, where waiting for a body would leave the helpers undefined
     for the first caption of every page. */
  let cap, cur, ring;
  const ensure = () => {
    if (cap && cap.isConnected) return true;
    if (!document.body) return false;
    const style = document.createElement('style');
    style.textContent = [
      '#__cap { position: fixed; left: 0; right: 0; bottom: 0; z-index: 2147483647;',
      '  font: 500 19px/1.45 -apple-system, "SF Pro Text", system-ui, sans-serif; color: #e9eef5;',
      '  background: linear-gradient(to top, rgba(6,9,14,.94), rgba(6,9,14,.80) 70%, rgba(6,9,14,0));',
      '  padding: 46px 40px 26px; opacity: 0; transition: opacity .35s ease; pointer-events: none;',
      '  text-shadow: 0 1px 3px rgba(0,0,0,.9); }',
      '#__cap.on { opacity: 1; }',
      '#__cap b { color: #4fd1c5; font-weight: 600; }',
      '#__cur { position: fixed; z-index: 2147483647; width: 22px; height: 22px; margin: -3px 0 0 -3px;',
      '  pointer-events: none; opacity: 0; transition: opacity .2s ease; }',
      '#__cur.on { opacity: 1; }',
      '#__cur svg { filter: drop-shadow(0 2px 4px rgba(0,0,0,.6)); }',
      '#__ring { position: fixed; z-index: 2147483646; width: 34px; height: 34px; margin: -17px 0 0 -17px;',
      '  border: 2.5px solid #4fd1c5; border-radius: 50%; pointer-events: none; opacity: 0; transform: scale(.35); }',
      '#__ring.go { animation: __pulse .5s ease-out; }',
      '@keyframes __pulse { 0% { opacity: .95; transform: scale(.35); } 100% { opacity: 0; transform: scale(1.5); } }',
    ].join('\n');
    document.head.appendChild(style);

    cap = document.createElement('div'); cap.id = '__cap';
    cur = document.createElement('div'); cur.id = '__cur';
    cur.innerHTML = '<svg viewBox="0 0 24 24" width="22" height="22">' +
      '<path d="M5 2l14 9-6.2 1.1L15 19l-2.6 1-2.3-6.6L5 17z" fill="#fff" stroke="#0b0f14" stroke-width="1.3"/></svg>';
    ring = document.createElement('div'); ring.id = '__ring';
    document.body.append(cap, cur, ring);
    return true;
  };

  window.__cap = (html) => {
    if (!ensure()) return;
    cap.innerHTML = html || '';
    cap.classList.toggle('on', Boolean(html));
  };
  window.__cursorTo = (x, y, ms) => {
    if (!ensure()) return;
    cur.classList.add('on');
    cur.style.transition = 'left ' + ms + 'ms cubic-bezier(.4,.05,.2,1), top ' + ms +
      'ms cubic-bezier(.4,.05,.2,1), opacity .2s';
    cur.style.left = x + 'px'; cur.style.top = y + 'px';
  };
  window.__cursorHide = () => { if (ensure()) cur.classList.remove('on'); };
  window.__ripple = (x, y) => {
    if (!ensure()) return;
    ring.style.left = x + 'px'; ring.style.top = y + 'px';
    ring.classList.remove('go'); void ring.offsetWidth; ring.classList.add('go');
  };
})();
`;

export async function open({ width = 1440, height = 900, outDir, exe = findBrowser() } = {}) {
  if (!exe) throw new Error('no Chrome or Edge found');
  rmSync(outDir, { recursive: true, force: true });
  mkdirSync(outDir, { recursive: true });

  const profile = join(outDir, 'profile');
  const browser = spawn(exe, [
    '--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`,
    `--window-size=${width},${height}`, '--hide-scrollbars', '--force-device-scale-factor=1',
    '--no-first-run', '--no-default-browser-check', '--disable-gpu',
    '--disable-features=Translate,MediaRouter', '--mute-audio',
    'about:blank',
  ], { stdio: ['ignore', 'pipe', 'pipe'] });

  const wsUrl = await new Promise((ok, fail) => {
    const t = setTimeout(() => fail(new Error('browser did not report a debugging port')), 20000);
    browser.stderr.on('data', (d) => {
      const m = /ws:\/\/[^\s]+/.exec(String(d));
      if (m) { clearTimeout(t); ok(m[0]); }
    });
    browser.on('exit', c => { clearTimeout(t); fail(new Error(`browser exited (${c})`)); });
  });

  const ws = new WebSocket(wsUrl);
  await new Promise((ok, fail) => {
    ws.addEventListener('open', ok, { once: true });
    ws.addEventListener('error', () => fail(new Error('could not attach')), { once: true });
  });

  let nextId = 0;
  const pending = new Map();
  const listeners = new Map();          // method -> Set(fn)
  ws.addEventListener('message', (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id !== undefined) {
      const p = pending.get(msg.id);
      if (!p) return;
      pending.delete(msg.id);
      if (msg.error) p.fail(new Error(`${p.method}: ${msg.error.message}`));
      else p.ok(msg.result);
      return;
    }
    for (const fn of listeners.get(msg.method) ?? []) fn(msg.params);
  });

  const raw = (method, params = {}, sid) => new Promise((ok, fail) => {
    const id = ++nextId;
    pending.set(id, { ok, fail, method });
    ws.send(JSON.stringify({ id, method, params, ...(sid ? { sessionId: sid } : {}) }));
  });
  const on = (method, fn) => {
    if (!listeners.has(method)) listeners.set(method, new Set());
    listeners.get(method).add(fn);
  };

  const { targetId } = await raw('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await raw('Target.attachToTarget', { targetId, flatten: true });
  const send = (method, params) => raw(method, params, sessionId);

  await send('Page.enable');
  await send('Runtime.enable');
  await send('Emulation.setDeviceMetricsOverride',
    { width, height, deviceScaleFactor: 1, mobile: false });
  await send('Page.addScriptToEvaluateOnNewDocument', { source: OVERLAY });

  const evaluate = async (expression) => {
    const r = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description ?? 'evaluate threw');
    return r.result?.value;
  };

  // --- recording ------------------------------------------------------------
  const frames = [];
  let recording = false;
  on('Page.screencastFrame', async (p) => {
    try { await send('Page.screencastFrameAck', { sessionId: p.sessionId }); } catch { /* closing */ }
    if (!recording) return;
    const n = String(frames.length).padStart(5, '0');
    const file = join(outDir, `f${n}.jpg`);
    writeFileSync(file, Buffer.from(p.data, 'base64'));
    frames.push({ file, t: p.metadata.timestamp });
  });

  const api = {
    send, evaluate, on, width, height, frames,
    async goto(url) {
      await send('Page.navigate', { url });
      await sleep(150);
    },
    async cookie(name, value, url) {
      await send('Network.enable');
      await send('Network.setCookie', { name, value, url, path: '/' });
    },
    async startRecording() {
      recording = true;
      await send('Page.startScreencast',
        { format: 'jpeg', quality: 92, maxWidth: width, maxHeight: height, everyNthFrame: 1 });
    },
    async stopRecording() {
      recording = false;
      try { await send('Page.stopScreencast'); } catch { /* already gone */ }
    },
    /** Caption, held for its own reading time unless told otherwise. */
    async caption(html, hold = 0) {
      await evaluate(`window.__cap(${JSON.stringify(html ?? '')})`);
      if (hold) await sleep(hold);
    },
    /** Move the synthetic cursor to an element and click it for real. */
    async click(selector, { settle = 700, move = 550 } = {}) {
      const box = await evaluate(`(() => {
        const el = document.querySelector(${JSON.stringify(selector)});
        if (!el) return null;
        el.scrollIntoView({ block: 'center', behavior: 'instant' });
        const r = el.getBoundingClientRect();
        return { x: Math.round(r.left + r.width / 2), y: Math.round(r.top + r.height / 2) };
      })()`);
      if (!box) throw new Error(`no element for ${selector}`);
      await evaluate(`window.__cursorTo(${box.x}, ${box.y}, ${move})`);
      await sleep(move + 120);
      await evaluate(`window.__ripple(${box.x}, ${box.y})`);
      await sleep(120);
      await evaluate(`document.querySelector(${JSON.stringify(selector)}).click()`);
      await sleep(settle);
    },
    /** Type into a field the way a person does, so the video shows it arrive. */
    async type(selector, text, { perChar = 26, settle = 400 } = {}) {
      const box = await evaluate(`(() => {
        const el = document.querySelector(${JSON.stringify(selector)});
        if (!el) return null;
        el.scrollIntoView({ block: 'center', behavior: 'instant' });
        el.focus();
        const r = el.getBoundingClientRect();
        return { x: Math.round(r.left + 24), y: Math.round(r.top + r.height / 2) };
      })()`);
      if (box) { await evaluate(`window.__cursorTo(${box.x}, ${box.y}, 380)`); await sleep(420); }
      for (const ch of text) {
        if (ch === '\n') {
          // A newline is a key, not a character: dispatched as text it is
          // swallowed and the next line runs on from the last one.
          await send('Input.dispatchKeyEvent',
            { type: 'keyDown', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, text: '\r' });
          await send('Input.dispatchKeyEvent',
            { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 });
        } else {
          await send('Input.dispatchKeyEvent', { type: 'keyDown', text: ch });
          await send('Input.dispatchKeyEvent', { type: 'keyUp' });
        }
        await sleep(perChar);
      }
      await sleep(settle);
    },
    async hide() { await evaluate('window.__cursorHide()'); },
    async close() {
      try { await api.stopRecording(); } catch { /* fine */ }
      try { ws.close(); } catch { /* fine */ }
      browser.kill('SIGTERM');
      setTimeout(() => browser.kill('SIGKILL'), 1500).unref();
    },
  };
  return api;
}

/** Frames plus their timestamps into an ffmpeg concat script. */
export function concatScript(frames) {
  const lines = [];
  for (let i = 0; i < frames.length; i++) {
    const next = frames[i + 1];
    const dur = next ? Math.max(0.016, next.t - frames[i].t) : 0.6;
    lines.push(`file '${frames[i].file}'`, `duration ${dur.toFixed(4)}`);
  }
  if (frames.length) lines.push(`file '${frames.at(-1).file}'`);
  return lines.join('\n') + '\n';
}


/* ------------------------------------------------------------------------- *
 * The two recordings.
 *
 * Kept in this file rather than as separate scripts because they share every
 * helper above and neither is long. What they are NOT is a test: a step that
 * cannot find its selector throws, and the frames captured up to that point are
 * still written, so a broken take is diagnosed by watching it.
 * ------------------------------------------------------------------------- */

const arg = (n, d) => {
  const i = process.argv.indexOf(`--${n}`);
  return i > -1 ? process.argv[i + 1] : d;
};

/** Wait on the application rather than on a guess about how fast it is. */
async function waitFor(page, selector, ms = 20000) {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    if (await page.evaluate(`Boolean(document.querySelector(${JSON.stringify(selector)}))`)) return true;
    await sleep(150);
  }
  throw new Error(`never appeared: ${selector}`);
}

const TITLE = (main, sub) => `document.body.innerHTML = ${JSON.stringify(
  `<div style="height:100vh;display:grid;place-items:center;background:#0b0f14;color:#e9eef5;`
  + `font:600 52px -apple-system,system-ui;letter-spacing:-1px;text-align:center;line-height:1.3">`
  + `${main}<div style="font:400 20px -apple-system,system-ui;color:#8b98a8;margin-top:16px;`
  + `letter-spacing:0">${sub}</div></div>`)}`;

/** The long one: the wizard on a fresh instance, then every view on a full one. */
async function tour(page, { setupUrl, setupToken, demoUrl, demoToken, live }) {
  const cap = (t, hold = 0) => page.caption(t, hold);
  const SETUP = setupUrl, SETUP_TOKEN = setupToken, DEMO = demoUrl, DEMO_TOKEN = demoToken;
  const LIVE = live;
  const route = async (name, settle = 1400) => {
    await page.click(`#nav a[data-route="${name}"]`, { settle: 300 });
    await sleep(settle);
  };

  // ---------------------------------------------------------------- title
  await page.goto(`${SETUP}/login`);
  await sleep(600);
  await page.startRecording();
  await page.evaluate(`document.body.innerHTML = '<div style="height:100vh;display:grid;' +
    'place-items:center;background:#0b0f14;color:#e9eef5;font:600 60px -apple-system,system-ui;' +
    'letter-spacing:-1px">Psephos<div style="font:400 21px -apple-system,system-ui;color:#8b98a8;' +
    'margin-top:14px;letter-spacing:0">a hunt workspace where nothing becomes a finding ' +
    'until a person says so</div></div>'`);
  await sleep(2600);

  // ---------------------------------------------------------------- setup
  await cap('A fresh clone has no mission, so the server comes up in <b>setup</b> and refuses to guess.');
  await page.goto(`${SETUP}/`);
  await page.cookie('hunt_token', SETUP_TOKEN, SETUP);
  await page.goto(`${SETUP}/`);
  await waitFor(page, '.wiz-rail');
  await sleep(1200);

  await cap('Six steps. First: which model runs the turns — and it is checked for real before it is saved.', 2600);
  await page.click('.wiz-card', { settle: 500 });
  await page.click('[data-act="model"]', { settle: 600 });
  await waitFor(page, '[data-act="mission"]', 60000);
  await sleep(900);

  await cap('The engagement. A gitignored folder is created for it under <b>missions/</b>.', 2000);
  await page.type('[data-f="name"]', 'Northern Watch 27-1', { perChar: 45 });
  await page.type('[data-f="week"]', 'Week 2 — Linux and OT', { perChar: 45 });
  await page.click('[data-act="mission"]', { settle: 900 });
  await waitFor(page, '[data-act="briefing"]');

  await cap('What the model must not assume. This is the difference between "no evidence found" '
    + 'and "no telemetry exists to find it".', 2600);
  await page.type('[data-f="briefing"]',
    '4625 is not collected on the Linux estate.\nEndpoint sensors landed 14 Aug; silence before that means nothing.',
    { perChar: 22 });
  await page.click('[data-act="briefing"]', { settle: 900 });
  await waitFor(page, '[data-act="roster"]');

  await cap('The team. Each person gets their own token and their own chat window — '
    + 'so the token says who you are and nobody types a name.', 2800);
  const roster = [
    ['Reyes', 'Mission Commander', 'Command'],
    ['Okafor', 'Mission Element Lead', 'Bravo'],
    ['Lindqvist', 'Host Analyst', 'Bravo'],
  ];
  for (let i = 0; i < roster.length; i++) {
    if (i) await page.click('[data-act="addrow"]', { settle: 250 });
    const [n, r, t] = roster[i];
    await page.type(`tr:nth-child(${i + 1}) [data-f="name"]`, n, { perChar: 34, settle: 120 });
    await page.type(`tr:nth-child(${i + 1}) [data-f="role"]`, r, { perChar: 20, settle: 120 });
    await page.type(`tr:nth-child(${i + 1}) [data-f="team"]`, t, { perChar: 34, settle: 120 });
  }
  await page.click('[data-act="roster"]', { settle: 900 });
  await waitFor(page, '[data-act="noterrain"]');

  await cap('Terrain is the estate you were given. Paste an inventory and the model structures it, '
    + 'or start with none and let evidence name the hosts.', 3000);
  await page.click('[data-act="noterrain"]', { settle: 1200 });
  await waitFor(page, '[data-act="planexample"]', 30000);

  await cap('And a hunt plan to start from.', 1800);
  await page.click('[data-act="planexample"]', { settle: 1500 });
  await sleep(2600);
  await cap('Set up. Every token is printed to the console the server was started from, never to a browser.', 3000);

  // ---------------------------------------------------------------- the app
  await cap('Here is one already in progress.', 1800);
  await page.goto(`${DEMO}/login`);
  await page.cookie('hunt_token', DEMO_TOKEN, DEMO);
  await page.goto(`${DEMO}/#/sessions`);
  await waitFor(page, '#view .transcript', 20000);
  await sleep(1600);

  await cap('One persistent window per analyst. The roster <b>is</b> the session list, '
    + 'so there is never a question about whose window is whose.', 3200);
  await sleep(600);

  if (LIVE) {
    await cap('Evidence goes in as you found it — paste the log, say what you see.', 2400);
    await page.type('#ta',
      'Two Bravo workstations show the same scheduled task, created 40 seconds apart:\n'
      + 'RL-04  \\Microsoft\\Windows\\UpdateOrchestrator\\Reboot  runs powershell -enc\n'
      + 'RL-06  \\Microsoft\\Windows\\UpdateOrchestrator\\Reboot  same command line\n'
      + 'Neither host has the entry in the 26 Aug baseline.',
      { perChar: 11, settle: 700 });
    await cap('This is a real turn against the Claude CLI. Watch the reply arrive.', 1800);
    await page.click('#cf .primary', { settle: 400 });
    await cap('The model reads the case file it is given — every record already collected, '
      + 'the terrain, the baselines — and answers against it.');
    // The turn is real, so this waits on it rather than on a guess.
    const until = Date.now() + 180000;
    let saw = false;
    while (Date.now() < until) {
      saw = await page.evaluate(
        `Boolean(document.querySelector('#view .composer .primary:not([disabled])'))`);
      if (saw) break;
      await sleep(500);
    }
    await sleep(2500);
    await cap('Anything it wants in the case file it must <b>propose</b> through a typed tool. '
      + 'A proposal is a candidate, never a record.', 3400);
  }

  await cap('Proposals land in the pending rail. Confirm or deny is a person\'s act, '
    + 'and each one writes an audit row saying who decided.', 3400);
  await page.evaluate(`document.querySelector('#view .rail, #view .pending, #view aside')
    ?.scrollIntoView({ block: 'start', behavior: 'smooth' })`);
  await sleep(900);

  // ---------------------------------------------------------------- records
  await cap('');
  await route('records');
  await cap('Every finding, searched on the server rather than in the browser — '
    + 'so the answer is computed over the whole case file, not over what happened to load.', 3200);
  await page.type('#q', 'log-sync', { perChar: 60, settle: 1600 });
  await cap('Open one and you get its whole trail: the fields, the artifact it came from, '
    + 'and every decision anybody made about it.', 3000);
  await page.click('#view tbody tr:first-child', { settle: 1600 });
  await sleep(2200);
  await page.evaluate(`document.querySelector('#drawer')?.scrollTo({ top: 420, behavior: 'smooth' })`);
  await sleep(2000);
  // Escape closes it, and the filter goes back to empty — everything after this
  // reads the same query, and a stale one would quietly empty the next view.
  await page.send('Input.dispatchKeyEvent',
    { type: 'keyDown', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27 });
  await page.send('Input.dispatchKeyEvent',
    { type: 'keyUp', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27 });
  await sleep(600);
  await page.evaluate(`(() => {
    const q = document.querySelector('#view #q');
    if (!q) return;
    q.value = '';
    q.dispatchEvent(new Event('input', { bubbles: true }));
  })()`);
  await sleep(1200);

  // ---------------------------------------------------------------- map
  await cap('');
  await route('map', 3200);
  await cap('The estate, clustered by enclave. Fill is evidence and verdict; the outline is presence — '
    + 'whether the host answered at all.', 3600);
  await sleep(1200);
  await cap('The intrusion path is drawn from the findings themselves, not from anybody\'s diagram.', 3200);
  await sleep(1000);

  // ---------------------------------------------------------------- timeline
  await cap('');
  await route('timeline', 2600);
  await cap('The same evidence in time. Filled marks are adjudicated, hollow are pending, '
    + 'and the purple arcs are causality somebody confirmed.', 3600);
  await sleep(1400);

  // ---------------------------------------------------------------- characterization
  await cap('');
  await route('characterization', 2600);
  await cap('What normal looks like, so a finding has something to be judged against. '
    + 'An unfamiliar process on one host of eighty is worth a look; on all eighty it is inventory.', 4000);
  await sleep(1200);
  await cap('Nineteen repositories, each diffed against the last collection — and the gaps are '
    + 'recorded as gaps, so a field nobody collected never reads as a field with nothing in it.', 4000);
  await sleep(1200);

  // ---------------------------------------------------------------- plan
  await cap('');
  await route('plan', 2200);
  await cap('The hunt plan. The file is the authority and the database is rebuilt from it at every '
    + 'start, so a week of team edits cannot be lost to a restart.', 3600);
  await page.click('#view [data-expand]', { settle: 1800 });
  await cap('Procedure, expected evidence, who it is assigned to, and its own history.', 3000);
  await sleep(800);

  await cap('And the same plan against ATT&CK — coloured by what it <b>intends</b>, '
    + 'which is a different question from what was found.', 3200);
  await page.click('#view [data-mode="coverage"]', { settle: 2600 });
  await sleep(1400);
  await cap('Three states, not two: unnamed, named by a task with nothing written under it, '
    + 'and named by a task that carries steps. Forty stubs look thorough in a list.', 4000);
  await page.click('#view .cov-cell.cov-none', { settle: 2200 });
  await cap('A gap opens the bank entry behind it — 794 techniques to draw from, '
    + 'and what backs each entry is stamped on it.', 3600);
  await sleep(1200);

  // ---------------------------------------------------------------- comms
  await cap('');
  await route('comms', 2400);
  await cap('And a place for the team to talk that is not the model. '
    + 'Direct messages are the one thing here that is private.', 3400);
  await sleep(1600);

  // ---------------------------------------------------------------- close
  await cap('');
  await sleep(600);
  await page.evaluate(`document.body.innerHTML = '<div style="height:100vh;display:grid;' +
    'place-items:center;background:#0b0f14;color:#e9eef5;font:600 46px -apple-system,system-ui;' +
    'letter-spacing:-1px;text-align:center">Nothing here becomes a finding<br>until a person ' +
    'decides it has.<div style="font:400 20px ui-monospace,monospace;color:#4fd1c5;margin-top:26px">' +
    'github.com/japatton/psephos</div></div>'`);
  await sleep(3400);
}

/** The short one: ninety seconds for a README, with no live turn in it. */
async function reel(page, { url, token }) {
  const cap = (t, hold = 0) => page.caption(t, hold);
  const URL_ = url, TOKEN = token;
  const route = async (name, settle = 1200) => {
    await page.click(`#nav a[data-route="${name}"]`, { settle: 300 });
    await sleep(settle);
  };
  const card = (html) => page.evaluate(`document.body.innerHTML = ${JSON.stringify(html)}`);

  await page.goto(`${URL_}/login`);
  await page.cookie('hunt_token', TOKEN, URL_);
  await sleep(500);
  await page.startRecording();

  await card('<div style="height:100vh;display:grid;place-items:center;background:#0b0f14;'
    + 'color:#e9eef5;font:600 58px -apple-system,system-ui;letter-spacing:-1px;text-align:center">'
    + 'Psephos<div style="font:400 20px -apple-system,system-ui;color:#8b98a8;margin-top:14px;'
    + 'letter-spacing:0">a hunt workspace where nothing becomes a finding until a person says so</div></div>');
  await sleep(2800);

  // 1. the session
  await page.goto(`${URL_}/#/sessions`);
  await waitFor(page, '#view .transcript');
  await sleep(1400);
  await cap('You work evidence with a model. It proposes findings through typed tools — '
    + 'never straight into the case file.', 4200);

  // 2. the act that matters
  await cap('Every proposal is a candidate until a person confirms it.', 2600);
  await page.click('#view .cand .ok', { settle: 1800 });
  await cap('That is one audit row: who decided, when, and what it looked like before.', 3000);

  // 3. records
  await cap('');
  await route('records', 1400);
  await cap('The case file. Searched on the server, exported as a workbook, an ATT&CK layer, '
    + 'IOCs, or the report itself.', 4000);
  await sleep(600);

  // 4. map
  await cap('');
  await route('map', 3000);
  await cap('The estate, clustered by enclave — fill is evidence and verdict, outline is whether '
    + 'the host answered at all.', 4200);
  await sleep(800);

  // 5. timeline
  await cap('');
  await route('timeline', 2200);
  await cap('The same findings in time, with confirmed causality drawn between them.', 3400);

  // 6. characterization
  await cap('');
  await route('characterization', 2200);
  await cap('And what normal looked like first — so "unusual" is a measurement, not an impression.', 3800);

  // 7. coverage
  await cap('');
  await route('plan', 1600);
  await page.click('#view [data-mode="coverage"]', { settle: 2400 });
  await cap('The plan against ATT&CK: what it intends to hunt, which is not what it found.', 3600);
  await page.click('#view .cov-cell.cov-none', { settle: 2000 });
  await cap('Every gap opens a bank entry you can draw straight into the plan.', 3200);

  await cap('');
  await sleep(400);
  await card('<div style="height:100vh;display:grid;place-items:center;background:#0b0f14;'
    + 'color:#e9eef5;font:600 40px -apple-system,system-ui;letter-spacing:-.5px;text-align:center;'
    + 'line-height:1.35">No dependencies. No build step.<br>Node 24 and your own machine.'
    + '<div style="font:400 19px ui-monospace,monospace;color:#4fd1c5;margin-top:28px">'
    + 'github.com/japatton/psephos</div></div>');
  await sleep(3200);
}

// --- drive it ---------------------------------------------------------------

const WHICH = process.argv.includes('--tour') ? 'tour'
  : process.argv.includes('--reel') ? 'reel' : null;
if (!WHICH) {
  console.error('pick one: --reel or --tour');
  process.exit(1);
}
const url = arg('url');
const token = arg('token');
if (!url || !token) {
  console.error('--url and --token are required (a member token from the demo banner)');
  process.exit(1);
}
/*
  The same guard tools/screenshots.mjs carries, for the same reason: 8787 is the
  port a real server runs on, and a recording of one cannot be taken back.
*/
if (/:8787(\/|$)/.test(url) && !process.argv.includes('--yes-this-is-a-demo')) {
  console.error('that is the default port of a real server; start a demo instance instead');
  process.exit(1);
}

const out = arg('out', `frames-${WHICH}`);
const page = await open({ outDir: out, width: 1440, height: 900 });
try {
  if (WHICH === 'reel') await reel(page, { url, token });
  else {
    await tour(page, {
      setupUrl: arg('setup-url'), setupToken: arg('setup-token'),
      demoUrl: url, demoToken: token,
      live: !process.argv.includes('--no-live'),
    });
  }
} catch (e) {
  console.error(`the take failed at: ${e.message}`);
  console.error('the frames up to that point are still written — watch them to see where it went wrong');
  process.exitCode = 1;
} finally {
  await page.stopRecording();
  writeFileSync(join(out, 'concat.txt'), concatScript(page.frames));
  console.log(`${page.frames.length} frames in ${out}`);
  console.log('encode with:');
  console.log(`  ffmpeg -y -f concat -safe 0 -i ${out}/concat.txt \\`);
  console.log(`    -vf "fps=30,format=yuv420p" -c:v libx264 -crf 21 -movflags +faststart ${WHICH}.mp4`);
  await page.close();
}
