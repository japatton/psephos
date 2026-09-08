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
      '#__cap b { color: #2de2ff; font-weight: 600; }',
      '#__cur { position: fixed; z-index: 2147483647; width: 22px; height: 22px; margin: -3px 0 0 -3px;',
      '  pointer-events: none; opacity: 0; transition: opacity .2s ease; }',
      '#__cur.on { opacity: 1; }',
      '#__cur svg { filter: drop-shadow(0 2px 4px rgba(0,0,0,.6)); }',
      '#__ring { position: fixed; z-index: 2147483646; width: 34px; height: 34px; margin: -17px 0 0 -17px;',
      '  border: 2.5px solid #2de2ff; border-radius: 50%; pointer-events: none; opacity: 0; transform: scale(.35); }',
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


/* ------------------------------------------------------------------------- *
 * The cards.
 *
 * Rendered by replacing the document, so they cut to and from the application
 * with no seam: same ground as --bg, which is #05070d rather than black
 * because saturated neon on true black halates (theme.css says why at length).
 *
 * The shield from web/mark.png, never docs/logo.png — that one carries a
 * strapline in a register this project spends its whole README refusing.
 * ------------------------------------------------------------------------- */

const OPENING = `
<style>
  #card{height:100vh;display:grid;place-content:center;justify-items:center;gap:22px;
    background:#05070d;color:#e6f3ff;font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
    text-align:center;overflow:hidden}
  #card img{height:132px;width:auto;animation:in .35s ease-out both}
  .word{position:relative;height:72px;width:420px}
  .word i{position:absolute;inset:0;display:block;font-style:normal;font-size:66px;line-height:72px;
    color:#e6f3ff;font-family:"Times New Roman",Palatino,"Noto Serif",serif;
    animation:in .35s ease-out .06s both, drop .32s ease-in 1500ms forwards}
  .word b{position:absolute;inset:0;display:block;font-size:52px;line-height:72px;font-weight:700;
    letter-spacing:.06em;background:linear-gradient(100deg,#2de2ff 10%,#ff2d95 90%);
    -webkit-background-clip:text;background-clip:text;color:transparent;
    -webkit-text-fill-color:transparent;opacity:0;animation:land .38s ease-out 1720ms forwards}
  .rule{width:420px;height:1px;transform:scaleX(0);
    background:linear-gradient(90deg,transparent,rgba(45,226,255,.55) 25%,rgba(255,45,149,.55) 75%,transparent);
    animation:rule .36s ease-out 2100ms forwards}
  .sub{max-width:44ch;color:#7f93ad;font-size:19px;line-height:1.45;opacity:0;
    animation:land .4s ease-out 2350ms forwards}
  @keyframes in{from{opacity:0;transform:translateY(6px)}}
  @keyframes drop{to{opacity:0;transform:translateY(.35em)}}
  @keyframes land{from{opacity:0;transform:translateY(-.3em)}to{opacity:1;transform:none}}
  @keyframes rule{to{transform:scaleX(1)}}
</style>
<div id="card">
  <img src="/mark.png" alt="">
  <div class="word"><i>&#968;&#8134;&#966;&#959;&#962;</i><b>PSEPHOS</b></div>
  <div class="rule"></div>
  <p class="sub">A workspace for threat-hunt teams. The name is the pebble an Athenian juror
  dropped into the urn to cast a verdict.</p>
</div>`;

const CLOSING = `
<style>
  #end{height:100vh;display:grid;place-content:center;justify-items:center;gap:26px;background:#05070d;
    color:#e6f3ff;font:16px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;text-align:center}
  #end h1{margin:0;font-size:44px;font-weight:600;letter-spacing:-.5px;line-height:1.25;max-width:22ch;
    animation:in .4s ease-out both}
  #end h1 b{font-weight:600;color:#2de2ff}
  #end .url{font:500 21px ui-monospace,SFMono-Regular,Consolas,monospace;color:#2de2ff;opacity:0;
    animation:in .4s ease-out .9s forwards}
  #end .rule{width:360px;height:1px;
    background:linear-gradient(90deg,transparent,rgba(45,226,255,.55) 25%,rgba(255,45,149,.55) 75%,transparent)}
  #end .foot{color:#56667e;font-size:14px;letter-spacing:.02em;opacity:0;animation:in .4s ease-out 1.4s forwards}
  @keyframes in{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
</style>
<div id="end">
  <h1>Nothing here becomes a finding<br>until <b>a person</b> decides it has.</h1>
  <div class="rule"></div>
  <div class="url">github.com/japatton/psephos</div>
  <div class="foot">Node 24 &middot; no dependencies &middot; no build step &middot; Apache-2.0</div>
</div>`;

/* The cut from the wizard's "NW-27-1 is live" to a populated estate would
   otherwise read as the wizard having produced it, which is false. */
const MIDROLL = `
<style>
  #mid{height:100vh;display:grid;place-content:center;justify-items:center;gap:14px;background:#05070d;
    color:#e6f3ff;font:16px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;text-align:center}
  #mid h1{margin:0;font-size:34px;font-weight:600;letter-spacing:-.4px}
  #mid p{margin:0;color:#7f93ad;font-size:19px;max-width:40ch;line-height:1.45}
</style>
<div id="mid">
  <h1>A different instance, mid-hunt.</h1>
  <p>Synthetic exercise data on documentation addresses. Every host, name and record is invented.</p>
</div>`;

const card = (page, html) => page.evaluate(`document.body.innerHTML = ${JSON.stringify(html)}`);

/** The pending cards on screen, so a caption never claims one that is not there. */
const pendingCount = (page) =>
  page.evaluate(`document.querySelectorAll('#view .cand').length`);

/**
 * Captions that run while something slow happens.
 *
 * The model check and a real turn are both up to a minute of a spinner, and
 * the rough cut covered each with one line and dead air. Every line here is
 * true whatever the reply turns out to be, so none of them is a promise the
 * footage has to keep. When `done()` goes true the caption in flight finishes
 * and the rest are dropped.
 */
async function fill(page, lines, done) {
  for (const [text, hold] of lines) {
    await page.caption(text, hold);
    if (await done()) return true;
  }
  while (!(await done())) await sleep(500);
  return true;
}

/* ------------------------------------------------------------------------- *
 * The short one: about seventy-five seconds, for the top of the README.
 *
 * The first eight seconds decide whether a stranger watches the rest, so the
 * card states what the thing is and the first shot is the product's whole
 * argument: a model proposal sitting in a rail, not in the case file.
 * ------------------------------------------------------------------------- */
async function reel(page, { url, token }) {
  const cap = (t, hold = 0) => page.caption(t, hold);
  const route = async (name, settle = 1200) => {
    await page.click(`#nav a[data-route="${name}"]`, { settle: 300 });
    await sleep(settle);
  };

  await page.goto(`${url}/login`);
  await page.cookie('hunt_token', token, url);
  await sleep(400);
  await page.startRecording();

  await card(page, OPENING);
  await sleep(4200);

  await page.goto(`${url}/#/sessions`);
  await waitFor(page, '#view .transcript');
  await sleep(1600);                                   // read the screen first
  await cap('Evidence goes in as it was found. The model reads it against the whole case '
    + 'file and answers.', 3400);
  await cap('Anything it wants recorded lands on the right as a <b>candidate</b>. It has not '
    + 'entered the case file, and nothing the model can do puts it there.', 4200);

  await cap('Filing it is a person\'s act.', 1600);
  await page.click('#view .cand .ok', { settle: 300 });
  await cap('', 1500);

  await route('records', 1200);
  await page.type('#q', 'ntdsutil', { perChar: 55, settle: 1200 });
  await page.click('#view tbody tr:first-child', { settle: 1400 });
  await page.evaluate(`document.querySelector('#drawer')?.scrollTo({ top: 99999, behavior: 'smooth' })`);
  await sleep(900);
  await cap('The record now carries who confirmed it and when. Every verdict here writes one '
    + 'such row, and no tool the model has can write one.', 4400);

  await page.send('Input.dispatchKeyEvent',
    { type: 'keyDown', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27 });
  await page.send('Input.dispatchKeyEvent',
    { type: 'keyUp', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27 });
  await page.evaluate(`(() => {
    const q = document.querySelector('#view #q');
    if (!q) return;
    q.value = '';
    q.dispatchEvent(new Event('input', { bubbles: true }));
  })()`);
  await sleep(1400);
  await cap('The case file. Denied is kept, not deleted: that the evidence showed nothing is '
    + 'still a judgement, and a later reader needs it.', 4000);

  await cap('');
  await route('map', 3000);                            // the force layout settles first
  await sleep(1200);
  await cap('Fill is the verdict; the outline is whether the address answered — two questions '
    + 'the map will not merge.', 4400);
  await cap('The path is drawn from the records, never stored. Deny a record and its edge goes '
    + 'with it.', 3200);

  await cap('');
  await route('timeline', 2200);
  await cap('The same records in time. Filled marks are adjudicated, hollow are still waiting. '
    + 'The arcs are causality somebody confirmed.', 4400);

  await cap('');
  await route('characterization', 1800);
  await page.click('[data-repo="scheduled-tasks"]', { settle: 1600 });
  await cap('What normal looked like first. Three cron entries across six hosts, and a fourth '
    + 'on one of them. <b>1 of 6</b> is the finding; on 6 of 6 it would be inventory.', 4600);

  await cap('');
  await route('plan', 1400);
  await page.click('#view [data-mode="coverage"]', { settle: 2400 });
  await cap('The plan against ATT&CK, coloured by what it <b>intends</b> to look for — a '
    + 'different question from what was found.', 3600);
  await page.click('#view .cov-cell.cov-none', { settle: 2000 });
  await cap('A gap opens its bank entry. This one has no authored task, and the panel says so '
    + 'rather than dressing MITRE\'s own text as tradecraft.', 4000);

  await cap('');
  await sleep(400);
  await card(page, CLOSING);
  await sleep(5000);
}

/* ------------------------------------------------------------------------- *
 * The long one: the wizard walked on an empty instance, then the whole
 * application on a populated one, with a real turn filmed as it happens.
 * ------------------------------------------------------------------------- */
async function tour(page, { setupUrl, setupToken, demoUrl, demoToken, live }) {
  const cap = (t, hold = 0) => page.caption(t, hold);
  const route = async (name, settle = 1400) => {
    await page.click(`#nav a[data-route="${name}"]`, { settle: 300 });
    await sleep(settle);
  };

  await page.goto(`${setupUrl}/login`);
  await sleep(500);
  await page.startRecording();
  await card(page, OPENING);
  await sleep(4200);

  // --- the wizard ----------------------------------------------------------
  await page.cookie('hunt_token', setupToken, setupUrl);
  await page.goto(`${setupUrl}/`);
  await waitFor(page, '.wiz-rail');
  await sleep(1000);
  await cap('A fresh clone has no mission, so the server comes up in <b>setup</b> and will not '
    + 'guess. A guess against the wrong terrain takes hosts off the map along with every '
    + 'verdict recorded against them.', 5000);

  await cap('First: which model runs the turns. The CLI keeps its own login, so this '
    + 'application never holds a credential.', 3600);
  await page.click('.wiz-card', { settle: 400 });
  await page.click('[data-act="model"]', { settle: 200 });
  /* The probe is a real call and can take a minute. */
  await fill(page, [
    ['It is checked for real before it is saved: a backend that cannot answer now will not '
      + 'start answering at the first piece of evidence.', 4200],
    ['The other two options take a key and, for anything speaking the OpenAI chat API, a base '
      + 'URL — a local endpoint keeps the case file on your own hardware.', 5000],
    ['The key is written owner-only, read by one function no route calls, and never returned '
      + 'to a browser.', 4000],
    ['Checking.', 2500],
  ], async () => page.evaluate(`Boolean(document.querySelector('[data-act="mission"]'))`));
  await sleep(600);

  await cap('The engagement. Its name goes into the header and into every prompt; the profile '
    + 'is written to a gitignored folder under <b>missions/</b>, because a network map is not '
    + 'source.', 1000);
  await page.type('[data-f="name"]', 'Northern Watch 27-1', { perChar: 40 });
  await page.type('[data-f="week"]', 'Week 2 — Linux and OT', { perChar: 40 });
  await page.click('[data-act="mission"]', { settle: 800 });
  await waitFor(page, '[data-act="briefing"]');

  await cap('What the model must not assume. One line each, sent with every turn.', 2400);
  await page.type('[data-f="briefing"]',
    '4625 is not collected on the Linux estate.\n'
    + 'Endpoint sensors landed 14 Aug; silence before that means nothing.', { perChar: 20 });
  await cap('This is the difference between "no evidence found" and "no telemetry exists to '
    + 'find it".', 3000);
  await page.click('[data-act="briefing"]', { settle: 800 });
  await waitFor(page, '[data-act="roster"]');

  await cap('The team, in chain-of-command order. Each person gets a token and their own '
    + 'window; the token says who you are, so nobody types a name and nobody types the wrong '
    + 'one.', 1200);
  const roster = [
    ['Reyes', 'Mission Commander', 'Command'],
    ['Okafor', 'Mission Element Lead', 'Bravo'],
    ['Lindqvist', 'Host Analyst', 'Bravo'],
  ];
  for (let i = 0; i < roster.length; i++) {
    if (i) await page.click('[data-act="addrow"]', { settle: 220 });
    const [n, r, t] = roster[i];
    await page.type(`tr:nth-child(${i + 1}) [data-f="name"]`, n, { perChar: 22, settle: 100 });
    await page.type(`tr:nth-child(${i + 1}) [data-f="role"]`, r, { perChar: 18, settle: 100 });
    await page.type(`tr:nth-child(${i + 1}) [data-f="team"]`, t, { perChar: 22, settle: 100 });
  }
  await page.click('[data-act="roster"]', { settle: 800 });
  await waitFor(page, '[data-act="noterrain"]');

  await cap('Terrain is the estate you were given. Paste whatever the inventory actually is '
    + 'and the model structures it — or start with none, and let evidence name the hosts.', 4400);
  await page.click('[data-act="noterrain"]', { settle: 1200 });
  await waitFor(page, '[data-act="planexample"]', 30000);

  await cap('And a plan to start from. It is edited in the app all week; this is only where it '
    + 'begins.', 3000);
  await page.click('[data-act="planexample"]', { settle: 1500 });
  await sleep(2600);                                   // the done screen says it itself
  await cap('Every token is printed to the console the server was started from — never to a '
    + 'browser, and not recoverable from one.', 3600);

  await cap('');
  await card(page, MIDROLL);
  await sleep(2800);

  // --- the populated instance ----------------------------------------------
  await page.goto(`${demoUrl}/login`);
  await page.cookie('hunt_token', demoToken, demoUrl);
  await page.goto(`${demoUrl}/#/sessions`);
  await waitFor(page, '#view .transcript', 20000);
  await sleep(1800);
  await cap('One persistent window per analyst. The roster <b>is</b> the session list, and '
    + 'everyone can read every window — review across the team is the point.', 4400);

  if (live) {
    const before = await pendingCount(page);
    await cap('Evidence goes in as it was found. This continues the exchange above — the reply '
      + 'asked for the file\'s timestamp and the shape of the egress.', 1200);
    await page.type('#ta',
      'stat on /etc/cron.d/log-sync: modified 2026-03-11 22:38:51Z. svc_deploy\'s ssh login '
      + 'from 192.0.2.12 was 22:02:10Z, and nothing else under /etc/cron.d changed that day.\n'
      + 'Egress from RL-03 to 203.0.113.200:8443 since 22:45: a POST every 15 minutes, '
      + '2.8-3.4 MB each.', { perChar: 11, settle: 600 });

    await cap('This is a real turn against the Claude CLI, in real time. It usually takes a '
      + 'minute or so.', 2600);
    await page.click('#cf .primary', { settle: 300 });

    /*
      The wait is the most informative minute in the recording, so it is spent
      on what the model was and was not given rather than on a spinner.
    */
    await fill(page, [
      ['What it was given: the evidence above, every record already in the case file, the '
        + 'terrain, the baselines, and the briefing.', 4200],
      ['What it was not given: a shell, the filesystem, the network, or any tool of your own. '
        + 'The subprocess starts with zero tools and gains six.', 4800],
      ['Six. Propose a finding. Propose a link. Query the terrain. Search the records. Stage '
        + 'baseline rows. Ask what normal looks like.', 4600],
      ['None of them files anything. A proposed finding is written as <b>pending</b> and '
        + 'waits.', 3400],
      ['The other channel on the composer, Research, takes the two writing tools away for the '
        + 'turn — so a question cannot become a record because the model decided it should.', 5200],
      ['It runs in an empty directory of its own. Your CLAUDE.md and memory files never reach '
        + 'a session a teammate on the LAN can start.', 4400],
      ['The same six tools on every backend: an MCP server for the CLI, tool definitions for '
        + 'an HTTP API. What the mode allows is what the model is offered.', 5000],
      ['Still working.', 3000],
    ], async () => page.evaluate(
      `Boolean(document.querySelector('#view .composer .primary:not([disabled])'))`));

    await cap('', 3500);                               // read the reply
    const after = await pendingCount(page);
    await cap(after > before
      ? 'Anything it wanted in the case file it had to <b>propose</b>. The proposal is a '
        + 'candidate, not a record, and it is sitting on the right.'
      : 'This time it asked for more before proposing anything. That is also an answer, and it '
        + 'recorded nothing.', 4200);
  }

  await page.evaluate(`document.querySelector('#view .rail, #view aside')
    ?.scrollTo({ top: 0, behavior: 'smooth' })`);
  await cap('Confirm or deny is a person\'s act, and each one writes an audit row with their '
    + 'name on it. Assigning a thread first puts the finding in a line of enquiry.', 4400);

  // --- records -------------------------------------------------------------
  await cap('');
  await route('records');
  await page.type('#q', 'log-sync', { perChar: 55, settle: 1500 });
  await cap('Every finding, searched on the server rather than in the browser, so the answer '
    + 'covers the whole case file and not what happened to load.', 4000);
  await page.click('#view tbody tr:first-child', { settle: 1500 });
  await page.evaluate(`document.querySelector('#drawer')?.scrollTo({ top: 99999, behavior: 'smooth' })`);
  await sleep(1000);
  await cap('Open one and it carries its trail: the fields, the host it is bound to, and under '
    + '<b>Adjudication</b> every decision anybody made about it, with a name and a time.', 4800);

  await page.send('Input.dispatchKeyEvent',
    { type: 'keyDown', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27 });
  await page.send('Input.dispatchKeyEvent',
    { type: 'keyUp', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27 });
  await page.evaluate(`(() => {
    const q = document.querySelector('#view #q');
    if (!q) return;
    q.value = '';
    q.dispatchEvent(new Event('input', { bubbles: true }));
  })()`);
  await sleep(1300);
  await cap('Denied is kept — it is a judgement. Archiving is separate and retires a record '
    + 'from the map, the timeline and the prompt; nothing is ever deleted.', 4400);

  // --- map -----------------------------------------------------------------
  await cap('');
  await route('map', 3200);
  await sleep(1200);
  await cap('The estate, clustered by enclave. Fill is evidence and verdict; the outline is '
    + 'presence — whether the address answered. A box that answers a ping is not thereby '
    + 'clean.', 4800);
  await cap('The diamond is an address nobody entered. Evidence named it, so it is on the map, '
    + 'marked as absent from the terrain rather than quietly added to it.', 4400);
  await cap('The edges are derived from the records on read and never stored, so the graph '
    + 'cannot drift from the evidence that justifies it.', 3800);

  // --- timeline ------------------------------------------------------------
  await cap('');
  await route('timeline', 2600);
  await cap('The same evidence in time. Filled is adjudicated, hollow is pending; a dashed '
    + 'outline means the recorded time was approximate. The purple arcs are causality '
    + 'somebody confirmed.', 5000);
  await cap('The fourth link is still a proposal, with its rationale, waiting for a call. It '
    + 'opened on the densest stretch on purpose — a month-old outlier beside a night\'s work '
    + 'leaves the night unreadable.', 5200);

  // --- characterization ----------------------------------------------------
  await cap('');
  await route('characterization', 2400);
  await cap('What normal looks like, so a finding has something to be judged against.', 2800);
  await cap('A second collection came back without the shell and home columns. A naive diff '
    + 'calls every row changed; here the gap was acknowledged, the rows band as <b>Partial</b>, '
    + 'and they stop counting as changes.', 5600);
  await cap('Coverage is stated, not implied: the hosts a snapshot has not reached, and when '
    + 'each was last seen. It stays "still collecting" until somebody says it is done.', 4600);
  await page.click('[data-repo="scheduled-tasks"]', { settle: 1800 });
  await cap('Nineteen repositories, each with its own idea of identity. Three cron entries on '
    + 'six hosts and a fourth on one — <b>1 of 6</b> is worth a look; 6 of 6 would be '
    + 'inventory.', 5000);

  // --- plan ----------------------------------------------------------------
  await cap('');
  await route('plan', 2200);
  await cap('The hunt plan. The file is the authority and the database is rebuilt from it at '
    + 'every start, so a week of team edits cannot be lost to a restart.', 4200);
  await page.click('#view [data-expand]', { settle: 1800 });
  await cap('Intent, technique, the procedure to run, the evidence to expect, who has it, and '
    + 'its own history.', 3600);

  await page.click('#view [data-mode="coverage"]', { settle: 2600 });
  await cap('The same plan against ATT&CK, coloured by what it <b>intends</b> — a different '
    + 'question from the Navigator export, which says what was found. The gap between them is '
    + 'the useful part.', 5200);
  await cap('Three states, not two: nothing names it; a task names it with nothing written '
    + 'under it; a task names it and carries steps. Forty stubs look thorough in a list.', 5000);
  await page.click('#view .cov-cell.cov-none', { settle: 2200 });
  await cap('A gap opens its bank entry — every live technique, 697 Enterprise and 97 ICS, '
    + 'plus entries ATT&CK has no id for. What backs each one is stamped on it, and a stub '
    + 'says it is a stub.', 5400);

  // --- comms ---------------------------------------------------------------
  await cap('');
  await route('comms', 2400);
  await cap('And a place for the team to talk that is not the model. A session can produce '
    + 'records; a channel produces nothing but its own history.', 4200);
  await cap('Direct messages are the one thing here that is private. Everything else is open, '
    + 'because review across the team is what the tool is for.', 4000);

  await cap('');
  await sleep(600);
  await card(page, CLOSING);
  await sleep(5500);
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
