/**
 * Record a headless browser session to frames, over the DevTools protocol.
 *
 *   node tools/record-demo.mjs --reel --url http://127.0.0.1:8799 --token XXXXXXXX
 *   node tools/record-demo.mjs --tour --url ... --token ... --setup-url ... --setup-token ...
 *
 * Same argument as tools/screenshots.mjs: point it at a demo instance, never a
 * live one, because what is on screen ends up published. Start one with
 * tools/demo-data.mjs — and rebuild it before every take. A recording is not a
 * read-only operation: the reel confirms a candidate and the tour's live turn
 * files a proposal, so the second take against one store films a different
 * application from the first.
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
import { spawn, execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { synthesise, schedule, narrationPlan, srt } from './narration.mjs';

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

/** Silence after a line, so one beat does not run into the next. */
const NARRATION_PAD = 700;

export async function open({
  width = 1440, height = 900, outDir, exe = findBrowser(),
  /* caption text -> { file, ms }. Empty in the silent cut, which is why the
     silent cut still honours the hold written into the script. */
  narration = new Map(),
} = {}) {
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
  /* Every caption and the frame timestamp it went up on, so a narration track
     can be built against the picture afterwards. */
  const beats = [];
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
    send, evaluate, on, width, height, frames, beats,
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
    /*
      A caption, and where it sits in the recording.

      The offset is taken from the newest frame's own timestamp rather than
      from Date.now(): the frames carry the browser's clock, the audio is laid
      against the frames, and mixing two clocks puts the voice a little further
      out of step with every beat.

      In narrated mode `hold` is ignored — the shot is held for as long as the
      line takes to say, which is the whole reason the audio is synthesised
      before anything is filmed.
    */
    async caption(html, hold = 0) {
      const at = frames.length ? frames.at(-1).t : null;
      await evaluate(`window.__cap(${JSON.stringify(html ?? '')})`);
      if (html) beats.push({ text: html, at });
      const spoken = html ? narration.get(html) : null;
      if (spoken) await sleep(spoken.ms + NARRATION_PAD);
      else if (hold) await sleep(hold);
    },
    /*
      Hold for a line without putting it in the caption bar.

      Used by the cards, which already say the words on screen. The beat is
      still logged, so the narration lands against the card rather than after
      it and the subtitle file has the line in it.
    */
    async speak(text, silentHold = 0) {
      const clip = narration.get(text);
      if (clip) {
        beats.push({ text, at: frames.length ? frames.at(-1).t : null });
        await sleep(clip.ms + NARRATION_PAD);
      } else if (silentHold) {
        await sleep(silentHold);
      }
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
    /** Point at something without pressing it. */
    async hover(selector, { move = 500, settle = 300 } = {}) {
      const box = await evaluate(`(() => {
        const el = document.querySelector(${JSON.stringify(selector)});
        if (!el) return null;
        const r = el.getBoundingClientRect();
        return { x: Math.round(r.left + r.width / 2), y: Math.round(r.top + r.height / 2) };
      })()`);
      if (!box) return false;
      await evaluate(`window.__cursorTo(${box.x}, ${box.y}, ${move})`);
      await sleep(move + settle);
      return true;
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

/*
  A card, held for as long as its own line takes to say.

  The card carries the words already, so the caption bar stays off and the
  voice reads what is on the card. Silent, it falls back to the hold written
  into the call — which is why the cards were four seconds before there was a
  voice and about nine after: reading time and speaking time are not the same
  quantity.
*/
async function cardBeat(page, html, line, silentHold) {
  await card(page, html);
  await page.speak(line, silentHold);
}

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
 * The lines.
 *
 * One table, because the subtitle and the voice are the same words. A line
 * that only works spoken is the wrong line for a recording whose captions are
 * part of the picture, and a line that only works read is the wrong line for
 * one with a voice.
 *
 * Exported as objects so the synthesiser can speak every line before the
 * browser opens: with narration on, a shot is held for exactly as long as its
 * line takes, and there is nothing to align afterwards.
 * ------------------------------------------------------------------------- */

const CARD_LINE = {
  opening: 'Psephos. A workspace for threat hunt teams. The name is the pebble an Athenian '
    + 'juror dropped into the urn to cast a verdict.',
  midroll: 'A different instance, mid-hunt. Synthetic exercise data on documentation '
    + 'addresses. Every host, name and record is invented.',
  closing: 'Nothing here becomes a finding until a person decides it has.',
};

const REEL_LINES = {
  sessions: 'Evidence goes in as it was found. The model reads it against the whole case file '
    + 'and answers.',
  candidate: 'Anything it wants recorded lands on the right as a <b>candidate</b>. Nothing the '
    + 'model can do puts it in the case file.',
  confirm: 'Filing it is a person\'s act.',
  audit: 'The record now says who confirmed it and when. Every verdict here writes a row like '
    + 'this, and no tool the model has can write one.',
  denied: 'The case file. Denied is kept, not deleted. That the evidence showed nothing is '
    + 'still a judgement, and a later reader needs it.',
  map: 'Fill is evidence and verdict. The outline is whether the address answered. The map '
    + 'will not merge those two questions.',
  edges: 'The path is drawn from the records and never stored. Deny a record and its edge goes '
    + 'with it.',
  timeline: 'The same records in time. Filled marks are adjudicated, hollow ones are still '
    + 'waiting. The arcs are causality somebody confirmed.',
  baseline: 'What normal looked like first. Three cron entries on six hosts, and a fourth on '
    + 'one of them. <b>One of six</b> is the finding. Six of six would be inventory.',
  coverage: 'The plan against ATT&CK, coloured by what it intends to look for. That is a '
    + 'different question from what was found.',
  bank: 'A gap opens its bank entry. There is no authored task for this one, and the panel '
    + 'says so.',
  ...CARD_LINE,
};

const TOUR_LINES = {
  setup: 'A fresh clone has no mission, so the server comes up in setup and will not guess. '
    + 'The wrong terrain takes hosts off the map, and every verdict on them goes with them.',
  model: 'First, which model runs the turns. The CLI keeps its own login, so this application '
    + 'never holds a credential.',
  probe1: 'It is checked before it is saved. A backend that cannot answer now will not start '
    + 'answering at the first piece of evidence.',
  probe2: 'An API key, if you use one, is written owner-only and never returned to a browser.',
  probe3: 'A base URL pointing at your own hardware keeps the case file on it.',
  mission: 'The engagement. The name goes into every prompt. The profile is written under '
    + 'missions, which is gitignored, because a network map is not source.',
  briefing: 'What the model must not assume. One line each, sent with every turn. It is the '
    + 'difference between no evidence found, and no telemetry to find it with.',
  team: 'The team, in chain of command order. Each person gets a token and their own window. '
    + 'The token says who you are, so nobody types a name and nobody types the wrong one.',
  terrain: 'Terrain is the estate you were given. Paste the inventory as it is and the model '
    + 'structures it. Or start with none, and let the evidence name the hosts.',
  plan: 'And a plan to start from. It is edited in the app all week. This is only where it '
    + 'begins.',
  done: 'Every token is printed to the console the server was started from, and never to a '
    + 'browser.',

  window: 'One persistent window per analyst. The roster is the session list, and everyone can '
    + 'read every window. Review across the team is the point.',
  research: 'The other button, Research, takes the two writing tools away for the turn. A '
    + 'question cannot become a record because the model decided it should.',
  evidence: 'Evidence goes in as it was found. This continues the exchange above, which asked '
    + 'for the file\'s timestamp and the shape of the egress.',
  send: 'This is a real turn against the Claude CLI, unedited. It takes about a minute.',
  /*
    Two lines over the spinner, not seven.
    Both were wrong in the silent cut and are corrected here: an evidence turn
    is offered five hunt tools, not six — stage_entities is denied in that mode
    — and the prompt does not carry the terrain or the baselines. It names not
    one of the twelve seeded hosts; the model has to go and ask.
  */
  given: 'It was given the evidence above, every record already on file, and the briefing. '
    + 'Terrain and baselines it has to ask for, with tools.',
  withheld: 'It was not given a shell, the filesystem, the network, or any tool of your own. '
    + 'It starts with no tools and gains five, and none of the five can file a finding.',
  away: 'The rest of the application does not wait for it.',

  search: 'Every finding, searched on the server, so the answer covers the whole case file and '
    + 'not what happened to load.',
  drawer: 'Open one and it carries its trail. The fields, the host it is bound to, and under '
    + '<b>Adjudication</b>, every decision anybody made about it, with a name and a time.',
  archive: 'Denied is kept. It is a judgement. Archiving is separate, and retires a record '
    + 'from the map, the timeline and the prompt. Nothing is deleted.',
  map: 'The estate, clustered by enclave. Fill is evidence and verdict. The outline is '
    + 'presence, whether the address answered. A box that answers a ping is not thereby clean.',
  diamond: 'The diamond is an address nobody entered. Evidence named it, so it is on the map, '
    + 'marked as discovered rather than passed off as inventory.',

  back: 'Back in the window, the reply has landed.',
  proposed: 'Anything it wanted in the case file it had to propose. The proposal is a candidate '
    + 'on the right, and it is not a record.',
  asked: 'This time it asked for more before proposing anything. That is also an answer, and it '
    + 'recorded nothing.',
  rail: 'Confirm or deny is a person\'s act, and each one writes an audit row with a name on '
    + 'it. The thread selector puts the finding in a line of enquiry.',

  timeline: 'The same evidence in time. Filled is adjudicated, hollow is pending. A dashed '
    + 'outline means the recorded time was approximate. The purple arcs are causality somebody '
    + 'confirmed.',
  link: 'The fourth link is still a proposal, with its rationale, waiting for a call.',

  normal: 'What normal looks like, so a finding has something to be judged against.',
  partial: 'A second collection came back without the shell and home columns. A naive diff '
    + 'would call every row changed. Here the gap was acknowledged, so the rows band as '
    + '<b>Partial</b> and stop counting as changes.',
  coverageBand: 'Coverage is stated, not implied. The hosts a snapshot has not reached, and '
    + 'when each was last seen. It reads still collecting until somebody marks it complete.',
  rare: 'Nineteen repositories, each with its own idea of identity. Three cron entries on six '
    + 'hosts, and a fourth on one. <b>One of six</b> is worth a look. Six of six would be '
    + 'inventory.',

  hunt: 'The hunt plan. The file is the authority and the database is rebuilt from it at every '
    + 'start, so a week of team edits cannot be lost to a restart.',
  task: 'Each task carries its intent, its procedure, the evidence to expect, who has it, and '
    + 'its own history.',
  coverage: 'The same plan against ATT&CK, coloured by what it intends to look for. The '
    + 'Navigator export says what was found. The gap between them is the useful part.',
  states: 'Three states, not two. Nothing names the technique. A task names it but nothing is '
    + 'written under it. Or a task names it and carries steps. Forty stubs look thorough in a '
    + 'list.',
  bank: 'A gap opens its bank entry. What backs each entry is stamped on it, and a stub says '
    + 'it is a stub.',
  comms: 'And a place to talk that is not the model. A session can produce records. A channel '
    + 'produces nothing but its own history. Direct messages are the one thing here that is '
    + 'private.',
  ...CARD_LINE,
};

/* ------------------------------------------------------------------------- *
 * The short one: under two minutes, for the top of the README.
 * ------------------------------------------------------------------------- */
async function reel(page, { url, token }) {
  const L = REEL_LINES;
  const cap = (line, hold = 0) => page.caption(line, hold);
  const route = async (name, settle = 1200) => {
    await page.click(`#nav a[data-route="${name}"]`, { settle: 300 });
    await sleep(settle);
  };

  await page.goto(`${url}/login`);
  await page.cookie('hunt_token', token, url);
  await sleep(400);
  await page.startRecording();

  await sleep(400);
  await cardBeat(page, OPENING, L.opening, 4200);
  await sleep(800);

  await page.goto(`${url}/#/sessions`);
  await waitFor(page, '#view .transcript');
  await sleep(1600);                                   // orient on a new interface
  await cap(L.sessions, 3400);
  await cap(L.candidate, 4200);
  await sleep(800);

  await cap(L.confirm, 1600);
  /*
    The take mutates the store it films: this click confirms a candidate, and a
    live turn in the long form adds one. So a second take against the same
    store finds a rail that no longer matches the script — which is worth
    saying plainly rather than reporting as a missing selector.
  */
  if (!await page.evaluate(`Boolean(document.querySelector('#view .cand .ok'))`)) {
    throw new Error('no pending candidate in the rail — rebuild the demo store '
      + '(tools/demo-data.mjs) before recording; a previous take confirmed it');
  }
  await page.click('#view .cand .ok', { settle: 1500 });

  await route('records', 1200);
  await page.type('#q', 'ntdsutil', { perChar: 55, settle: 1000 });
  await page.click('#view tbody tr:first-child', { settle: 1300 });
  await page.evaluate(`document.querySelector('#drawer')?.scrollTo({ top: 99999, behavior: 'smooth' })`);
  await sleep(600);
  await cap(L.audit, 4400);
  await sleep(600);

  await closeDrawerAndClear(page);
  await sleep(1000);
  await cap(L.denied, 4000);
  await sleep(600);

  await route('map', 1500);                            // speak into the settle, not after it
  await cap(L.map, 4400);
  await cap(L.edges, 3200);
  await sleep(800);

  await route('timeline', 1400);
  await cap(L.timeline, 4400);
  await sleep(800);

  await route('characterization', 1200);
  await page.click('[data-repo="scheduled-tasks"]', { settle: 1200 });
  await cap(L.baseline, 4600);
  await sleep(800);

  await route('plan', 1400);
  await page.click('#view [data-mode="coverage"]', { settle: 2400 });
  await cap(L.coverage, 3600);
  await page.click('#view .cov-cell.cov-none', { settle: 1200 });
  await cap(L.bank, 4000);
  await sleep(1000);

  await cap('');
  await sleep(500);
  await cardBeat(page, CLOSING, L.closing, 5000);
  await sleep(4000);
}

/** Escape out of the drawer and put the search back to empty. */
async function closeDrawerAndClear(page) {
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
}

/* ------------------------------------------------------------------------- *
 * The long one.
 *
 * The turn is real and takes about a minute, and the recording no longer
 * stands over the spinner for all of it: two lines about what the model was
 * and was not given, then it leaves and tours the records and the map while
 * the turn runs, and comes back to a reply that has landed. That is also the
 * truer picture — the turn is one process on a server the rest of the team is
 * still using.
 * ------------------------------------------------------------------------- */
async function tour(page, { setupUrl, setupToken, demoUrl, demoToken, live }) {
  const L = TOUR_LINES;
  const cap = (line, hold = 0) => page.caption(line, hold);
  const route = async (name, settle = 1400) => {
    await page.click(`#nav a[data-route="${name}"]`, { settle: 300 });
    await sleep(settle);
  };

  await page.goto(`${setupUrl}/login`);
  await sleep(500);
  await page.startRecording();
  await sleep(400);
  await cardBeat(page, OPENING, L.opening, 4200);
  await sleep(800);

  // --- the wizard ----------------------------------------------------------
  await page.cookie('hunt_token', setupToken, setupUrl);
  await page.goto(`${setupUrl}/`);
  await waitFor(page, '.wiz-rail');
  await sleep(1000);
  await cap(L.setup, 5000);
  await sleep(600);

  await cap(L.model, 3600);
  await page.click('.wiz-card', { settle: 400 });
  await page.click('[data-act="model"]', { settle: 200 });
  /* A real probe, up to a minute. Three claims worth making, then silence —
     the button already says "Working…", and a voice that announces a wait and
     then stops is worse than the button alone. */
  await fill(page, [[L.probe1, 2000], [L.probe2, 2000], [L.probe3, 3000]],
    async () => page.evaluate(`Boolean(document.querySelector('[data-act="mission"]'))`));
  await sleep(600);

  // Typing runs under the line: the field filling while it is described is the
  // one place picture and voice can share a beat without either being idle.
  await cap(L.mission, 900);
  await page.type('[data-f="name"]', 'Northern Watch 27-1', { perChar: 40 });
  await page.type('[data-f="week"]', 'Week 2 — Linux and OT', { perChar: 40 });
  await page.click('[data-act="mission"]', { settle: 800 });
  await waitFor(page, '[data-act="briefing"]');

  await cap(L.briefing, 900);
  await page.type('[data-f="briefing"]',
    '4625 is not collected on the Linux estate.\n'
    + 'Endpoint sensors landed 14 Aug; silence before that means nothing.', { perChar: 20 });
  await page.click('[data-act="briefing"]', { settle: 800 });
  await waitFor(page, '[data-act="roster"]');

  await cap(L.team, 900);
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

  await cap(L.terrain, 4400);
  await page.click('[data-act="noterrain"]', { settle: 1200 });
  await waitFor(page, '[data-act="planexample"]', 30000);

  await cap(L.plan, 3000);
  await page.click('[data-act="planexample"]', { settle: 1500 });
  await sleep(2000);                                   // the headline says it itself
  await cap(L.done, 3600);
  await sleep(1000);

  await cap('');
  await cardBeat(page, MIDROLL, L.midroll, 2800);
  await sleep(800);

  // --- the session ---------------------------------------------------------
  await page.goto(`${demoUrl}/login`);
  await page.cookie('hunt_token', demoToken, demoUrl);
  await page.goto(`${demoUrl}/#/sessions`);
  await waitFor(page, '#view .transcript', 20000);
  await sleep(1800);
  await cap(L.window, 4400);
  await sleep(600);

  let before = 0;
  if (live) {
    /* Said where the button is, and pointed at, rather than over a spinner
       fifty seconds later with nothing on screen to attach it to. */
    await page.hover('#view .composer [data-mode="research"]');
    await cap(L.research, 5200);
    await page.hover('#view .composer [data-mode="evidence"]');
    await sleep(800);

    before = await pendingCount(page);
    await cap(L.evidence, 1200);
    await page.type('#ta',
      'stat on /etc/cron.d/log-sync: modified 2026-03-11 22:38:51Z. svc_deploy\'s ssh login '
      + 'from 192.0.2.12 was 22:02:10Z, and nothing else under /etc/cron.d changed that day.\n'
      + 'Egress from RL-03 to 203.0.113.200:8443 since 22:45: a POST every 15 minutes, '
      + '2.8-3.4 MB each.', { perChar: 11, settle: 500 });

    await cap(L.send, 2600);
    await page.click('#cf .primary', { settle: 300 });

    const answered = async () => page.evaluate(
      `Boolean(document.querySelector('#view .composer .primary:not([disabled])'))`);
    await fill(page, [[L.given, 2500], [L.withheld, 2500]], answered);
    await cap(L.away, 1800);
  }

  // --- records and map, while the turn runs --------------------------------
  await cap('');
  await route('records');
  await page.type('#q', 'log-sync', { perChar: 55, settle: 1200 });
  await cap(L.search, 4000);
  await page.click('#view tbody tr:first-child', { settle: 1400 });
  await page.evaluate(`document.querySelector('#drawer')?.scrollTo({ top: 99999, behavior: 'smooth' })`);
  await sleep(800);
  await cap(L.drawer, 4800);
  await sleep(600);

  await closeDrawerAndClear(page);
  await sleep(1000);
  await cap(L.archive, 4400);
  await sleep(600);

  await cap('');
  await route('map', 1500);
  await cap(L.map, 4800);
  await cap(L.diamond, 4400);
  await sleep(800);

  // --- back to the window --------------------------------------------------
  if (live) {
    await cap('');
    await route('sessions', 1200);
    await waitFor(page, '#view .transcript', 20000);
    /* If it is somehow still running, wait it out in silence rather than
       talking over a spinner a second time. */
    while (!(await page.evaluate(
      `Boolean(document.querySelector('#view .composer .primary:not([disabled])'))`))) {
      await sleep(700);
    }
    await sleep(1200);
    await cap(L.back, 2400);
    await sleep(3000);                                 // read the reply
    const after = await pendingCount(page);
    await cap(after > before ? L.proposed : L.asked, 4200);
    await page.evaluate(`document.querySelector('#view .rail, #view aside')
      ?.scrollTo({ top: 0, behavior: 'smooth' })`);
    await sleep(600);
    await cap(L.rail, 4400);
    await sleep(1000);
  }

  // --- timeline ------------------------------------------------------------
  await cap('');
  await route('timeline', 2000);
  await cap(L.timeline, 5000);
  /* The tray sits below the chart and can be under the fold at 900px; the line
     must not describe a card the viewer cannot see. */
  await page.evaluate(`document.querySelector('#view .tray')
    ?.scrollIntoView({ block: 'center', behavior: 'smooth' })`);
  await sleep(900);
  await cap(L.link, 3200);
  await sleep(1000);

  // --- characterization ----------------------------------------------------
  await cap('');
  await route('characterization', 2000);
  await cap(L.normal, 2800);
  await cap(L.partial, 5600);
  await cap(L.coverageBand, 4600);
  await page.click('[data-repo="scheduled-tasks"]', { settle: 1600 });
  await cap(L.rare, 5000);
  await sleep(800);

  // --- plan ----------------------------------------------------------------
  await cap('');
  await route('plan', 1800);
  await cap(L.hunt, 4200);
  await page.click('#view [data-expand]', { settle: 1600 });
  await cap(L.task, 3600);
  await page.click('#view [data-mode="coverage"]', { settle: 2400 });
  await cap(L.coverage, 5200);
  await cap(L.states, 5000);
  await page.click('#view .cov-cell.cov-none', { settle: 1800 });
  await cap(L.bank, 5400);
  await sleep(1000);

  // --- comms ---------------------------------------------------------------
  await cap('');
  await route('comms', 2000);
  await cap(L.comms, 4200);
  await sleep(1000);

  await cap('');
  await sleep(600);
  await cardBeat(page, CLOSING, L.closing, 5500);
  await sleep(4000);
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

/*
  Narration, when asked for. Everything is spoken and measured before the
  browser opens: the shot lengths come from the audio, so there is nothing to
  align afterwards.
*/
const voice = arg('voice');
/*
  Filled after the browser opens, not before: open() clears the output
  directory, and the clips live under it. The recorder closes over this map, so
  filling it here is the same as having passed it full.
*/
const narration = new Map();
const page = await open({ outDir: out, width: 1440, height: 900, narration });
if (voice) {
  const lines = WHICH === 'reel' ? Object.values(REEL_LINES) : Object.values(TOUR_LINES);
  process.stdout.write(`speaking ${lines.length} lines as ${voice}… `);
  for (const [k, v] of await synthesise(lines, {
    voice, dir: join(out, 'voice'), rate: arg('rate') ? Number(arg('rate')) : null,
  })) narration.set(k, v);
  const total = [...narration.values()].reduce((n, c) => n + c.ms, 0);
  console.log(`${Math.round(total / 1000)}s of speech`);
}
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

  if (voice && page.frames.length) {
    /*
      The audio track, written as its own concat script: silence up to each
      line, then the line. One schedule feeds both this and the subtitles, so
      a line the voice skips cannot still appear as a caption.
    */
    const cues = schedule(page.beats, narration, page.frames);
    const plan = narrationPlan(cues, page.frames);
    const silences = join(out, 'voice');
    const parts = [];
    for (const [i, step] of plan.entries()) {
      if (step.silence > 0) {
        const gap = join(silences, `gap-${String(i).padStart(3, '0')}.wav`);
        execFileSync('ffmpeg', ['-y', '-loglevel', 'error', '-f', 'lavfi',
          '-i', `anullsrc=r=22050:cl=mono`, '-t', (step.silence / 1000).toFixed(3), gap]);
        parts.push(gap);
      }
      if (step.file) parts.push(step.file);
    }
    writeFileSync(join(out, 'audio.txt'),
      parts.map(f => `file '${f}'`).join('\n') + '\n');
    writeFileSync(join(out, `${WHICH}.srt`), srt(cues));
    console.log(`narration: ${cues.length} cues, subtitles in ${WHICH}.srt`);
  }

  console.log('encode with:');
  console.log(`  ffmpeg -y -f concat -safe 0 -i ${out}/concat.txt \\`);
  console.log(`    -vf "fps=30,format=yuv420p" -c:v libx264 -crf 21 -movflags +faststart ${WHICH}.mp4`);
  if (voice) {
    console.log('then lay the voice under it:');
    console.log(`  ffmpeg -y -f concat -safe 0 -i ${out}/audio.txt -i ${WHICH}.mp4 \\`);
    console.log(`    -map 1:v -map 0:a -c:v copy -c:a aac -b:a 128k -shortest ${WHICH}-narrated.mp4`);
  }
  await page.close();
}
