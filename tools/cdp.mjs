/**
 * A small Chrome DevTools Protocol client.
 *
 * Extracted from tools/screenshots.mjs so the screenshot run and the view smoke
 * test drive the browser the same way. Two copies of a protocol client is two
 * sets of timing assumptions that drift apart, and the second one is always the
 * one nobody maintains.
 *
 * No dependencies, which is the whole point: Node has a WebSocket client built
 * in and the browser is already on the machine, so headless Chrome is reachable
 * without adding anything to a repository that installs nothing.
 */
import { spawn } from 'node:child_process';
import { existsSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const BROWSERS = [
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  'C:/Program Files/Microsoft/Edge/Application/msedge.exe',
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  '/usr/bin/google-chrome',
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
];

/**
 * Where Edge or Chrome is, or null.
 *
 * Returned rather than thrown so a caller can decide. A screenshot run without
 * a browser is a failure; a test run without one is a skip, and conflating
 * those turns "this machine has no Chrome" into a red build.
 */
export const findBrowser = () => BROWSERS.find(p => existsSync(p)) ?? null;

export const sleep = (ms) => new Promise(r => setTimeout(r, ms));

/**
 * Launch headless Chrome and attach to one page.
 *
 * @returns {Promise<{send:Function, once:Function, evaluate:Function,
 *   errors:Function, ready:Function, goto:Function, close:Function}>}
 */
export async function launch({ width = 1680, height = 1020, exe = findBrowser() } = {}) {
  if (!exe) throw new Error('no Edge or Chrome found');

  const profile = join(tmpdir(), `hunt-cdp-${process.pid}-${Date.now()}`);
  const browser = spawn(exe, [
    '--headless=new',
    '--remote-debugging-port=0',
    `--user-data-dir=${profile}`,
    '--no-first-run', '--no-default-browser-check',
    '--disable-extensions', '--disable-background-networking',
    '--hide-scrollbars', '--disable-gpu',
    /*
      Both for containers. A container's /dev/shm is small and Chrome dies
      mid-navigation without the first, which reads as a flaky test rather than
      as a missing mount.

      --no-sandbox because CI runs as root, where Chrome refuses to start
      otherwise. It is the standard CI trade and it is worth naming: the sandbox
      is what contains a hostile page, so this is only acceptable because the
      only pages opened here are served by this repository's own server on
      loopback. Do not reuse this client to browse anything else.
    */
    '--disable-dev-shm-usage', '--no-sandbox',
    `--window-size=${width},${height}`,
    'about:blank',
  ], { stdio: ['ignore', 'pipe', 'pipe'] });

  /** The port is chosen by the browser and announced on stderr. */
  const endpoint = await new Promise((ok, fail) => {
    let buf = '';
    const t = setTimeout(() => fail(new Error('browser never announced a debugging port')), 20000);
    browser.stderr.on('data', (d) => {
      buf += d;
      const m = buf.match(/ws:\/\/[^\s]+/);
      if (m) { clearTimeout(t); ok(m[0]); }
    });
    browser.on('exit', (c) => { clearTimeout(t); fail(new Error(`browser exited (${c})`)); });
  });

  const ws = new WebSocket(endpoint);
  await new Promise((ok, fail) => {
    ws.addEventListener('open', ok, { once: true });
    ws.addEventListener('error', () => fail(new Error('could not attach to the browser')), { once: true });
  });

  let nextId = 0;
  const pending = new Map();
  const waiters = [];

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
    // Events. Copied first: a waiter that resolves may register another.
    for (const w of [...waiters]) {
      if (w.method !== msg.method) continue;
      waiters.splice(waiters.indexOf(w), 1);
      w.ok(msg.params);
    }
  });

  const rawSend = (method, params = {}, sessionId) => new Promise((ok, fail) => {
    const id = ++nextId;
    pending.set(id, { ok, fail, method });
    ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
  });

  const once = (method, ms = 20000) => new Promise((ok, fail) => {
    const w = { method, ok };
    waiters.push(w);
    setTimeout(() => {
      const i = waiters.indexOf(w);
      if (i > -1) { waiters.splice(i, 1); fail(new Error(`timed out waiting for ${method}`)); }
    }, ms).unref();
  });

  const { targetId } = await rawSend('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await rawSend('Target.attachToTarget', { targetId, flatten: true });
  const send = (method, params) => rawSend(method, params, sessionId);

  await send('Page.enable');
  await send('Runtime.enable');
  await send('Network.enable');

  /*
    Installed before any page script runs, so a view that throws during mount is
    still caught. Without this the read below is always empty and a page that
    rendered nothing passes silently — which is exactly the failure this whole
    harness exists to catch.
  */
  await send('Page.addScriptToEvaluateOnNewDocument', {
    source: `window.__errors = [];
      addEventListener('error', e => window.__errors.push(String(e.message)));
      addEventListener('unhandledrejection', e => window.__errors.push(String(e.reason)));
      const _e = console.error;
      console.error = (...a) => { window.__errors.push(a.join(' ')); _e(...a); };`,
  });

  const evaluate = async (expression) => {
    // awaitPromise resolves a promise result rather than handing back an
    // opaque wrapper; replMode permits a bare top-level `await` in the
    // expression, the way typing it into the DevTools console would — without
    // it, `await` outside an async function is just an undefined identifier
    // and the call fails silently (result.value comes back undefined).
    const { result } = await send('Runtime.evaluate', {
      expression, returnByValue: true, awaitPromise: true, replMode: true,
    });
    return result.value;
  };

  return {
    send,
    once,
    sessionId,
    evaluate,

    setCookie: (name, value, url) => send('Network.setCookie', {
      name, value, domain: new URL(url).hostname, path: '/',
    }),

    metrics: (h = height) => send('Emulation.setDeviceMetricsOverride', {
      width, height: h, deviceScaleFactor: 1, mobile: false,
    }),

    /*
      Through about:blank each time. A hash change on the same document is a
      same-document navigation, so there is no load event to wait for and the
      caller races the render.
    */
    async goto(url) {
      /*
        Each hop registers its waiter before the navigate meant to satisfy it.
        Page.navigate resolves when a navigation starts, not when it finishes,
        so a waiter registered after it can be resolved by the load of the page
        being left behind — and the caller then scripts a document that is
        still parsing, whose inline handlers are not attached yet.
      */
      const hop = async (to) => {
        const loaded = once('Page.loadEventFired');
        await send('Page.navigate', { url: to });
        await loaded;
      };
      await hop('about:blank');
      await hop(url);
    },

    /** Whatever the page has thrown or console.error'd so far. */
    errors: () => evaluate('(window.__errors || []).slice()'),

    /**
     * Wait until the view has actually painted something.
     *
     * Every view mounts empty and fills in from fetches, so a load event means
     * nothing. This asks the page whether the shell is still showing its
     * placeholder.
     */
    async ready(timeout = 15000) {
      const until = Date.now() + timeout;
      while (Date.now() < until) {
        const ok = await evaluate(`(() => {
          const v = document.querySelector('#view');
          if (!v) return false;
          // A direct child only. Views reuse .loading for their empty states,
          // and matching those would wait out the timeout on every quiet view.
          if (v.querySelector(':scope > .loading')) return false;
          return v.textContent.trim().length > 40;
        })()`);
        if (ok === true) return true;
        await sleep(200);
      }
      return false;
    },

    close() {
      try { ws.close(); } catch { /* already gone */ }
      browser.kill();
      try { rmSync(profile, { recursive: true, force: true }); } catch { /* browser may hold it */ }
    },
  };
}
