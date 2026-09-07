/**
 * Server-sent events hub.
 *
 * Every store write broadcasts a typed delta so open browsers stay in step
 * without polling. There is deliberately no server-side replay buffer: a
 * client that misses events reconnects and re-fetches /api/state, which is
 * cheaper to reason about than a cursor.
 */
const clients = new Set();

/*
  How much unsent data a client may accumulate before it is dropped.

  res.write() returns false when the socket cannot keep up and Node buffers the
  rest in user space; nothing here read that, and nothing bounded the buffer. A
  clean disconnect fires 'close' and the client is removed — but a laptop closed
  mid-engagement, a Wi-Fi drop, or a NAT timeout leaves a socket that is neither
  writable nor closed, and every subsequent broadcast appended to it. On an
  exercise running for days, that is a slow leak with no ceiling.

  Dropping is safe here precisely because this hub keeps no replay buffer: the
  client reconnects and re-fetches /api/state, which is the path app.js's
  resync() already exists to take. A dropped client loses nothing a reconnect
  does not restore.

  256 KB is far above any legitimate burst — a delta is a few hundred bytes —
  and far below anything that matters to the process.
*/
const MAX_BUFFERED = Number(process.env.HUNT_SSE_MAX_BUFFER || 256 * 1024);
// Keep-alive timers by response, so closeAll can stop them even where the
// socket never emits 'close' — a leaked interval keeps the event loop alive
// and the process refuses to exit on SIGINT.
const timers = new Map();

export function addClient(res) {
  res.writeHead(200, {
    'content-type': 'text/event-stream',
    'cache-control': 'no-cache, no-transform',
    connection: 'keep-alive',
    'x-accel-buffering': 'no',
  });
  res.write('retry: 2000\n\n');
  clients.add(res);

  const keepAlive = setInterval(() => {
    try {
      res.write(': keep-alive\n\n');
      // The keep-alive is often the first write to notice a socket that went
      // away without saying so, which is the case 'close' does not cover.
      if ((res.writableLength ?? 0) > MAX_BUFFERED) dropClient(res);
    } catch { dropClient(res); }
  }, 25_000);

  timers.set(res, keepAlive);
  res.on('close', () => dropClient(res));
  res.on('error', () => dropClient(res));
}

/** Forget a client and stop its keep-alive. Safe to call more than once. */
function dropClient(res) {
  clearInterval(timers.get(res));
  timers.delete(res);
  clients.delete(res);
  // Ending it tells a client that is merely slow to reconnect, rather than
  // leaving it holding a stream nothing will ever write to again.
  try { res.end(); } catch { /* already gone */ }
}

/** Open streams. Exported so a test can watch one be dropped. */
export const clientCountNow = () => clients.size;

/** @param {string} type e.g. 'record.created', 'host.verdict', 'session.message' */
export function broadcast(type, payload) {
  const line = `data: ${JSON.stringify({ type, payload })}\n\n`;
  for (const res of clients) {
    try {
      res.write(line);
      /*
        Written first, then checked. A client that has fallen this far behind is
        not going to catch up, and holding it only grows the buffer — so it is
        dropped and left to reconnect, which is the same thing it does after any
        other interruption.
      */
      if ((res.writableLength ?? 0) > MAX_BUFFERED) dropClient(res);
    } catch { dropClient(res); }
  }
}

export const clientCount = () => clients.size;

export function closeAll() {
  for (const t of timers.values()) clearInterval(t);
  timers.clear();
  for (const res of clients) { try { res.end(); } catch { /* already gone */ } }
  clients.clear();
}
