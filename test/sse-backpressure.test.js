import { test, beforeEach } from 'node:test';
import assert from 'node:assert';
import { addClient, broadcast, clientCountNow, closeAll } from '../server/sse.js';

/*
  A client that stops reading must not grow a buffer without end.

  res.write() returns false when the socket cannot keep up and Node holds the
  rest in user space. Nothing read that, and nothing bounded it. A clean
  disconnect fires 'close' and the client is removed — but a laptop closed
  mid-engagement, a Wi-Fi drop or a NAT timeout leaves a socket that is neither
  writable nor closed, and every broadcast after that appended to it. On an
  exercise running for days that is a leak with no ceiling.

  Dropping is safe because this hub keeps no replay buffer, which it says so
  itself: a client that misses events reconnects and re-fetches /api/state.
*/

/** A response that accepts writes and never drains, like a sleeping laptop. */
const stalledClient = () => {
  const handlers = {};
  return {
    writableLength: 0,
    ended: false,
    writeHead() {},
    write(chunk) { this.writableLength += Buffer.byteLength(chunk); return false; },
    end() { this.ended = true; },
    on(evt, fn) { handlers[evt] = fn; },
    emit(evt) { handlers[evt]?.(); },
  };
};

/** One that drains immediately, like a browser that is actually listening. */
const healthyClient = () => {
  const c = stalledClient();
  c.write = function write(chunk) { void chunk; return true; };
  return c;
};

beforeEach(() => closeAll());

test('a client that never drains is dropped rather than buffered forever', () => {
  const stalled = stalledClient();
  const healthy = healthyClient();
  addClient(stalled);
  addClient(healthy);
  assert.equal(clientCountNow(), 2);

  // Enough deltas to pass the ceiling. Each is a few hundred bytes, so this is
  // far more than any real burst.
  const payload = { note: 'x'.repeat(2000) };
  for (let i = 0; i < 400 && clientCountNow() > 1; i++) broadcast('record.created', payload);

  assert.equal(clientCountNow(), 1, 'the stalled client was never dropped');
  assert.ok(stalled.ended, 'a dropped client should be ended, not left holding a dead stream');
});

test('a client that keeps up is left alone', () => {
  const healthy = healthyClient();
  addClient(healthy);
  for (let i = 0; i < 500; i++) broadcast('record.created', { note: 'x'.repeat(2000) });
  assert.equal(clientCountNow(), 1, 'a client that drains must not be dropped');
  assert.equal(healthy.ended, false);
});

test('closing a socket removes it, as before', () => {
  const c = healthyClient();
  addClient(c);
  assert.equal(clientCountNow(), 1);
  c.emit('close');
  assert.equal(clientCountNow(), 0);
});

test('broadcasting to nobody is not an error', () => {
  assert.equal(clientCountNow(), 0);
  broadcast('record.created', {});
});
