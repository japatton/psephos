import { test, afterEach } from 'node:test';
import assert from 'node:assert';
import { EventEmitter } from 'node:events';
import { addClient, broadcast, clientCount, closeAll } from '../server/sse.js';

/*
  The hub every live update goes through, and until now untested.

  A fake response rather than a real socket: the cases that matter are a client
  that throws on write and a shutdown that has to stop the keep-alive timers,
  and neither is convenient to arrange with a real connection.
*/
class FakeRes extends EventEmitter {
  constructor({ failOnWrite = false } = {}) {
    super();
    this.failOnWrite = failOnWrite;
    this.head = null;
    this.written = [];
    this.ended = false;
  }

  writeHead(status, headers) { this.head = { status, headers }; return this; }

  write(chunk) {
    if (this.failOnWrite) throw new Error('socket closed');
    this.written.push(chunk);
    return true;
  }

  end() { this.ended = true; this.emit('close'); }

  /** Everything this client received, minus the protocol preamble and pings. */
  events() {
    return this.written
      .filter(w => w.startsWith('data: '))
      .map(w => JSON.parse(w.slice(6)));
  }
}

afterEach(() => closeAll());

test('a new client gets event-stream headers and a retry hint', () => {
  const res = new FakeRes();
  addClient(res);
  assert.equal(res.head.status, 200);
  assert.equal(res.head.headers['content-type'], 'text/event-stream');
  assert.equal(res.head.headers['cache-control'], 'no-cache, no-transform');
  // Proxies that buffer would defeat the whole point of streaming.
  assert.equal(res.head.headers['x-accel-buffering'], 'no');
  assert.match(res.written[0], /^retry: \d+/);
  assert.equal(clientCount(), 1);
});

test('a broadcast reaches every client, typed and framed', () => {
  const a = new FakeRes();
  const b = new FakeRes();
  addClient(a);
  addClient(b);

  broadcast('record.created', { id: 'r1', description: 'something' });

  for (const c of [a, b]) {
    assert.deepEqual(c.events(), [{ type: 'record.created', payload: { id: 'r1', description: 'something' } }]);
    assert.ok(c.written.at(-1).endsWith('\n\n'), 'each event must be terminated');
  }
});

test('a payload containing a newline does not break the frame', () => {
  const res = new FakeRes();
  addClient(res);
  broadcast('session.delta', { text: 'line one\nline two' });
  const frames = res.written.filter(w => w.startsWith('data: '));
  assert.equal(frames.length, 1, 'a raw newline would have split this into two events');
  assert.equal(res.events()[0].payload.text, 'line one\nline two');
});

/*
  A client whose socket has gone is dropped rather than retried forever, and
  dropping it mid-iteration must not skip the clients after it.
*/
test('a dead client is dropped without costing the live ones their event', () => {
  const alive = new FakeRes();
  const dead = new FakeRes();
  const after = new FakeRes();
  addClient(alive);
  addClient(dead);
  addClient(after);
  // Registered healthy, then the socket goes away, which is the real sequence.
  dead.failOnWrite = true;

  assert.equal(clientCount(), 3);
  broadcast('hosts.changed', [{ id: 'h1' }]);

  assert.equal(clientCount(), 2, 'the dead one is gone');
  assert.equal(alive.events().length, 1);
  assert.equal(after.events().length, 1, 'a client after the dead one still got it');
});

test('a closed client stops counting', () => {
  const res = new FakeRes();
  addClient(res);
  assert.equal(clientCount(), 1);
  res.emit('close');
  assert.equal(clientCount(), 0);
  broadcast('x', {});
  assert.equal(res.events().length, 0);
});

test('an errored client stops counting', () => {
  const res = new FakeRes();
  addClient(res);
  res.emit('error', new Error('reset'));
  assert.equal(clientCount(), 0);
});

/*
  Shutdown has to stop the keep-alive timers, not just forget the clients. A
  leaked interval keeps the event loop alive, and the process then ignores
  SIGINT until the shutdown fallback fires.
*/
test('closeAll ends every client and leaves no timer running', () => {
  const before = process.getActiveResourcesInfo().filter(r => r === 'Timeout').length;
  const a = new FakeRes();
  const b = new FakeRes();
  addClient(a);
  addClient(b);
  assert.ok(process.getActiveResourcesInfo().filter(r => r === 'Timeout').length > before,
    'the keep-alive timers are running');

  closeAll();

  assert.equal(clientCount(), 0);
  assert.ok(a.ended && b.ended, 'both responses were ended');
  assert.equal(process.getActiveResourcesInfo().filter(r => r === 'Timeout').length, before,
    'a keep-alive timer outlived shutdown');
});

test('broadcasting with nobody listening is not an error', () => {
  assert.equal(clientCount(), 0);
  assert.doesNotThrow(() => broadcast('nobody.home', { a: 1 }));
});
