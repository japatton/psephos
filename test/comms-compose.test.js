import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import { execSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

import { sendComposed } from '../web/views/comms.js';

/*
  Composing is the one place in the client where a request is built from state
  that a colleague — or you, clicking elsewhere — can change while the request
  is in flight. An upload takes long enough for that to happen, and the cost is
  not a lost message: it is a message delivered to a window that was not the one
  it was written in. A direct message is described in the UI as private to you
  both, so posting one into the team channel is a disclosure, not a glitch.

  The defence is structural rather than careful: the destination is an argument.
  A function that cannot see the mutable variable cannot read it late.
*/

const realFetch = globalThis.fetch;
let calls;

const ok = (bodyObj) => ({
  ok: true, status: 200, statusText: 'OK', json: async () => bodyObj,
});

beforeEach(() => {
  calls = [];
  globalThis.fetch = async (path, init) => {
    calls.push({ path, method: init?.method ?? 'GET', body: init?.body });
    return ok(path === '/api/files' ? { id: 'file-1' } : {});
  };
});

afterEach(() => { globalThis.fetch = realFetch; });

test('a composed message is posted to the channel it was given', async () => {
  await sendComposed('channel-A', { body: 'ready to hand over' });

  const post = calls.find(c => c.method === 'POST');
  assert.ok(post, 'nothing was sent');
  assert.equal(post.path, '/api/chat/channel-A/messages');
  assert.equal(JSON.parse(post.body).body, 'ready to hand over');
});

test('an attachment does not let the destination drift while it uploads', async () => {
  // The upload resolves first; the message must still address the channel the
  // caller named, not whatever the view is showing by then.
  await sendComposed('channel-A', {
    body: 'see attached',
    file: { name: 'evidence.txt', type: 'text/plain' },
  });

  assert.deepEqual(calls.map(c => c.path),
    ['/api/files', '/api/chat/channel-A/messages']);
  assert.equal(JSON.parse(calls[1].body).fileId, 'file-1');
});

test('a failure reaches the caller, so the text can be put back', async () => {
  globalThis.fetch = async () => ({
    ok: false, status: 500, statusText: 'Internal Server Error',
    json: async () => ({ error: 'the store is locked' }),
  });

  await assert.rejects(
    () => sendComposed('channel-A', { body: 'a long careful message' }),
    /the store is locked/,
    'swallowing this is how the analyst loses what they typed');
});

/*
  Enforced across the client, not just here: a request path built from a mutable
  module variable is only correct while nobody looks away, and which of those
  are safe depends on where the awaits happen to fall. Capturing the value makes
  the question unnecessary.
*/
test('no request path is built from the mutable active id', () => {
  const files = execSync('git ls-files web', { encoding: 'utf8' })
    .trim().split('\n').filter(f => f.endsWith('.js'));
  const bad = [];
  for (const f of files) {
    for (const m of readFileSync(f, 'utf8').matchAll(/(?:api|fetch)\(\s*`([^`]*)`/g)) {
      if (m[1].includes('${activeId}')) bad.push(`${f}: ${m[1]}`);
    }
  }
  assert.deepEqual(bad, [], 'capture the id into a local before awaiting');
});
