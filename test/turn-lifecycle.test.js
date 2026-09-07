import { test, before, after } from 'node:test';
import assert from 'node:assert';
import { mkdtempSync, writeFileSync, chmodSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/*
  A turn's subprocess must not outlive the server.

  It spawns the CLI, which spawns its own MCP server, and that grandchild holds
  an independent connection to the case file. Nothing tracked either of them, so
  shutdown closed the HTTP server and the event hub and left them running: the
  operator watches the process exit while a model still holds a writable handle
  on the evidence, and the shutdown snapshot is taken around whatever it is
  doing.

  These drive the real spawn path with a stand-in binary rather than the CLI,
  because what is being tested is the lifecycle and not the model.
*/

const DIR = mkdtempSync(join(tmpdir(), 'turnlife-'));
const LOG = join(DIR, 'child.log');

/*
  A child that ignores SIGTERM, which is the case that matters: a CLI that stops
  when asked was never the problem. Polite termination alone would leave this
  one running, so it is what proves the escalation to SIGKILL.
*/
const STUBBORN = join(DIR, 'stubborn.mjs');
writeFileSync(STUBBORN, `
import { appendFileSync } from 'node:fs';
process.on('SIGTERM', () => appendFileSync(${JSON.stringify(LOG)}, 'ignored SIGTERM\\n'));
appendFileSync(${JSON.stringify(LOG)}, 'started\\n');
setInterval(() => {}, 1000);
process.stdin.resume();
`);
const BIN = join(DIR, 'stubborn');
writeFileSync(BIN, `#!/bin/sh\nexec node ${STUBBORN} "$@"\n`);
chmodSync(BIN, 0o755);

process.env.HUNT_CLAUDE_BIN = BIN;
process.env.HUNT_MISSION = 'example';
/*
  Skip the capability probe. It spawns the binary once with --append-system-
  prompt-file and waits up to fifteen seconds for it to close; a stand-in that
  deliberately hangs would hold the probe open and the turn would never spawn at
  all — which is exactly what happened while this test was being written, and
  looked like the tracking being broken.
*/
process.env.HUNT_NO_PROMPT_FILE = '1';

const { openDb, initSchema } = await import('../store/db.js');
const { seedThreads } = await import('../store/threads.js');
const { seedHosts } = await import('../store/hosts.js');
const { createSession } = await import('../store/sessions.js');
const { runTurn, killAllTurns, liveTurnCount, awaitTurnsExit } = await import('../claude/runner.js');

after(() => rmSync(DIR, { recursive: true, force: true }));

const fresh = () => {
  const db = openDb(':memory:');
  initSchema(db);
  seedThreads(db);
  seedHosts(db);
  return db;
};

const settle = (ms) => new Promise(r => setTimeout(r, ms));

/*
  Never wait on the turn forever.

  If the tracking regresses, killAllTurns signals nothing, the stand-in keeps
  running and the promise never settles — so the test hangs instead of failing,
  which in CI is a stuck job rather than a red one. Bound it: a turn that has
  not ended after the kill is itself the failure.
*/
const bounded = (p, ms, what) => Promise.race([
  p,
  new Promise((_, rej) => {
    const t = setTimeout(() => rej(new Error(`${what} never ended — the child outlived the kill`)), ms);
    t.unref?.();
  }),
]);

test('a running turn is tracked, and shutdown stops it', async () => {
  const db = fresh();
  const s = createSession(db, { title: 't', analyst: 'Lindqvist' });

  // Deliberately not awaited: the turn is meant to still be running.
  const turn = runTurn(db, s.id, 'hello', { analyst: 'Lindqvist', mode: 'research' })
    .catch(() => { /* killed out from under it, which is the point */ });

  await settle(700);
  assert.ok(existsSync(LOG) && readFileSync(LOG, 'utf8').includes('started'),
    'the stand-in never launched, so this test proves nothing');
  assert.equal(liveTurnCount(), 1, 'a turn in flight must be tracked');

  const stopped = killAllTurns({ graceMs: 300 });
  assert.equal(stopped, 1, 'shutdown must report what it signalled');

  // SIGTERM is ignored by this child on purpose; the escalation is what ends it.
  await settle(1500);
  assert.equal(liveTurnCount(), 0, 'a child that ignores SIGTERM was left running');
  assert.match(readFileSync(LOG, 'utf8'), /ignored SIGTERM/,
    'the fixture must actually have refused the polite signal');

  await bounded(turn, 5000, 'the turn');
});

test('killing turns when none are running is not an error', () => {
  assert.equal(liveTurnCount(), 0);
  assert.equal(killAllTurns(), 0);
});

/*
  The count has to come back down on its own too. If it only fell when
  killAllTurns ran, an ordinary finished turn would leave a dead child in the
  set and shutdown would report a number that means nothing.
*/
test('a turn that ends by itself stops being tracked', async () => {
  const db = fresh();
  const s = createSession(db, { title: 't2', analyst: 'Lindqvist' });
  const turn = runTurn(db, s.id, 'hello', { analyst: 'Lindqvist', mode: 'research' })
    .catch(() => {});
  await settle(600);
  assert.equal(liveTurnCount(), 1);
  killAllTurns({ graceMs: 200 });
  await settle(1200);
  assert.equal(liveTurnCount(), 0, 'the set still holds a process that has exited');
  await bounded(turn, 5000, 'the turn');
});

/*
  Shutdown has to WAIT for what it signalled.

  killAllTurns escalates to SIGKILL after a grace period, and nothing reached
  it: serve.js exited from server.close()'s callback about a millisecond later,
  so a child that ignores SIGTERM outlived the server every time — still
  holding, through its MCP grandchild, a writable handle on the case file. The
  test above proved the escalation works when something waits; this proves the
  waiting is available to the caller that needs it, with no sleep of its own.
*/
test('waiting for the signalled turns outlasts the escalation', async () => {
  const db = fresh();
  const s = createSession(db, { title: 't3', analyst: 'Lindqvist' });
  const turn = runTurn(db, s.id, 'hello', { analyst: 'Lindqvist', mode: 'research' })
    .catch(() => {});

  await settle(700);
  assert.equal(liveTurnCount(), 1, 'the stand-in never launched, so this proves nothing');

  killAllTurns({ graceMs: 300 });
  const left = await awaitTurnsExit({ timeoutMs: 4000 });
  assert.equal(left, 0, 'shutdown returned while a child that ignores SIGTERM was still alive');
  assert.equal(liveTurnCount(), 0);
  await bounded(turn, 5000, 'the turn');
});

/*
  A prompt bigger than the OS pipe buffer, handed to a CLI that has already
  exited — an unknown flag on an older build, a rejected --resume id, or not
  being logged in. The write raises EPIPE, and an unhandled 'error' on a stream
  ends the process: the whole server went down on a large paste. Measured
  before the fix at ~64KB, and the message endpoint accepts four megabytes.

  If this regresses the failure is not an assertion — it is this file's process
  dying, which is the same thing the server did.
*/
test('a child that exits before reading the prompt does not take the server with it', async () => {
  const QUITTER = join(DIR, 'quitter');
  writeFileSync(QUITTER, '#!/bin/sh\nexit 3\n');
  chmodSync(QUITTER, 0o755);
  const was = process.env.HUNT_CLAUDE_BIN;
  process.env.HUNT_CLAUDE_BIN = QUITTER;
  try {
    const db = fresh();
    const s = createSession(db, { title: 't4', analyst: 'Lindqvist' });
    const big = 'x'.repeat(900_000);
    await assert.rejects(
      bounded(runTurn(db, s.id, big, { analyst: 'Lindqvist', mode: 'research' }), 8000, 'the turn'),
      'a turn against a CLI that will not start must fail, not crash');
    assert.equal(liveTurnCount(), 0, 'and must not leave the count wrong');
  } finally {
    process.env.HUNT_CLAUDE_BIN = was;
  }
});
