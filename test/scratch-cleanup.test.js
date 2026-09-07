import { test } from 'node:test';
import assert from 'node:assert';
import { readdirSync, rmSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openDb, initSchema } from '../store/db.js';
import { seedThreads } from '../store/threads.js';
import { createSession } from '../store/sessions.js';
import { runTurn } from '../claude/runner.js';

/*
  A directory of this test's own.

  This used to list os.tmpdir() and treat anything new since the snapshot as
  its own leak — so a second `npm test`, CI parallelism, or a real Psephos
  server taking a turn on the same machine failed this test and then deleted
  the other process's live MCP config out from under it. Observed, not
  theorised: a run of four suites at once failed here with another process's
  hunt-mcp- directory named as the leak.
*/
const ROOT = mkdtempSync(join(tmpdir(), 'scratch-test-'));

const scratchDirs = () => readdirSync(ROOT)
  .filter(d => d.startsWith('hunt-mcp-') || d.startsWith('hunt-sys-'));

/*
  Every turn wrote an MCP config and, once the prompt moved to a file, the
  whole case file too — and removed neither. A week of hunting left thousands
  of directories behind, with the findings in them, in the temp directory of a
  machine other people use.

  The turn is made to fail immediately by pointing at a binary that does not
  exist, which exercises the error path rather than the happy one: that is the
  path a leak survives on.
*/
test('a turn removes its scratch files even when the subprocess never starts', async () => {
  const before = new Set(scratchDirs());
  const db = openDb(':memory:');
  initSchema(db);
  seedThreads(db);
  const s = createSession(db, { title: 't', analyst: 'Lindqvist' });

  const prev = process.env.HUNT_CLAUDE_BIN;
  const prevNoFile = process.env.HUNT_NO_PROMPT_FILE;
  const prevRoot = process.env.HUNT_SCRATCH_DIR;
  process.env.HUNT_SCRATCH_DIR = ROOT;
  process.env.HUNT_CLAUDE_BIN = join(tmpdir(), 'definitely-not-a-real-binary-xyz');
  // Skip the capability probe: it spawns too, and this test is about cleanup.
  process.env.HUNT_NO_PROMPT_FILE = '1';
  try {
    await assert.rejects(() => runTurn(db, s.id, 'hello', { analyst: 'Lindqvist', mode: 'research' }));
  } finally {
    if (prev === undefined) delete process.env.HUNT_CLAUDE_BIN;
    else process.env.HUNT_CLAUDE_BIN = prev;
    if (prevNoFile === undefined) delete process.env.HUNT_NO_PROMPT_FILE;
    else process.env.HUNT_NO_PROMPT_FILE = prevNoFile;
    if (prevRoot === undefined) delete process.env.HUNT_SCRATCH_DIR;
    else process.env.HUNT_SCRATCH_DIR = prevRoot;
  }

  const leaked = scratchDirs().filter(d => !before.has(d));
  // Clean up anything this test did leak, so a failure here does not litter.
  rmSync(ROOT, { recursive: true, force: true });
  assert.deepEqual(leaked, [], 'these were left behind');
});
