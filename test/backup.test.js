import { test, before, after } from 'node:test';
import assert from 'node:assert';
import { mkdtempSync, rmSync, readdirSync, writeFileSync, existsSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { openDb, initSchema } from '../store/db.js';
import { createRecord, listRecords } from '../store/records.js';
import { takeBackup, backupIfChanged, backupDir } from '../store/backup.js';

/*
  The store is the whole case file and, unlike the plan, nothing was protecting
  it. The backlog records why that matters here specifically: of three backups
  found on disk, one held ten records and twenty-one messages that existed
  nowhere else, and survived only because somebody checked before deleting.
*/

let DIR, dbPath, db;

before(() => {
  DIR = mkdtempSync(join(tmpdir(), 'huntbackup-'));
  dbPath = join(DIR, 'hunt.db');
  db = openDb(dbPath);
  initSchema(db);
  createRecord(db, { description: 'first finding', hostname: 'EX-DC' }, { analyst: 'seed' });
});

after(() => { db?.close(); rmSync(DIR, { recursive: true, force: true }); });

test('a backup is a single self-contained file holding the same rows', () => {
  const out = takeBackup(db, { dbPath, label: 'test' });
  assert.ok(existsSync(out.path));

  // The trap the backlog describes: a .db that secretly needs its sidecar.
  assert.equal(existsSync(`${out.path}-wal`), false, 'the copy needs a sidecar');
  assert.equal(existsSync(`${out.path}-shm`), false, 'the copy needs a sidecar');

  const copy = new DatabaseSync(out.path);
  assert.equal(copy.prepare('pragma integrity_check').get().integrity_check, 'ok');
  const rows = copy.prepare('select description from records').all();
  copy.close();
  assert.deepEqual(rows.map(r => r.description), listRecords(db).map(r => r.description));
});

test('backups are pruned oldest first, down to what was asked for', () => {
  for (const n of ['a', 'b', 'c', 'd']) takeBackup(db, { dbPath, label: `keep${n}`, keep: 99 });
  const out = takeBackup(db, { dbPath, label: 'keepe', keep: 2 });
  assert.equal(out.kept, 2);
  const mine = readdirSync(backupDir(dbPath)).filter(f => f.endsWith('.db'));
  assert.equal(mine.length, 2, `left behind: ${mine.join(', ')}`);
});

/*
  A file somebody put here by hand, or an older tool's copy, is a deliberate
  safety copy. Pruning is allowed to tidy up after itself and nothing else.
*/
test('a backup this tool did not write is never pruned', () => {
  const theirs = join(backupDir(dbPath), 'pre-reset-case-2026-08-24.db');
  writeFileSync(theirs, 'not really a database');
  takeBackup(db, { dbPath, label: 'sweep', keep: 1 });
  assert.ok(existsSync(theirs), 'somebody else\'s backup was deleted');
});

// --- the scheduled path ------------------------------------------------------------

/*
  A timer that fires whether or not anything happened fills the directory with
  identical copies and prunes the one interesting snapshot out the back. The
  question is not "has time passed" but "has anything been written".
*/
test('an unchanged store is not backed up again', () => {
  const state = {};
  const first = backupIfChanged(db, { dbPath, label: 'auto', keep: 9 }, state);
  assert.ok(first, 'the first call has nothing to compare against and must take one');

  assert.equal(backupIfChanged(db, { dbPath, label: 'auto', keep: 9 }, state), null,
    'nothing was written, so there was nothing to snapshot');
});

test('a write since the last backup brings the next one back', () => {
  const state = {};
  backupIfChanged(db, { dbPath, label: 'auto2', keep: 9 }, state);
  createRecord(db, { description: 'a later finding', hostname: 'EX-WEB' }, { analyst: 'seed' });
  assert.ok(backupIfChanged(db, { dbPath, label: 'auto2', keep: 9 }, state),
    'a new record must be worth a snapshot');
});

/*
  A backup is the store: the same member tokens in plaintext, the same DM
  bodies, the same uploaded bytes. Both were written at whatever the umask
  said — world-readable on this machine — while the operator token file next
  to them was deliberately 0600.
*/
test('the store and its backups are readable only by their owner', () => {
  const dir = mkdtempSync(join(tmpdir(), 'psephos-modes-'));
  const dbPath = join(dir, 'hunt.db');
  const db = openDb(dbPath);
  initSchema(db);
  assert.equal(statSync(dbPath).mode & 0o077, 0, 'the store was readable by other accounts');

  const out = takeBackup(db, { dbPath, label: 'manual' });
  assert.equal(statSync(out.path).mode & 0o077, 0, 'a backup was readable by other accounts');
  db.close();
});
