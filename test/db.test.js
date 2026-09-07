import { test } from 'node:test';
import assert from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openDb, initSchema } from '../store/db.js';
import { stageSnapshot, stagedPreview } from '../store/characterization.js';

const fresh = () => { const db = openDb(':memory:'); initSchema(db); return db; };

test('initSchema creates every table', () => {
  const names = fresh().prepare(
    "select name from sqlite_master where type='table' order by name"
  ).all().map(r => r.name);
  for (const t of ['audit', 'edges', 'hosts', 'messages', 'records', 'sessions', 'threads']) {
    assert.ok(names.includes(t), `missing table ${t}`);
  }
});

test('initSchema is idempotent', () => {
  const db = fresh();
  assert.doesNotThrow(() => initSchema(db));
});

test('records keeps the 18 source columns with their exact names', () => {
  const cols = fresh().prepare('pragma table_info(records)').all().map(c => c.name);
  const eighteen = [
    'event_id', 'event_time', 'hostname', 'source_ip', 'destination_ip', 'user',
    'indicator', 'command', 'pid', 'sha256', 'description', 'misp',
    'evidence_source', 'confidence', 'triage_status', 'analyst_notes', 'mitre', 'reference',
  ];
  for (const c of eighteen) assert.ok(cols.includes(c), `missing column ${c}`);
});

test('records rejects a state outside the vocabulary', () => {
  const db = fresh();
  assert.throws(() => db.prepare(
    'insert into records (id,state,created_at,time_tier) values (?,?,?,?)'
  ).run('x', 'bogus', 'now', 'exact'));
});

test('hosts rejects a verdict outside the vocabulary', () => {
  const db = fresh();
  assert.throws(() => db.prepare(
    'insert into hosts (id,name,source,verdict) values (?,?,?,?)'
  ).run('h', 'DC', 'seeded', 'probably-fine'));
});

test('audit id is a monotonic integer, because ordering carries meaning', () => {
  const db = fresh();
  const ins = db.prepare(
    'insert into audit (ts,analyst,action,target_type,target_id) values (?,?,?,?,?)'
  );
  ins.run('t1', 'a', 'promote', 'record', 'r1');
  ins.run('t2', 'a', 'deny', 'record', 'r2');
  const ids = db.prepare('select id from audit order by id').all().map(r => r.id);
  assert.deepEqual(ids, [1, 2]);
});

/*
  initSchema runs at every boot, so a migration that backfills gets exactly one
  chance to be right — and this one had to be told so. Written unguarded, it
  stamped committed_at over every uncommitted upload it found, which on the
  first boot meant "everything here predates staging" and on every boot after
  meant "everything an analyst has staged for review". The queue emptied
  overnight, discardStaged could no longer reach the rows, and nothing in the
  audit trail said a commit had happened.
*/
test('a staged import is still awaiting review after a restart', () => {
  const dir = mkdtempSync(join(tmpdir(), 'psephos-schema-'));
  const path = join(dir, 'hunt.db');

  let db = openDb(path);
  initSchema(db);
  stageSnapshot(db, {
    repo: 'accounts', host: 'EX-DC', sourceFormat: 'text',
    claimedRows: 2, countedRows: 2, analyst: 'Reyes', staged: true,
    entities: [{ name: 'svc-backup' }, { name: 'attacker' }],
  });
  assert.equal(stagedPreview(db).length, 1, 'the import should land staged');
  db.close();

  db = openDb(path);
  initSchema(db);
  assert.equal(stagedPreview(db).length, 1,
    'restarting the server committed an import nobody had reviewed');
  db.close();
});

/* The other half: on the boot that adds the column, everything already stored
   really does predate staging, and leaving it uncommitted would hide a whole
   estate's baseline behind a review queue nobody asked for. */
test('the boot that adds committed_at commits what was already there', () => {
  const dir = mkdtempSync(join(tmpdir(), 'psephos-schema-'));
  const path = join(dir, 'hunt.db');

  const db = openDb(path);
  initSchema(db);
  stageSnapshot(db, {
    repo: 'accounts', host: 'EX-DC', sourceFormat: 'text',
    claimedRows: 1, countedRows: 1, analyst: 'Reyes',
    entities: [{ name: 'svc-backup' }],
  });
  // Wind the store back to before staging existed.
  db.exec('alter table char_uploads drop column committed_at');
  initSchema(db);

  assert.equal(stagedPreview(db).length, 0,
    'a pre-staging upload must come back live, not stranded in a review queue');
  db.close();
});
