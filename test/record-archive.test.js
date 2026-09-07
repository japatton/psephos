import { test } from 'node:test';
import assert from 'node:assert';
import { openDb, initSchema } from '../store/db.js';
import {
  createRecord, listRecords, listArchivedRecords, getRecord,
  archiveRecord, restoreRecord, denyRecord, promoteRecord, derivedConnections,
} from '../store/records.js';
import { listHosts, withdrawnHosts, bindUnplacedRecords, seedHosts } from '../store/hosts.js';
import { listAudit } from '../store/audit.js';

const fresh = () => { const db = openDb(':memory:'); initSchema(db); return db; };

/*
  Two different decisions, deliberately kept apart.

  Denying says the evidence did not show what it appeared to. Archiving says
  the team is finished with it either way — a confirmed finding can be archived
  once it is written up, and a denied one can stay on screen as long as anybody
  still wants to look at it.
*/

test('archiving is not denying, and neither implies the other', () => {
  const db = fresh();
  const r = createRecord(db, { hostname: 'H', description: 'x' }, { analyst: 'Okafor' });

  archiveRecord(db, r.id, { actor: 'Okafor', reason: 'written up' });
  const after = getRecord(db, r.id);
  assert.ok(after.archived_at);
  assert.equal(after.state, 'pending', 'archiving did not adjudicate it');

  restoreRecord(db, r.id, { actor: 'Okafor' });
  denyRecord(db, r.id, 'Okafor');
  assert.equal(getRecord(db, r.id).archived_at, null, 'denying did not archive it');
});

test('an archived finding leaves every working view', () => {
  const db = fresh();
  const kept = createRecord(db, { hostname: 'H', description: 'kept' }, { analyst: 'Okafor' });
  const gone = createRecord(db, { hostname: 'H', description: 'gone' }, { analyst: 'Okafor' });
  promoteRecord(db, kept.id, 'Okafor');
  promoteRecord(db, gone.id, 'Okafor');

  archiveRecord(db, gone.id, { actor: 'Okafor' });

  assert.deepEqual(listRecords(db).map(r => r.description), ['kept']);
  assert.equal(listRecords(db, { includeArchived: true }).length, 2, 'still on file');
  assert.deepEqual(listArchivedRecords(db).map(r => r.description), ['gone']);
});

test('a filter does not smuggle an archived finding back in', () => {
  const db = fresh();
  const r = createRecord(db, { hostname: 'H', description: 'x' }, { analyst: 'Okafor' });
  promoteRecord(db, r.id, 'Okafor');
  archiveRecord(db, r.id, { actor: 'Okafor' });

  assert.deepEqual(listRecords(db, { state: 'filed' }), []);
  assert.deepEqual(listRecords(db, { hostname: 'H' }), []);
});

/*
  The map is the reason this exists: the finding was retired and its
  consequences were still on screen.
*/
test('the connection an archived finding implied is forgotten', () => {
  const db = fresh();
  const r = createRecord(db,
    { hostname: 'H', source_ip: '192.0.2.10', destination_ip: '192.0.2.20', description: 'x' },
    { analyst: 'Okafor' });
  promoteRecord(db, r.id, 'Okafor');
  assert.equal(derivedConnections(db).length, 1);

  archiveRecord(db, r.id, { actor: 'Okafor' });
  assert.deepEqual(derivedConnections(db), [], 'no edge without a finding behind it');

  restoreRecord(db, r.id, { actor: 'Okafor' });
  assert.equal(derivedConnections(db).length, 1, 'and it comes back');
});

test('a host left holding only archived findings is offered for archiving', () => {
  const db = fresh();
  const r = createRecord(db, { hostname: '192.0.2.50', description: 'x' }, { analyst: 'Okafor' });
  assert.ok(listHosts(db).some(h => h.name === '192.0.2.50'));
  // Filed, not denied: archiving alone is enough to leave the host with nothing.
  promoteRecord(db, r.id, 'Okafor');
  assert.deepEqual(withdrawnHosts(db), [], 'while the finding stands, the host stands');

  archiveRecord(db, r.id, { actor: 'Okafor' });
  assert.deepEqual(withdrawnHosts(db).map(h => h.name), ['192.0.2.50']);
});

test('a later survey does not go back and bind an archived finding', () => {
  const db = fresh();
  // Nothing answers to this name yet, so the finding lands unbound.
  const r = createRecord(db, { hostname: 'LATE-01', description: 'orphan' }, { analyst: 'Okafor' });
  db.prepare('update records set host_id = null where id = ?').run(r.id);
  archiveRecord(db, r.id, { actor: 'Okafor' });

  // The host turns up in a survey. A live finding would be bound by this; a
  // retired one is left alone rather than quietly rejoining the case.
  seedHosts(db, [{ name: 'LATE-01', ip: '192.0.2.99', enclave: 'A', segment: 'core' }]);
  bindUnplacedRecords(db);
  assert.equal(getRecord(db, r.id).host_id, null);
});

test('archiving and restoring are audited, with who and why', () => {
  const db = fresh();
  const r = createRecord(db, { hostname: 'H', description: 'x' }, { analyst: 'Okafor' });
  archiveRecord(db, r.id, { actor: 'Reyes', reason: 'cleared of the adversary' });
  restoreRecord(db, r.id, { actor: 'Lindqvist' });

  const rows = listAudit(db).filter(a => a.action.startsWith('record.arch')
    || a.action === 'record.restore');
  assert.deepEqual(rows.map(a => a.action).sort(), ['record.archive', 'record.restore']);
  const arch = rows.find(a => a.action === 'record.archive');
  assert.equal(arch.analyst, 'Reyes');
  assert.equal(JSON.parse(arch.after).reason, 'cleared of the adversary');
});

test('archiving twice does not restamp, and an unknown id is an error', () => {
  const db = fresh();
  const r = createRecord(db, { hostname: 'H', description: 'x' }, { analyst: 'Okafor' });
  const first = archiveRecord(db, r.id, { actor: 'Okafor' }).archived_at;
  assert.equal(archiveRecord(db, r.id, { actor: 'Reyes' }).archived_at, first);
  assert.throws(() => archiveRecord(db, 'nope'), /no such record/);
  assert.throws(() => restoreRecord(db, 'nope'), /no such record/);
});
