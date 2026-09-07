import { test } from 'node:test';
import assert from 'node:assert';
import { openDb, initSchema } from '../store/db.js';
import {
  listHosts, listArchivedHosts, withdrawnHosts, archiveHost, restoreHost,
  createHost, resolveHost, removeHost, seedHosts, getHost,
} from '../store/hosts.js';
import { createRecord, denyRecord, promoteRecord } from '../store/records.js';
import { listAudit } from '../store/audit.js';

const fresh = () => { const db = openDb(':memory:'); initSchema(db); return db; };

/*
  The workflow this exists for: a finding names a host nobody has heard of, so
  a host is created to hold it. The analyst investigates, clears the machine,
  and denies the finding. The finding stops counting — but the host it invented
  stays on the map wearing an evidence ring with nothing behind it, and cannot
  be deleted, because the denied record still points at it.
*/

test('a denied finding leaves behind a host that cannot simply be deleted', () => {
  const db = fresh();
  const rec = createRecord(db, { hostname: '192.0.2.50', description: 'beaconing' },
    { analyst: 'Okafor' });
  const host = listHosts(db).find(h => h.name === '192.0.2.50');
  assert.ok(host, 'the finding created a host to hang itself on');
  assert.equal(host.presence, 'evidence-only');

  denyRecord(db, rec.id, 'Okafor');
  assert.throws(() => removeHost(db, host.id), /still carries/,
    'deleting would orphan the record that explains why it exists');
});

test('withdrawnHosts is exactly the set whose evidence was denied', () => {
  const db = fresh();
  const denied = createRecord(db, { hostname: '192.0.2.50', description: 'x' }, { analyst: 'Okafor' });
  const kept = createRecord(db, { hostname: '192.0.2.51', description: 'y' }, { analyst: 'Okafor' });
  denyRecord(db, denied.id, 'Okafor');
  promoteRecord(db, kept.id, 'Okafor');

  const names = withdrawnHosts(db).map(h => h.name);
  assert.deepEqual(names, ['192.0.2.50']);
});

test('a seeded host is never withdrawn, whatever happened to its findings', () => {
  const db = fresh();
  seedHosts(db, [{ name: 'DC-01', ip: '192.0.2.10', enclave: 'A', segment: 'core' }]);
  const rec = createRecord(db, { hostname: 'DC-01', description: 'x' }, { analyst: 'Okafor' });
  denyRecord(db, rec.id, 'Okafor');

  assert.deepEqual(withdrawnHosts(db).map(h => h.name), [],
    'a machine in terrain is real whatever its findings turned out to be');
});

test('a host still carrying baseline rows is not withdrawn', () => {
  const db = fresh();
  const rec = createRecord(db, { hostname: '192.0.2.50', description: 'x' }, { analyst: 'Okafor' });
  denyRecord(db, rec.id, 'Okafor');
  db.prepare(`insert into char_uploads (id, repo, host, status, ts, kind, committed_at)
              values ('u1','processes','192.0.2.50','ok',?, 'collection', ?)`)
    .run('2026-08-26T00:00:00.000Z', '2026-08-26T00:00:00.000Z');
  db.prepare(`insert into char_entities (id, upload_id, repo, host, ident, label, attrs, ts)
              values ('e1','u1','processes','192.0.2.50','a.exe','a.exe','{}',?)`)
    .run('2026-08-26T00:00:00.000Z');

  assert.deepEqual(withdrawnHosts(db).map(h => h.name), [],
    'it is still holding something, so it is not a leftover');
});

// --- archiving ------------------------------------------------------------------

test('archiving takes a host off every read without destroying it', () => {
  const db = fresh();
  const h = createHost(db, { name: 'ghost', actor: 'Okafor' });
  assert.equal(listHosts(db).length, 1);

  archiveHost(db, h.id, { actor: 'Okafor', reason: 'evidence denied' });

  assert.equal(listHosts(db).length, 0, 'gone from the map and the list');
  assert.equal(listHosts(db, { includeArchived: true }).length, 1, 'still on file');
  assert.deepEqual(listArchivedHosts(db).map(x => x.name), ['ghost']);
  assert.ok(getHost(db, h.id).archived_at, 'and says when');
});

test('archiving and restoring are both audited, with who and why', () => {
  const db = fresh();
  const h = createHost(db, { name: 'ghost', actor: 'Okafor' });
  archiveHost(db, h.id, { actor: 'Reyes', reason: 'cleared of the adversary' });
  restoreHost(db, h.id, { actor: 'Lindqvist' });

  const rows = listAudit(db).filter(r => r.action.startsWith('host.arch')
    || r.action === 'host.restore');
  assert.deepEqual(rows.map(r => r.action).sort(), ['host.archive', 'host.restore']);
  const arch = rows.find(r => r.action === 'host.archive');
  assert.equal(arch.analyst, 'Reyes');
  assert.equal(JSON.parse(arch.after).reason, 'cleared of the adversary');
});

test('restoring puts it back', () => {
  const db = fresh();
  const h = createHost(db, { name: 'ghost', actor: 'Okafor' });
  archiveHost(db, h.id, { actor: 'Okafor' });
  restoreHost(db, h.id, { actor: 'Okafor' });
  assert.equal(listHosts(db).length, 1);
  assert.equal(getHost(db, h.id).archived_at, null);
});

test('archiving twice is not an error and does not restamp', () => {
  const db = fresh();
  const h = createHost(db, { name: 'ghost', actor: 'Okafor' });
  const first = archiveHost(db, h.id, { actor: 'Okafor' }).archived_at;
  assert.equal(archiveHost(db, h.id, { actor: 'Reyes' }).archived_at, first);
  assert.throws(() => archiveHost(db, 'no-such-host'), /no such host/);
});

test('an archived host is not offered for archiving again', () => {
  const db = fresh();
  const rec = createRecord(db, { hostname: '192.0.2.50', description: 'x' }, { analyst: 'Okafor' });
  denyRecord(db, rec.id, 'Okafor');
  const [ghost] = withdrawnHosts(db);
  archiveHost(db, ghost.id, { actor: 'Okafor' });
  assert.deepEqual(withdrawnHosts(db), []);
});

/*
  The host stops appearing, and so does the evidence attached to it — which is
  the whole point. A denied finding was already excluded from the counts; what
  was left was a node asserting that something was known about an address.
*/
test('resolveHost does not resurrect an archived host by naming it again', () => {
  const db = fresh();
  const rec = createRecord(db, { hostname: '192.0.2.50', description: 'x' }, { analyst: 'Okafor' });
  denyRecord(db, rec.id, 'Okafor');
  const [ghost] = withdrawnHosts(db);
  archiveHost(db, ghost.id, { actor: 'Okafor' });

  // A new finding naming the same address binds to the archived row rather
  // than minting a duplicate; restoring is the analyst's decision, not a
  // side effect of someone typing the address again.
  const again = resolveHost(db, { hostname: '192.0.2.50' });
  assert.equal(again, ghost.id);
  assert.ok(getHost(db, ghost.id).archived_at, 'still archived');
});
