import { test } from 'node:test';
import assert from 'node:assert';
import { openDb, initSchema } from '../store/db.js';
import { seedHosts, listHosts } from '../store/hosts.js';
import {
  createRecord, listRecords, updateRecord, promoteRecord, denyRecord, derivedConnections,
} from '../store/records.js';
import { proposeEdge, confirmEdge, denyEdge, listEdges } from '../store/edges.js';

const fresh = () => {
  const db = openDb(':memory:');
  initSchema(db);
  seedHosts(db);
  return db;
};
const auditCount = (db, id) =>
  db.prepare('select count(*) c from audit where target_id = ?').get(id).c;

test('a created record is pending and time-parsed', () => {
  const db = fresh();
  const r = createRecord(db, {
    event_time: '2026-08-13 17:59:02Z',
    hostname: 'EX-MAIL.example.test',
    source_ip: '10.20.1.11',
    destination_ip: '203.0.113.25',
    description: 'EARLIEST EVIDENCE OF COMPROMISE',
    confidence: 'High',
    mitre: 'T1071.001',
  }, { analyst: 'Lindqvist' });

  assert.equal(r.state, 'pending');
  assert.equal(r.time_tier, 'exact');
  assert.equal(r.time_parsed, '2026-08-13T17:59:02.000Z');
  assert.equal(r.created_by, 'Lindqvist');
});

test('an unmapped destination is discovered as a host', () => {
  const db = fresh();
  const before = listHosts(db).length;
  createRecord(db, {
    source_ip: '10.20.1.11', destination_ip: '198.51.100.7', description: 'c2',
  }, { analyst: 'a' });
  const after = listHosts(db);
  assert.equal(after.length, before + 1);
  assert.equal(after.find(h => h.ip === '198.51.100.7').source, 'discovered');
});

test('blank and N/A fields are stored as null, not empty strings', () => {
  const db = fresh();
  const r = createRecord(db, { description: 'x', pid: '', sha256: '   ' }, { analyst: 'a' });
  assert.equal(r.pid, null);
  assert.equal(r.sha256, null);
});

test('promote and deny each write exactly one audit row', () => {
  const db = fresh();
  const r = createRecord(db, { description: 'x' }, { analyst: 'a' });
  const p = promoteRecord(db, r.id, 'Lindqvist');
  assert.equal(p.state, 'filed');
  assert.equal(p.adjudicated_by, 'Lindqvist');
  assert.equal(auditCount(db, r.id), 1);
  const d = denyRecord(db, r.id, 'Lindqvist');
  assert.equal(d.state, 'denied');
  assert.equal(auditCount(db, r.id), 2);
});

test('correcting event_time re-derives the timeline position', () => {
  const db = fresh();
  const r = createRecord(db, { event_time: 'N/A', description: 'x' }, { analyst: 'a' });
  assert.equal(r.time_tier, 'unplaceable');
  const u = updateRecord(db, r.id, { event_time: '2026-08-19 ~11:59' }, 'Lindqvist');
  assert.equal(u.time_tier, 'approximate');
  assert.equal(u.time_parsed, '2026-08-19T11:59:00.000Z');
});

test('derived connections aggregate by address pair', () => {
  const db = fresh();
  const f = { source_ip: '10.20.1.11', destination_ip: '203.0.113.25', description: 'c2' };
  createRecord(db, f, { analyst: 'a' });
  createRecord(db, f, { analyst: 'a' });
  createRecord(db, { source_ip: '10.20.12.24', destination_ip: '203.0.113.25:8443', description: 'c2' }, { analyst: 'a' });

  const conns = derivedConnections(db);
  assert.equal(conns.length, 2);
  assert.equal(conns.find(c => c.src === '10.20.1.11').count, 2);
  assert.equal(conns.find(c => c.src === '10.20.12.24').dst, '203.0.113.25');
});

test('records with no address pair produce no connection', () => {
  const db = fresh();
  createRecord(db, { description: 'host forensics only', hostname: 'EX2 Webserver' }, { analyst: 'a' });
  assert.equal(derivedConnections(db).length, 0);
});

test('denying a record withdraws its connection from the map', () => {
  const db = fresh();
  const r = createRecord(db, {
    source_ip: '10.20.1.11', destination_ip: '198.51.100.7', description: 'c2',
  }, { analyst: 'a' });
  assert.equal(derivedConnections(db).length, 1);
  denyRecord(db, r.id, 'Lindqvist');
  assert.equal(derivedConnections(db).length, 0);
});

test('listRecords filters by state and orders unplaceable last', () => {
  const db = fresh();
  const a = createRecord(db, { description: 'a', event_time: '2026-08-19' }, { analyst: 'x' });
  createRecord(db, { description: 'b', event_time: 'N/A' }, { analyst: 'x' });
  createRecord(db, { description: 'c', event_time: '2026-08-13 17:59:02Z' }, { analyst: 'x' });
  promoteRecord(db, a.id, 'x');

  assert.equal(listRecords(db, { state: 'filed' }).length, 1);
  assert.equal(listRecords(db, { state: 'pending' }).length, 2);

  const order = listRecords(db).map(r => r.description);
  assert.deepEqual(order, ['c', 'a', 'b'], 'unplaceable sinks to the bottom');
});

test('listRecords filters by time window', () => {
  const db = fresh();
  createRecord(db, { description: 'early', event_time: '2026-08-13 17:59:02Z' }, { analyst: 'x' });
  createRecord(db, { description: 'late', event_time: '2026-08-19 15:26:00Z' }, { analyst: 'x' });
  const got = listRecords(db, { from: '2026-08-18T00:00:00.000Z' });
  assert.deepEqual(got.map(r => r.description), ['late']);
});

// --- causality edges -------------------------------------------------------

test('a proposed edge starts proposed and adjudicates once', () => {
  const db = fresh();
  const a = createRecord(db, { description: 'exchange beacon' }, { analyst: 'x' });
  const b = createRecord(db, { description: 'workstation beacon' }, { analyst: 'x' });

  const e = proposeEdge(db, { srcRecordId: a.id, dstRecordId: b.id, kind: 'caused', rationale: '5h05m later' }, 'claude');
  assert.equal(e.status, 'proposed');

  const c = confirmEdge(db, e.id, 'Lindqvist');
  assert.equal(c.status, 'confirmed');
  assert.equal(c.adjudicated_by, 'Lindqvist');
  assert.equal(auditCount(db, e.id), 1);

  denyEdge(db, e.id, 'Lindqvist');
  assert.equal(auditCount(db, e.id), 2);
  assert.equal(listEdges(db, { status: 'denied' }).length, 1);
});

test('an edge to a missing record is refused', () => {
  const db = fresh();
  const a = createRecord(db, { description: 'x' }, { analyst: 'x' });
  assert.throws(() => proposeEdge(db, { srcRecordId: a.id, dstRecordId: 'nope', kind: 'caused' }));
  assert.throws(() => proposeEdge(db, { srcRecordId: a.id, dstRecordId: a.id, kind: 'caused' }));
});
