import { test, before } from 'node:test';
import assert from 'node:assert';
import { openDb, initSchema } from '../store/db.js';
import { seedThreads, listThreads } from '../store/threads.js';
import { seedHosts, listHosts, createHost } from '../store/hosts.js';
import {
  createRecord, listRecords, denyRecord, evidenceByHost, recordsForHost, unplacedRecords,
  bindRecordHost, updateRecord, getRecord,
} from '../store/records.js';

/*
  The map draws a badge per host from a count of the findings that touch it. It
  built that from the whole records array in the browser, which is why the array
  had to be there at all — and it is the only reason the payload grows with the
  case file rather than with the estate.

  Moving the count to the server is only safe if it counts the same things. The
  rule is fiddly and was arrived at by fixing a bug: the binding, either address,
  or an exact name, and short names deliberately excluded because two hosts
  called "Web" each showed a finding belonging to one of them. So this pins the
  server against a transcription of the browser's own algorithm rather than
  against numbers I worked out by hand — if the two ever disagree, one of them
  has changed and the test says which inputs made them differ.
*/

let db, hosts, threadId;

/** The browser's evidenceIndex(), transcribed. The reference, not the subject. */
function clientCounts(records, hostList, { includeDenied = false } = {}) {
  const ipOf = (v) => {
    if (!v) return null;
    const m = /(\d{1,3}(?:\.\d{1,3}){3})/.exec(String(v));
    return m ? m[1] : null;
  };
  const byIp = new Map(); const byName = new Map();
  const push = (m, k, id) => { if (k) m.set(k, [...(m.get(k) ?? []), id]); };
  for (const h of hostList) { push(byIp, h.ip, h.id); push(byName, (h.name ?? '').toLowerCase(), h.id); }

  const counts = new Map();
  for (const r of records) {
    if (!includeDenied && r.state === 'denied') continue;
    const touched = new Set();
    if (r.host_id) touched.add(r.host_id);
    for (const ip of [ipOf(r.source_ip), ipOf(r.destination_ip)]) {
      for (const id of byIp.get(ip) ?? []) touched.add(id);
    }
    if (!r.host_id) {
      for (const id of byName.get((r.hostname ?? '').toLowerCase()) ?? []) touched.add(id);
    }
    for (const id of touched) counts.set(id, (counts.get(id) ?? 0) + 1);
  }
  return Object.fromEntries(counts);
}

before(() => {
  db = openDb(':memory:');
  initSchema(db);
  seedThreads(db); seedHosts(db);
  threadId = listThreads(db)[0]?.id ?? null;
  hosts = listHosts(db);
  const known = hosts.find(h => h.ip) ?? hosts[0];

  const mk = (o) => createRecord(db, o, { analyst: 'seed', threadId });
  // A finding on a host by name.
  mk({ description: 'by name', hostname: known.name });
  // One that names the same host by address as well, which must count once.
  mk({ description: 'name and address', hostname: known.name, source_ip: known.ip });
  // One that touches two hosts through its two addresses.
  const other = hosts.find(h => h.ip && h.id !== known.id);
  mk({ description: 'two ends', source_ip: known.ip, destination_ip: other?.ip ?? null });
  // One nothing can place.
  mk({ description: 'nowhere', hostname: 'NOT-IN-TERRAIN', confidence: 'Low' });
  // And one that gets denied, which the map does not draw.
  const doomed = mk({ description: 'ruled out', hostname: known.name });
  denyRecord(db, doomed.id, 'analyst');
});

test('the server counts what the browser counted', () => {
  assert.deepEqual(
    evidenceByHost(db, hosts),
    clientCounts(listRecords(db), hosts));
});

test('a finding that names a host twice still counts once', () => {
  const known = hosts.find(h => h.ip);
  const server = evidenceByHost(db, hosts);
  // Two placeable findings touch it by name, one of which also names its
  // address; the denied one is excluded.
  assert.equal(server[known.id], clientCounts(listRecords(db), hosts)[known.id]);
});

test('a denied finding is not drawn on the map', () => {
  const withDenied = clientCounts(listRecords(db), hosts, { includeDenied: true });
  const server = evidenceByHost(db, hosts);
  const known = hosts.find(h => h.ip);
  assert.ok(withDenied[known.id] > server[known.id], 'the fixture no longer covers denial');
});

test('the same filters the browser applied still narrow it', () => {
  const all = evidenceByHost(db, hosts);
  const narrowed = evidenceByHost(db, hosts, { q: 'two ends' });
  assert.ok(Object.keys(narrowed).length > 0);
  assert.ok(Object.values(narrowed).reduce((a, b) => a + b, 0)
    < Object.values(all).reduce((a, b) => a + b, 0), 'the query did not narrow anything');
});

/*
  The point of the exercise: what comes back is one entry per host that carries
  evidence, not one per finding, so it stops growing with the case file.
*/
test('the result is bounded by the estate, not by the findings', () => {
  for (let i = 0; i < 300; i++) {
    createRecord(db, { description: `bulk ${i}`, hostname: hosts[0].name },
      { analyst: 'seed', threadId });
  }
  const counts = evidenceByHost(db, hosts);
  assert.ok(listRecords(db).length > 300);
  assert.ok(Object.keys(counts).length <= hosts.length,
    'the aggregate grew with the findings rather than with the estate');
});

// --- the two the drawer and the map read directly -----------------------------------

/*
  recordsForHost backs the host drawer's finding list and unplacedRecords backs
  the map's bind-by-hand flow, and neither had a test of its own. The route for
  the first is called from no test at all; the second is called once and only
  asserted to be an array.

  Both are one line from re-surfacing a denied finding as live evidence, which
  is the failure that matters: a record somebody ruled out reappearing on the
  host it was ruled out for, in the panel an analyst uses to decide what is
  still open. The client-side twin in web/core.js is tested; these are not the
  same function.
*/
test('a denied finding is not offered as evidence for its host', () => {
  const db2 = openDb(':memory:');
  initSchema(db2);
  seedThreads(db2); seedHosts(db2);
  const hs = listHosts(db2);
  const t = listThreads(db2)[0]?.id ?? null;
  const target = hs.find(h => h.ip) ?? hs[0];

  const live = createRecord(db2, { description: 'live one', hostname: target.name },
    { analyst: 'seed', threadId: t });
  const ruled = createRecord(db2, { description: 'ruled out', hostname: target.name },
    { analyst: 'seed', threadId: t });
  denyRecord(db2, ruled.id, 'Lindqvist');

  const shown = recordsForHost(db2, hs, target).map(r => r.id);
  assert.ok(shown.includes(live.id), 'the live finding should be offered');
  assert.ok(!shown.includes(ruled.id),
    'a denied finding was offered as evidence for the host it was ruled out on');
});

test('a denied finding is not offered for hand-binding either', () => {
  const db2 = openDb(':memory:');
  initSchema(db2);
  seedThreads(db2); seedHosts(db2);
  const hs = listHosts(db2);
  const t = listThreads(db2)[0]?.id ?? null;

  /*
    Nothing to place them by. A hostname nothing matches would not do: filing
    one discovers a host under that name, and the record lands bound. A finding
    with no host and no address named in it is what actually reaches the
    bind-by-hand list.
  */
  const orphan = createRecord(db2, { description: 'beaconing seen at the egress, source not attributed' },
    { analyst: 'seed', threadId: t });
  const ruled = createRecord(db2, { description: 'the same beacon, traced to the backup agent' },
    { analyst: 'seed', threadId: t });
  denyRecord(db2, ruled.id, 'Lindqvist');

  const offered = unplacedRecords(db2, hs).map(r => r.id);
  assert.ok(offered.includes(orphan.id), 'an unplaceable live finding should be offered');
  assert.ok(!offered.includes(ruled.id),
    'a denied finding was offered for binding to a host');
});

/*
  A bare name must not claim back a finding already placed somewhere else.

  This is the rule the whole binding exists for — two hosts are legitimately
  called "Web", and before host_id one rootkit finding rendered on both of
  them. The client twin is pinned in test/evidence-placement.test.js; deleting
  the guard from either of the two server functions the map and drawer actually
  call failed nothing at all.
*/
const twoWebs = () => {
  const d = openDb(':memory:');
  initSchema(d);
  const a = createHost(d, { name: 'Web', ip: '10.20.1.12', enclave: 'Enclave A', actor: 'seed' });
  const b = createHost(d, { name: 'Web', ip: '10.21.1.20', enclave: 'Enclave B', actor: 'seed' });
  return { db: d, a, b, hosts: listHosts(d) };
};

test('a name cannot claim back a finding already placed on another host', () => {
  const { db: d, a, b, hosts: hs } = twoWebs();
  // Bound to the Enclave B box, and naming the shared short name.
  const r = createRecord(d, { description: 'rootkit', hostname: 'Web' }, { analyst: 'seed' });
  bindRecordHost(d, r.id, b.id, { analyst: 'Lindqvist' });

  assert.deepEqual(recordsForHost(d, hs, b).map(x => x.id), [r.id]);
  assert.deepEqual(recordsForHost(d, hs, a).map(x => x.id), [],
    'the other Web shares only a name, and the finding is already placed');
  assert.deepEqual(evidenceByHost(d, hs), { [b.id]: 1 },
    'a placed finding must be counted once, on the host it is placed on');
});

/*
  Correcting the host a finding names has to move the finding.

  updateRecord called resolveHost for its side effect — discovering the host —
  and threw the answer away, so the binding still pointed at whoever the
  ORIGINAL name resolved to. The corrected finding stayed about the host it had
  just been corrected away from, and the map counted it on both.
*/
test('correcting the hostname moves the finding to the host it now names', () => {
  const d = openDb(':memory:');
  initSchema(d);
  seedHosts(d);
  const hs = listHosts(d);
  const from = hs.find(h => h.name === 'EX-DC.example.test');
  const to = hs.find(h => h.name === 'EX-WS-1.example.test');

  const r = createRecord(d, { description: 'beacon', hostname: from.name, source_ip: from.ip },
    { analyst: 'seed' });
  assert.equal(getRecord(d, r.id).host_id, from.id, 'filed against the host it named');

  updateRecord(d, r.id, { hostname: to.name, source_ip: to.ip }, 'Lindqvist');

  assert.equal(getRecord(d, r.id).host_id, to.id, 'the correction should re-bind it');
  assert.deepEqual(evidenceByHost(d, listHosts(d)), { [to.id]: 1 },
    'a corrected finding must not stay counted on the host it was corrected away from');
});

/* A hand-binding is a person's decision about a case a name could not settle,
   so a later correction to the name does not overrule it. */
test('a correction does not overrule a binding an analyst made by hand', () => {
  const { db: d, a, b, hosts: hs } = twoWebs();
  const r = createRecord(d, { description: 'rootkit', hostname: 'Web' }, { analyst: 'seed' });
  bindRecordHost(d, r.id, b.id, { analyst: 'Lindqvist' });

  updateRecord(d, r.id, { hostname: 'Web', source_ip: a.ip }, 'Okafor');
  assert.equal(getRecord(d, r.id).host_id, b.id,
    'the hand-binding should survive a correction to the fields it was made in spite of');
});
