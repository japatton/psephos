import { test, before } from 'node:test';
import assert from 'node:assert';
import { openDb, initSchema } from '../store/db.js';
import { seedThreads, listThreads } from '../store/threads.js';
import {
  createRecord, promoteRecord, searchRecords, listRecordSummaries, SUMMARY_FIELDS,
} from '../store/records.js';

/*
  Filtering lived in the browser, which meant every record had to be resident
  for search to work at all — so paginating the bootstrap payload would have
  quietly started returning answers computed over a subset. The search moves to
  the server first; that is the ordering constraint, and it is much cheaper to
  honour now than after there is data to migrate.
*/

let db, threadId;

before(() => {
  db = openDb(':memory:');
  initSchema(db);
  seedThreads(db);
  threadId = listThreads(db)[0]?.id ?? null;

  const mk = (over) => createRecord(db, {
    description: 'baseline observation', hostname: 'EX-DC',
    ...over,
  }, { analyst: 'seed', threadId });

  mk({ description: 'schtasks created a task', indicator: 'schtasks.exe', mitre: 'T1053.005' });
  mk({ description: 'suspicious logon', hostname: 'EX-WEB', user: 'svc_backup' });
  mk({ description: 'beacon traffic', destination_ip: '203.0.113.25', command: 'curl -s' });
  mk({ description: 'disk at 95% capacity', hostname: 'EX-FILE' });
  mk({ description: 'named pipe a_b observed', hostname: 'EX-FILE' });
});

const q = (opts) => searchRecords(db, opts);

test('a query searches the same fields the browser used to', () => {
  assert.equal(q({ q: 'schtasks' }).total, 1, 'description/indicator');
  assert.equal(q({ q: 'svc_backup' }).total, 1, 'user');
  assert.equal(q({ q: '203.0.113.25' }).total, 1, 'destination_ip');
  assert.equal(q({ q: 'curl' }).total, 1, 'command');
  assert.equal(q({ q: 'T1053' }).total, 1, 'mitre');
  assert.equal(q({ q: 'EX-WEB' }).total, 1, 'hostname');
});

test('matching ignores case, as it did in the browser', () => {
  assert.equal(q({ q: 'SCHTASKS' }).total, 1);
  assert.equal(q({ q: 'ex-web' }).total, 1);
});

/*
  LIKE treats % and _ as wildcards. An analyst searching for a literal "95%" or
  a pipe named a_b would otherwise get a silently wrong answer — the worst kind
  here, because a search that quietly over-matches looks like a search that
  worked.
*/
test('a query is matched literally, not as a LIKE pattern', () => {
  assert.equal(q({ q: '95%' }).total, 1, 'the percent was treated as a wildcard');
  assert.equal(q({ q: '%' }).total, 1, 'a bare percent matched everything');
  assert.equal(q({ q: 'a_b' }).total, 1, 'the underscore was treated as a wildcard');
  assert.equal(q({ q: 'a-b' }).total, 0, 'the underscore matched a different character');
});

test('filters combine rather than replace one another', () => {
  const all = q({}).total;
  const filed = q({ state: 'filed' }).total;
  assert.ok(filed < all, 'nothing is filed yet, so this should narrow');

  const id = q({ q: 'schtasks' }).rows[0].id;
  promoteRecord(db, id, 'analyst');
  assert.equal(q({ state: 'filed', q: 'schtasks' }).total, 1);
  assert.equal(q({ state: 'filed', q: 'beacon' }).total, 0);
});

test('a page is a window on the matches, and total counts them all', () => {
  const page = q({ limit: 2 });
  assert.equal(page.rows.length, 2);
  assert.equal(page.total, 5, 'total must count the matches, not the page');
});

test('paging walks every match exactly once', () => {
  const seen = [];
  for (let offset = 0; offset < 5; offset += 2) {
    seen.push(...q({ limit: 2, offset }).rows.map(r => r.id));
  }
  assert.equal(seen.length, 5);
  assert.equal(new Set(seen).size, 5, 'a record appeared on two pages or on none');
});

test('an unmatched query returns nothing rather than everything', () => {
  const out = q({ q: 'no-such-string-anywhere' });
  assert.deepEqual(out.rows, []);
  assert.equal(out.total, 0);
});

/*
  The bootstrap payload carries a projection, not whole records.

  Half of a record by weight is prose only the drawer ever shows — analyst notes,
  the command, the hash — and the bootstrap ships every record to every browser
  on every load and now on every reconnect. Measured at 2,000 findings: 2.24 MB
  whole, 1.11 MB projected.

  The list below is derived from what the views actually read, so it is the thing
  that goes stale when somebody renders a new field. That is what these assert.
*/

test('the summary carries every field a view renders', () => {
  // Each of these is read somewhere in web/ off state.records. Dropping one
  // from SUMMARY_FIELDS blanks it in a view rather than failing loudly, so it
  // is pinned here where the failure is legible.
  for (const f of [
    'id', 'state', 'thread_id', 'host_id', 'hostname', 'source_ip', 'destination_ip',
    'time_parsed', 'time_tier', 'event_time', 'archived_at',
    'description', 'indicator', 'mitre', 'confidence', 'created_by',
  ]) {
    assert.ok(SUMMARY_FIELDS.includes(f), `${f} is read by a view and must be in the summary`);
  }
});

test('and leaves behind the prose only the drawer opens', () => {
  for (const f of ['analyst_notes', 'command', 'sha256', 'misp', 'reference']) {
    assert.equal(SUMMARY_FIELDS.includes(f), false,
      `${f} is the weight this projection exists to drop`);
  }
});

test('a summary row has the summary fields and nothing else', () => {
  const rows = listRecordSummaries(db);
  assert.ok(rows.length > 0);
  assert.deepEqual(Object.keys(rows[0]).sort(), [...SUMMARY_FIELDS].sort());
});

test('the summary is the same set of records the full read returns', () => {
  assert.deepEqual(
    listRecordSummaries(db).map(r => r.id).sort(),
    searchRecords(db, {}).rows.map(r => r.id).sort());
});
