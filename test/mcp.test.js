import { test } from 'node:test';
import { saveFile } from '../store/files.js';
import assert from 'node:assert';
import { openDb, initSchema } from '../store/db.js';
import { seedHosts } from '../store/hosts.js';
import { listRecords, createRecord } from '../store/records.js';
import { listEdges } from '../store/edges.js';
import { handleToolCall, TOOLS } from '../claude/mcp-server.js';
import { repoView } from '../store/characterization.js';

const fresh = () => {
  const db = openDb(':memory:');
  initSchema(db);
  seedHosts(db);
  return db;
};
const ctx = { sessionId: null, analyst: 'claude' };

test('every hunt tool is declared with a usable schema', () => {
  assert.deepEqual(TOOLS.map(t => t.name).sort(),
    ['propose_edge', 'propose_finding', 'query_baseline', 'query_terrain',
      'search_records', 'stage_entities']);
  for (const t of TOOLS) {
    assert.equal(t.inputSchema.type, 'object', `${t.name} needs an object schema`);
    assert.ok(t.description.length > 40, `${t.name} needs a usable description`);
  }
});

test('propose_finding inserts a pending record and reports its tier', () => {
  const db = fresh();
  const res = handleToolCall(db, 'propose_finding', {
    description: 'Root cron script masquerading as a log-sync utility',
    hostname: 'EX2 Webserver',
    event_time: '2026-08-19 ~11:59 (discovered)',
    mitre: 'T1053.003',
    confidence: 'High',
  }, ctx);

  assert.equal(res.isError, false);
  const rows = listRecords(db, { state: 'pending' });
  assert.equal(rows.length, 1);
  assert.equal(rows[0].time_tier, 'approximate');
  assert.match(res.content[0].text, /approximate/);
});

test('propose_finding without a description is a validation error, not a write', () => {
  const db = fresh();
  const res = handleToolCall(db, 'propose_finding', { hostname: 'EX-DC' }, ctx);
  assert.equal(res.isError, true);
  assert.equal(listRecords(db).length, 0, 'a rejected proposal must not leave a row');
});

test('propose_edge links two records and starts proposed', () => {
  const db = fresh();
  const a = createRecord(db, { description: 'exchange beacon' }, { analyst: 'x' });
  const b = createRecord(db, { description: 'workstation beacon' }, { analyst: 'x' });
  const res = handleToolCall(db, 'propose_edge', {
    src_record_id: a.id, dst_record_id: b.id, kind: 'caused', rationale: '5h05m later',
  }, ctx);
  assert.equal(res.isError, false);
  assert.equal(listEdges(db, { status: 'proposed' }).length, 1);
});

test('propose_edge with a bad record id returns a correctable error', () => {
  const db = fresh();
  const res = handleToolCall(db, 'propose_edge',
    { src_record_id: 'nope', dst_record_id: 'also-nope', kind: 'caused' }, ctx);
  assert.equal(res.isError, true);
  assert.match(res.content[0].text, /no such record/);
});

test('query_terrain finds a seeded host by address', () => {
  const res = handleToolCall(fresh(), 'query_terrain', { ip: '10.30.2.100' }, ctx);
  assert.equal(res.isError, false);
  assert.match(res.content[0].text, /MQTT/);
});

test('query_terrain identifies a host the survey named after the fact', () => {
  // The address an early finding could not resolve. Once the survey names it,
  // the tool has to name it too, or the analyst re-investigates a known box.
  const res = handleToolCall(fresh(), 'query_terrain', { ip: '10.20.1.12' }, ctx);
  assert.equal(res.isError, false);
  assert.match(res.content[0].text, /EX-WEB/);
});

test('query_terrain says plainly when an address really is unmapped', () => {
  const res = handleToolCall(fresh(), 'query_terrain', { ip: '203.0.113.77' }, ctx);
  assert.equal(res.isError, false);
  assert.match(res.content[0].text, /not in the Example Engagement inventory/);
});

test('query_terrain lists a segment by prefix', () => {
  const res = handleToolCall(fresh(), 'query_terrain', { cidr: '10.30.2.' }, ctx);
  assert.match(res.content[0].text, /IP Cam 1/);
});

test('search_records supports dedupe before proposing', () => {
  const db = fresh();
  createRecord(db, { description: 'LSASS injection on EX-WS-12-4', hostname: 'EX-WS-12-4' }, { analyst: 'x' });
  const hit = handleToolCall(db, 'search_records', { text: 'lsass' }, ctx);
  assert.match(hit.content[0].text, /LSASS injection/);
  const miss = handleToolCall(db, 'search_records', { text: 'nothing-like-this' }, ctx);
  assert.match(miss.content[0].text, /No matching records/);
});

test('an unknown tool is an error, never a throw', () => {
  const db = fresh();
  assert.doesNotThrow(() => {
    const res = handleToolCall(db, 'rm_rf', {}, ctx);
    assert.equal(res.isError, true);
  });
});

test('malformed arguments never crash the turn', () => {
  const db = fresh();
  for (const args of [null, undefined, { description: 123 }, { description: {} }]) {
    assert.doesNotThrow(() => handleToolCall(db, 'propose_finding', args, ctx));
  }
});

/*
  The repository is the window the analyst is standing in, not a choice the
  model makes. This is the guard that replaces the one that failed: the
  catch-all it used to pick when unsure keyed every row on a constant label,
  and 879 rows of 912 overwrote each other before anybody noticed.
*/
test('the window pins the repository, whatever the model asks for', () => {
  const db = fresh();
  const out = handleToolCall(db, 'stage_entities', {
    repo: 'unclassified', entities: [{ name: 'a.exe', path: 'C:/a.exe' }],
  }, { repo: 'processes', host: 'HOST-A' });

  assert.ok(!out.isError, out.content[0].text);
  assert.match(out.content[0].text, /into processes/);
  // Said out loud rather than silently corrected, so the analyst learns their
  // paste was not what this tab is for.
  assert.match(out.content[0].text, /you asked for unclassified/);
  assert.equal(repoView(db, 'processes').rows.length, 1);
  assert.equal(repoView(db, 'unclassified').rows.length, 0);
});

/*
  The provenance check, wired end to end.

  The store can only judge an identity against the source when a caller hands it
  one, and this is the caller that has it: an attached file the extraction claims
  to have read. The warning has to reach the model in its tool result, because
  the model is the thing that can go back and re-read the file.
*/
test('an identity that is not in the attached file is reported back to the model', () => {
  const db = fresh();
  const file = saveFile(db, {
    name: 'accounts.txt', mime: 'text/plain', uploadedBy: 'Lindqvist',
    buffer: Buffer.from('Name      Enabled\nsvc_sql   True\njdoe      False\n'),
  });

  const out = handleToolCall(db, 'stage_entities', {
    entities: [{ username: 'svc_sql' }, { username: 'administrator' }],
  }, { repo: 'domain-accounts', host: 'range.example', fileId: file.id });

  assert.ok(!out.isError, out.content[0].text);
  assert.match(out.content[0].text, /WARNING/);
  assert.match(out.content[0].text, /administrator/,
    'the model cannot check its own work unless the value is named');
  // Flagged, not refused: the rows are still there to be looked at.
  assert.equal(repoView(db, 'domain-accounts').rows.length, 2);
});

test('an extraction whose identities are all in the file passes without a warning', () => {
  const db = fresh();
  const file = saveFile(db, {
    name: 'accounts.txt', mime: 'text/plain', uploadedBy: 'Lindqvist',
    buffer: Buffer.from('Name      Enabled\nsvc_sql   True\njdoe      False\n'),
  });
  const out = handleToolCall(db, 'stage_entities', {
    entities: [{ username: 'svc_sql' }, { username: 'jdoe' }],
  }, { repo: 'domain-accounts', host: 'range.example', fileId: file.id });

  assert.doesNotMatch(out.content[0].text, /WARNING/, out.content[0].text);
});

test('with no window pinned the model still chooses, and a bad choice is refused', () => {
  const db = fresh();
  assert.match(
    handleToolCall(db, 'stage_entities', { repo: 'nonsense', entities: [{ name: 'x' }] }, {}).content[0].text,
    /unknown repository/);
  const ok = handleToolCall(db, 'stage_entities',
    { repo: 'processes', entities: [{ name: 'a.exe', path: 'C:/a.exe' }] }, { host: 'H' });
  assert.match(ok.content[0].text, /into processes/);
});
