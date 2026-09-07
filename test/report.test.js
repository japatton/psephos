import { test } from 'node:test';
import assert from 'node:assert';
import { buildReport } from '../export/report.js';
import { openDb, initSchema } from '../store/db.js';
import { seedHosts, listHosts, setVerdict } from '../store/hosts.js';

/*
  The engagement deliverable is a report and the tool produced spreadsheets.
  Every input one needs was already in the store; the gaps section especially,
  which most teams write from memory at the end because nothing recorded
  coverage as it went.
*/

const input = () => ({
  mission: { name: 'Northern Watch', week: 'Week 2' },
  generatedAt: '2026-09-01T10:00:00.000Z',
  threads: [
    { id: 't1', key: 'A', name: 'Scheduled task persistence' },
    { id: 't2', key: 'B', name: 'Credential access' },
  ],
  records: [
    { id: 'r1', event_id: 'EV-1', state: 'filed', thread_id: 't1', hostname: 'EX-DC',
      description: 'schtasks created a task running from ProgramData', mitre: 'T1053.005',
      event_time: '2026-08-26 04:12:00Z', analyst_notes: 'confirmed on host' },
    { id: 'r2', event_id: 'EV-2', state: 'pending', thread_id: 't1', hostname: 'EX-WEB',
      description: 'unreviewed proposal', mitre: 'T1059' },
    { id: 'r3', event_id: 'EV-3', state: 'denied', thread_id: 't2', hostname: 'EX-FILE',
      description: 'ruled out', mitre: 'T1003' },
  ],
  hosts: [
    { id: 'h1', name: 'EX-DC', ip: '10.20.1.10', verdict: 'confirmed' },
    { id: 'h2', name: 'EX-WEB', ip: '10.20.1.12', verdict: null },
    { id: 'h3', name: 'EX-WS-2', ip: '10.20.2.20', verdict: null, presence: 'unanswered' },
  ],
  plan: {
    summary: { total: 4, complete: 2 },
    phases: [{ name: 'P1 — Hunt', tasks: [
      { key: 'p1-spray', title: 'Hunt for password spraying', status: 'complete' },
      { key: 'p1-persist', title: 'Hunt for scheduled-task persistence', status: 'pending' },
    ] }],
  },
  gaps: [{ repo: 'accounts', field: 'shell', note: 'Get-ADUser run without -Properties' }],
  emptyRepos: ['listening-ports', 'spns'],
});

const build = (over = {}) => buildReport({ ...input(), ...over });

test('the report names the engagement and when it was produced', () => {
  const md = build();
  assert.match(md, /Northern Watch/);
  assert.match(md, /Week 2/);
  assert.match(md, /2026-09-01/);
});

/*
  The distinction the whole tool is built on. A report that lists a proposal
  beside a confirmed finding launders an unreviewed model output into a
  deliverable somebody acts on.
*/
test('only adjudicated findings appear as findings', () => {
  const md = build();
  assert.match(md, /EV-1/, 'the confirmed finding is missing');
  assert.doesNotMatch(md, /unreviewed proposal/, 'a pending record was reported as a finding');
  assert.doesNotMatch(md, /ruled out/, 'a denied record was reported as a finding');
});

test('pending work is reported as outstanding, not hidden and not as a finding', () => {
  const md = build();
  const line = md.split('\n').find(l => /awaiting adjudication/i.test(l));
  assert.ok(line, 'the reader cannot tell that anything is still unadjudicated');
  assert.match(line, /\b1\b/, 'the count of outstanding proposals is not stated');
});

test('findings are grouped under the thread they belong to', () => {
  const md = build();
  const a = md.indexOf('Scheduled task persistence');
  const ev = md.indexOf('EV-1');
  assert.ok(a >= 0 && ev > a, 'the finding is not under its thread');
});

/*
  The section most teams reconstruct from memory. This tool has been recording
  coverage gaps as structured data the whole way through.
*/
test('the gaps section reports what was not collected', () => {
  const md = build();
  assert.match(md, /shell/, 'an acknowledged field gap is missing');
  assert.match(md, /listening-ports/, 'an empty repository is missing');
  assert.match(md, /EX-WS-2/, 'a host that never answered is missing');
});

test('hosts with a verdict are reported, and the rest are not asserted about', () => {
  const md = build();
  assert.match(md, /EX-DC/);
  assert.doesNotMatch(md, /EX-WEB[^\n]*compromis/i,
    'a host with no verdict was described as though one had been reached');
});

test('what was looked for is reported alongside what was found', () => {
  const md = build();
  assert.match(md, /Hunt for password spraying/);
  assert.match(md, /Hunt for scheduled-task persistence/);
});

test('an empty case file produces a report that says so rather than an empty one', () => {
  const md = buildReport({
    ...input(), records: [], hosts: [], gaps: [], emptyRepos: [],
  });
  assert.match(md, /Northern Watch/);
  assert.match(md, /no (confirmed )?findings/i,
    'a report with nothing in it must say nothing was found, not stay silent');
});

test('the same inputs produce the same report', () => {
  assert.equal(build(), build());
});

/*
  The two host lines, built from the store rather than from a fixture I typed.

  Both filters were written against words the store cannot hold — 'compromised'
  for a verdict (the schema allows unknown, suspected, confirmed, cleared; the
  drawer's LABEL is "Confirmed compromised") and 'no-response' for presence
  (the survey writes 'unanswered'; "no response" is the map's label for it). So
  the deliverable said zero compromised hosts and no coverage gaps whatever the
  team had adjudicated, and the fixture above — hand-written in the same two
  invented words — agreed with it.

  Passing real rows is the point: a verdict the schema rejects cannot be
  written here, so a filter that drifts from the vocabulary fails.
*/
test('the host lines are built from words the store can actually hold', () => {
  const db = openDb(':memory:');
  initSchema(db);
  seedHosts(db, [
    { name: 'EX-DC.example.test', ip: '10.20.1.10', enclave: 'A', segment: 'servers' },
    { name: 'EX-WS-2.example.test', ip: '10.20.2.22', enclave: 'A', segment: 'workstations',
      presence: 'unanswered' },
  ]);
  const dc = listHosts(db).find(h => h.name === 'EX-DC.example.test');
  setVerdict(db, dc.id, 'confirmed', 'Lindqvist');

  const md = build({ hosts: listHosts(db) });
  assert.match(md, /\*\*1\*\* host assessed compromised of 2 in the estate/,
    'an adjudicated host must reach the summary');
  assert.match(md, /\*\*EX-WS-2\.example\.test\*\* did not answer collection/,
    'a host that never answered is a coverage gap, and the report is where it is said');
  assert.doesNotMatch(md, /No coverage gaps were recorded/);
});
